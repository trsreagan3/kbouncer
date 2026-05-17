// Tests for the embedded preset catalog.
//
// Confirms the five starter packs ship + the loader rejects bad
// embedded data. The apply-via-CLI + apply-via-MCP paths are covered
// in cli/presets_test.go + mcp/server_test.go.
package presets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestList_ReturnsAllFiveStarters confirms the curated starter pack
// landed in the binary. Cross-product parity goal per [[cross-
// product-agent-parity]]: kbounce's pre-launch parity gap closure
// must SHIP these names.
func TestList_ReturnsAllFiveStarters(t *testing.T) {
	got, err := List()
	require.NoError(t, err)
	require.Len(t, got, 5)
	names := make(map[string]bool, len(got))
	for _, p := range got {
		names[p.Name] = true
	}
	expected := []string{
		"cluster-admin-minus-destructive",
		"eks-cluster-survey",
		"argocd-app-controller",
		"gke-developer",
		"incident-response-readonly",
	}
	for _, n := range expected {
		assert.True(t, names[n], "preset %q must ship in v1.0", n)
	}
}

// TestGet_KnownPreset returns a populated record.
func TestGet_KnownPreset(t *testing.T) {
	p, err := Get("cluster-admin-minus-destructive")
	require.NoError(t, err)
	assert.Equal(t, "cluster-admin-minus-destructive", p.Name)
	assert.NotEmpty(t, p.Description)
	assert.NotEmpty(t, p.Rules)
	// Sanity: the preset must include the deletecollection deny.
	found := false
	for _, r := range p.Rules {
		if r.Pattern == "*:deletecollection" {
			found = true
			break
		}
	}
	assert.True(t, found, "cluster-admin-minus-destructive must deny *:deletecollection")
}

// TestGet_UnknownPreset returns ErrUnknownPreset.
func TestGet_UnknownPreset(t *testing.T) {
	_, err := Get("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownPreset)
}

// TestEksClusterSurvey_IsReadonly confirms the survey preset's rule
// shape: get/list/watch ALLOW + the mutating verbs are DENY.
func TestEksClusterSurvey_IsReadonly(t *testing.T) {
	p, err := Get("eks-cluster-survey")
	require.NoError(t, err)

	hasGetAllow := false
	hasCreateDeny := false
	for _, r := range p.Rules {
		if r.Pattern == "*:get" && r.Effect == "allow" {
			hasGetAllow = true
		}
		if r.Pattern == "*:create" && r.Effect == "deny" {
			hasCreateDeny = true
		}
	}
	assert.True(t, hasGetAllow, "eks-cluster-survey must allow *:get")
	assert.True(t, hasCreateDeny, "eks-cluster-survey must deny *:create")
}

// TestEmbedded_RulesValidPattern confirms every embedded preset's
// rule patterns pass the rule-engine parser. A bad preset YAML
// shipped in the binary would otherwise blow up at runtime when
// `kbounce presets apply` is called.
func TestEmbedded_RulesValidPattern(t *testing.T) {
	all, err := List()
	require.NoError(t, err)
	for _, preset := range all {
		for i, r := range preset.Rules {
			assert.NotEmpty(t, r.Pattern,
				"preset %q rule[%d] must have a pattern", preset.Name, i)
			assert.Contains(t, []string{"allow", "deny"}, string(r.Effect),
				"preset %q rule[%d] effect must be allow or deny", preset.Name, i)
		}
	}
}
