// CLI smoke tests for `kbouncer presets`.
package cli

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCLIRaw invokes the root command WITHOUT appending --db, for
// subcommands like `presets list/show` that don't accept the flag.
func runCLIRaw(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func TestCLI_Presets_List(t *testing.T) {
	out, _, err := runCLIRaw(t, "presets", "list")
	require.NoError(t, err)
	// All five starter presets must be visible.
	for _, name := range []string{
		"cluster-admin-minus-destructive",
		"eks-cluster-survey",
		"argocd-app-controller",
		"gke-developer",
		"incident-response-readonly",
	} {
		assert.Contains(t, out, name, "presets list must include %q", name)
	}
}

func TestCLI_Presets_Show(t *testing.T) {
	out, _, err := runCLIRaw(t, "presets", "show", "cluster-admin-minus-destructive")
	require.NoError(t, err)
	assert.Contains(t, out, "cluster-admin-minus-destructive")
	assert.Contains(t, out, "*:deletecollection")
	assert.Contains(t, out, "deny")
}

func TestCLI_Presets_Show_Unknown(t *testing.T) {
	_, _, err := runCLIRaw(t, "presets", "show", "nope")
	require.Error(t, err)
}

func TestCLI_Presets_Apply(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	out, _, err := runCLI(t, db, "presets", "apply", "eks-cluster-survey")
	require.NoError(t, err)
	assert.Contains(t, out, "applied")
	assert.Contains(t, out, "eks-cluster-survey")

	// Verify rules landed via `rules list`.
	out, _, err = runCLI(t, db, "rules", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "*:get")
	assert.Contains(t, out, "*:list")
}

func TestCLI_Presets_Apply_AddsNotOverwrites(t *testing.T) {
	// Audit-cadence (b) confirmation: applying the same preset twice
	// adds the rules twice — does NOT silently dedupe.
	db := filepath.Join(t.TempDir(), "kb.db")
	_, _, err := runCLI(t, db, "presets", "apply", "eks-cluster-survey")
	require.NoError(t, err)
	_, _, err = runCLI(t, db, "presets", "apply", "eks-cluster-survey")
	require.NoError(t, err)

	out, _, err := runCLI(t, db, "rules", "list")
	require.NoError(t, err)
	// At least two "*:get" rules (one per apply).
	hits := 0
	for _, line := range splitLines(out) {
		if containsAll(line, "*:get", "allow") {
			hits++
		}
	}
	assert.GreaterOrEqual(t, hits, 2,
		"applying twice must produce duplicate rules (audit-cadence (b))")
}

func splitLines(s string) []string {
	out := []string{}
	cur := ""
	for _, ch := range s {
		if ch == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(ch)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !contains(s, n) {
			return false
		}
	}
	return true
}

func contains(s, n string) bool {
	for i := 0; i+len(n) <= len(s); i++ {
		if s[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
