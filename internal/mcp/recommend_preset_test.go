// MCP tool tests for kbounce_recommend_rules + kbounce_apply_preset
// (the two tools added alongside the recommender + presets work).
//
// Per audit-cadence (c) in the parent commit body: the recommend
// tool returns recommendations but does NOT apply them; the
// apply_preset tool DOES write to the store + we confirm the rule
// IDs come back so the agent can echo them.
package mcp

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

func TestMCP_RecommendRules_ReturnsRecommendations(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	// Seed 3 ALLOW decisions for pods:get.
	for i := 0; i < 3; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			ParsedResource:  "pods",
			ParsedVerb:      "get",
			ParsedNamespace: "default",
			DecisionVerdict: "allow",
		})
		require.NoError(t, err)
	}
	s := NewServer(Config{Store: st})

	got, err := s.toolRecommendRules(map[string]any{
		"min_support": 3,
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	recs, ok := got["recommendations"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, recs, 1)
	assert.Equal(t, "pods:get", recs[0]["proposed_rule"].(map[string]any)["pattern"])
	assert.Equal(t, 1, got["count"])
}

func TestMCP_RecommendRules_NoStore(t *testing.T) {
	s := NewServer(Config{Store: nil})
	_, err := s.toolRecommendRules(map[string]any{})
	require.Error(t, err)
}

func TestMCP_ApplyPreset_Success(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	s := NewServer(Config{Store: st})

	got, err := s.toolApplyPreset(map[string]any{
		"name": "eks-cluster-survey",
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "eks-cluster-survey", got["preset"])
	applied, _ := got["applied"].(int)
	assert.Greater(t, applied, 0)
	ids, _ := got["rule_ids"].([]int64)
	assert.Len(t, ids, applied,
		"rule_ids count must match applied count")

	// Verify rules landed.
	rs, err := st.ListRules()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rs), 1)
}

func TestMCP_ApplyPreset_Unknown(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	s := NewServer(Config{Store: st})

	_, err = s.toolApplyPreset(map[string]any{
		"name": "definitely-not-a-real-preset",
	})
	require.Error(t, err)
}

func TestMCP_ListPresets_ReturnsCatalog(t *testing.T) {
	s := NewServer(Config{})
	got, err := s.toolListPresets(nil)
	require.NoError(t, err)
	count, _ := got["count"].(int)
	assert.Equal(t, 5, count, "must surface all 5 starter presets")
}
