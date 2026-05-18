// MCP tests for the bulk-answer tools.
//
// Per [[deliberate-feature-completion]] + the bulk-prompt-answer-ux
// memo's "Don't" list: the bulk_answer tool MUST be off by default.
// Test the gate explicitly.

package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

func TestBulkAnswerMCP_DefaultDisabled(t *testing.T) {
	st := freshStore(t)
	// Seed a burst + pending prompts so the tool has something to act on.
	_, err := st.AddPendingPrompt(store.PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "test",
	})
	require.NoError(t, err)
	_, err = st.RecordBurstEvent(5, 60)
	require.NoError(t, err)

	// No BulkAnswerToken configured → tool refuses.
	s := NewServer(Config{Store: st})
	_, err = s.toolPromptsBulkAnswer(map[string]any{
		"decision":       store.BulkResolution10min,
		"operator_token": "anything-goes-still-refuses",
	})
	require.Error(t, err, "default-disabled: token unset → tool always refuses")
	assert.Contains(t, err.Error(), "disabled")
}

func TestBulkAnswerMCP_TokenMismatchRefuses(t *testing.T) {
	st := freshStore(t)
	_, err := st.AddPendingPrompt(store.PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "test",
	})
	require.NoError(t, err)
	_, err = st.RecordBurstEvent(5, 60)
	require.NoError(t, err)
	s := NewServer(Config{Store: st, BulkAnswerToken: "right-secret"})
	_, err = s.toolPromptsBulkAnswer(map[string]any{
		"decision":       store.BulkResolution10min,
		"operator_token": "wrong-secret",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operator_token")
}

func TestBulkAnswerMCP_TokenMatchAccepts(t *testing.T) {
	st := freshStore(t)
	for i := 0; i < 2; i++ {
		_, err := st.AddPendingPrompt(store.PromptInput{
			DecisionID: int64(100 + i), Verb: "get", Resource: "pods", DenyReason: "test",
		})
		require.NoError(t, err)
	}
	_, err := st.RecordBurstEvent(2, 60)
	require.NoError(t, err)
	s := NewServer(Config{Store: st, BulkAnswerToken: "secret"})
	got, err := s.toolPromptsBulkAnswer(map[string]any{
		"decision":       store.BulkResolution10min,
		"operator_token": "secret",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, got["summary"])
	assert.Equal(t, store.BulkResolution10min, got["decision"])

	// Burst is resolved.
	b, err := st.LatestUnresolvedBurst()
	require.NoError(t, err)
	assert.Nil(t, b)
	// One time-bounded rule installed.
	rs, err := st.LoadRuleSet()
	require.NoError(t, err)
	assert.Equal(t, 1, rs.Len())
}

func TestBulkAnswerMCP_NoBurstFails(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{Store: st, BulkAnswerToken: "secret"})
	_, err := s.toolPromptsBulkAnswer(map[string]any{
		"decision":       store.BulkResolution10min,
		"operator_token": "secret",
	})
	require.Error(t, err, "no unresolved burst → tool errors clearly")
	assert.Contains(t, err.Error(), "no unresolved burst")
}

func TestBulkPendingMCP_AlwaysAvailable(t *testing.T) {
	st := freshStore(t)
	_, err := st.AddPendingPrompt(store.PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "test",
	})
	require.NoError(t, err)
	_, err = st.RecordBurstEvent(3, 60)
	require.NoError(t, err)

	// No token → still works (read-only).
	s := NewServer(Config{Store: st})
	got, err := s.toolPromptsBulkPending(map[string]any{})
	require.NoError(t, err)
	assert.Positive(t, got["burst_id"].(int64))
	assert.Equal(t, 1, got["pending_now"])
	assert.False(t, got["bulk_answer_enabled"].(bool),
		"bulk_answer_enabled echoes whether the token gate is wired")

	// With token configured the introspection flips.
	s2 := NewServer(Config{Store: st, BulkAnswerToken: "x"})
	got2, err := s2.toolPromptsBulkPending(map[string]any{})
	require.NoError(t, err)
	assert.True(t, got2["bulk_answer_enabled"].(bool))
}

func TestBulkPendingMCP_NoBurst_ReturnsZero(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{Store: st})
	got, err := s.toolPromptsBulkPending(map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), got["burst_id"])
	assert.Equal(t, 0, got["pending_now"])
}

func TestBulkAnswerMCP_ProfileRequiresName(t *testing.T) {
	st := freshStore(t)
	_, err := st.AddPendingPrompt(store.PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "test",
	})
	require.NoError(t, err)
	_, err = st.RecordBurstEvent(2, 60)
	require.NoError(t, err)
	s := NewServer(Config{Store: st, BulkAnswerToken: "x"})
	_, err = s.toolPromptsBulkAnswer(map[string]any{
		"decision":       store.BulkResolutionProfile,
		"operator_token": "x",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "profile")
}

func TestBulkAnswerMCP_ToolListIncludesBothTools(t *testing.T) {
	descs := ToolDescriptors()
	names := make(map[string]bool, len(descs))
	for _, d := range descs {
		names[d["name"].(string)] = true
	}
	assert.True(t, names["kbounce_prompts_bulk_pending"],
		"kbounce_prompts_bulk_pending must be in tools/list")
	assert.True(t, names["kbounce_prompts_bulk_answer"],
		"kbounce_prompts_bulk_answer must be in tools/list (even if token-gated at call time)")
}
