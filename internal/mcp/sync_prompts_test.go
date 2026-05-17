// MCP-surface tests for the #203 kbounce_pending_sync_prompts tool.
//
// Determinism: the tool is a thin SQL + waiter-map intersection. The
// tests here exercise both halves:
//
//   - Empty waiter set → empty list (count=0)
//   - A live waiter (AddSyncPendingPrompt with no Forget) → 1 row,
//     carrying the sync_wait_id + the parsed verb/resource/namespace
//   - After Forget (simulates a crashed proxy losing the waiter) →
//     row is excluded even though it's still in pending_prompts
package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

func TestPendingSyncPrompts_EmptyByDefault(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{Store: st})
	got := callTool(t, srv, "kbounce_pending_sync_prompts", nil)
	assert.EqualValues(t, 0, got["count"])
	rows, _ := got["waiting_prompts"].([]any)
	assert.Empty(t, rows)
}

func TestPendingSyncPrompts_ReturnsActiveWaiters(t *testing.T) {
	st := freshStore(t)
	syncID, _, err := st.AddSyncPendingPrompt(store.PromptInput{
		DecisionID: 1, Verb: "list", Resource: "pods", Namespace: "default",
		DenyReason: "default policy: deny",
	})
	require.NoError(t, err)
	defer st.ForgetSyncWaiter(syncID)

	srv := NewServer(Config{Store: st})
	got := callTool(t, srv, "kbounce_pending_sync_prompts", nil)
	require.EqualValues(t, 1, got["count"])
	rows := got["waiting_prompts"].([]any)
	require.Len(t, rows, 1)
	row := rows[0].(map[string]any)
	assert.Equal(t, "list", row["verb"])
	assert.Equal(t, "pods", row["resource"])
	assert.Equal(t, "default", row["namespace"])
	assert.Equal(t, syncID, row["sync_wait_id"])
}

func TestPendingSyncPrompts_ExcludesForgottenWaiters(t *testing.T) {
	// Simulates a crashed proxy: row is still on disk, but the
	// in-memory waiter is gone. The MCP tool must not surface it —
	// nothing can wake that row anymore + telling the operator's
	// agent there's "an active wait" would be a lie.
	st := freshStore(t)
	id, _, err := st.AddSyncPendingPrompt(store.PromptInput{DecisionID: 1, DenyReason: "t"})
	require.NoError(t, err)
	st.ForgetSyncWaiter(id)

	srv := NewServer(Config{Store: st})
	got := callTool(t, srv, "kbounce_pending_sync_prompts", nil)
	assert.EqualValues(t, 0, got["count"])
}

func TestPendingSyncPrompts_RequiresStore(t *testing.T) {
	// Without a store configured, the tool surfaces a clear error.
	srv := NewServer(Config{})
	got := callTool(t, srv, "kbounce_pending_sync_prompts", nil)
	// Tool errors come back as structuredContent.error per the
	// dispatcher convention.
	errMsg, ok := got["error"].(string)
	require.True(t, ok, "expected error key on no-store tool call; got %v", got)
	assert.Contains(t, errMsg, "store not configured")
}
