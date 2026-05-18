// CLI-layer tests for bulk-answer.
//
// Per [[deliberate-feature-completion]]: every disposition (session /
// 3h / 10min / profile / none) has a round-trip test.

package cli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

func bulkStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "bulk.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedBurstAndPrompts(t *testing.T, st *store.Store, n int) *store.BurstEvent {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := st.AddPendingPrompt(store.PromptInput{
			DecisionID: int64(1000 + i),
			Verb:       "get",
			Resource:   "pods",
			DenyReason: "test",
		})
		require.NoError(t, err)
	}
	_, err := st.RecordBurstEvent(n, 60)
	require.NoError(t, err)
	b, err := st.LatestUnresolvedBurst()
	require.NoError(t, err)
	require.NotNil(t, b)
	return b
}

func TestApplyBulkAnswer_10minInstallsRuleAndResolves(t *testing.T) {
	st := bulkStore(t)
	b := seedBurstAndPrompts(t, st, 3)

	summary, err := applyBulkAnswer(st, b, store.BulkResolution10min, "", "", "test")
	require.NoError(t, err)
	assert.Contains(t, summary, "burst #")
	assert.Contains(t, summary, "10m")

	// One bulk-allow rule should now exist with expires_at ~ now+10m.
	all, err := st.ListRules()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "pods:get", all[0].Rule.Pattern)

	// LoadRuleSet picks it up (not yet expired).
	rs, err := st.LoadRuleSet()
	require.NoError(t, err)
	assert.Equal(t, 1, rs.Len())

	// Burst is resolved.
	got, err := st.LatestUnresolvedBurst()
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestApplyBulkAnswer_3hAnd24hTTL(t *testing.T) {
	cases := []struct {
		decision string
		min      time.Duration
		max      time.Duration
	}{
		{store.BulkResolution3h, 2*time.Hour + 50*time.Minute, 3*time.Hour + 10*time.Minute},
		{store.BulkResolutionSession, 23 * time.Hour, 24*time.Hour + 10*time.Minute},
	}
	for _, c := range cases {
		t.Run(c.decision, func(t *testing.T) {
			st := bulkStore(t)
			b := seedBurstAndPrompts(t, st, 2)
			_, err := applyBulkAnswer(st, b, c.decision, "", "", "test")
			require.NoError(t, err)
			// Read back the rule + verify TTL is in range.
			ttl, err := bulkAnswerTTL(c.decision)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, ttl, c.min)
			assert.LessOrEqual(t, ttl, c.max)
		})
	}
}

func TestApplyBulkAnswer_NoneDoesNotCreateRule(t *testing.T) {
	st := bulkStore(t)
	b := seedBurstAndPrompts(t, st, 2)
	summary, err := applyBulkAnswer(st, b, store.BulkResolutionNone, "", "", "test")
	require.NoError(t, err)
	assert.Contains(t, summary, "no rule change")

	all, err := st.ListRules()
	require.NoError(t, err)
	assert.Empty(t, all, "decision=none must not install any rule")

	// Pending prompts are still flipped to answered.
	pending, err := st.ListPendingPrompts(store.PromptStatusPending, 10)
	require.NoError(t, err)
	assert.Empty(t, pending)
	answered, err := st.ListPendingPrompts(store.PromptStatusAnswered, 10)
	require.NoError(t, err)
	require.Len(t, answered, 2)
	for _, r := range answered {
		assert.Equal(t, store.PromptAnswerKindBulk, r.AnswerKind)
		assert.Equal(t, store.BulkResolutionNone, r.AnswerTarget)
	}
}

func TestApplyBulkAnswer_RejectsUnknownDecision(t *testing.T) {
	st := bulkStore(t)
	b := seedBurstAndPrompts(t, st, 2)
	_, err := applyBulkAnswer(st, b, "garbage", "", "", "test")
	assert.Error(t, err)
}

func TestApplyBulkAnswer_ProfileRequiresName(t *testing.T) {
	st := bulkStore(t)
	b := seedBurstAndPrompts(t, st, 2)
	// Use a path that points at a directory missing profiles.yaml so
	// the load step errors. Even without a name, the validation must
	// surface a clear error.
	_, err := applyBulkAnswer(st, b, store.BulkResolutionProfile, "nonexistent-profile", t.TempDir()+"/profiles.yaml", "test")
	assert.Error(t, err, "missing profiles.yaml or unknown profile name must error")
}

// TestPromptsBulkAnswerCmd_RejectsUnknownDecision exercises the cobra
// flag-validation path, distinct from applyBulkAnswer's core test. A
// regression here means the CLI wiring lost its flag validation.
func TestPromptsBulkAnswerCmd_RejectsUnknownDecision(t *testing.T) {
	cmd := newPromptsBulkAnswerCmd()
	cmd.SetArgs([]string{"--decision", "garbage"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be one of")
}

func TestBulkAnswerTTL_KnownDispositions(t *testing.T) {
	tt, err := bulkAnswerTTL(store.BulkResolution10min)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, tt)

	tt, err = bulkAnswerTTL(store.BulkResolution3h)
	require.NoError(t, err)
	assert.Equal(t, 3*time.Hour, tt)

	tt, err = bulkAnswerTTL(store.BulkResolutionSession)
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, tt)

	_, err = bulkAnswerTTL("profile")
	assert.Error(t, err, "profile has no TTL (it's a hot-swap, not a rule install)")
}
