// Tests for the bulk-answer state layer (burst events, time-bounded
// rules, profile-reload signal, pending-prompt snapshot + bulk-answer).
//
// Per [[deliberate-feature-completion]]: every new store method has at
// least one round-trip test + a determinism test.

package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/rules"
)

func TestAddTimeBoundedRule_PermanentMatchesAddRule(t *testing.T) {
	s := freshDB(t)
	id, err := s.AddTimeBoundedRule(rules.ProxyRule{
		Pattern: "pods:get",
		Effect:  rules.EffectAllow,
	}, time.Time{}, "")
	require.NoError(t, err)
	assert.Positive(t, int64(id))

	active, err := s.ListActiveRules(time.Now().UTC())
	require.NoError(t, err)
	require.Len(t, active, 1, "permanent rule should appear in active set")
	assert.Equal(t, "pods:get", active[0].Rule.Pattern)
}

func TestAddTimeBoundedRule_ExpiredFilteredFromActive(t *testing.T) {
	s := freshDB(t)
	past := time.Now().UTC().Add(-1 * time.Hour)
	_, err := s.AddTimeBoundedRule(rules.ProxyRule{
		Pattern: "pods:get",
		Effect:  rules.EffectAllow,
	}, past, "bulk-answer")
	require.NoError(t, err)

	active, err := s.ListActiveRules(time.Now().UTC())
	require.NoError(t, err)
	assert.Empty(t, active, "expired rule must not appear in active set")

	// ListRules (unfiltered) MUST still return it — [[creates-never-
	// mutates]] preserves the audit trail.
	all, err := s.ListRules()
	require.NoError(t, err)
	require.Len(t, all, 1, "expired rule preserved for audit history")
}

func TestLoadRuleSet_FiltersExpired(t *testing.T) {
	s := freshDB(t)
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(1 * time.Hour)
	_, err := s.AddTimeBoundedRule(rules.ProxyRule{
		Pattern: "pods:get",
		Effect:  rules.EffectAllow,
	}, past, "bulk-answer")
	require.NoError(t, err)
	_, err = s.AddTimeBoundedRule(rules.ProxyRule{
		Pattern: "pods:list",
		Effect:  rules.EffectAllow,
	}, future, "bulk-answer")
	require.NoError(t, err)

	rs, err := s.LoadRuleSet()
	require.NoError(t, err)
	require.Equal(t, 1, rs.Len(), "LoadRuleSet should drop the expired row")
}

func TestCountExpiredRules(t *testing.T) {
	s := freshDB(t)
	past := time.Now().UTC().Add(-1 * time.Hour)
	for i := 0; i < 3; i++ {
		_, err := s.AddTimeBoundedRule(rules.ProxyRule{
			Pattern: "pods:" + []string{"get", "list", "watch"}[i],
			Effect:  rules.EffectAllow,
		}, past, "bulk-answer")
		require.NoError(t, err)
	}
	n, err := s.CountExpiredRules(time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

func TestRecordBurstEvent_RoundTrip(t *testing.T) {
	s := freshDB(t)
	id, err := s.RecordBurstEvent(12, 60)
	require.NoError(t, err)
	assert.Positive(t, id)

	b, err := s.LatestUnresolvedBurst()
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, id, b.ID)
	assert.Equal(t, 12, b.PromptCount)
	assert.Equal(t, 60, b.WindowSeconds)
	assert.Empty(t, b.ResolvedAt)
}

func TestRecordBurstEvent_RejectsNonPositive(t *testing.T) {
	s := freshDB(t)
	_, err := s.RecordBurstEvent(0, 60)
	assert.Error(t, err)
	_, err = s.RecordBurstEvent(5, 0)
	assert.Error(t, err)
}

func TestResolveBurstEvent_BookendsRow(t *testing.T) {
	s := freshDB(t)
	id, err := s.RecordBurstEvent(5, 60)
	require.NoError(t, err)
	ok, err := s.ResolveBurstEvent(id, BulkResolution10min)
	require.NoError(t, err)
	assert.True(t, ok)

	b, err := s.LatestUnresolvedBurst()
	require.NoError(t, err)
	assert.Nil(t, b, "after resolution there is no unresolved burst")

	// Idempotent: a second resolve of the same id returns false.
	ok, err = s.ResolveBurstEvent(id, BulkResolution10min)
	require.NoError(t, err)
	assert.False(t, ok, "ResolveBurstEvent must be idempotent on already-resolved rows")
}

func TestResolveBurstEvent_RejectsUnknownKind(t *testing.T) {
	s := freshDB(t)
	id, err := s.RecordBurstEvent(5, 60)
	require.NoError(t, err)
	_, err = s.ResolveBurstEvent(id, "made-up")
	assert.Error(t, err)
}

func TestSnapshotPendingPromptShapes_DedupAndOrder(t *testing.T) {
	s := freshDB(t)
	// Insert prompts of varying shapes.
	for i := 0; i < 3; i++ {
		_, err := s.AddPendingPrompt(PromptInput{
			DecisionID: int64(100 + i),
			Verb:       "get",
			Resource:   "pods",
			DenyReason: "test",
		})
		require.NoError(t, err)
	}
	_, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 200,
		Verb:       "list",
		Resource:   "deployments",
		DenyReason: "test",
	})
	require.NoError(t, err)

	shapes, err := s.SnapshotPendingPromptShapes()
	require.NoError(t, err)
	require.Len(t, shapes, 2)
	// Most-frequent first.
	assert.Equal(t, "pods", shapes[0].Resource)
	assert.Equal(t, "get", shapes[0].Verb)
	assert.Equal(t, 3, shapes[0].Count)
	assert.Equal(t, "deployments", shapes[1].Resource)
	assert.Equal(t, 1, shapes[1].Count)
}

func TestSnapshotPendingPromptShapes_SkipsEmptyVerbOrResource(t *testing.T) {
	s := freshDB(t)
	_, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 1,
		// Verb + Resource both empty (e.g. unclassifiable URL deny)
		DenyReason: "test",
	})
	require.NoError(t, err)
	shapes, err := s.SnapshotPendingPromptShapes()
	require.NoError(t, err)
	assert.Empty(t, shapes, "empty verb+resource shapes are skipped (no valid pattern)")
}

func TestBulkAnswerPendingPrompts_FlipsAllPending(t *testing.T) {
	s := freshDB(t)
	for i := 0; i < 3; i++ {
		_, err := s.AddPendingPrompt(PromptInput{
			DecisionID: int64(100 + i),
			Verb:       "get",
			Resource:   "pods",
			DenyReason: "test",
		})
		require.NoError(t, err)
	}
	n, err := s.BulkAnswerPendingPrompts(BulkResolution10min, "test-actor")
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)

	// All should now be answered with kind=bulk + target=10min.
	rows, err := s.ListPendingPrompts(PromptStatusAnswered, 10)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	for _, r := range rows {
		assert.Equal(t, PromptAnswerKindBulk, r.AnswerKind)
		assert.Equal(t, BulkResolution10min, r.AnswerTarget)
		assert.Equal(t, "test-actor", r.AnsweredBy)
	}
}

func TestBulkAnswerPendingPrompts_WakesSyncWaiters(t *testing.T) {
	s := freshDB(t)
	syncID, ch, err := s.AddSyncPendingPrompt(PromptInput{
		DecisionID: 999,
		Verb:       "create",
		Resource:   "pods",
		DenyReason: "test",
	})
	require.NoError(t, err)
	require.NotEmpty(t, syncID)
	defer s.ForgetSyncWaiter(syncID)

	_, err = s.BulkAnswerPendingPrompts(BulkResolution3h, "actor")
	require.NoError(t, err)

	select {
	case d := <-ch:
		assert.True(t, d.Allow, "session/3h/10min/profile bulk-answer wakes waiter with Allow=true")
		assert.Equal(t, PromptAnswerKindBulk, d.Kind)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("sync waiter never woke")
	}
}

func TestBulkAnswerPendingPrompts_NoneWakesWithDeny(t *testing.T) {
	s := freshDB(t)
	syncID, ch, err := s.AddSyncPendingPrompt(PromptInput{
		DecisionID: 1234,
		Verb:       "create",
		Resource:   "pods",
		DenyReason: "test",
	})
	require.NoError(t, err)
	defer s.ForgetSyncWaiter(syncID)

	_, err = s.BulkAnswerPendingPrompts(BulkResolutionNone, "actor")
	require.NoError(t, err)
	select {
	case d := <-ch:
		assert.False(t, d.Allow, "decision=none wakes waiter with Allow=false (original 403 stands)")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("sync waiter never woke on none")
	}
}

func TestProfileReloadSignal_UpsertRoundTrip(t *testing.T) {
	s := freshDB(t)
	got, err := s.GetProfileReloadSignal()
	require.NoError(t, err)
	assert.Nil(t, got, "no signal exists on fresh DB")

	require.NoError(t, s.SetProfileReloadSignal("staging-work", "alice"))
	got, err = s.GetProfileReloadSignal()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "staging-work", got.ProfileName)
	assert.Equal(t, "alice", got.RequestedBy)
	assert.Empty(t, got.AppliedAt, "freshly-set signal is unacked")

	// Overwriting clears applied_at again.
	require.NoError(t, s.AckProfileReloadSignal())
	got, err = s.GetProfileReloadSignal()
	require.NoError(t, err)
	assert.NotEmpty(t, got.AppliedAt)

	require.NoError(t, s.SetProfileReloadSignal("incident-response", "bob"))
	got, err = s.GetProfileReloadSignal()
	require.NoError(t, err)
	assert.Equal(t, "incident-response", got.ProfileName)
	assert.Equal(t, "bob", got.RequestedBy)
	assert.Empty(t, got.AppliedAt, "re-set must clear applied_at so watcher re-fires")
}

func TestProfileReloadSignal_RejectsEmptyName(t *testing.T) {
	s := freshDB(t)
	err := s.SetProfileReloadSignal("", "alice")
	assert.Error(t, err)
}

func TestSchemaVersion_Bumped(t *testing.T) {
	// Bulk-answer ux adds rules.expires_at + rules.created_by + 2
	// new tables (burst_events + profile_reload_signal). Bump must
	// land so reopens of an older DB pick up the additive migration.
	assert.GreaterOrEqual(t, SchemaVersion, 7)
}
