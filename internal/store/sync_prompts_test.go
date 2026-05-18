// Store-level tests for #203 synchronous deny-prompt v1.1.
//
// Covered here:
//
//   - AddSyncPendingPrompt returns a unique sync_wait_id + a channel
//     the caller can select on
//   - WakeSyncPendingPrompt fires the channel with the supplied
//     PromptDecision
//   - AnswerPendingPrompt(kind=ignore) → PromptDecision{Allow:false}
//   - AnswerPendingPrompt(kind=always|profile) → PromptDecision{Allow:true}
//   - ForgetSyncWaiter releases the in-memory slot (no leak)
//   - Two concurrent sync prompts get distinct sync_wait_ids + channels
//   - ListWaitingSyncPrompts filters to rows with an active waiter
//   - Wake after Forget is a no-op (no panic; channel send dropped)
//   - Race-clean via concurrent goroutine drivers
package store

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddSyncPendingPrompt_ReturnsIDAndChannel(t *testing.T) {
	s := freshDB(t)
	defer s.ForgetSyncWaiter("") // no-op; just exercise the path

	id, ch, err := s.AddSyncPendingPrompt(PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, id, "sync_wait_id must be non-empty (UUID-shaped)")
	assert.NotNil(t, ch, "caller needs a channel to select on")
	assert.Equal(t, 1, s.SyncWaiterCount(), "exactly one waiter registered")

	// Row landed on disk + carries the sync_wait_id.
	rows, err := s.ListPendingPrompts(PromptStatusPending, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, id, rows[0].SyncWaitID, "row must carry the sync_wait_id")

	s.ForgetSyncWaiter(id)
	assert.Equal(t, 0, s.SyncWaiterCount(), "waiter map must release after Forget")
}

func TestWakeSyncPendingPrompt_FiresChannel(t *testing.T) {
	s := freshDB(t)
	syncID, ch, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 1, DenyReason: "t"})
	require.NoError(t, err)
	defer s.ForgetSyncWaiter(syncID)

	go func() {
		// Small jitter so the receiver is actually blocked when we wake.
		time.Sleep(5 * time.Millisecond)
		s.WakeSyncPendingPrompt(syncID, PromptDecision{Allow: true, Kind: "always"})
	}()

	select {
	case d := <-ch:
		assert.True(t, d.Allow)
		assert.Equal(t, "always", d.Kind)
	case <-time.After(time.Second):
		t.Fatal("channel never fired")
	}
}

func TestAnswerPendingPrompt_IgnoreWakesAsDeny(t *testing.T) {
	s := freshDB(t)
	syncID, ch, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 1, DenyReason: "t"})
	require.NoError(t, err)

	// AddSyncPendingPrompt didn't return the row id directly; look it up.
	rows, err := s.ListPendingPrompts(PromptStatusPending, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	rowID := rows[0].ID
	require.Equal(t, syncID, rows[0].SyncWaitID)

	doneCh := make(chan PromptDecision, 1)
	go func() {
		doneCh <- <-ch
	}()

	ok, err := s.AnswerPendingPrompt(rowID, PromptAnswerKindIgnore, "", "tester")
	require.NoError(t, err)
	require.True(t, ok)

	select {
	case d := <-doneCh:
		assert.False(t, d.Allow, "ignore must resolve to DENY")
		assert.Equal(t, PromptAnswerKindIgnore, d.Kind)
		assert.Equal(t, "tester", d.AnsweredBy)
	case <-time.After(time.Second):
		t.Fatal("waiter never received decision")
	}
}

func TestAnswerPendingPrompt_AlwaysWakesAsAllow(t *testing.T) {
	s := freshDB(t)
	syncID, ch, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 7, DenyReason: "t"})
	require.NoError(t, err)
	rows, err := s.ListPendingPrompts(PromptStatusPending, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	rowID := rows[0].ID
	require.Equal(t, syncID, rows[0].SyncWaitID)

	doneCh := make(chan PromptDecision, 1)
	go func() {
		doneCh <- <-ch
	}()

	ok, err := s.AnswerPendingPrompt(rowID, PromptAnswerKindAlways, "", "alice")
	require.NoError(t, err)
	require.True(t, ok)

	select {
	case d := <-doneCh:
		assert.True(t, d.Allow, "always must resolve to ALLOW")
		assert.Equal(t, PromptAnswerKindAlways, d.Kind)
	case <-time.After(time.Second):
		t.Fatal("waiter never received decision")
	}
}

func TestAnswerPendingPrompt_ProfileWakesAsAllow(t *testing.T) {
	s := freshDB(t)
	_, ch, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 8, DenyReason: "t"})
	require.NoError(t, err)
	rows, _ := s.ListPendingPrompts(PromptStatusPending, 50)
	require.Len(t, rows, 1)

	doneCh := make(chan PromptDecision, 1)
	go func() { doneCh <- <-ch }()

	_, err = s.AnswerPendingPrompt(rows[0].ID, PromptAnswerKindProfile, "my-prof", "bob")
	require.NoError(t, err)

	select {
	case d := <-doneCh:
		assert.True(t, d.Allow, "profile-kind answer must resolve to ALLOW")
		assert.Equal(t, PromptAnswerKindProfile, d.Kind)
	case <-time.After(time.Second):
		t.Fatal("waiter never received decision")
	}
}

func TestForgetSyncWaiter_Idempotent(t *testing.T) {
	s := freshDB(t)
	id, _, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 1, DenyReason: "t"})
	require.NoError(t, err)
	require.Equal(t, 1, s.SyncWaiterCount())
	s.ForgetSyncWaiter(id)
	s.ForgetSyncWaiter(id) // duplicate must not panic
	assert.Equal(t, 0, s.SyncWaiterCount())
}

func TestWakeAfterForget_NoPanic(t *testing.T) {
	// Caller's responsibility ordering: ForgetSyncWaiter runs in the
	// request goroutine's defer; a delayed answer that arrives after
	// the goroutine gave up (timeout, ctx cancel) must NOT crash the
	// store. The buffered chan + missing-key short-circuit make this
	// safe; this test pins the invariant.
	s := freshDB(t)
	id, _, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 1, DenyReason: "t"})
	require.NoError(t, err)
	s.ForgetSyncWaiter(id)
	// Wake after forget — must be a no-op.
	s.WakeSyncPendingPrompt(id, PromptDecision{Allow: true})
}

func TestAddSyncPendingPrompt_DistinctIDs(t *testing.T) {
	s := freshDB(t)
	id1, _, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 1, DenyReason: "t"})
	require.NoError(t, err)
	id2, _, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 2, DenyReason: "t"})
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2, "each sync prompt gets its own sync_wait_id")
	assert.Equal(t, 2, s.SyncWaiterCount())
	s.ForgetSyncWaiter(id1)
	s.ForgetSyncWaiter(id2)
}

func TestListWaitingSyncPrompts_OnlyActiveWaiters(t *testing.T) {
	s := freshDB(t)

	// Two sync prompts; forget the second's waiter to simulate a
	// crashed-proxy row (sync_wait_id still on disk, but no in-memory
	// waiter).
	id1, _, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 1, DenyReason: "t1"})
	require.NoError(t, err)
	id2, _, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 2, DenyReason: "t2"})
	require.NoError(t, err)
	s.ForgetSyncWaiter(id2)
	defer s.ForgetSyncWaiter(id1)

	waiting, err := s.ListWaitingSyncPrompts(50)
	require.NoError(t, err)
	require.Len(t, waiting, 1, "only the still-waiting row should appear")
	assert.Equal(t, id1, waiting[0].SyncWaitID)
}

func TestSyncWaiterTimeoutPath_NoLeak(t *testing.T) {
	// Simulate the timeout path: the waiter goroutine gives up + calls
	// ForgetSyncWaiter. The store must not deadlock + must release the
	// map slot. Also exercise a delayed Wake to confirm the no-panic
	// invariant under realistic timing.
	s := freshDB(t)
	id, ch, err := s.AddSyncPendingPrompt(PromptInput{DecisionID: 1, DenyReason: "t"})
	require.NoError(t, err)

	// "Caller times out."
	s.ForgetSyncWaiter(id)
	assert.Equal(t, 0, s.SyncWaiterCount())

	// Wake arrives after Forget — drained into the dropped channel.
	s.WakeSyncPendingPrompt(id, PromptDecision{Allow: true})

	// Channel should still be readable (capacity 1, no send went through).
	select {
	case <-ch:
		t.Fatal("channel should not have received a value after Forget")
	case <-time.After(50 * time.Millisecond):
		// expected — no value sent
	}
}

func TestSyncWaiter_ConcurrentRace(t *testing.T) {
	// Race-clean: many concurrent wake + forget cycles against the
	// in-memory waiter map must not data-race. Run with `go test -race`.
	//
	// SQLite is single-writer per file so we DO NOT parallelize the
	// AddSyncPendingPrompt path here (it's covered serially by the
	// other tests). The concurrency-sensitive code is the syncMu-guarded
	// map + chan send pair; this test slams those directly.
	s := freshDB(t)
	const n = 50
	ids := make([]string, n)
	chs := make([]<-chan PromptDecision, n)
	for i := 0; i < n; i++ {
		id, ch, err := s.AddSyncPendingPrompt(PromptInput{
			DecisionID: int64(i + 1), DenyReason: "race",
		})
		require.NoError(t, err)
		ids[i] = id
		chs[i] = ch
	}
	require.Equal(t, n, s.SyncWaiterCount())

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			doneCh := make(chan struct{}, 1)
			go func() {
				select {
				case <-chs[i]:
				case <-time.After(2 * time.Second):
				}
				doneCh <- struct{}{}
			}()
			s.WakeSyncPendingPrompt(ids[i], PromptDecision{Allow: i%2 == 0})
			<-doneCh
			s.ForgetSyncWaiter(ids[i])
		}()
	}
	wg.Wait()
	assert.Equal(t, 0, s.SyncWaiterCount(), "all waiters must be released")
}

// GetPendingPromptBySyncWaitID — exercises the lookup helper added for
// the cross-process poll fallback. The helper underpins the proxy's
// ability to detect an answer issued from a DIFFERENT process (the
// typical `kbounce prompts answer` invocation): the in-memory channel
// wake fires in the answerer's process; the proxy notices via SQLite.

func TestGetPendingPromptBySyncWaitID_ReturnsRow(t *testing.T) {
	s := freshDB(t)
	syncID, _, err := s.AddSyncPendingPrompt(PromptInput{
		DecisionID: 11, Verb: "get", Resource: "pods", DenyReason: "lookup-by-sync-id",
	})
	require.NoError(t, err)
	defer s.ForgetSyncWaiter(syncID)

	row, err := s.GetPendingPromptBySyncWaitID(syncID)
	require.NoError(t, err)
	require.NotNil(t, row, "must return the row keyed by sync_wait_id")
	assert.Equal(t, syncID, row.SyncWaitID)
	assert.Equal(t, int64(11), row.DecisionID)
	assert.Equal(t, "get", row.Verb)
	assert.Equal(t, PromptStatusPending, row.Status,
		"freshly-added sync prompt must still be pending")
	assert.Empty(t, row.AnswerKind, "no answer recorded yet")
}

func TestGetPendingPromptBySyncWaitID_ReturnsNilWhenMissing(t *testing.T) {
	s := freshDB(t)
	row, err := s.GetPendingPromptBySyncWaitID("0123456789abcdef0123456789abcdef")
	require.NoError(t, err, "missing row must NOT be an error (mirrors GetPendingPrompt)")
	assert.Nil(t, row, "missing row must return nil")

	// Empty id is a defensive short-circuit; document that it returns nil
	// rather than scanning a NULL match.
	row, err = s.GetPendingPromptBySyncWaitID("")
	require.NoError(t, err)
	assert.Nil(t, row, "empty sync_wait_id must short-circuit to nil")
}

func TestGetPendingPromptBySyncWaitID_ReflectsAnsweredStatusUpdate(t *testing.T) {
	// The poll-fallback contract: after AnswerPendingPrompt commits,
	// a subsequent GetPendingPromptBySyncWaitID must see the new status
	// + answer_kind. This is what the proxy's 200ms ticker depends on
	// to detect cross-process resolution.
	s := freshDB(t)
	syncID, _, err := s.AddSyncPendingPrompt(PromptInput{
		DecisionID: 12, Verb: "delete", Resource: "deployments",
		DenyReason: "status-update-visible",
	})
	require.NoError(t, err)

	// Snapshot the row id so we can issue the answer.
	rows, err := s.ListPendingPrompts(PromptStatusPending, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	rowID := rows[0].ID
	require.Equal(t, syncID, rows[0].SyncWaitID)

	ok, err := s.AnswerPendingPrompt(rowID, PromptAnswerKindIgnore, "", "operator-bob")
	require.NoError(t, err)
	require.True(t, ok)

	row, err := s.GetPendingPromptBySyncWaitID(syncID)
	require.NoError(t, err)
	require.NotNil(t, row, "answered row must still be findable by sync_wait_id")
	assert.Equal(t, PromptStatusAnswered, row.Status)
	assert.Equal(t, PromptAnswerKindIgnore, row.AnswerKind)
	assert.Equal(t, "operator-bob", row.AnsweredBy)
	assert.NotEmpty(t, row.AnsweredAt, "answered_at must be populated")
}
