// Proxy-integration tests for #203 synchronous deny-prompt v1.1.
//
// Behavior matrix the spec pins:
//
//   - cooperative + sync-prompt-on-deny → flag is silently ignored
//     (cooperative DENYs are advisory; nothing to block on)
//   - transparent + DENY + sync-prompt-on-deny + answer ALLOW (in-flight)
//     → forward to upstream + return upstream's response
//   - transparent + DENY + sync-prompt-on-deny + answer DENY (in-flight)
//     → return 403 with sync-prompt resolution header = "deny"
//   - transparent + DENY + sync-prompt-on-deny + TIMEOUT, default deny
//     → return 403 with sync-prompt resolution header = "timeout"
//   - transparent + DENY + sync-prompt-on-deny + TIMEOUT, default allow
//     → forward to upstream + return upstream's response (header = "timeout-allow")
//   - pause active → sync prompt does NOT fire (effective mode demoted
//     to cooperative; obs.Enforced=false)
//   - MCP integration: kbounce_pending_sync_prompts surfaces the
//     in-flight wait (test in mcp package).

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

func TestSyncPrompt_AnswerAllowForwardsToUpstream(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 2 * time.Second,
		SyncPromptDefault: DefaultPolicyDeny,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// Goroutine: poll for the sync prompt + answer "always" to unblock.
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			rows, err := st.ListWaitingSyncPrompts(10)
			if err == nil && len(rows) == 1 {
				_, _ = st.AnswerPendingPrompt(rows[0].ID, store.PromptAnswerKindAlways, "", "tester")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"sync-prompt allow must surface upstream's status, not the original 403; body=%s",
		string(body))
	assert.Contains(t, string(body), "PodList",
		"sync-prompt allow must forward to upstream + return upstream's response")
	assert.Equal(t, SyncPromptResolutionAllow, resp.Header.Get(SyncPromptResponseHeader),
		"resolution header must record 'allow'")
	require.Len(t, fas.received, 1, "exactly one request must reach the apiserver")

	// Async path is suppressed when sync is on.
	pending, err := st.ListPendingPrompts(store.PromptStatusPending, 50)
	require.NoError(t, err)
	assert.Empty(t, pending, "no pending row should remain (sync flow answered it)")
}

func TestSyncPrompt_AnswerIgnoreReturns403(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 2 * time.Second,
		SyncPromptDefault: DefaultPolicyDeny,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			rows, err := st.ListWaitingSyncPrompts(10)
			if err == nil && len(rows) == 1 {
				_, _ = st.AnswerPendingPrompt(rows[0].ID, store.PromptAnswerKindIgnore, "", "tester")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, SyncPromptResolutionDeny, resp.Header.Get(SyncPromptResponseHeader))
	assert.Empty(t, fas.received, "no upstream request must happen on deny resolution")

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Status",
		"deny resolution must emit the K8s-shaped Status body")
}

func TestSyncPrompt_TimeoutDefaultDenyReturns403(t *testing.T) {
	// No goroutine answers; the waiter times out. With
	// SyncPromptDefault=Deny the response is the original 403 with the
	// "timeout" resolution header.
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 150 * time.Millisecond,
		SyncPromptDefault: DefaultPolicyDeny,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, SyncPromptResolutionTimeout, resp.Header.Get(SyncPromptResponseHeader))
	assert.Empty(t, fas.received, "no upstream request on timeout-deny")

	// Waiter map must be released (no leak).
	assert.Equal(t, 0, st.SyncWaiterCount(), "waiter map must release after timeout")
}

func TestSyncPrompt_TimeoutDefaultAllowForwards(t *testing.T) {
	// SyncPromptDefault=Allow → timeout treats the call as answered-allow
	// and forwards. The header records the timeout-allow distinction so
	// reviewers can tell "this got through because no one answered" apart
	// from "this got through because the operator said allow."
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 150 * time.Millisecond,
		SyncPromptDefault: DefaultPolicyAllow,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	header := resp.Header.Get(SyncPromptResponseHeader)
	assert.True(t, strings.HasPrefix(header, SyncPromptResolutionTimeout),
		"timeout resolution header expected, got %q", header)
	require.Len(t, fas.received, 1, "timeout-allow must forward to upstream")
}

func TestSyncPrompt_CooperativeIgnoresFlag(t *testing.T) {
	// Cooperative mode: the sync flag must be a no-op (cooperative
	// DENYs are advisory; there is no 403 to block on). The request
	// completes immediately via the cooperative-allow path.
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:              ModeCooperative,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 30 * time.Second, // would block forever if it fired
		SyncPromptDefault: DefaultPolicyDeny,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
		require.NoError(t, err)
		defer resp.Body.Close()
		// Cooperative + deny still forwards (it's advisory).
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get(SyncPromptResponseHeader),
			"sync flag must not fire in cooperative mode")
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cooperative path must NOT block on sync prompt")
	}

	pending, err := st.ListWaitingSyncPrompts(10)
	require.NoError(t, err)
	assert.Empty(t, pending, "no sync prompt should have been enqueued in cooperative mode")
}

func TestSyncPrompt_PauseActiveSkipsSyncFlow(t *testing.T) {
	// Pause-active demotes effective mode to cooperative inside the
	// evaluator; obs.Enforced becomes false; the sync flow never fires.
	st := freshStore(t)
	_, err := st.StartPause(600, "test", "ops")
	require.NoError(t, err)

	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 30 * time.Second,
		SyncPromptDefault: DefaultPolicyDeny,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
		require.NoError(t, err)
		defer resp.Body.Close()
		// Pause demotes to cooperative → forwarded; no sync header set.
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get(SyncPromptResponseHeader))
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pause-active must skip the sync-prompt wait")
	}

	pending, err := st.ListWaitingSyncPrompts(10)
	require.NoError(t, err)
	assert.Empty(t, pending, "no sync prompt should fire during a pause")
}

func TestSyncPrompt_NoAsyncEnqueueWhenSyncOn(t *testing.T) {
	// Sync flow takes ownership of the enqueue. The legacy async row
	// must NOT also land — otherwise the operator sees two prompts for
	// one decision + answering one orphans the other.
	st := freshStore(t)

	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		PromptOnDeny:      true, // would fire async if not for sync's takeover
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 100 * time.Millisecond,
		SyncPromptDefault: DefaultPolicyDeny,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	rows, err := st.ListPendingPrompts(store.PromptStatusPending, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1, "exactly one row should exist (the sync row)")
	assert.NotEmpty(t, rows[0].SyncWaitID, "the row must be the sync-flow row")
}

func TestNormalize_AppliesSyncPromptDefaults(t *testing.T) {
	c := Config{}.Normalize()
	assert.Equal(t, DefaultSyncPromptTimeout, c.SyncPromptTimeout)
	assert.Equal(t, DefaultPolicyDeny, c.SyncPromptDefault)
}

// Cross-process poll fallback — pins the gap that the in-process #203
// wake mechanism leaves open. The typical operator runs `kbounce run`
// and `kbounce prompts answer` in DIFFERENT processes; each process
// has its own in-memory waiter map, so the answerer's wakeSyncWaiter
// call hits the wrong map and the proxy goroutine never sees it. The
// 200ms poll path closes that gap by reading pending_prompts.status
// from the shared SQLite file.

func TestSyncWait_CrossProcessAnswerPollsToDecision(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	// Second Store handle on the SAME SQLite file simulates a separate
	// `kbounce prompts answer` process: its own (empty) syncWaiters
	// map means the in-memory wake is a no-op; only the poll fallback
	// can resolve the proxy's wait.
	answerer, err := store.Open(st.Path())
	require.NoError(t, err)
	t.Cleanup(func() { _ = answerer.Close() })

	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: 3 * time.Second,
		SyncPromptDefault: DefaultPolicyDeny,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// "Other process" answers via the second store handle.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			// Poll the persisted table via the second handle — its
			// in-memory waiter map is empty, so this lookup is the
			// only thing tying the two processes together.
			rows, lerr := answerer.ListPendingPrompts(store.PromptStatusPending, 10)
			if lerr == nil && len(rows) == 1 && rows[0].SyncWaitID != "" {
				_, _ = answerer.AnswerPendingPrompt(
					rows[0].ID, store.PromptAnswerKindAlways, "", "other-process",
				)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	start := time.Now()
	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()
	elapsed := time.Since(start)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"cross-process answer (poll fallback) must surface upstream's status; body=%s",
		string(body))
	assert.Equal(t, SyncPromptResolutionAllow, resp.Header.Get(SyncPromptResponseHeader),
		"poll-fallback wake must resolve as a normal allow")
	require.Len(t, fas.received, 1, "exactly one upstream call after poll-resolved allow")

	// Latency budget: poll cadence is 200ms; the answerer loop sleeps
	// 10ms between checks. End-to-end resolution should land well
	// under 1s and emphatically NOT at the 3s timeout.
	assert.Less(t, elapsed, 1500*time.Millisecond,
		"poll fallback should resolve within ~poll-cadence + answerer-loop slack, got %s",
		elapsed)

	// Waiter slot must be released even though the wake came from poll
	// (defer ForgetSyncWaiter handles it).
	assert.Equal(t, 0, st.SyncWaiterCount(), "waiter map must release after poll resolution")

	// No leftover pending row.
	pending, err := st.ListPendingPrompts(store.PromptStatusPending, 50)
	require.NoError(t, err)
	assert.Empty(t, pending, "row should be marked answered, not pending")
}

func TestSyncWait_CrossProcessPollRespectsTimeout(t *testing.T) {
	// Same shape, but nobody ever answers. The poll ticker fires
	// repeatedly + finds the row still pending; the request must
	// resolve at SyncPromptTimeout with the default-deny verdict.
	// Pins that the poll loop does NOT mask the timeout path.
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	timeout := 350 * time.Millisecond
	s := NewServer(Config{
		Mode:              ModeTransparent,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: timeout,
		SyncPromptDefault: DefaultPolicyDeny,
		Upstream:          up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	start := time.Now()
	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()
	elapsed := time.Since(start)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"unanswered sync prompt must time out to the default deny")
	assert.Equal(t, SyncPromptResolutionTimeout, resp.Header.Get(SyncPromptResponseHeader))
	assert.Empty(t, fas.received, "no upstream call on timeout-deny")

	// Sanity: the response landed AT OR AFTER the timeout, not before
	// it. Without an upper bound — under load the test runner might
	// add latency — but we still want to confirm the timeout fired
	// (not, say, instant deny from a bug in the new poll path).
	assert.GreaterOrEqual(t, elapsed, timeout,
		"timeout path must wait at least SyncPromptTimeout, got %s", elapsed)

	assert.Equal(t, 0, st.SyncWaiterCount(), "waiter map must release on timeout")
}
