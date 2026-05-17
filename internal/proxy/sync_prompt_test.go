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
