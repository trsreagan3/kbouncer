package audit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretToken is the bearer used across token-leak tests. Long
// enough to defeat the maskTokenInString length guard.
const secretToken = "super-secret-bearer-abcdef-1234567890"

func TestWebhookPusher_RequiresHTTPS(t *testing.T) {
	_, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:        "http://example.com/audit",
		Token:      secretToken,
		LookupHost: stubLookup("93.184.216.34"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https://")
}

func TestWebhookPusher_RequiresToken(t *testing.T) {
	_, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:        "https://example.com/audit",
		Token:      "",
		LookupHost: stubLookup("93.184.216.34"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Bearer token")
}

func TestWebhookPusher_SSRFRejectsRFC1918(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1"} {
		_, err := NewWebhookPusher(context.Background(), WebhookOptions{
			URL:        "https://" + ip + "/audit",
			Token:      secretToken,
			LookupHost: stubLookup(ip),
		})
		require.Error(t, err, "should reject %s", ip)
		assert.Contains(t, err.Error(), "internal range", "ip=%s", ip)
	}
}

func TestWebhookPusher_SSRFRejectsLoopback(t *testing.T) {
	_, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:        "https://127.0.0.1/audit",
		Token:      secretToken,
		LookupHost: stubLookup("127.0.0.1"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "127.0.0.0/8")
}

func TestWebhookPusher_SSRFRejectsCloudMetadata(t *testing.T) {
	_, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:        "https://169.254.169.254/audit",
		Token:      secretToken,
		LookupHost: stubLookup("169.254.169.254"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "169.254.0.0/16")
}

func TestWebhookPusher_SSRFRejectsInternalTLD(t *testing.T) {
	_, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:        "https://collector.internal/audit",
		Token:      secretToken,
		LookupHost: stubLookup("93.184.216.34"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".internal")
}

func TestWebhookPusher_SSRFAllowInternalOptOut(t *testing.T) {
	// Spin up a test server bound to 127.0.0.1; require --allow-
	// internal-webhook to use it. Default rejection without flag
	// already covered above.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()
	assert.NotNil(t, wp)
}

func TestWebhookPusher_SuccessfulPush(t *testing.T) {
	var received int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&received, 1)
		// Confirm the Authorization header carried the bearer.
		assert.Equal(t, "Bearer "+secretToken, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true, // httptest binds 127.0.0.1
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()

	for i := 0; i < 5; i++ {
		require.NoError(t, wp.Push(context.Background(), FromDecision(
			DecisionInput{DecisionID: int64(i), Verdict: "allow"})))
	}
	require.Eventually(t, func() bool {
		return atomic.LoadInt64(&received) == 5
	}, 3*time.Second, 10*time.Millisecond, "collector should receive 5 events")
	assert.Equal(t, int64(5), wp.Total())
}

func TestWebhookPusher_RetriesOn5xx(t *testing.T) {
	var attempts int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt64(&attempts, 1)
		if n < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()

	require.NoError(t, wp.Push(context.Background(), FromDecision(
		DecisionInput{DecisionID: 1, Verdict: "deny"})))
	// 1s backoff → must wait at least that before retry succeeds.
	require.Eventually(t, func() bool {
		return wp.Total() == 1
	}, 5*time.Second, 50*time.Millisecond)
	assert.GreaterOrEqual(t, atomic.LoadInt64(&attempts), int64(2),
		"should have retried at least once after 5xx")
}

func TestWebhookPusher_TokenNeverLeaksToOutput(t *testing.T) {
	// Server that always 500s — forces retries + lastError population
	// that captures the URL but MUST NOT capture the token.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit?secret=" + secretToken,
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()

	require.NoError(t, wp.Push(context.Background(), FromDecision(
		DecisionInput{DecisionID: 1, Verdict: "deny"})))
	// Give the worker enough time to fail at least once.
	require.Eventually(t, func() bool {
		return wp.LastError() != ""
	}, 5*time.Second, 50*time.Millisecond)

	// MaskedURL strips query string entirely.
	assert.NotContains(t, wp.MaskedURL(), secretToken,
		"masked URL must not contain the token")
	assert.NotContains(t, wp.MaskedURL(), "secret=",
		"masked URL must not contain the query string")
	assert.NotContains(t, wp.LastError(), secretToken,
		"last error message must not contain the token")
}

func TestWebhookPusher_OverflowDropsAndEmitsMarker(t *testing.T) {
	// A blocking server pins the worker on the first delivery so
	// subsequent pushes pile up + overflow.
	release := make(chan struct{})
	var seen int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt64(&seen, 1)
		if n == 1 {
			<-release // block first request
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
		QueueDepth:    2,
	})
	require.NoError(t, err)
	defer func() {
		close(release)
		wp.Close()
	}()

	// First push pins the worker. Subsequent pushes fill the queue
	// then overflow.
	for i := 0; i < 20; i++ {
		_ = wp.Push(context.Background(), FromDecision(
			DecisionInput{DecisionID: int64(i), Verdict: "allow"}))
	}
	require.Eventually(t, func() bool {
		return wp.Dropped() > 0
	}, 2*time.Second, 10*time.Millisecond, "should record drops")
}

func TestWebhookPusher_PushNeverBlocks(t *testing.T) {
	// Even with a queue depth of 1 + a wedged server, Push must
	// return quickly. We measure the deadline.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
		QueueDepth:    1,
	})
	require.NoError(t, err)
	defer wp.Close()

	start := time.Now()
	for i := 0; i < 1000; i++ {
		_ = wp.Push(context.Background(), FromDecision(
			DecisionInput{DecisionID: int64(i), Verdict: "allow"}))
	}
	elapsed := time.Since(start)
	assert.Less(t, elapsed, 500*time.Millisecond,
		"1000 Pushes must complete in well under a second even with wedged server")
}

func TestWebhookPusher_MaskURLStripsUserinfo(t *testing.T) {
	masked := maskURL("https://user:pass@example.com/path?q=1")
	assert.NotContains(t, masked, "user")
	assert.NotContains(t, masked, "pass")
	assert.NotContains(t, masked, "q=1")
	assert.Contains(t, masked, "example.com")
}

func TestWebhookPusher_StatusJSONNeverContainsToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()

	mgr := NewManager(ManagerOptions{WebhookPusher: wp})
	_ = wp.Push(context.Background(), FromDecision(
		DecisionInput{DecisionID: 1, Verdict: "deny"}))
	require.Eventually(t, func() bool {
		return wp.LastError() != ""
	}, 5*time.Second, 50*time.Millisecond)
	status := mgr.Status()
	b, err := json.Marshal(status)
	require.NoError(t, err)
	out := string(b)
	assert.NotContains(t, out, secretToken,
		"manager Status JSON must never contain the bearer token; got %s", out)
}

// stubLookup builds a fake DNS resolver that returns the given IPs.
// Lets the SSRF tests assert against a deterministic IP set without
// depending on real DNS.
func stubLookup(ips ...string) func(string) ([]string, error) {
	return func(string) ([]string, error) {
		return ips, nil
	}
}

// silenceTestLog drops zerolog output so the test runner stays clean.
var _ = silenceTestLog

func silenceTestLog() io.Writer { return io.Discard }

// Defensive: make sure these constants stay non-trivial.
func TestWebhookConstants(t *testing.T) {
	assert.Equal(t, 5, MaxWebhookAttempts)
	assert.GreaterOrEqual(t, len(webhookBackoffs), 5)
	assert.Equal(t, 32*time.Second, webhookBackoffs[len(webhookBackoffs)-1])
}

// Defensive: the manager's no-op + audit-disabled paths must not panic.
func TestManager_NilSafe(t *testing.T) {
	var m *Manager
	m.Emit(context.Background(), FromDecision(DecisionInput{}))
	assert.Equal(t, Status{}, m.Status())
	m.Close()
}

func TestManager_EmitFanOut(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: dir + "/a.jsonl"})
	require.NoError(t, err)
	defer lw.Close()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wp, err := NewWebhookPusher(ctx, WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()

	mgr := NewManager(ManagerOptions{LogWriter: lw, WebhookPusher: wp})
	defer mgr.Close()

	mgr.Emit(ctx, FromDecision(DecisionInput{DecisionID: 1, Verdict: "allow"}))
	require.Eventually(t, func() bool {
		return lw.Total() == 1 && wp.Total() == 1
	}, 3*time.Second, 10*time.Millisecond, "both channels should receive the event")
	st := mgr.Status()
	assert.True(t, st.LogConfigured)
	assert.True(t, st.WebhookConfigured)
	assert.Equal(t, int64(1), st.TotalEvents)
}

// Token-leak grep test: walk a captured manager Status + verify the
// raw token never appears in any field by scanning all string
// fields.
func TestTokenNeverInStatusFields(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()
	mgr := NewManager(ManagerOptions{WebhookPusher: wp})
	st := mgr.Status()
	for _, field := range []string{st.LogPath, st.LogLastError, st.WebhookMaskedURL, st.WebhookLastError} {
		assert.False(t, strings.Contains(field, secretToken),
			"token leaked in status field %q", field)
	}
}
