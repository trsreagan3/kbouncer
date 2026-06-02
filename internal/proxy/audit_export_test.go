package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/parser"
)

const integrationToken = "integration-bearer-1234567890-secret"

// TestAuditExport_ProxyDecideFansToLogAndWebhook is the Slice 1
// end-to-end contract: a proxy decision fires emitAuditEvent which
// reaches BOTH the JSONL log file AND the HTTPS webhook with the
// same event body.
func TestAuditExport_ProxyDecideFansToLogAndWebhook(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Webhook collector that records every body it receives.
	var received atomic.Int64
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		_ = json.NewDecoder(r.Body).Decode(&raw)
		// Confirm Bearer is present (token leak test is separate)
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer "+integrationToken, auth)
		b, _ := json.Marshal(raw)
		bodies = append(bodies, string(b))
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	lw, err := audit.NewLogWriter(ctx, audit.LogWriterOptions{Path: logPath})
	require.NoError(t, err)
	defer lw.Close()
	wp, err := audit.NewWebhookPusher(ctx, audit.WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         integrationToken,
		AllowInternal: true, // httptest binds 127.0.0.1
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()
	mgr := audit.NewManager(audit.ManagerOptions{LogWriter: lw, WebhookPusher: wp})
	defer mgr.Close()

	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p1")
	obs := EvaluateRequestFull(req, st, ModeCooperative, DefaultPolicyDeny,
		nil, "", EvalOptions{
			AuditEmitter:  mgr,
			AuditHost:     "127.0.0.1:8766",
			AuditUpstream: "kubernetes.default.svc",
		})
	require.NotNil(t, obs)

	// Log file gets the event in OCSF wire shape.
	require.Eventually(t, func() bool {
		return lw.Total() == 1
	}, 3*time.Second, 10*time.Millisecond, "log writer should receive 1 event")
	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &m))
	assert.Equal(t, float64(6003), m["class_uid"])
	meta := m["metadata"].(map[string]any)
	prod := meta["product"].(map[string]any)
	assert.Equal(t, "kbounce", prod["name"])
	assert.Equal(t, "iam-jit", prod["vendor_name"])
	// src_endpoint surfaces the proxy bind host:port; dst_endpoint
	// surfaces the upstream apiserver. Both required by OCSF.
	src := m["src_endpoint"].(map[string]any)
	assert.Equal(t, "127.0.0.1", src["ip"])
	assert.Equal(t, float64(8766), src["port"])
	dst := m["dst_endpoint"].(map[string]any)
	assert.Equal(t, "kubernetes.default.svc", dst["hostname"])

	// Webhook gets the event.
	require.Eventually(t, func() bool {
		return received.Load() == 1
	}, 3*time.Second, 10*time.Millisecond, "webhook should receive 1 event")
	require.Len(t, bodies, 1)
	// The webhook body must NOT contain the bearer token.
	assert.NotContains(t, bodies[0], integrationToken,
		"webhook body must not contain the bearer token")
}

func TestAuditExport_TokenNeverInLogFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := audit.NewLogWriter(ctx, audit.LogWriterOptions{Path: logPath})
	require.NoError(t, err)
	defer lw.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wp, err := audit.NewWebhookPusher(ctx, audit.WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         integrationToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()
	mgr := audit.NewManager(audit.ManagerOptions{LogWriter: lw, WebhookPusher: wp})
	defer mgr.Close()

	st := freshStore(t)
	for i := 0; i < 10; i++ {
		req := parser.MustParseTestURL(http.MethodGet, "/api/v1/pods")
		EvaluateRequestFull(req, st, ModeCooperative, DefaultPolicyDeny,
			nil, "", EvalOptions{AuditEmitter: mgr})
	}
	require.Eventually(t, func() bool {
		return lw.Total() == 10
	}, 3*time.Second, 10*time.Millisecond)
	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), integrationToken,
		"JSONL audit log MUST NOT contain the webhook bearer token")
}

// TestAuditExport_HotPathNeverBlocks asserts the [[security-team-
// audit-export]] hot-path invariant: even with a wedged webhook,
// proxy decision evaluation completes promptly. We use a webhook
// that sleeps forever + queue depth = 1.
//
// The bound is race-aware: hotPathBound is 2s under normal builds and
// 15s under -race (race instrumentation adds ~10-20x overhead per
// synchronisation point). 15s is still well below the 30s wedge and
// proves the enqueue never serialises behind the wedged worker.
//
// Teardown fix: the original test used plain defer ordering that left
// the webhook worker stuck inside sendOnce for the full 30s wedge
// sleep before Close() could return (defers are LIFO, so
// wp.Close() ran before cancel()). We now:
//  1. Give the fake server handler a cancellable context so it exits
//     promptly when teardown starts (srv.CloseClientConnections lets
//     httptest.Server.Close() return without waiting for the handler).
//  2. Cancel the worker context before calling mgr.Close() so the
//     in-flight HTTP request is aborted via context cancellation
//     rather than waiting for the client.Timeout.
func TestAuditExport_HotPathNeverBlocks(t *testing.T) {
	// wedgeCtx gates the server-side 30s sleep. Cancelling it lets
	// the handler exit immediately so httptest.Server.Close() doesn't
	// block waiting for the active connection to drain.
	wedgeCtx, wedgeCancel := context.WithCancel(context.Background())

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-time.After(30 * time.Second): // pretend the collector is wedged
		case <-wedgeCtx.Done():
		}
	}))

	// Worker context: cancelled before Close() so sendOnce aborts via
	// context rather than waiting for client.Timeout.
	ctx, cancel := context.WithCancel(context.Background())

	// Belt-and-suspenders: short client timeout so any race between
	// context cancellation and the HTTP round-trip doesn't leave the
	// worker goroutine blocked indefinitely.
	baseClient := srv.Client()
	baseClient.Timeout = 3 * time.Second

	wp, err := audit.NewWebhookPusher(ctx, audit.WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         integrationToken,
		AllowInternal: true,
		HTTPClient:    baseClient,
		QueueDepth:    1,
	})
	require.NoError(t, err)
	mgr := audit.NewManager(audit.ManagerOptions{WebhookPusher: wp})

	st := freshStore(t)
	start := time.Now()
	for i := 0; i < 500; i++ {
		req := parser.MustParseTestURL(http.MethodGet, "/api/v1/pods")
		EvaluateRequestFull(req, st, ModeCooperative, DefaultPolicyDeny,
			nil, "", EvalOptions{AuditEmitter: mgr})
	}
	elapsed := time.Since(start)
	assert.Less(t, elapsed, hotPathBound,
		"500 decisions with wedged webhook must complete in well under the wedge timeout (%s bound; 30s wedge)", hotPathBound)

	// Tear down in an order that avoids all blocking paths:
	//  1. Cancel the server-side wedge so the handler exits promptly.
	//  2. Cancel the worker context so the in-flight HTTP request is
	//     aborted (sendOnce uses NewRequestWithContext).
	//  3. Close the manager (waits for the worker goroutine to exit —
	//     now fast because the context is already cancelled).
	//  4. Close the httptest server (now fast because the handler has
	//     already returned, freeing the active connection).
	wedgeCancel()
	cancel()
	mgr.Close()
	srv.Close()
}
