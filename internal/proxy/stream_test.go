package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------
// classifyStream — pure-function tests
// ---------------------------------------------------------------------

func TestClassifyStream_DetectsWatchQuery(t *testing.T) {
	for _, q := range []string{"watch=true", "watch=1", "watch=TRUE", "watch=yes"} {
		r := mustNewRequest(t, http.MethodGet, "http://x/api/v1/pods?"+q, nil)
		assert.Equal(t, StreamKindWatch, classifyStream(r),
			"query %q should classify as watch", q)
	}
}

func TestClassifyStream_DetectsFollowQuery(t *testing.T) {
	r := mustNewRequest(t, http.MethodGet,
		"http://x/api/v1/namespaces/default/pods/my-pod/log?follow=true&tailLines=10", nil)
	assert.Equal(t, StreamKindWatch, classifyStream(r),
		"`follow=true` (kubectl logs -f) is the watch-equivalent on logs")
}

func TestClassifyStream_DetectsUpgrade(t *testing.T) {
	r := mustNewRequest(t, http.MethodGet, "http://x/api/v1/pods/p/exec", nil)
	r.Header.Set("Upgrade", "SPDY/3.1")
	r.Header.Set("Connection", "Upgrade")
	assert.Equal(t, StreamKindSPDY, classifyStream(r))
}

func TestClassifyStream_DetectsWebSocketUpgrade(t *testing.T) {
	r := mustNewRequest(t, http.MethodGet, "http://x/api/v1/pods/p/portforward", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	assert.Equal(t, StreamKindSPDY, classifyStream(r))
}

func TestClassifyStream_RestRequestIsNone(t *testing.T) {
	r := mustNewRequest(t, http.MethodGet, "http://x/api/v1/namespaces/default/pods", nil)
	assert.Equal(t, StreamKindNone, classifyStream(r))
}

func TestClassifyStream_WatchFalseIsNone(t *testing.T) {
	// kubectl will literally send `watch=false` for a paginated list;
	// classifyStream must treat false / 0 / empty as non-stream so the
	// buffered REST path stays the default.
	for _, q := range []string{"watch=false", "watch=0", "watch="} {
		r := mustNewRequest(t, http.MethodGet, "http://x/api/v1/pods?"+q, nil)
		assert.Equal(t, StreamKindNone, classifyStream(r),
			"query %q must NOT classify as a stream", q)
	}
}

// ---------------------------------------------------------------------
// Watch streaming — fake apiserver emits 3 NDJSON events; proxy must
// forward each chunk-by-chunk so the client sees them in order.
// ---------------------------------------------------------------------

func TestStreaming_WatchChunksFlowThrough(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	// Emit three watch events with a small sleep between them. With
	// kbouncer's K-Slice 2 buffered path the client would receive all
	// three at once at the END; with K-Slice 5 streaming they should
	// arrive one at a time.
	fas.SetResponder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, `{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"pod-%d"}}}`+"\n", i)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	up := upstreamFor(t, fas)
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods?watch=true")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "watch", resp.Header.Get("x-kbouncer-stream"),
		"watch streams must surface their stream-kind on the response header")

	// Decode three NDJSON events back. If the proxy had buffered we'd
	// still see them all eventually — what differs is the ordering /
	// arrival pattern. The stronger correctness check: each line
	// parses + the apiserver received exactly one request.
	scanner := bufio.NewScanner(resp.Body)
	got := []string{}
	for scanner.Scan() {
		got = append(got, scanner.Text())
	}
	require.Len(t, got, 3, "all three watch events must reach the client in order")
	for i, line := range got {
		assert.Contains(t, line, fmt.Sprintf(`"name":"pod-%d"`, i),
			"event #%d must be in order; the streaming forwarder must NOT reorder", i)
	}
	require.Len(t, fas.received, 1,
		"exactly one request must reach the apiserver — streaming is ONE decision, not one per chunk")
}

// ---------------------------------------------------------------------
// Audit semantics: a streaming request produces ONE decision row, not
// one per chunk.
// ---------------------------------------------------------------------

func TestStreaming_WatchProducesOneAuditRowNotOnePerChunk(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	fas.SetResponder(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			_, _ = fmt.Fprintf(w, `{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"p-%d"}}}`+"\n", i)
			if flusher != nil {
				flusher.Flush()
			}
		}
	})
	up := upstreamFor(t, fas)
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods?watch=true")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	rows, err := st.RecentDecisions(50)
	require.NoError(t, err)
	require.Len(t, rows, 1,
		"streaming MUST open ONE decision row, not one per chunk")
	assert.True(t, rows[0].IsStream, "is_stream must be true on a streaming decision row")
	assert.Equal(t, "watch", rows[0].StreamKind,
		"stream_kind must label the streaming type for audit-log filters")
}

// ---------------------------------------------------------------------
// Non-streaming REST request must NOT be tagged is_stream.
// ---------------------------------------------------------------------

func TestStreaming_RestRequestNotTaggedAsStream(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	_ = resp.Body.Close()

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.False(t, rows[0].IsStream, "REST request must NOT be tagged is_stream")
	assert.Empty(t, rows[0].StreamKind, "REST request must have empty stream_kind")
}

// ---------------------------------------------------------------------
// SPDY upgrade — fake apiserver accepts the upgrade + echoes bytes.
// Proxy must hijack + pipe bidirectionally.
// ---------------------------------------------------------------------

func TestStreaming_SPDYUpgradeHijacksAndPipesBidirectionally(t *testing.T) {
	st := freshStore(t)
	// Build a fake "apiserver" via httptest that performs a 101
	// upgrade + echoes bytes. We need a Hijacker-capable handler.
	fas := newFakeAPIServer(t, true)
	upgradeReceived := make(chan struct{}, 1)
	fas.SetResponder(func(w http.ResponseWriter, r *http.Request) {
		// Confirm the proxy preserved the Upgrade header.
		if r.Header.Get("Upgrade") != "SPDY/3.1" {
			http.Error(w, "no upgrade header", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// Send 101 Switching Protocols.
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: SPDY/3.1\r\n"+
			"Connection: Upgrade\r\n\r\n")
		upgradeReceived <- struct{}{}
		// Echo bytes back to the client until close.
		_, _ = io.Copy(conn, buf.Reader)
	})
	up := upstreamFor(t, fas)
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)

	// We need a real listener so http.Hijacker works; httptest.Server
	// supports it.
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// Build a raw TCP request that asks for the upgrade, then read
	// the 101 + send some bytes + read them back.
	tsURL := strings.TrimPrefix(ts.URL, "http://")
	conn, err := net.Dial("tcp", tsURL)
	require.NoError(t, err)
	defer conn.Close()
	_, _ = io.WriteString(conn,
		"GET /api/v1/namespaces/default/pods/p/exec HTTP/1.1\r\n"+
			"Host: 127.0.0.1\r\n"+
			"Upgrade: SPDY/3.1\r\n"+
			"Connection: Upgrade\r\n\r\n")

	rd := bufio.NewReader(conn)
	statusLine, err := rd.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, statusLine, "101", "proxy must replay the apiserver's 101")
	// Drain headers up to blank line.
	for {
		line, err := rd.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			break
		}
	}

	select {
	case <-upgradeReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("apiserver never saw the upgrade — proxy did not pipe the request through")
	}

	// Bidirectional pipe test: send a payload, read it back.
	payload := []byte("hello-spdy-bytes")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	got := make([]byte, len(payload))
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	_, err = io.ReadFull(rd, got)
	require.NoError(t, err)
	assert.Equal(t, payload, got,
		"bytes written by the client must echo back through the bidirectional pipe")
}

// ---------------------------------------------------------------------
// Transparent-mode DENY on an exec request must NOT hijack the conn.
// The audit row is still written + tagged with stream_kind=spdy.
// ---------------------------------------------------------------------

func TestStreaming_TransparentDenyOnExecRejects403NoHijack(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	upgradeAttempted := false
	fas.SetResponder(func(w http.ResponseWriter, r *http.Request) {
		upgradeAttempted = true
	})
	up := upstreamFor(t, fas)
	// Active profile that denies anything with "prod" in the namespace.
	p := loadStagingProfile(t)
	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: p,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/api/v1/namespaces/prod-app/pods/p/exec", nil)
	require.NoError(t, err)
	req.Header.Set("Upgrade", "SPDY/3.1")
	req.Header.Set("Connection", "Upgrade")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"transparent DENY on an exec must return 403 — not hijack")
	assert.False(t, upgradeAttempted, "denied exec must NOT reach the apiserver")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "deny", rows[0].DecisionVerdict)
	assert.Equal(t, "spdy", rows[0].StreamKind,
		"the denied exec's audit row must still record the stream kind so a reviewer "+
			"can ask 'what exec attempts were denied this week?'")
}

// ---------------------------------------------------------------------
// Helper: build a synthetic request without going through httptest
// (the classifyStream tests need only a *http.Request shape).
// ---------------------------------------------------------------------

func mustNewRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	if body == nil {
		body = bytes.NewReader(nil)
	}
	r, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	return r
}
