package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/upstream"
)

// fakeAPIServer is a recording httptest.Server that stands in for the
// real kube-apiserver. Tests assert on which requests it actually
// received so a forwarding bug (DENY-transparent still forwarding,
// host-allowlist tripped a forward, etc.) shows up immediately.
type fakeAPIServer struct {
	ts       *httptest.Server
	received []receivedReq
	respond  func(w http.ResponseWriter, r *http.Request)
}

type receivedReq struct {
	Method        string
	Path          string
	Authorization string
	HostHeader    string
	Headers       http.Header
	Body          []byte
}

func newFakeAPIServer(t *testing.T, useTLS bool) *fakeAPIServer {
	t.Helper()
	fas := &fakeAPIServer{}
	fas.respond = func(w http.ResponseWriter, r *http.Request) {
		// Default: 200 with a small JSON body that looks like the
		// apiserver responded successfully. Tests can swap in custom
		// handlers via SetResponder.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kind":"PodList","apiVersion":"v1","items":[]}`))
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fas.received = append(fas.received, receivedReq{
			Method:        r.Method,
			Path:          r.URL.RequestURI(),
			Authorization: r.Header.Get("Authorization"),
			HostHeader:    r.Host,
			Headers:       r.Header.Clone(),
			Body:          body,
		})
		fas.respond(w, r)
	})
	if useTLS {
		fas.ts = httptest.NewTLSServer(handler)
	} else {
		fas.ts = httptest.NewServer(handler)
	}
	t.Cleanup(fas.ts.Close)
	return fas
}

func (f *fakeAPIServer) URL() string                 { return f.ts.URL }
func (f *fakeAPIServer) SetResponder(h http.HandlerFunc) { f.respond = h }

// upstreamFor builds an Upstream pointing at the fake apiserver, with
// the fake's self-signed TLS cert trusted (no insecure-skip needed —
// this matches the production code path where a real CA bundle is
// loaded from kubeconfig).
func upstreamFor(t *testing.T, fas *fakeAPIServer) *upstream.Upstream {
	t.Helper()
	u, err := url.Parse(fas.URL())
	require.NoError(t, err)

	pool := x509.NewCertPool()
	if fas.ts.TLS != nil {
		// httptest's TLS server exposes its self-signed cert via
		// ts.Certificate(); trust it so the proxy's outbound client
		// can validate the connection (matches the production path
		// where a real CA bundle is loaded from kubeconfig).
		pool.AddCert(fas.ts.Certificate())
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: stripPort(u.Host),
		RootCAs:    pool,
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &upstream.Upstream{URL: u, Client: client, Source: "test"}
}

func stripPort(hp string) string {
	if i := strings.LastIndex(hp, ":"); i >= 0 {
		return hp[:i]
	}
	return hp
}

// ---------------------------------------------------------------------
// ALLOW verdict → forwards to fake apiserver with headers + body intact
// ---------------------------------------------------------------------

func TestForwarding_AllowForwardsRequestToUpstream(t *testing.T) {
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

	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/api/v1/namespaces/default/pods", strings.NewReader(""))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-bearer-12345")
	req.Header.Set("X-Custom-Trace", "trace-abc")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"ALLOW verdict must surface apiserver's status, not kbouncer's")
	assert.Contains(t, string(body), "PodList",
		"upstream response body must be returned verbatim")
	assert.Equal(t, VerdictAllow, resp.Header.Get(VerdictHeader))

	require.Len(t, fas.received, 1, "exactly one request reaches the apiserver")
	got := fas.received[0]
	assert.Equal(t, "/api/v1/namespaces/default/pods", got.Path)
	assert.Equal(t, "Bearer test-bearer-12345", got.Authorization,
		"bearer token must be preserved verbatim (kbouncer never re-signs)")
	assert.Equal(t, "trace-abc", got.Headers.Get("X-Custom-Trace"))
}

// ---------------------------------------------------------------------
// DENY transparent → fake apiserver receives NOTHING
// ---------------------------------------------------------------------

func TestForwarding_TransparentDenyDoesNotForward(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)
	p := loadStagingProfile(t)

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: p,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// Profile staging-work denies anything with "prod" in the namespace.
	resp, err := http.Get(ts.URL + "/api/v1/namespaces/prod-app/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, fas.received,
		"transparent-mode DENY must NOT forward to the apiserver")

	body, _ := io.ReadAll(resp.Body)
	var status map[string]any
	require.NoError(t, json.Unmarshal(body, &status))
	assert.Equal(t, "Status", status["kind"],
		"transparent-deny must return K8s-shaped Status so kubectl prints it cleanly")
	assert.Equal(t, "Forbidden", status["reason"])
	assert.EqualValues(t, 403, status["code"])
}

// ---------------------------------------------------------------------
// DENY cooperative → fake apiserver DOES receive the call (advisory)
// ---------------------------------------------------------------------

func TestForwarding_CooperativeDenyStillForwards(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)
	p := loadStagingProfile(t)

	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: p,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/prod-app/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"cooperative-mode DENY is advisory; the apiserver's 200 wins")
	require.Len(t, fas.received, 1,
		"cooperative DENY must still forward (advisory mode)")
	// Advisory header surfaces that transparent mode would have blocked.
	assert.Equal(t, "would-deny-in-transparent",
		resp.Header.Get("x-kbouncer-advisory"))
}

// ---------------------------------------------------------------------
// Forward failure → 502 with kbouncer-shaped JSON error
// ---------------------------------------------------------------------

func TestForwarding_UpstreamErrorReturnsBadGateway(t *testing.T) {
	st := freshStore(t)
	// Point upstream at a closed port → connection refused on every call.
	u, _ := url.Parse("http://127.0.0.1:1") // port 1 = unassigned
	up := &upstream.Upstream{
		URL:    u,
		Client: &http.Client{Timeout: 500 * time.Millisecond},
		Source: "test",
	}
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode,
		"upstream-unreachable must surface as 502, not 403 (the proxy didn't refuse)")
	assert.Equal(t, "true", resp.Header.Get("x-kbouncer-forward-error"))

	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))
	assert.Equal(t, "kbounce forward to kube-apiserver failed", payload["error"])
	assert.NotEmpty(t, payload["upstream_error"],
		"upstream_error must explain WHY the forward failed")
}

// ---------------------------------------------------------------------
// Forward failure where the apiserver returns 500
// (this is NOT a 502 — the apiserver IS reachable; pass-through verbatim)
// ---------------------------------------------------------------------

func TestForwarding_Upstream500PassedThroughVerbatim(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	fas.SetResponder(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","code":500}`))
	})
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
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"apiserver-returned 500 must be passed through verbatim, not rewritten to 502")
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"code":500`)
}

// ---------------------------------------------------------------------
// Outbound host allowlist: Host pointing elsewhere is rejected
// ---------------------------------------------------------------------

func TestForwarding_RefusesForwardWhenHostHeaderMismatches(t *testing.T) {
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

	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	// Attacker sets Host to a different destination — the proxy must
	// REFUSE; the upstream URL is the only legal forward target.
	req.Host = "attacker.example.com"

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"host-mismatch refusal returns 403, not 502")
	assert.Equal(t, "forward-host-mismatch", resp.Header.Get(RefusalHeader),
		"refusal header MUST name the reason so audit-log readers can filter")
	assert.Empty(t, fas.received,
		"a host-mismatch refusal must NOT forward to the apiserver")
}

// ---------------------------------------------------------------------
// Outbound host allowlist: matching Host (the upstream's own host) IS allowed
// ---------------------------------------------------------------------

func TestForwarding_HostHeaderMatchingUpstreamForwards(t *testing.T) {
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

	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	req.Host = up.Host() // matches the upstream → allowed.

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, fas.received, 1)
}

// ---------------------------------------------------------------------
// Hop-by-hop headers stripped before forwarding
// ---------------------------------------------------------------------

func TestForwarding_StripsHopByHopHeaders(t *testing.T) {
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

	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer keep-me")
	req.Header.Set("Proxy-Authorization", "Basic strip-me")
	req.Header.Set("X-Survives", "yes")
	// Connection header naming a custom hop-by-hop field, per RFC 7230 §6.1.
	req.Header.Set("Connection", "X-Custom-Hop")
	req.Header.Set("X-Custom-Hop", "should-be-stripped")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Len(t, fas.received, 1)
	got := fas.received[0]
	assert.Equal(t, "Bearer keep-me", got.Authorization,
		"end-to-end Authorization must survive forwarding")
	assert.Equal(t, "yes", got.Headers.Get("X-Survives"))
	assert.Empty(t, got.Headers.Get("Proxy-Authorization"),
		"RFC 7230 hop-by-hop Proxy-Authorization must be stripped")
	assert.Empty(t, got.Headers.Get("Connection"),
		"Connection header itself is hop-by-hop")
	assert.Empty(t, got.Headers.Get("X-Custom-Hop"),
		"Connection-named hop-by-hop fields must be stripped per RFC 7230 §6.1")
}

// ---------------------------------------------------------------------
// POST + body: body bytes round-trip
// ---------------------------------------------------------------------

func TestForwarding_PostBodyRoundTrips(t *testing.T) {
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

	payload := `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"hello"}}`
	req, err := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/namespaces/default/pods",
		strings.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Len(t, fas.received, 1)
	got := fas.received[0]
	assert.Equal(t, http.MethodPost, got.Method)
	assert.Equal(t, payload, string(got.Body),
		"POST body must reach the apiserver byte-identical")
}

// ---------------------------------------------------------------------
// Watch (long-poll) currently behaves as a normal GET in K-Slice 2.
// Documented as deferred to K-Slice 5 (proper streaming).
// ---------------------------------------------------------------------

func TestForwarding_WatchCompletesAsNormalGetInKSlice2(t *testing.T) {
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	fas.SetResponder(func(w http.ResponseWriter, r *http.Request) {
		// Apiserver returns a finite watch response and closes. K-Slice 5
		// will switch this to true streaming; for K-Slice 2 we just
		// verify the request reaches the apiserver with watch=true preserved.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"type":"ADDED","object":{"kind":"Pod"}}` + "\n"))
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
	require.Len(t, fas.received, 1)
	assert.Contains(t, fas.received[0].Path, "watch=true",
		"watch query must round-trip to the apiserver")
}

// ---------------------------------------------------------------------
// Unit tests for the helpers (run without the server)
// ---------------------------------------------------------------------

func TestStripHopHeaders_ReturnsNewMapWithoutHopHeaders(t *testing.T) {
	in := http.Header{
		"Authorization":       {"Bearer xyz"},
		"X-Custom":            {"keep"},
		"Connection":          {"keep-alive, X-Extra"},
		"Keep-Alive":          {"300"},
		"Proxy-Authenticate":  {"Basic"},
		"Proxy-Authorization": {"Basic c2VjcmV0"},
		"Te":                  {"trailers"},
		"Trailers":            {"X-Custom"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"websocket"},
		"Content-Length":      {"42"},
		"X-Extra":             {"named-by-Connection-so-stripped"},
	}
	out := stripHopHeaders(in)

	assert.Equal(t, "Bearer xyz", out.Get("Authorization"),
		"Authorization is end-to-end, must survive")
	assert.Equal(t, "keep", out.Get("X-Custom"),
		"non-hop custom header survives")
	for _, k := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding",
		"Upgrade", "Content-Length", "X-Extra",
	} {
		assert.Empty(t, out.Get(k), "%s must be stripped", k)
	}

	// Verify the function does not mutate the input.
	assert.Equal(t, "Basic c2VjcmV0", in.Get("Proxy-Authorization"),
		"input header map must not be mutated")
}

func TestHostAllowed(t *testing.T) {
	u, _ := url.Parse("https://apiserver.example.com:6443")
	up := &upstream.Upstream{URL: u}

	// Empty inbound Host is allowed (kbouncer rewrites to the upstream's Host).
	assert.True(t, hostAllowed("", up))
	// Exact match.
	assert.True(t, hostAllowed("apiserver.example.com:6443", up))
	// Case-insensitive.
	assert.True(t, hostAllowed("APISERVER.EXAMPLE.COM:6443", up))
	// Hostname matches but port omitted on inbound — allowed.
	assert.True(t, hostAllowed("apiserver.example.com", up))
	// Different hostname — REJECTED. This is the WB32-01-equivalent
	// closure: attacker-controlled Host headers must not pivot the
	// proxy onto a different destination.
	assert.False(t, hostAllowed("attacker.example.com", up))
	assert.False(t, hostAllowed("attacker.example.com:6443", up))
	// Nil upstream — fail-closed.
	assert.False(t, hostAllowed("", nil))
}

// ---------------------------------------------------------------------
// Smoke: ensure the proxy still works in K-Slice 1 observation mode
// (no upstream configured). Regression guard for the additive change.
// ---------------------------------------------------------------------

func TestForwarding_NoUpstreamFallsBackToObservationJSON(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		// Upstream intentionally nil — K-Slice 1 behavior preserved.
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods/my-pod")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var decoded struct {
		Observation *RequestObservation `json:"proxy_observation"`
	}
	require.NoError(t, json.Unmarshal(body, &decoded))
	require.NotNil(t, decoded.Observation,
		"with no upstream, K-Slice 1 observation body must still surface")
}
