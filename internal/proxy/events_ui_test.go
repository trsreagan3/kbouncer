// events_ui_test.go covers the GET / live audit-stream web UI shipped
// in #272. Sibling of the dbounce + gbounce + ibounce UI tests; the
// HTML body shape is cross-product-identical (only the product name
// in the title differs) so structural assertions parallel them.
package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestAuditEventsUI_RendersHTMLAtRoot(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q; want text/html", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(body))), "<!doctype html>") {
		t.Errorf("body does not start with <!doctype html>: %s", string(body[:200]))
	}
}

func TestAuditEventsUI_TitleContainsBouncerName(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	body := mustGetBody(t, srv.URL+"/")
	if !strings.Contains(body, "<title>kbounce - live audit stream</title>") {
		t.Errorf("title missing kbounce: %q", excerpt(body, "<title>", "</title>"))
	}
}

func TestAuditEventsUI_HasRequiredColumns(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	body := strings.ToLower(mustGetBody(t, srv.URL+"/"))
	for _, col := range []string{"time", "severity", "event type", "actor", "operation", "verdict"} {
		if !strings.Contains(body, col) {
			t.Errorf("missing column header: %s", col)
		}
	}
}

func TestAuditEventsUI_EmbedsAuditEventsURL(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	body := mustGetBody(t, srv.URL+"/")
	if !strings.Contains(body, "/audit/events") {
		t.Errorf("body does not reference /audit/events")
	}
}

func TestAuditEventsUI_NoEmbeddedToken(t *testing.T) {
	const secret = "TOKEN-MUST-NOT-LEAK-INTO-HTML-AAA1234"
	srv := httptest.NewServer(auditEventsUIHandler(secret))
	defer srv.Close()
	body := mustGetBody(t, srv.URL+"/")
	if strings.Contains(body, secret) {
		t.Errorf("bearer token leaked into HTML body")
	}
}

func TestAuditEventsUI_NoExternalDependencies(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	body := strings.ToLower(mustGetBody(t, srv.URL+"/"))
	forbidden := []string{
		"googleapis.com",
		"gstatic.com",
		"cloudflare",
		"cdn.",
		"googletagmanager",
		"google-analytics",
		"fonts.google",
		"//unpkg.com",
		"//cdnjs.",
		"//jsdelivr.",
	}
	for _, needle := range forbidden {
		if strings.Contains(body, needle) {
			t.Errorf("external dependency leaked: %s", needle)
		}
	}
}

func TestAuditEventsUI_SafetyNotSurveillanceLanguage(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	body := strings.ToLower(mustGetBody(t, srv.URL+"/"))
	// Word-boundary check to avoid false positives in long identifiers.
	for _, term := range []string{"violation", "infraction", "unauthorized"} {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(term) + `\b`)
		if re.MatchString(body) {
			t.Errorf("forbidden surveillance term in UI: %s", term)
		}
	}
}

func TestAuditEventsUI_ReadOnlyNoMutatingControls(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	body := strings.ToLower(mustGetBody(t, srv.URL+"/"))
	for _, term := range []string{
		"kill session", "revoke session", "delete profile",
		"approve request", "deny request", "pause profile",
		`method="post"`, `method="delete"`, `method="put"`,
	} {
		if strings.Contains(body, term) {
			t.Errorf("mutating control leaked: %s", term)
		}
	}
}

func TestAuditEventsUI_StrictCSPHeader(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self': %q", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none': %q", csp)
	}
	if strings.Contains(csp, "http://") || strings.Contains(csp, "https://") {
		t.Errorf("CSP allows remote sources: %q", csp)
	}
}

func TestAuditEventsUI_HTMLUnder500Lines(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	body := mustGetBody(t, srv.URL+"/")
	n := strings.Count(body, "\n") + 1
	if n >= 500 {
		t.Errorf("HTML grew to %d lines (cap 500)", n)
	}
}

func TestAuditEventsUI_LoopbackNoAuthRequired(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler(""))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d (want 200)", resp.StatusCode)
	}
}

func TestAuditEventsUI_ExternalAcceptsCorrectBearer(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler("s3kret"))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer s3kret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d (want 200)", resp.StatusCode)
	}
}

func TestAuditEventsUI_ExternalRejectsWrongBearer(t *testing.T) {
	srv := httptest.NewServer(auditEventsUIHandler("s3kret"))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d (want 403)", resp.StatusCode)
	}
}

func TestAuditEventsUI_ExternalServesHTMLWithoutHeader(t *testing.T) {
	// A bare browser visit (no Authorization header) should still
	// render the page so the JS can show the "auth required" banner.
	// Only an EXPLICIT bad Authorization header triggers 403.
	srv := httptest.NewServer(auditEventsUIHandler("s3kret"))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d (want 200)", resp.StatusCode)
	}
	body := mustReadBody(t, resp)
	if strings.Contains(body, "s3kret") {
		t.Errorf("token leaked into HTML body when served without header")
	}
}

func TestAuditEventsUI_HTMLEscapesBouncerName(t *testing.T) {
	body := renderAuditEventsUI("<script>alert(1)</script>")
	if strings.Contains(body, "<script>alert(1)") {
		t.Errorf("bouncer name not HTML-escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)") {
		t.Errorf("escaped bouncer name missing")
	}
}

func TestAuditEventsUIRoot_RootGetsUI(t *testing.T) {
	uiCalls := 0
	fallbackCalls := 0
	ui := func(w http.ResponseWriter, r *http.Request) { uiCalls++ }
	fb := func(w http.ResponseWriter, r *http.Request) { fallbackCalls++ }
	srv := httptest.NewServer(auditEventsUIRoot(ui, fb))
	defer srv.Close()
	_, _ = http.Get(srv.URL + "/")
	if uiCalls != 1 || fallbackCalls != 0 {
		t.Errorf("GET / should route to ui (ui=%d fb=%d)", uiCalls, fallbackCalls)
	}
}

func TestAuditEventsUIRoot_NonRootGoesToFallback(t *testing.T) {
	uiCalls := 0
	fallbackCalls := 0
	ui := func(w http.ResponseWriter, r *http.Request) { uiCalls++ }
	fb := func(w http.ResponseWriter, r *http.Request) { fallbackCalls++ }
	srv := httptest.NewServer(auditEventsUIRoot(ui, fb))
	defer srv.Close()
	_, _ = http.Get(srv.URL + "/api/v1/namespaces")
	if uiCalls != 0 || fallbackCalls != 1 {
		t.Errorf("non-root path should fall through (ui=%d fb=%d)", uiCalls, fallbackCalls)
	}
}

func TestAuditEventsUIRoot_NonGETGoesToFallback(t *testing.T) {
	uiCalls := 0
	fallbackCalls := 0
	ui := func(w http.ResponseWriter, r *http.Request) { uiCalls++ }
	fb := func(w http.ResponseWriter, r *http.Request) { fallbackCalls++ }
	srv := httptest.NewServer(auditEventsUIRoot(ui, fb))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/", nil)
	_, _ = http.DefaultClient.Do(req)
	if uiCalls != 0 || fallbackCalls != 1 {
		t.Errorf("POST / should fall through to proxy (ui=%d fb=%d)", uiCalls, fallbackCalls)
	}
}

// TestAuditEventsUIRoot_KubernetesProtocolNeverHitsBareRoot documents
// why kbounce is structurally safe from the same-class shadowing bug
// fixed in the ibounce sibling (iam-roles d045eee). In ibounce the
// audit-stream UI's GET / registration silently shadowed AWS SDK
// root-path calls (S3 ListBuckets, presigned-URL redirects, opaque
// unclassifiable proxy traffic) because the AWS protocol legitimately
// targets `/` and the aiohttp route did exact-path matching with no
// Accept-header sniffing fallback.
//
// kbounce is not affected because:
//
//  1. The Kubernetes apiserver protocol NEVER routes a kubectl /
//     client-go call to bare `GET /`. Every legitimate request goes
//     to `/api`, `/apis`, `/api/{ver}/...`, `/apis/{group}/{ver}/...`,
//     `/healthz`, `/readyz`, `/livez`, `/version`, `/openapi/v2`,
//     `/openapi/v3`, or `/metrics`. There is no API operation whose
//     request-line target is the single byte `/`.
//
//  2. The auditEventsUIRoot wrapper above uses an EXACT-path match
//     (`r.URL.Path == "/"`) — not a prefix or aiohttp-style catch-
//     all. Any other path falls through to s.handle untouched.
//
//  3. Defense in depth: even if a request DID arrive at bare `/` and
//     somehow bypassed the UI wrapper, parser.Parse() rejects it as
//     ErrMalformedURL (parser.go: `if trimmed == "" { return nil,
//     ErrMalformedURL }`), routing it through the default-policy
//     opaque path rather than letting it slip through unevaluated.
//
// This test pins the assumption: every canonical kubectl request path
// resolves to the proxy fallback, never to the UI. If kubernetes ever
// added a bare-root API operation, this test would fail and force a
// re-evaluation of the wrapper design (which would then need the
// Accept-header sniffing pattern ibounce adopted).
func TestAuditEventsUIRoot_KubernetesProtocolNeverHitsBareRoot(t *testing.T) {
	// Canonical kubectl + client-go request paths covering every
	// well-known apiserver surface a real client targets in production.
	// None of these resolve to `/` alone; all must route to the proxy
	// fallback handler.
	kubernetesClientPaths := []struct {
		method string
		path   string
		desc   string
	}{
		{"GET", "/api", "core-api discovery"},
		{"GET", "/apis", "named-group discovery"},
		{"GET", "/api/v1", "core-v1 discovery"},
		{"GET", "/api/v1/namespaces", "list namespaces"},
		{"GET", "/api/v1/namespaces/default/pods", "list pods in ns"},
		{"GET", "/api/v1/namespaces/default/pods/p", "get pod"},
		{"POST", "/api/v1/namespaces/default/pods", "create pod"},
		{"DELETE", "/api/v1/namespaces/default/pods/p", "delete pod"},
		{"PATCH", "/api/v1/namespaces/default/pods/p", "patch pod"},
		{"GET", "/api/v1/namespaces/default/secrets/s", "get secret"},
		{"POST", "/api/v1/namespaces/default/pods/p/exec", "exec into pod"},
		{"GET", "/api/v1/namespaces/default/pods/p/log", "tail pod logs"},
		{"GET", "/apis/apps/v1/namespaces/default/deployments", "list deployments"},
		{"POST", "/apis/rbac.authorization.k8s.io/v1/clusterroles", "create clusterrole"},
		{"GET", "/healthz", "liveness probe"},
		{"GET", "/readyz", "readiness probe"},
		{"GET", "/livez", "liveness probe v2"},
		{"GET", "/version", "apiserver version"},
		{"GET", "/openapi/v2", "openapi schema"},
		{"GET", "/openapi/v3", "openapi v3 schema"},
		{"GET", "/metrics", "prometheus metrics"},
	}

	for _, tc := range kubernetesClientPaths {
		tc := tc
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			uiCalls := 0
			fallbackCalls := 0
			ui := func(w http.ResponseWriter, r *http.Request) { uiCalls++ }
			fb := func(w http.ResponseWriter, r *http.Request) { fallbackCalls++ }
			srv := httptest.NewServer(auditEventsUIRoot(ui, fb))
			defer srv.Close()
			req, err := http.NewRequest(tc.method, srv.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("build req: %v", err)
			}
			// Mimic a real kubectl client advertising JSON (mirrors
			// the ibounce SDK-detection vector). The wrapper must
			// still route to the fallback purely on path/method.
			req.Header.Set("Accept", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do req: %v", err)
			}
			_ = resp.Body.Close()
			if uiCalls != 0 {
				t.Errorf("%s (%s): UI handler fired for K8s client path "+
					"(ui=%d fb=%d); this would silently shadow real "+
					"apiserver traffic", tc.desc, tc.path, uiCalls,
					fallbackCalls)
			}
			if fallbackCalls != 1 {
				t.Errorf("%s (%s): fallback miscount (ui=%d fb=%d)",
					tc.desc, tc.path, uiCalls, fallbackCalls)
			}
		})
	}
}

// --- helpers ---------------------------------------------------------

func mustGetBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	return mustReadBody(t, resp)
}

func mustReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func excerpt(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return "(start not found)"
	}
	j := strings.Index(s[i:], end)
	if j < 0 {
		return s[i:min(i+80, len(s))]
	}
	return s[i : i+j+len(end)]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
