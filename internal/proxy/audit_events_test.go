// audit_events_test.go covers GET /audit/events shipped in #271. Same
// shape as the gbounce + dbounce + ibounce sibling tests; see
// docs/QUERYING-AUDIT-LOGS.md for the wire spec.

package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/store"
)

func seedAuditEventsStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	base := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	rows := []store.DecisionRow{
		{
			At:              base,
			Method:          "GET",
			Path:            "/api/v1/namespaces/default/pods",
			ParsedVerb:      "list",
			ParsedResource:  "pods",
			ParsedNamespace: "default",
			DecisionVerdict: "ALLOW",
			DecisionReason:  "allow-by-default",
			ModeAtDecision:  "cooperative",
		},
		{
			At:              base.Add(10 * time.Second),
			Method:          "DELETE",
			Path:            "/api/v1/namespaces/default/pods/x",
			ParsedVerb:      "delete",
			ParsedResource:  "pods",
			ParsedNamespace: "default",
			DecisionVerdict: "DENY",
			DecisionReason:  "delete is denied",
			ModeAtDecision:  "transparent",
			Enforced:        true,
		},
		{
			At:              base.Add(20 * time.Second),
			Method:          "POST",
			Path:            "/api/v1/namespaces/prod/configmaps",
			ParsedVerb:      "create",
			ParsedResource:  "configmaps",
			ParsedNamespace: "prod",
			DecisionVerdict: "ALLOW",
			ModeAtDecision:  "cooperative",
		},
	}
	for _, r := range rows {
		if _, err := st.RecordDecision(r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	return st
}

func newAuditEventsTestServer(t *testing.T, requireToken string) (*httptest.Server, *store.Store) {
	t.Helper()
	st := seedAuditEventsStore(t)
	srv := httptest.NewServer(auditEventsHandler(st, requireToken))
	t.Cleanup(srv.Close)
	return srv, st
}

func TestAuditEvents_GetReturnsJSONL(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content-type = %q; want application/x-ndjson", ct)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("line %d: invalid JSON: %v", n+1, err)
		}
		n++
	}
	if n != 3 {
		t.Errorf("got %d events; want 3", n)
	}
}

func TestAuditEvents_FilterByNamespaceMatches(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	q.Set("limit", "10")
	q.Add("filter", "resource.namespace=prod")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	if n != 1 {
		t.Errorf("got %d events; want 1 (filtered to namespace=prod)", n)
	}
}

func TestAuditEvents_BadFilterReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	q.Add("filter", "no_operator_here")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d (want 400)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]string
	_ = json.Unmarshal(body, &payload)
	if !strings.Contains(payload["error"], "filter") {
		t.Errorf("error body = %q; want filter-mentioning", payload["error"])
	}
}

func TestAuditEvents_LimitCapsResults(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?limit=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	if n != 1 {
		t.Errorf("got %d events; want 1 (limit)", n)
	}
}

func TestAuditEvents_LimitOverMaxRejected(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(fmt.Sprintf("%s?limit=%d", srv.URL, AuditEventsMaxLimit+1))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_SinceUntilBoundsWork(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	noneURL := fmt.Sprintf("%s?since=%s",
		srv.URL,
		url.QueryEscape(time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339)),
	)
	resp, err := http.Get(noneURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	resp.Body.Close()
	if n != 0 {
		t.Errorf("since=30min-ago: got %d events; want 0", n)
	}
	allURL := fmt.Sprintf("%s?since=%s",
		srv.URL,
		url.QueryEscape(time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339)),
	)
	resp2, err := http.Get(allURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp2.Body.Close()
	scanner2 := bufio.NewScanner(resp2.Body)
	n2 := 0
	for scanner2.Scan() {
		n2++
	}
	if n2 != 3 {
		t.Errorf("since=2h-ago: got %d events; want 3", n2)
	}
}

func TestAuditEvents_BadTimeBoundReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?since=not-a-time")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_OCSFBundleFormat(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?format=ocsf-bundle&limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var bundle map[string]any
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatalf("decode bundle: %v\n%s", err, body)
	}
	if cl, _ := bundle["class_uid"].(float64); cl != 2004 {
		t.Errorf("class_uid = %v; want 2004", bundle["class_uid"])
	}
	events, ok := bundle["events"].([]any)
	if !ok {
		t.Fatalf("events not an array; got %T", bundle["events"])
	}
	if len(events) != 3 {
		t.Errorf("bundle events len = %d; want 3", len(events))
	}
}

func TestAuditEvents_UnknownFormatReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?format=wat")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenMissingReturns401(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d (want 401)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenWrongReturns403(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d (want 403)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenCorrectReturns200(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d (want 200)", resp.StatusCode)
	}
}

func TestAuditEvents_NonGETMethodRejected(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	req, _ := http.NewRequest("POST", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d (want 405)", resp.StatusCode)
	}
}

// TestAuditEvents_SurfacesPersistedAgentIdentity confirms that the
// /audit/events HTTP surface (the same wire feed the #272 web UI
// long-polls) carries the agent_name + agent_session_id columns
// added in #289 under the OCSF unmapped.iam_jit.agent block — same
// shape ibounce + dbounce + gbounce ship per
// [[cross-product-agent-parity]].
func TestAuditEvents_SurfacesPersistedAgentIdentity(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	at := time.Now().UTC().Truncate(time.Second)
	_, err = st.RecordDecision(store.DecisionRow{
		At:              at,
		Method:          "POST",
		Path:            "/api/v1/namespaces/default/pods",
		ParsedVerb:      "create",
		ParsedResource:  "pods",
		ParsedNamespace: "default",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
		AgentName:       "claude-code",
		AgentSessionID:  "01956c44-c5c1-7c31-9bca-7c0aaa0000ab",
	})
	if err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}

	srv := httptest.NewServer(auditEventsHandler(st, ""))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "?limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	// JSONL: one event per line; we wrote one row.
	line := strings.TrimSpace(string(body))
	if line == "" {
		t.Fatalf("expected one JSONL line; got empty body")
	}

	var ev map[string]any
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("unmarshal: %v (body=%q)", err, line)
	}
	unmapped, _ := ev["unmapped"].(map[string]any)
	if unmapped == nil {
		t.Fatalf("unmapped missing; ev=%v", ev)
	}
	iamjit, _ := unmapped["iam_jit"].(map[string]any)
	if iamjit == nil {
		t.Fatalf("unmapped.iam_jit missing; unmapped=%v", unmapped)
	}
	agent, _ := iamjit["agent"].(map[string]any)
	if agent == nil {
		t.Fatalf("unmapped.iam_jit.agent missing; iam_jit=%v", iamjit)
	}
	if got := agent["name"]; got != "claude-code" {
		t.Errorf("agent.name = %v; want claude-code", got)
	}
	if got := agent["session_id"]; got != "01956c44-c5c1-7c31-9bca-7c0aaa0000ab" {
		t.Errorf("agent.session_id = %v; want 01956c44-...0000ab", got)
	}
	// actor.user.name should also mirror the agent name (cross-product
	// spec — analysts can pivot from agent block to principal query).
	actor, _ := ev["actor"].(map[string]any)
	if actor == nil {
		t.Fatalf("actor missing; ev=%v", ev)
	}
	user, _ := actor["user"].(map[string]any)
	if user == nil {
		t.Fatalf("actor.user missing; actor=%v", actor)
	}
	if got := user["name"]; got != "claude-code" {
		t.Errorf("actor.user.name = %v; want claude-code", got)
	}
}

// TestAuditEvents_320_DetectedFromReadsStoredColumn is the §A18
// regression guard: when an HTTP-header-detected request lands in
// SQLite with DetectedFrom=DetectionSourceHTTPHeader, the
// /audit/events projection MUST surface that exact value instead
// of the pre-§A18 heuristic that mis-labelled any row with a
// session_id as mcp_clientinfo. UAT 2026-05-22 caught this: SOC
// analysts pulling cross-product events saw kbounce rows tagged
// `detected_from=mcp_clientinfo` even when the agent declared
// itself via HTTP header.
func TestAuditEvents_320_DetectedFromReadsStoredColumn(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	const wantSession = "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
	if _, err := st.RecordDecision(store.DecisionRow{
		At:              time.Now().UTC(),
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
		AgentName:       "claude-code",
		AgentSessionID:  wantSession,
		DetectedFrom:    audit.DetectionSourceHTTPHeader,
	}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	srv := httptest.NewServer(auditEventsHandler(st, ""))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "?limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	line := strings.TrimSpace(string(body))
	var ev map[string]any
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	unmapped, _ := ev["unmapped"].(map[string]any)
	iamjit, _ := unmapped["iam_jit"].(map[string]any)
	agent, _ := iamjit["agent"].(map[string]any)
	if got := agent["detected_from"]; got != audit.DetectionSourceHTTPHeader {
		t.Errorf("agent.detected_from = %v; want %q (heuristic mis-labelling NOT fixed)",
			got, audit.DetectionSourceHTTPHeader)
	}
	if got := agent["session_id"]; got != wantSession {
		t.Errorf("agent.session_id = %v; want %q", got, wantSession)
	}
}
