package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/parser"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// freshStore opens a temp-file SQLite store the test cleans up.
func freshStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "kbouncer-test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestModeValues(t *testing.T) {
	assert.True(t, ModeCooperative.IsValid())
	assert.True(t, ModeTransparent.IsValid())
	assert.False(t, Mode("bogus").IsValid())
	assert.False(t, Mode("").IsValid())
}

func TestDefaultPolicyValues(t *testing.T) {
	assert.True(t, DefaultPolicyAllow.IsValid())
	assert.True(t, DefaultPolicyDeny.IsValid())
	assert.False(t, DefaultPolicy("maybe").IsValid())
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	assert.Equal(t, "127.0.0.1", c.Host, "default host must be loopback")
	assert.Equal(t, 8766, c.Port, "default port must be 8766 (distinct from iam-jit-bouncer's 8767)")
	assert.Equal(t, ModeCooperative, c.Mode)
	assert.Equal(t, DefaultPolicyDeny, c.DefaultPolicy)
}

func TestConfigNormalize_FillsZeroFields(t *testing.T) {
	got := Config{}.Normalize()
	want := DefaultConfig()
	assert.Equal(t, want, got)
}

func TestConfigNormalize_PreservesExplicitValues(t *testing.T) {
	c := Config{Host: "0.0.0.0", Port: 9999, Mode: ModeTransparent, DefaultPolicy: DefaultPolicyAllow}
	assert.Equal(t, c, c.Normalize())
}

func TestEvaluateRequest_ClassifiesCanonicalGet(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/my-pod")
	obs := EvaluateRequest(req, st, ModeCooperative, DefaultPolicyDeny)

	require.NotNil(t, obs)
	assert.Equal(t, "get", obs.ParsedVerb)
	assert.Equal(t, "pods", obs.ParsedResource)
	assert.Equal(t, "default", obs.ParsedNamespace)
	assert.Equal(t, "my-pod", obs.ParsedName)
	assert.Equal(t, string(ModeCooperative), obs.ModeAtDecision)
	// Cooperative mode never enforces, even with verdict=deny.
	assert.False(t, obs.Enforced)
	// With default-deny + no rules loaded, K-Slice 1 falls through to deny.
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
}

func TestEvaluateRequest_DefaultAllowFlipsVerdict(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/my-pod")
	obs := EvaluateRequest(req, st, ModeCooperative, DefaultPolicyAllow)

	require.NotNil(t, obs)
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.False(t, obs.Enforced, "allow is never enforced as a block")
}

func TestEvaluateRequest_UnclassifiableYieldsDeny(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/healthz")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)

	require.NotNil(t, obs)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Contains(t, obs.DecisionReason, "unclassifiable")
	// Transparent + deny → enforced
	assert.True(t, obs.Enforced)
}

func TestEvaluateRequest_CooperativeNeverEnforces(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodPost, "/api/v1/namespaces/default/pods/my-pod/exec")
	obs := EvaluateRequest(req, st, ModeCooperative, DefaultPolicyDeny)

	require.NotNil(t, obs)
	assert.Equal(t, "exec", obs.ParsedVerb)
	assert.Equal(t, "exec", obs.ParsedSubresource)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.False(t, obs.Enforced, "cooperative mode must NEVER enforce")
}

func TestEvaluateRequest_TransparentEnforcesDeny(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodDelete, "/api/v1/namespaces/default/pods/my-pod")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyDeny)

	require.NotNil(t, obs)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.True(t, obs.Enforced)
	assert.Equal(t, string(ModeTransparent), obs.ModeAtDecision)
}

func TestEvaluateRequest_RecordsDecisionToStore(t *testing.T) {
	st := freshStore(t)
	before, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(0), before)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods")
	_ = EvaluateRequest(req, st, ModeCooperative, DefaultPolicyDeny)

	after, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(1), after, "exactly one decision row should be recorded")
}

func TestEvaluateRequest_NilStoreIsSafe(t *testing.T) {
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/pods")
	obs := EvaluateRequest(req, nil, ModeCooperative, DefaultPolicyDeny)
	require.NotNil(t, obs)
	assert.Equal(t, "list", obs.ParsedVerb)
}

func TestEvaluateRequest_WatchClassified(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods?watch=true")
	obs := EvaluateRequest(req, st, ModeCooperative, DefaultPolicyAllow)

	require.NotNil(t, obs)
	assert.Equal(t, "watch", obs.ParsedVerb)
	assert.True(t, obs.IsWatch)
}

func TestEvaluateRequest_DryRunPreserved(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodPost, "/api/v1/namespaces/default/configmaps?dryRun=All")
	obs := EvaluateRequest(req, st, ModeCooperative, DefaultPolicyAllow)

	require.NotNil(t, obs)
	assert.True(t, obs.IsDryRun)
	assert.Equal(t, "create", obs.ParsedVerb)
}

// End-to-end: bind via httptest, GET, decode the JSON body, assert
// observation fields.
func TestServer_EndToEnd_RespondsWithObservationJSON(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods/my-pod")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var decoded struct {
		Observation         *RequestObservation `json:"proxy_observation"`
		ObservationOnlyNote string              `json:"_observation_only_note"`
	}
	require.NoError(t, json.Unmarshal(body, &decoded))

	require.NotNil(t, decoded.Observation)
	assert.Equal(t, "get", decoded.Observation.ParsedVerb)
	assert.Equal(t, "pods", decoded.Observation.ParsedResource)
	assert.Equal(t, "my-pod", decoded.Observation.ParsedName)
	// UAT-K2 MED-K2-04: the wrapper field is _observation_only_note + the
	// message explains observation-only mode in user-visible terms (not
	// "K-Slice 1" internal task terminology).
	assert.Contains(t, decoded.ObservationOnlyNote, "observation-only mode")

	// And it should have written exactly one decision row.
	n, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestServer_EndToEnd_TransparentDenyReturns403(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{Mode: ModeTransparent, DefaultPolicy: DefaultPolicyDeny}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/default/pods/my-pod")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	// K-Slice 2: transparent-deny responses use the K8s Status shape so
	// kubectl + client-go parse them as a clean "Error: ... forbidden"
	// instead of unparseable JSON.
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var status map[string]any
	require.NoError(t, json.Unmarshal(body, &status))
	assert.Equal(t, "Status", status["kind"])
	assert.Equal(t, "v1", status["apiVersion"])
	assert.Equal(t, "Failure", status["status"])
	assert.Equal(t, "Forbidden", status["reason"])
	assert.EqualValues(t, 403, status["code"])
	// Decision-source header still surfaces the rule layer.
	assert.Equal(t, SourceDefault, resp.Header.Get(DecisionSourceHeader))
}

func TestServer_ShutdownIsClean(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyDeny}, st)
	// Bind via httptest to skip needing to allocate a privileged port.
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// We don't actually run our server here (httptest manages the
	// listener); the Shutdown call should still be a safe no-op on the
	// un-started http.Server.
	err := s.Shutdown(ctx)
	// http.Server.Shutdown returns nil on never-started servers in Go 1.22+;
	// be lenient and only require it doesn't panic.
	if err != nil {
		t.Logf("shutdown returned error (acceptable for never-started server): %v", err)
	}
}

func TestParseMode(t *testing.T) {
	m, err := ParseMode("cooperative")
	require.NoError(t, err)
	assert.Equal(t, ModeCooperative, m)

	m, err = ParseMode("transparent")
	require.NoError(t, err)
	assert.Equal(t, ModeTransparent, m)

	_, err = ParseMode("nope")
	require.Error(t, err)
}

func TestParseDefaultPolicy(t *testing.T) {
	p, err := ParseDefaultPolicy("allow")
	require.NoError(t, err)
	assert.Equal(t, DefaultPolicyAllow, p)

	p, err = ParseDefaultPolicy("deny")
	require.NoError(t, err)
	assert.Equal(t, DefaultPolicyDeny, p)

	_, err = ParseDefaultPolicy("maybe")
	require.Error(t, err)
}

// ---------------------------------------------------------------------
// K-Slice 7: profile integration.
// ---------------------------------------------------------------------

// loadStagingProfile constructs the canonical "staging-work" community
// profile in memory. The 2026-05-17 default-profile reshape
// ([[bounce-default-profile-pattern]]) moved staging-work out of the
// embedded defaults + into community-profiles/, so the integration
// tests build it locally to keep exercising the same profile shape an
// operator gets when they install community-profiles/staging-work.yaml.
func loadStagingProfile(t *testing.T) *profile.Profile {
	t.Helper()
	return &profile.Profile{
		Name:        "staging-work",
		Description: "Working on staging; block anything that looks like prod.",
		DenyKeywords: []string{
			"prod", "production", "uat", "live", "customer",
		},
		KeywordTargets: []profile.KeywordTarget{
			profile.TargetResourceName,
			profile.TargetNamespace,
		},
		KeywordMatch: profile.MatchWordBoundary,
		Exceptions:   []string{"eng-productivity-tooling"},
	}
}

// loadSandboxProfile constructs the canonical "sandbox" community
// profile in memory (only_clusters restriction). Same rationale as
// loadStagingProfile.
func loadSandboxProfile(t *testing.T) *profile.Profile {
	t.Helper()
	return &profile.Profile{
		Name:         "sandbox",
		Description:  "Sandbox-only work; restricts the proxy to the sandbox cluster.",
		OnlyClusters: []string{"sandbox-cluster"},
	}
}

func TestEvaluateRequestWithProfile_KeywordDenyShortCircuits(t *testing.T) {
	st := freshStore(t)
	p := loadStagingProfile(t)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/prod-app/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, p, "")

	require.NotNil(t, obs)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceProfile, obs.DecisionSource,
		"profile-driven deny must label decision_source=profile")
	assert.True(t, obs.Enforced, "transparent + deny → enforced")
	assert.Equal(t, "staging-work", obs.ProfileName)
	assert.Contains(t, obs.DecisionReason, "prod")
}

func TestEvaluateRequestWithProfile_ProfileBeatsDefaultAllow(t *testing.T) {
	// The "default policy = allow" path would have allowed prod-app/foo
	// in K-Slice 1. With the profile active, the profile deny short-
	// circuits BEFORE the default-policy fallthrough. This is the
	// "profile beats global allow" property SecOps cares about — and
	// the property that will hold against the K-Slice 3 task scope too.
	st := freshStore(t)
	p := loadStagingProfile(t)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/prod-app/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, p, "")
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceProfile, obs.DecisionSource)
}

func TestEvaluateRequestWithProfile_NilProfileNoRegression(t *testing.T) {
	// Profile=nil must match pre-K-Slice-7 behavior exactly: every
	// well-formed request falls through to the default policy, source
	// is "default".
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/prod-app/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, nil, "")
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceDefault, obs.DecisionSource)
	assert.Empty(t, obs.ProfileName)
}

func TestEvaluateRequestWithProfile_FullUserProfileNoRegression(t *testing.T) {
	st := freshStore(t)
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	fu, err := ps.Active("full-user")
	require.NoError(t, err)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/prod-app/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, fu, "")
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceDefault, obs.DecisionSource,
		"full-user profile must abstain → default policy applies")
	assert.Equal(t, "full-user", obs.ProfileName)
}

func TestEvaluateRequestWithProfile_ExceptionAllows(t *testing.T) {
	// Staging profile has "eng-productivity-tooling" in exceptions.
	// A request whose namespace contains that exception substring
	// must NOT trigger the keyword deny.
	st := freshStore(t)
	p := loadStagingProfile(t)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/eng-productivity-tooling/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, p, "")
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict,
		"exception must suppress the keyword deny")
	assert.Equal(t, SourceDefault, obs.DecisionSource)
}

func TestEvaluateRequestWithProfile_OnlyClustersMismatchDenies(t *testing.T) {
	st := freshStore(t)
	sandbox := loadSandboxProfile(t)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/foo")
	// Cluster "prod-cluster" is not in only_clusters; deny.
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, sandbox, "prod-cluster")
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceProfile, obs.DecisionSource)
	assert.Contains(t, obs.DecisionReason, "only_clusters")
}

func TestEvaluateRequestWithProfile_OnlyClustersMatchAllows(t *testing.T) {
	st := freshStore(t)
	sandbox := loadSandboxProfile(t)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, sandbox, "sandbox-cluster")
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceDefault, obs.DecisionSource)
}

func TestEvaluateRequestWithProfile_DenyVerbsBlockMutation(t *testing.T) {
	st := freshStore(t)
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	ro, err := ps.Active("readonly")
	require.NoError(t, err)

	// delete is in the readonly deny_verbs list.
	req := parser.MustParseTestURL(http.MethodDelete, "/api/v1/namespaces/default/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, ro, "")
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceProfile, obs.DecisionSource)
	assert.Contains(t, obs.DecisionReason, "delete")

	// get is read-only; allowed (falls to default policy = allow).
	req = parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/foo")
	obs = EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, ro, "")
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
}

func TestServer_EndToEnd_ProfileDenySetsHeader(t *testing.T) {
	// Bind the server and exercise the actual HTTP path so we cover
	// (a) the response status code, (b) the x-kbouncer-decision-source
	// header, (c) the JSON body fields. This is the smoke test the spec
	// describes — proves what curl will see.
	st := freshStore(t)
	p := loadStagingProfile(t)
	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: p,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/prod-app/pods/foo")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"transparent + profile deny → 403")
	assert.Equal(t, "profile", resp.Header.Get("x-kbouncer-decision-source"),
		"decision-source header must name the profile layer")
	assert.Equal(t, "staging-work", resp.Header.Get("x-kbouncer-profile"))

	// K-Slice 2: transparent-deny body is a K8s Status. Decision-source
	// + profile name surface in the details map and on the headers.
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var status map[string]any
	require.NoError(t, json.Unmarshal(body, &status))
	assert.Equal(t, "Status", status["kind"])
	details, ok := status["details"].(map[string]any)
	require.True(t, ok, "details map present on K8s Status body")
	assert.Equal(t, SourceProfile, details["kbouncer_decision_source"])
	assert.Equal(t, "staging-work", details["kbouncer_profile"])
}

func TestServer_EndToEnd_NoProfileMatchesKSlice1(t *testing.T) {
	// Regression guard: a server with no active profile MUST behave
	// exactly like K-Slice 1 — same JSON shape, same status code,
	// decision_source="default" rather than "profile".
	st := freshStore(t)
	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/namespaces/prod-app/pods/foo")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "default", resp.Header.Get("x-kbouncer-decision-source"),
		"with no profile loaded, decision_source must be 'default'")
	assert.Empty(t, resp.Header.Get("x-kbouncer-profile"))
}

// Healthz must serve on the dedicated route, return 200 + JSON, NOT
// write an audit-decision row, and report the server's current mode +
// active profile so monitoring can fail fast if it observes drift.
func TestServer_Healthz_RespondsOK_NoAuditWrite(t *testing.T) {
	st := freshStore(t)
	cfg := Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyDeny,
	}
	s := NewServer(cfg, st)

	// Use the full mux (NewServer wires it) by binding the real Server.
	// httptest takes a ListenAndServe equivalent via httptest.NewServer
	// with the underlying handler from s.http.Handler.
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var payload struct {
		Status         string `json:"status"`
		Mode           string `json:"mode"`
		DefaultPolicy  string `json:"default_policy"`
		ActiveProfile  string `json:"active_profile"`
		DecisionsCount int64  `json:"decisions_count"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	assert.Equal(t, "ok", payload.Status)
	assert.Equal(t, string(ModeTransparent), payload.Mode)
	assert.Equal(t, string(DefaultPolicyDeny), payload.DefaultPolicy)
	assert.Empty(t, payload.ActiveProfile, "no profile configured → empty string")

	// Critical: /healthz must NOT have written an audit row. The
	// audit log is reserved for proxy decisions, not liveness probes.
	n, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(0), n,
		"/healthz must not generate audit rows")
}

func TestServer_Healthz_ReportsActiveProfileName(t *testing.T) {
	st := freshStore(t)
	prof := &profile.Profile{Name: "staging-work"}
	cfg := Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: prof,
	}
	s := NewServer(cfg, st)
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var payload struct {
		ActiveProfile string `json:"active_profile"`
	}
	require.NoError(t, json.Unmarshal(body, &payload))
	assert.Equal(t, "staging-work", payload.ActiveProfile)
}

func TestServer_Healthz_DoesNotShadowProxyEvaluation(t *testing.T) {
	// Regression guard: an arbitrary URL that happens to start with
	// /healthz... must still hit the catch-all proxy handler, not the
	// healthz handler. ServeMux's exact-vs-prefix rules mean "/healthz"
	// (no trailing slash) only matches the exact path.
	st := freshStore(t)
	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)
	ts := httptest.NewServer(s.http.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthzzz/api/v1/pods")
	require.NoError(t, err)
	defer resp.Body.Close()
	// Should fall through to proxy handler — Content-Type still
	// application/json but body contains a proxy_observation envelope.
	body, _ := io.ReadAll(resp.Body)
	var probe map[string]any
	require.NoError(t, json.Unmarshal(body, &probe))
	_, hasObservation := probe["proxy_observation"]
	assert.True(t, hasObservation,
		"/healthzzz/... must route to proxy handler, not /healthz")
}
