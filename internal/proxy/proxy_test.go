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
		Observation *RequestObservation `json:"proxy_observation"`
		SliceNote   string              `json:"_slice1_note"`
	}
	require.NoError(t, json.Unmarshal(body, &decoded))

	require.NotNil(t, decoded.Observation)
	assert.Equal(t, "get", decoded.Observation.ParsedVerb)
	assert.Equal(t, "pods", decoded.Observation.ParsedResource)
	assert.Equal(t, "my-pod", decoded.Observation.ParsedName)
	assert.Contains(t, decoded.SliceNote, "K-Slice 1")

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

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded struct {
		Observation *RequestObservation `json:"proxy_observation"`
	}
	require.NoError(t, json.Unmarshal(body, &decoded))
	require.NotNil(t, decoded.Observation)
	assert.True(t, decoded.Observation.Enforced)
	assert.Equal(t, VerdictDeny, decoded.Observation.DecisionVerdict)
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

// loadStagingProfile returns the embedded "staging-work" default profile.
// Used by the proxy-integration tests so they exercise the SAME profile
// shape an operator gets out of the box.
func loadStagingProfile(t *testing.T) *profile.Profile {
	t.Helper()
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	p, err := ps.Active("staging-work")
	require.NoError(t, err)
	return p
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

func TestEvaluateRequestWithProfile_NoneProfileNoRegression(t *testing.T) {
	st := freshStore(t)
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	none, err := ps.Active("none")
	require.NoError(t, err)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/prod-app/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, none, "")
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceDefault, obs.DecisionSource,
		"none profile must abstain → default policy applies")
	assert.Equal(t, "none", obs.ProfileName)
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
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sandbox, err := ps.Active("sandbox")
	require.NoError(t, err)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/foo")
	// Cluster "prod-cluster" is not in only_clusters; deny.
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, sandbox, "prod-cluster")
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceProfile, obs.DecisionSource)
	assert.Contains(t, obs.DecisionReason, "only_clusters")
}

func TestEvaluateRequestWithProfile_OnlyClustersMatchAllows(t *testing.T) {
	st := freshStore(t)
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sandbox, err := ps.Active("sandbox")
	require.NoError(t, err)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/foo")
	obs := EvaluateRequestWithProfile(req, st, ModeTransparent, DefaultPolicyAllow, sandbox, "sandbox-cluster")
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceDefault, obs.DecisionSource)
}

func TestEvaluateRequestWithProfile_DenyVerbsBlockMutation(t *testing.T) {
	st := freshStore(t)
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	ro, err := ps.Active("prod-readonly")
	require.NoError(t, err)

	// delete is in the prod-readonly deny_verbs list.
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

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded struct {
		Observation *RequestObservation `json:"proxy_observation"`
	}
	require.NoError(t, json.Unmarshal(body, &decoded))
	require.NotNil(t, decoded.Observation)
	assert.Equal(t, SourceProfile, decoded.Observation.DecisionSource)
	assert.Equal(t, "staging-work", decoded.Observation.ProfileName)
	assert.True(t, decoded.Observation.Enforced)
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
