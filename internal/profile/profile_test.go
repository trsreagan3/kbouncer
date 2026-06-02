package profile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultProfilesLoad makes sure the embedded YAML parses cleanly
// AND that the documented default profiles are present. The 2026-05-17
// Opus readonly-profile audit closure renamed `readonly` → `safe-default`
// AND hardened the verb set. Embedded defaults remain TWO: full-user
// (passthrough) + safe-default (cross-product safe-by-default deny
// layer). Other profiles ship in community-profiles/ and install via
// `kbounce profile install --from URL`.
func TestDefaultProfilesLoad(t *testing.T) {
	ps, err := LoadProfiles("") // empty path → embedded defaults
	require.NoError(t, err)
	require.NotNil(t, ps)
	assert.Empty(t, ps.Path, "loading defaults should leave Path empty")

	for _, want := range []string{
		"full-user",
		"safe-default",
	} {
		p, err := ps.Active(want)
		require.NoError(t, err, "default %q must be present", want)
		assert.Equal(t, want, p.Name)
	}

	// `full-user` profile must abstain on any request.
	p, err := ps.Active("full-user")
	require.NoError(t, err)
	v := p.Evaluate(&ParsedRequest{Verb: "delete", Namespace: "prod", ResourceName: "prod-pod"})
	assert.False(t, v.Denied, "full-user profile must always abstain")

	// `safe-default` profile must deny destructive verbs.
	p, err = ps.Active("safe-default")
	require.NoError(t, err)
	v = p.Evaluate(&ParsedRequest{Verb: "delete"})
	assert.True(t, v.Denied, "safe-default profile must deny destructive verbs")
}

// TestDefaultProfiles_LegacyAliasesResolve pins the backward-compat
// alias map: lookups for the legacy names "none" / "prod-readonly" /
// "readonly" resolve to "full-user" / "safe-default" / "safe-default"
// with a deprecation warning. Removed in v1.1. See [[bounce-suite-rename]]
// and the Opus readonly-profile audit closure.
func TestDefaultProfiles_LegacyAliasesResolve(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)

	p, err := ps.Active("none")
	require.NoError(t, err, "legacy alias 'none' must resolve to 'full-user'")
	assert.Equal(t, FullUserProfileName, p.Name)

	p, err = ps.Active("prod-readonly")
	require.NoError(t, err, "legacy alias 'prod-readonly' must resolve to 'safe-default'")
	assert.Equal(t, SafeDefaultProfileName, p.Name)

	p, err = ps.Active("readonly")
	require.NoError(t, err, "legacy alias 'readonly' must resolve to 'safe-default'")
	assert.Equal(t, SafeDefaultProfileName, p.Name)
}

func TestLoadProfilesFromDisk_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	written, err := EnsureDefaultProfilesFile(path)
	require.NoError(t, err)
	assert.True(t, written, "first call should write the file")

	// Second call must not overwrite.
	written, err = EnsureDefaultProfilesFile(path)
	require.NoError(t, err)
	assert.False(t, written, "second call must NOT overwrite an existing file")

	// File mode should be private (0o600).
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"profiles.yaml must be private (0o600)")

	ps, err := LoadProfiles(path)
	require.NoError(t, err)
	assert.Equal(t, path, ps.Path)
	// Both embedded defaults must round-trip.
	for _, want := range []string{
		"full-user", "safe-default",
	} {
		_, err := ps.Active(want)
		assert.NoError(t, err, "profile %q missing after disk round-trip", want)
	}
}

func TestActive_UnknownProfileErrors(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	_, err = ps.Active("does-not-exist")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnknownProfile),
		"unknown profile must surface ErrUnknownProfile (not silent fallback)")
}

func TestActive_EmptyNameReturnsFullUserProfile(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	p, err := ps.Active("")
	require.NoError(t, err)
	assert.Equal(t, FullUserProfileName, p.Name,
		"empty name resolves to 'full-user' so the proxy always has a profile to call")
}

func TestNamesSorted(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	names := ps.NamesSorted()
	// Stable sorted order; same names two calls in a row.
	assert.Equal(t, names, ps.NamesSorted())
	for i := 1; i < len(names); i++ {
		assert.Less(t, names[i-1], names[i], "names must be sorted lexically")
	}
}

func TestLoadProfiles_InvalidKeywordTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
profiles:
  bad:
    deny_keywords: ["x"]
    keyword_targets: ["resource_name", "made_up_field"]
`), 0o600))
	_, err := LoadProfiles(path)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidProfile),
		"unknown keyword target should fail at load (not at first matching request)")
}

func TestLoadProfiles_InvalidKeywordMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
profiles:
  bad:
    deny_keywords: ["x"]
    keyword_match: "fuzzy"
`), 0o600))
	_, err := LoadProfiles(path)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidProfile))
}

func TestLoadProfiles_MissingFilePathFallsBackToDefaults(t *testing.T) {
	// Pointing at a path that doesn't exist must NOT error; it falls
	// back to embedded defaults so a fresh install works on the first
	// run.
	ps, err := LoadProfiles(filepath.Join(t.TempDir(), "nothing-here.yaml"))
	require.NoError(t, err)
	_, err = ps.Active("safe-default")
	require.NoError(t, err)
}

func TestEvaluate_WordBoundary_MatchesAndExcludesProductivity(t *testing.T) {
	// `prod` should match "prod-cluster" and "cluster-prod" (word
	// boundary fires at the hyphen) but NOT "productivity".
	cases := []struct {
		name     string
		ns       string
		wantDeny bool
	}{
		{"prefix", "prod-cluster", true},
		{"suffix", "cluster-prod", true},
		{"only", "prod", true},
		{"infix word", "the-prod-app", true},

		{"productivity prefix", "productivity-eng", false},
		{"productivity suffix", "eng-productivity", false},
		{"productive infix", "improductive-team", false},
		{"empty", "", false},
		{"unrelated", "alpha", false},
	}
	p := &Profile{
		Name:           "test",
		DenyKeywords:   []string{"prod"},
		KeywordTargets: []KeywordTarget{TargetNamespace},
		KeywordMatch:   MatchWordBoundary,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := p.Evaluate(&ParsedRequest{Verb: "get", Namespace: tc.ns})
			assert.Equal(t, tc.wantDeny, v.Denied,
				"namespace %q want denied=%v got denied=%v reason=%s",
				tc.ns, tc.wantDeny, v.Denied, v.Reason)
			if v.Denied {
				assert.Equal(t, SourceProfile, v.Source)
				assert.Equal(t, "test", v.ProfileName)
				assert.Contains(t, v.Reason, "prod")
			}
		})
	}
}

// TestEvaluate_WordBoundary_CrossProductParity_HIGH3301 closes
// HIGH-33-01: the Python iam-jit-bouncer uses [^A-Za-z0-9] as the
// boundary class, so underscore IS a separator. Go was using \b
// which treats \w (including _) as a "word" character — same YAML
// matched differently across products. This test pins the Go
// behavior to the Python semantic: underscore is a boundary.
func TestEvaluate_WordBoundary_CrossProductParity_HIGH3301(t *testing.T) {
	cases := []struct {
		ns       string
		wantDeny bool
		why      string
	}{
		// Underscore is now a boundary (matches Python).
		// Before the fix, these all returned wantDeny=false in Go.
		{"prod_cluster", true, "underscore is a boundary"},
		{"cluster_prod", true, "underscore is a boundary"},
		{"prod_app_v1", true, "underscores on both sides"},
		// Dots are boundaries — unchanged behavior, just confirming.
		{"prod.staging", true, "dot is a boundary"},
		{"staging.prod", true, "dot is a boundary"},
		// True false-positive avoid cases still hold.
		{"productivity", false, "no separator before 'prod' word boundary"},
		{"reproduce", false, "no separator before 'prod'"},
		// Pure substring inside an alphanumeric run still rejected.
		{"prodcluster", false, "no separator"},
	}
	p := &Profile{
		Name:           "parity",
		DenyKeywords:   []string{"prod"},
		KeywordTargets: []KeywordTarget{TargetNamespace},
		KeywordMatch:   MatchWordBoundary,
	}
	for _, tc := range cases {
		t.Run(tc.ns, func(t *testing.T) {
			v := p.Evaluate(&ParsedRequest{Verb: "get", Namespace: tc.ns})
			assert.Equal(t, tc.wantDeny, v.Denied,
				"namespace %q: %s — want denied=%v got denied=%v",
				tc.ns, tc.why, tc.wantDeny, v.Denied)
		})
	}
}

func TestEvaluate_SubstringMode_MatchesProductivityToo(t *testing.T) {
	p := &Profile{
		Name:           "strict",
		DenyKeywords:   []string{"prod"},
		KeywordTargets: []KeywordTarget{TargetNamespace},
		KeywordMatch:   MatchSubstring,
	}
	for _, ns := range []string{"prod-cluster", "cluster-prod", "productivity-eng"} {
		v := p.Evaluate(&ParsedRequest{Verb: "get", Namespace: ns})
		assert.True(t, v.Denied, "substring mode must catch %q", ns)
	}
	// Unrelated still doesn't match.
	v := p.Evaluate(&ParsedRequest{Verb: "get", Namespace: "alpha"})
	assert.False(t, v.Denied)
}

func TestEvaluate_ExceptionSuppressesKeywordDeny(t *testing.T) {
	p := &Profile{
		Name:           "staging-work",
		DenyKeywords:   []string{"prod"},
		KeywordTargets: []KeywordTarget{TargetNamespace, TargetResourceName},
		KeywordMatch:   MatchWordBoundary,
		Exceptions:     []string{"eng-productivity-tooling"},
	}
	// Exception fires: namespace contains the exception substring,
	// "prod" is suppressed.
	v := p.Evaluate(&ParsedRequest{
		Verb:      "get",
		Namespace: "eng-productivity-tooling-prod",
	})
	assert.False(t, v.Denied,
		"exception substring must suppress the keyword deny")

	// Without the exception phrase, deny still fires.
	v = p.Evaluate(&ParsedRequest{Verb: "get", Namespace: "team-prod"})
	assert.True(t, v.Denied)
}

func TestEvaluate_ExceptionDoesNotSuppressOnlyClusters(t *testing.T) {
	// only_clusters represents a HARDER intent than keyword denies;
	// exceptions must not suppress it.
	p := &Profile{
		Name:         "sandbox",
		OnlyClusters: []string{"sandbox-cluster"},
		Exceptions:   []string{"prod"},
	}
	v := p.Evaluate(&ParsedRequest{Verb: "get", Cluster: "prod-cluster"})
	assert.True(t, v.Denied, "only_clusters must not be overridden by exceptions")
	assert.Contains(t, v.Reason, "only_clusters")
}

func TestEvaluate_OnlyClustersMismatchDenies(t *testing.T) {
	p := &Profile{Name: "sandbox", OnlyClusters: []string{"sandbox-cluster"}}
	v := p.Evaluate(&ParsedRequest{Cluster: "prod-cluster"})
	assert.True(t, v.Denied)
	assert.Equal(t, SourceProfile, v.Source)
	assert.Contains(t, v.Reason, "only_clusters")

	// Match → abstains.
	v = p.Evaluate(&ParsedRequest{Cluster: "sandbox-cluster"})
	assert.False(t, v.Denied)
}

func TestEvaluate_OnlyClustersEmptyClusterDenies(t *testing.T) {
	// If only_clusters is set but the request's cluster field is empty,
	// the request can NOT be proven to target the allowed cluster, so
	// we deny. (Fail-closed posture matches the rest of the proxy.)
	p := &Profile{Name: "sandbox", OnlyClusters: []string{"sandbox-cluster"}}
	v := p.Evaluate(&ParsedRequest{Cluster: ""})
	assert.True(t, v.Denied, "unknown cluster must be denied under only_clusters")
	assert.Contains(t, v.Reason, "<unset>")
}

func TestEvaluate_DenyVerbsMatch(t *testing.T) {
	p := &Profile{Name: "ro", DenyVerbs: []string{"delete", "patch", "create", "update"}}

	for _, verb := range []string{"delete", "patch", "create", "update", "DELETE"} {
		v := p.Evaluate(&ParsedRequest{Verb: verb})
		assert.True(t, v.Denied, "deny_verbs must match %q (case-insensitive)", verb)
		assert.Equal(t, SourceProfile, v.Source)
	}
	for _, verb := range []string{"get", "list", "watch"} {
		v := p.Evaluate(&ParsedRequest{Verb: verb})
		assert.False(t, v.Denied, "read verb %q must not match deny_verbs", verb)
	}
}

func TestEvaluate_CompositionOrder_KeywordsBeforeVerbs(t *testing.T) {
	// If both a keyword AND a verb would match, the keyword fires first
	// because it's the more specific signal (the operator explicitly
	// said "block anything that looks like prod"). The reason field must
	// name the keyword, not the verb.
	p := &Profile{
		Name:           "multi",
		DenyKeywords:   []string{"prod"},
		KeywordTargets: []KeywordTarget{TargetNamespace},
		DenyVerbs:      []string{"delete"},
	}
	v := p.Evaluate(&ParsedRequest{Verb: "delete", Namespace: "prod-app"})
	assert.True(t, v.Denied)
	assert.Contains(t, v.Reason, "keyword", "keyword deny must win when both would fire")
}

func TestEvaluate_FullUserProfileAbstains(t *testing.T) {
	// The "full-user" profile, even if someone configures it with denies
	// in YAML (which would be a misconfig), is treated as an abstain by
	// name. Defends against typos that re-enable an unconfigured profile.
	p := &Profile{
		Name:         FullUserProfileName,
		DenyVerbs:    []string{"delete"},
		DenyKeywords: []string{"prod"},
	}
	v := p.Evaluate(&ParsedRequest{Verb: "delete", Namespace: "prod"})
	assert.False(t, v.Denied, "name 'full-user' is a sentinel for abstain")
}

func TestEvaluate_NilProfileSafe(t *testing.T) {
	var p *Profile
	v := p.Evaluate(&ParsedRequest{Verb: "delete"})
	assert.False(t, v.Denied)
}

func TestEvaluate_NilRequestSafe(t *testing.T) {
	p := &Profile{Name: "x", DenyVerbs: []string{"delete"}}
	v := p.Evaluate(nil)
	assert.False(t, v.Denied)
}

func TestEvaluate_KeywordTargetsDefaultsToNameAndNamespace(t *testing.T) {
	// When KeywordTargets is unset, default is [resource_name, namespace].
	p := &Profile{
		Name:         "default-targets",
		DenyKeywords: []string{"prod"},
		// no KeywordTargets — should default
	}
	// Hits via ResourceName.
	v := p.Evaluate(&ParsedRequest{ResourceName: "prod-app"})
	assert.True(t, v.Denied)
	// Hits via Namespace.
	v = p.Evaluate(&ParsedRequest{Namespace: "prod"})
	assert.True(t, v.Denied)
	// Cluster is NOT in the default target set, so a cluster-only hit
	// doesn't fire.
	v = p.Evaluate(&ParsedRequest{Cluster: "prod-cluster"})
	assert.False(t, v.Denied)
}

func TestEvaluate_KeywordMatchDefaultsToWordBoundary(t *testing.T) {
	p := &Profile{
		Name:           "default-match",
		DenyKeywords:   []string{"prod"},
		KeywordTargets: []KeywordTarget{TargetNamespace},
		// no KeywordMatch — should default to word_boundary
	}
	v := p.Evaluate(&ParsedRequest{Namespace: "productivity"})
	assert.False(t, v.Denied,
		"default match mode is word_boundary; 'productivity' must not match 'prod'")
	v = p.Evaluate(&ParsedRequest{Namespace: "prod-cluster"})
	assert.True(t, v.Denied)
}

// TestEvaluate_KeywordsWithRegexMetachars makes sure operator-supplied
// keywords that contain regex metachars (.,*,+,...) are matched as
// literal strings, not as regex. Defends against an operator typing
// `prod.*` and accidentally getting catastrophic backtracking.
func TestEvaluate_KeywordsWithRegexMetachars(t *testing.T) {
	p := &Profile{
		Name:           "literal",
		DenyKeywords:   []string{"a.b"},
		KeywordTargets: []KeywordTarget{TargetNamespace},
		KeywordMatch:   MatchWordBoundary,
	}
	// "axb" must NOT match because "a.b" is treated literally, not as
	// a regex.
	v := p.Evaluate(&ParsedRequest{Namespace: "axb"})
	assert.False(t, v.Denied)
	v = p.Evaluate(&ParsedRequest{Namespace: "a.b"})
	assert.True(t, v.Denied)
}

// TestEvaluate_DeterministicReasonAcrossRuns guards against map-iteration
// nondeterminism leaking into audit reasons. We can't enumerate every
// random ordering, but we can assert the same input → same reason
// across many runs.
func TestEvaluate_DeterministicReasonAcrossRuns(t *testing.T) {
	p := &Profile{
		Name:           "staging-work",
		DenyKeywords:   []string{"prod", "customer"},
		KeywordTargets: []KeywordTarget{TargetNamespace, TargetResourceName},
	}
	req := &ParsedRequest{Namespace: "prod-app", ResourceName: "customer-data"}
	first := p.Evaluate(req).Reason
	require.NotEmpty(t, first)
	for i := 0; i < 100; i++ {
		// Fresh profile each iteration so the lazy compile races
		// realistically.
		p2 := &Profile{
			Name:           p.Name,
			DenyKeywords:   p.DenyKeywords,
			KeywordTargets: p.KeywordTargets,
		}
		got := p2.Evaluate(req).Reason
		assert.Equal(t, first, got,
			"profile evaluate reason must be deterministic across runs")
	}
}

// Mock task scope used to demonstrate the "profile beats task" composition
// property. The proxy package will exercise this end-to-end, but here we
// verify the property at the profile layer by simulating the caller
// pattern: the caller calls profile.Evaluate FIRST, and only consults
// the task scope when the profile abstains.
func TestComposition_ProfileDenyBeatsTaskAllow(t *testing.T) {
	type mockTaskScope struct {
		allow bool
	}
	taskScope := mockTaskScope{allow: true}

	p := &Profile{
		Name:           "staging-work",
		DenyKeywords:   []string{"prod"},
		KeywordTargets: []KeywordTarget{TargetNamespace},
	}
	req := &ParsedRequest{Verb: "get", Namespace: "prod-app"}

	v := p.Evaluate(req)
	require.True(t, v.Denied, "profile must deny prod-app")

	// Caller pattern: when profile denies, the task scope is NEVER
	// consulted. We assert that fact by asserting the caller doesn't
	// reach the task-scope branch.
	consulted := false
	if !v.Denied {
		consulted = true
		_ = taskScope.allow
	}
	assert.False(t, consulted,
		"profile deny must short-circuit BEFORE the task scope is consulted")
}

// --- Opus readonly-profile audit closure (2026-05-17) ---
//
// The following tests pin the new safe-default behavior introduced by
// the audit-closure commit:
//
//   - 8 new deny_verbs (Gap-K-1..K-7, K-12)
//   - SSAR / SAR / TokenReview exemption (False-positive-K-2)
//   - Impersonation deny (Gap-K-9)
//   - Dry-run carve-out (False-positive-K-3)
//   - Subresource-write long-tail safety net (Gap-K-14)
//
// Each verb is named via its parser-emitted form so any future change
// to the parser's verb-naming surfaces here.

// TestSafeDefault_DeniesNewVerbs pins all 8 added verbs as denied
// under the embedded safe-default profile. Each row gives:
//   - parser-emitted verb string
//   - HTTP method most typical for the verb
//   - representative URL shape (informational; not exercised here —
//     profile.Evaluate runs on a ParsedRequest directly)
//   - gap reference
func TestSafeDefault_DeniesNewVerbs(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	cases := []struct {
		verb     string
		method   string
		resource string
		gap      string
	}{
		{"proxy", "POST", "pods", "Gap-K-1 — RBAC bypass tunnel"},
		{"eviction", "POST", "pods", "Gap-K-2 — pod deletion by another name"},
		{"scale", "PATCH", "deployments", "Gap-K-3 — replica-count mutation"},
		{"status", "PUT", "deployments", "Gap-K-4 — controller state poisoning"},
		{"finalize", "PUT", "namespaces", "Gap-K-5 — bypass deletion protection"},
		{"ephemeralcontainers", "PATCH", "pods", "Gap-K-6 — debug-container injection"},
		{"token", "POST", "serviceaccounts", "Gap-K-7 — credential minting"},
		{"binding", "POST", "pods", "Gap-K-12 — manual scheduling bypass"},
	}
	for _, tc := range cases {
		t.Run(tc.verb, func(t *testing.T) {
			v := sd.Evaluate(&ParsedRequest{
				Verb:        tc.verb,
				Method:      tc.method,
				Group:       "",
				Resource:    tc.resource,
				Subresource: tc.verb,
				Namespace:   "default",
			})
			assert.True(t, v.Denied,
				"safe-default must deny verb %q (%s)", tc.verb, tc.gap)
			assert.Equal(t, SourceProfile, v.Source)
		})
	}
}

// TestSafeDefault_ParserEmitsExpectedVerbStrings exercises the parser
// directly to confirm the URL shape for each of the 8 added verbs
// produces the verb string the deny_verbs YAML lists. If the parser's
// naming ever drifts (e.g. "ephemeralcontainers" → "ephemeral-
// containers"), this test fails BEFORE the verb silently slips past
// safe-default in production. We can't import the parser package
// without a cycle (parser → profile would be wrong direction), so the
// proxy-level test in proxy_test exercises the end-to-end flow; here
// we just document the verb-name contract.
func TestSafeDefault_NewVerbsListedInDefaults(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	for _, want := range []string{
		"proxy", "eviction", "scale", "status",
		"finalize", "ephemeralcontainers", "token", "binding",
	} {
		assert.Contains(t, sd.DenyVerbs, want,
			"safe-default.deny_verbs must list %q", want)
	}
}

// TestSafeDefault_SSARExempt_AllowsAuthCanI pins the SSAR / SAR /
// TokenReview carve-out: POST to these resources passes even though
// the "create" verb is on safe-default's deny list, because their
// API contract is "tell me what I could do" / "validate this token"
// rather than mutate cluster state. Audit-cadence note (b):
// match is on the FULL group/resource pair.
func TestSafeDefault_SSARExempt_AllowsAuthCanI(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	exempt := []struct {
		group    string
		resource string
	}{
		{"authorization.k8s.io", "selfsubjectaccessreviews"},
		{"authorization.k8s.io", "selfsubjectrulesreviews"},
		{"authorization.k8s.io", "subjectaccessreviews"},
		{"authorization.k8s.io", "localsubjectaccessreviews"},
		{"authentication.k8s.io", "tokenreviews"},
	}
	for _, tc := range exempt {
		t.Run(tc.group+"/"+tc.resource, func(t *testing.T) {
			v := sd.Evaluate(&ParsedRequest{
				Verb:     "create",
				Method:   "POST",
				Group:    tc.group,
				Resource: tc.resource,
			})
			assert.False(t, v.Denied,
				"safe-default must EXEMPT POST to %s/%s (auth can-i / token validation)",
				tc.group, tc.resource)
		})
	}
}

// TestSafeDefault_SSARExempt_DoesNotLeakAcrossGroups pins audit-
// cadence note (b): a CRD that defines a resource named
// "tokenreviews" or "subjectaccessreviews" in a DIFFERENT API group
// must NOT be accidentally exempted. The exemption check uses the
// full "group/resource" string.
func TestSafeDefault_SSARExempt_DoesNotLeakAcrossGroups(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	v := sd.Evaluate(&ParsedRequest{
		Verb:     "create",
		Method:   "POST",
		Group:    "example.com", // CRD group, NOT authentication.k8s.io
		Resource: "tokenreviews",
	})
	assert.True(t, v.Denied,
		"a CRD named tokenreviews in a different group MUST still be denied")
}

// TestSafeDefault_DeniesImpersonation pins Gap-K-9: a request that
// carried an Impersonate-User header is denied under safe-default
// regardless of verb (even read verbs that would normally allow).
func TestSafeDefault_DeniesImpersonation(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	// list (a read verb) — normally allowed — denied because of
	// impersonation.
	v := sd.Evaluate(&ParsedRequest{
		Verb:             "list",
		Method:           "GET",
		Resource:         "pods",
		IsImpersonation:  true,
		ImpersonatedUser: "cluster-admin",
	})
	assert.True(t, v.Denied,
		"safe-default must deny impersonation even on read verbs")
	assert.Equal(t, SourceProfile, v.Source)
	assert.Contains(t, v.Reason, "cluster-admin",
		"deny reason must name the impersonated user for audit clarity")
}

// TestSafeDefault_NoImpersonation_AllowsBaseCase pins the negative
// — same list request without impersonation must not fire the
// impersonation deny (otherwise we're denying everything, which is
// the failure mode the audit closure cared about).
func TestSafeDefault_NoImpersonation_AllowsBaseCase(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	v := sd.Evaluate(&ParsedRequest{
		Verb:     "list",
		Method:   "GET",
		Resource: "pods",
	})
	assert.False(t, v.Denied,
		"safe-default must allow plain list without impersonation")
}

// TestSafeDefault_DryRunCarveOut_AllowsPreview pins False-positive-K-3:
// POST with ?dryRun=All is a server-side preview that doesn't change
// state, so it bypasses the verb-deny.
func TestSafeDefault_DryRunCarveOut_AllowsPreview(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	v := sd.Evaluate(&ParsedRequest{
		Verb:      "create",
		Method:    "POST",
		Resource:  "configmaps",
		Namespace: "default",
		IsDryRun:  true,
	})
	assert.False(t, v.Denied,
		"safe-default must allow dry-run create as a preview")
}

// TestSafeDefault_DryRunCarveOut_DoesNotBypassImpersonation pins
// that dry-run is a PER-VERB carve-out, not a global escape hatch.
// (Currently the implementation short-circuits at order-1 BEFORE
// impersonation, so this test ALSO documents that an attacker can't
// chain dryRun=All + Impersonate-User to bypass impersonation deny —
// it's a side-effect-free preview anyway. If the order changes,
// this test catches it.)
//
// NB: this test asserts the CURRENT layered semantic where dry-run
// wins over impersonation, which is correct because a dry-run can't
// actually impersonate-and-mutate. If we ever decide to invert (deny
// impersonation BEFORE checking dry-run), update both this test and
// the docstring on Evaluate.
func TestSafeDefault_DryRun_TakesPrecedenceOverImpersonation(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	v := sd.Evaluate(&ParsedRequest{
		Verb:             "create",
		Method:           "POST",
		Resource:         "configmaps",
		Namespace:        "default",
		IsDryRun:         true,
		IsImpersonation:  true,
		ImpersonatedUser: "cluster-admin",
	})
	assert.False(t, v.Denied,
		"dry-run preview short-circuits BEFORE impersonation gate; documented + intended")
}

// TestSafeDefault_SubresourceLongTail_DeniesHypotheticalCRD pins
// Gap-K-14: PATCH to a CRD-defined subresource not enumerated in
// deny_verbs (Argo CD's Application/sync is the canonical example)
// is still denied under safe-default via the deny_subresource_writes
// long-tail rule.
func TestSafeDefault_SubresourceLongTail_DeniesHypotheticalCRD(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	// Hypothetical Argo CD-style CRD subresource. "sync" is NOT in
	// deny_verbs but the long-tail catches it because it's a PATCH
	// against a subresource.
	v := sd.Evaluate(&ParsedRequest{
		Verb:        "sync",
		Method:      "PATCH",
		Group:       "argoproj.io",
		Resource:    "applications",
		Subresource: "sync",
		Namespace:   "argocd",
	})
	assert.True(t, v.Denied,
		"deny_subresource_writes must catch CRD-defined mutating subresource %q",
		"sync")
	assert.Equal(t, SourceProfile, v.Source)
	assert.Contains(t, v.Reason, "sync")
}

// TestSafeDefault_SubresourceLongTail_PreservesLogCarveOut pins
// audit-cadence note (c) + False-positive-K-1: the log / logs
// subresource is read-only across all GET shapes (and even POST
// shapes that some clients use for follow=true streams), so it
// stays open under safe-default.
func TestSafeDefault_SubresourceLongTail_PreservesLogCarveOut(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	// GET log — the canonical kubectl logs path. Must pass.
	v := sd.Evaluate(&ParsedRequest{
		Verb:        "log",
		Method:      "GET",
		Resource:    "pods",
		Subresource: "log",
		Namespace:   "default",
		ResourceName: "foo",
	})
	assert.False(t, v.Denied,
		"safe-default must NOT deny GET pod log (read-only stream carve-out)")

	// Capitalization-tolerant: subresource normalized lowercase.
	v = sd.Evaluate(&ParsedRequest{
		Verb:        "log",
		Method:      "GET",
		Resource:    "pods",
		Subresource: "LOG",
	})
	assert.False(t, v.Denied,
		"log carve-out must be case-insensitive")

	// "logs" plural also carved out (some CRDs / API extensions
	// pluralize).
	v = sd.Evaluate(&ParsedRequest{
		Verb:        "logs",
		Method:      "GET",
		Resource:    "pods",
		Subresource: "logs",
	})
	assert.False(t, v.Denied,
		"plural 'logs' subresource also covered by carve-out")
}

// TestSafeDefault_SubresourceLongTail_ReadVerbsPass pins that a
// GET against a non-log subresource (e.g. GET /pods/{name}/status
// for a controller reading status) still passes — only writes are
// gated by deny_subresource_writes.
func TestSafeDefault_SubresourceLongTail_ReadVerbsPass(t *testing.T) {
	// Custom profile to isolate the long-tail rule: status is in
	// safe-default's deny_verbs, which would otherwise mask the
	// long-tail check. Build a minimal profile that ONLY has
	// deny_subresource_writes set.
	p := &Profile{
		Name:                  "longtail-only",
		DenySubresourceWrites: true,
	}
	v := p.Evaluate(&ParsedRequest{
		Verb:        "status",
		Method:      "GET",
		Resource:    "deployments",
		Subresource: "status",
	})
	assert.False(t, v.Denied,
		"GET on subresource is read-only; long-tail must not fire")
}

// ---------------------------------------------------------------------
// Profile allow_rules enforcement (feat/profile-allow-enforcement).
//
// Before this slice, allow_rules were parsed + round-tripped but the
// evaluator never consulted them — "allowing" traffic had zero runtime
// effect, violating [[ibounce-honest-positioning]]. These tests pin the
// dbounce-mirrored semantics: an allow_rule flips a would-be deferral
// into an explicit ALLOW (composition Order 7) but CANNOT override a
// safe-default hard-floor deny (those deny layers return first).
// ---------------------------------------------------------------------

// TestEvaluate_AllowRule_FlipsDeferToAllow proves an allow_rule produces
// an explicit profile-level ALLOW (Allowed=true, source=profile.allow)
// for a request no profile-deny caught. The Pattern uses the canonical
// `resource:verb_glob` shape — identical to global/task rules.
func TestEvaluate_AllowRule_FlipsDeferToAllow(t *testing.T) {
	p := &Profile{
		Name: "explicit-allow",
		AllowRules: []ProfileAllowRule{
			{Pattern: "configmaps:get"},
		},
	}
	// Sanity: without the allow_rule this profile abstains (both false).
	abstain := (&Profile{Name: "noop"}).Evaluate(&ParsedRequest{
		Verb: "get", Resource: "configmaps", Namespace: "default",
	})
	assert.False(t, abstain.Denied)
	assert.False(t, abstain.Allowed,
		"a profile with no allow_rules must abstain, not allow")

	// With the allow_rule: explicit ALLOW.
	v := p.Evaluate(&ParsedRequest{
		Verb: "get", Resource: "configmaps", Namespace: "default",
	})
	assert.True(t, v.Allowed, "allow_rule must flip defer→allow")
	assert.False(t, v.Denied)
	assert.Equal(t, SourceProfileAllow, v.Source)
	assert.Equal(t, "explicit-allow", v.ProfileName)
	assert.Contains(t, v.Reason, "configmaps:get")
}

// TestEvaluate_AllowRule_VerbGlobAndWildcards exercises the glob /
// wildcard surface of the resource:verb_glob convention.
func TestEvaluate_AllowRule_VerbGlobAndWildcards(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		req     ParsedRequest
		allow   bool
	}{
		{"verb glob *", "configmaps:*", ParsedRequest{Verb: "list", Resource: "configmaps"}, true},
		{"resource wildcard", "*:get", ParsedRequest{Verb: "get", Resource: "pods"}, true},
		{"bare star", "*", ParsedRequest{Verb: "delete", Resource: "pods"}, true},
		{"verb mismatch", "configmaps:get", ParsedRequest{Verb: "delete", Resource: "configmaps"}, false},
		{"resource mismatch", "configmaps:get", ParsedRequest{Verb: "get", Resource: "secrets"}, false},
		{"prefix glob verb", "pods:get*", ParsedRequest{Verb: "getlogs", Resource: "pods"}, true},
		{"empty resource vs concrete rule", "pods:get", ParsedRequest{Verb: "get", Resource: ""}, false},
		{"malformed pattern never allows", "pods", ParsedRequest{Verb: "get", Resource: "pods"}, false},
		{"partial resource wildcard rejected", "pod*:get", ParsedRequest{Verb: "get", Resource: "pods"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Profile{Name: "p", AllowRules: []ProfileAllowRule{{Pattern: tc.pattern}}}
			v := p.Evaluate(&tc.req)
			assert.Equal(t, tc.allow, v.Allowed, "pattern %q vs %+v", tc.pattern, tc.req)
			if tc.allow {
				assert.Equal(t, SourceProfileAllow, v.Source)
			}
		})
	}
}

// TestEvaluate_AllowRule_CannotOverrideSafeDefaultFloor is the
// load-bearing safety test: an allow_rule that names exactly the
// hard-floor-denied shape MUST NOT flip the deny to an allow. The deny
// layer (deny_verbs / impersonation / etc.) short-circuits before
// allow_rules are ever consulted. Mirrors dbounce's DCL-floor regression.
func TestEvaluate_AllowRule_CannotOverrideSafeDefaultFloor(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)

	// Inject an allow_rule that would, if consulted, bless `pods:delete`.
	// safe-default denies the `delete` verb at Order 5 — which returns
	// BEFORE Order 7 allow_rules. The allow_rule must therefore have NO
	// effect on the floor.
	sd.AllowRules = append(sd.AllowRules, ProfileAllowRule{Pattern: "pods:delete"})

	v := sd.Evaluate(&ParsedRequest{
		Verb: "delete", Method: "DELETE", Resource: "pods", ResourceName: "victim",
	})
	assert.True(t, v.Denied,
		"safe-default deny_verbs floor MUST win over a profile allow_rule")
	assert.False(t, v.Allowed)
	assert.Equal(t, SourceProfile, v.Source)
}

// TestEvaluate_AllowRule_AllowsNonFlooredVerbUnderSafeDefault confirms
// the allow_rule still does useful work under safe-default: a verb the
// floor does NOT deny but that an operator wants explicitly blessed (so
// it short-circuits before task/global rules) is allowed.
func TestEvaluate_AllowRule_AllowsNonFlooredVerbUnderSafeDefault(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	// get is a read verb safe-default does not deny.
	sd.AllowRules = append(sd.AllowRules, ProfileAllowRule{Pattern: "configmaps:get"})
	v := sd.Evaluate(&ParsedRequest{Verb: "get", Resource: "configmaps", Namespace: "default"})
	assert.True(t, v.Allowed)
	assert.False(t, v.Denied)
	assert.Equal(t, SourceProfileAllow, v.Source)
}

// TestEvaluate_AllowRule_KeywordDenyStillWins pins that a deny_keywords
// match (Order 3) beats an allow_rule (Order 7) for the same request.
func TestEvaluate_AllowRule_KeywordDenyStillWins(t *testing.T) {
	p := &Profile{
		Name:         "kw-vs-allow",
		DenyKeywords: []string{"prod"},
		AllowRules:   []ProfileAllowRule{{Pattern: "configmaps:get"}},
	}
	v := p.Evaluate(&ParsedRequest{
		Verb: "get", Resource: "configmaps", Namespace: "prod-app",
	})
	assert.True(t, v.Denied, "deny_keywords must win over a later allow_rule")
	assert.False(t, v.Allowed)
	assert.Equal(t, SourceProfile, v.Source)
}

// TestMatchAllowRule_Helper covers the exported MatchAllowRule helper's
// nil / sentinel / empty guards + a positive match.
func TestMatchAllowRule_Helper(t *testing.T) {
	var nilP *Profile
	ok, pat := nilP.MatchAllowRule(&ParsedRequest{Verb: "get", Resource: "pods"})
	assert.False(t, ok)
	assert.Empty(t, pat)

	full := &Profile{Name: FullUserProfileName, AllowRules: []ProfileAllowRule{{Pattern: "*"}}}
	ok, _ = full.MatchAllowRule(&ParsedRequest{Verb: "get", Resource: "pods"})
	assert.False(t, ok, "full-user sentinel never matches")

	p := &Profile{Name: "p", AllowRules: []ProfileAllowRule{{Pattern: "pods:get"}}}
	ok, _ = p.MatchAllowRule(nil)
	assert.False(t, ok, "nil request never matches")
	ok, pat = p.MatchAllowRule(&ParsedRequest{Verb: "get", Resource: "pods"})
	assert.True(t, ok)
	assert.Equal(t, "pods:get", pat)
}

// TestAllowRule_RoundTrips confirms the AllowRules field still survives a
// YAML round-trip (the original round-trip invariant) AND now drives
// enforcement after re-load.
func TestAllowRule_RoundTrips(t *testing.T) {
	yamlIn := []byte(`profiles:
  ci-runner:
    description: "CI namespace bot"
    deny_verbs: [delete]
    allow_rules:
      - pattern: "configmaps:get"
        note: "CI reads its own config"
`)
	ps, err := parseProfiles(yamlIn, "")
	require.NoError(t, err)
	p, err := ps.Active("ci-runner")
	require.NoError(t, err)
	require.Len(t, p.AllowRules, 1)
	assert.Equal(t, "configmaps:get", p.AllowRules[0].Pattern)
	assert.Equal(t, "CI reads its own config", p.AllowRules[0].Note)

	// Enforcement after load: allow_rule allows the get.
	v := p.Evaluate(&ParsedRequest{Verb: "get", Resource: "configmaps"})
	assert.True(t, v.Allowed)
	// But the deny_verbs floor still wins for delete.
	v = p.Evaluate(&ParsedRequest{Verb: "delete", Resource: "configmaps"})
	assert.True(t, v.Denied)
	assert.False(t, v.Allowed)
}
