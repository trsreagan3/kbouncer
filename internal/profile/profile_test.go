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
// AND that every documented default profile is present. If someone
// renames a default profile in defaults.yaml without updating callers,
// this test will catch it.
func TestDefaultProfilesLoad(t *testing.T) {
	ps, err := LoadProfiles("") // empty path → embedded defaults
	require.NoError(t, err)
	require.NotNil(t, ps)
	assert.Empty(t, ps.Path, "loading defaults should leave Path empty")

	for _, want := range []string{
		"staging-work",
		"prod-readonly",
		"sandbox",
		"incident-response",
		"none",
	} {
		p, err := ps.Active(want)
		require.NoError(t, err, "default %q must be present", want)
		assert.Equal(t, want, p.Name)
	}

	// `none` profile must abstain on any request.
	p, err := ps.Active("none")
	require.NoError(t, err)
	v := p.Evaluate(&ParsedRequest{Verb: "delete", Namespace: "prod", ResourceName: "prod-pod"})
	assert.False(t, v.Denied, "none profile must always abstain")
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
	// All five defaults must round-trip.
	for _, want := range []string{
		"staging-work", "prod-readonly", "sandbox", "incident-response", "none",
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

func TestActive_EmptyNameReturnsNoneProfile(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	p, err := ps.Active("")
	require.NoError(t, err)
	assert.Equal(t, NoneProfileName, p.Name,
		"empty name resolves to 'none' so the proxy always has a profile to call")
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
	_, err = ps.Active("staging-work")
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

func TestEvaluate_NoneProfileAbstains(t *testing.T) {
	// The "none" profile, even if someone configures it with denies in
	// YAML (which would be a misconfig), is treated as an abstain by
	// name. Defends against typos that re-enable an unconfigured profile.
	p := &Profile{
		Name:         NoneProfileName,
		DenyVerbs:    []string{"delete"},
		DenyKeywords: []string{"prod"},
	}
	v := p.Evaluate(&ParsedRequest{Verb: "delete", Namespace: "prod"})
	assert.False(t, v.Denied, "name 'none' is a sentinel for abstain")
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
