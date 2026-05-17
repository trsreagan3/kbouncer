package rules

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePattern_Canonical(t *testing.T) {
	cases := map[string]struct {
		wantResource string
		wantVerb     string
	}{
		"pods:create":     {"pods", "create"},
		"secrets:get":     {"secrets", "get"},
		"pods:*":          {"pods", "*"},
		"*:delete*":       {"*", "delete*"},
		"*":               {"*", "*"},
		"Deployments:LIST": {"deployments", "LIST"}, // resource lowercased, verb preserved
	}
	for in, want := range cases {
		res, verb, err := ParsePattern(in)
		require.NoError(t, err, "input=%q", in)
		assert.Equal(t, want.wantResource, res, "resource for %q", in)
		assert.Equal(t, want.wantVerb, verb, "verb for %q", in)
	}
}

func TestParsePattern_RejectsMalformed(t *testing.T) {
	bad := []string{
		"",            // empty
		"   ",         // whitespace
		"pods-get",    // dash instead of colon (the WB23 MED-23-02 case)
		"pods:get:x",  // too many parts
		":get",        // empty resource
		"pods:",       // empty verb
		"pod*:get",    // partial wildcard at resource half
		"pods get",    // embedded whitespace
	}
	for _, in := range bad {
		_, _, err := ParsePattern(in)
		require.Error(t, err, "input=%q should be rejected", in)
		var ipe *ErrInvalidPattern
		assert.True(t, errors.As(err, &ipe), "should be ErrInvalidPattern (%q)", in)
	}
}

func TestProxyRule_Matches_PatternOnly(t *testing.T) {
	req := &ParsedRequest{Verb: "create", Resource: "pods"}

	cases := map[string]struct {
		pattern   string
		wantMatch bool
	}{
		"exact":               {"pods:create", true},
		"verb wildcard":       {"pods:*", true},
		"verb prefix glob":    {"pods:cre*", true},
		"resource wildcard":   {"*:create", true},
		"bare star":           {"*", true},
		"wrong verb":          {"pods:delete", false},
		"wrong resource":      {"secrets:create", false},
		"verb question mark":  {"pods:creat?", true},
		"verb glob no match":  {"pods:del*", false},
	}
	for name, tc := range cases {
		r := ProxyRule{Pattern: tc.pattern, Effect: EffectAllow}
		assert.Equal(t, tc.wantMatch, r.Matches(req), "case=%s pattern=%q", name, tc.pattern)
	}
}

func TestProxyRule_Matches_NamespaceScope(t *testing.T) {
	r := ProxyRule{Pattern: "pods:*", Effect: EffectAllow, NamespaceScope: "prod-*"}

	assert.True(t, r.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Namespace: "prod-billing"}))
	assert.True(t, r.Matches(&ParsedRequest{Verb: "list", Resource: "pods", Namespace: "prod-eng"}))
	assert.False(t, r.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Namespace: "staging"}))
	// Cluster-scoped (no namespace) does NOT match a namespace-scoped
	// rule — conservative fallthrough.
	assert.False(t, r.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Namespace: ""}))

	// "*" namespace scope matches anything (including cluster-scoped).
	r2 := ProxyRule{Pattern: "pods:*", Effect: EffectAllow, NamespaceScope: "*"}
	assert.True(t, r2.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Namespace: ""}))
	assert.True(t, r2.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Namespace: "anywhere"}))
}

func TestProxyRule_Matches_ResourceScope(t *testing.T) {
	r := ProxyRule{Pattern: "pods:get", Effect: EffectAllow, ResourceScope: "billing-*"}

	assert.True(t, r.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Name: "billing-api"}))
	assert.False(t, r.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Name: "metrics-api"}))
	// Collection-level get (Name="") doesn't match a name-scoped rule.
	assert.False(t, r.Matches(&ParsedRequest{Verb: "get", Resource: "pods", Name: ""}))
}

func TestProxyRule_Matches_GlobRejectsCharClass(t *testing.T) {
	// Per the WB23 LOW-23-02 fix on the Python side: globs are `*` and
	// `?` ONLY. A literal `[` should NOT take on character-class
	// semantics. The pattern below should never match because the
	// verb glob expects a LITERAL "[abc]" substring, not [abc].
	r := ProxyRule{Pattern: "pods:[abc]", Effect: EffectAllow}
	assert.False(t, r.Matches(&ParsedRequest{Verb: "a", Resource: "pods"}))
	assert.False(t, r.Matches(&ParsedRequest{Verb: "b", Resource: "pods"}))
	// But a literal "[abc]" verb would match.
	assert.True(t, r.Matches(&ParsedRequest{Verb: "[abc]", Resource: "pods"}))
}

func TestRuleSet_Add_RejectsMalformed(t *testing.T) {
	rs := NewRuleSet(nil)
	err := rs.Add(ProxyRule{Pattern: "pods-get", Effect: EffectAllow})
	require.Error(t, err)
	assert.Equal(t, 0, rs.Len())
}

func TestRuleSet_Add_RejectsBadEffect(t *testing.T) {
	rs := NewRuleSet(nil)
	err := rs.Add(ProxyRule{Pattern: "pods:get", Effect: Effect("maybe")})
	require.Error(t, err)
}

func TestRuleSet_Evaluate_DenyBeatsAllow(t *testing.T) {
	rs := NewRuleSet([]ProxyRule{
		{Pattern: "pods:*", Effect: EffectAllow},
		{Pattern: "pods:delete", Effect: EffectDeny},
	})
	// Allow rule appears FIRST but the deny still wins for "delete".
	got := rs.Evaluate(&ParsedRequest{Verb: "delete", Resource: "pods"})
	require.NotNil(t, got)
	assert.Equal(t, EffectDeny, got.Effect)
}

func TestRuleSet_Evaluate_FirstAllowWithinClass(t *testing.T) {
	first := ProxyRule{Pattern: "pods:get", Effect: EffectAllow, Note: "first"}
	second := ProxyRule{Pattern: "pods:get", Effect: EffectAllow, Note: "second"}
	rs := NewRuleSet([]ProxyRule{first, second})
	got := rs.Evaluate(&ParsedRequest{Verb: "get", Resource: "pods"})
	require.NotNil(t, got)
	assert.Equal(t, "first", got.Rule.Note, "first matching allow within class should win")
}

func TestRuleSet_Evaluate_NoMatchReturnsNil(t *testing.T) {
	rs := NewRuleSet([]ProxyRule{
		{Pattern: "secrets:*", Effect: EffectDeny},
	})
	got := rs.Evaluate(&ParsedRequest{Verb: "get", Resource: "pods"})
	assert.Nil(t, got)
}

func TestRuleSet_Evaluate_EmptySetIsNil(t *testing.T) {
	got := NewRuleSet(nil).Evaluate(&ParsedRequest{Verb: "get", Resource: "pods"})
	assert.Nil(t, got)
}

func TestRuleSet_Evaluate_CrossResourceDenyPattern(t *testing.T) {
	// The "*:delete*" cross-resource deny shape mentioned in package docs.
	rs := NewRuleSet([]ProxyRule{
		{Pattern: "*:delete*", Effect: EffectDeny},
	})
	for _, resource := range []string{"pods", "deployments", "configmaps"} {
		got := rs.Evaluate(&ParsedRequest{Verb: "delete", Resource: resource})
		require.NotNil(t, got, "resource=%s", resource)
		assert.Equal(t, EffectDeny, got.Effect)
	}
	// Non-delete verbs are NOT blocked by this rule.
	assert.Nil(t, rs.Evaluate(&ParsedRequest{Verb: "get", Resource: "pods"}))
}

func TestProxyRule_ToMap_RoundTrip(t *testing.T) {
	r := ProxyRule{
		Pattern:        "pods:get",
		Effect:         EffectAllow,
		NamespaceScope: "prod-*",
		ResourceScope:  "api-*",
		VerbScope:      "g*",
		Note:           "for the billing team",
		Origin:         OriginUser,
	}
	m := r.ToMap()
	assert.Equal(t, "pods:get", m["pattern"])
	assert.Equal(t, "allow", m["effect"])
	assert.Equal(t, "prod-*", m["namespace_scope"])
	assert.Equal(t, "api-*", m["resource_scope"])
	assert.Equal(t, "g*", m["verb_scope"])
	assert.Equal(t, "for the billing team", m["note"])
	assert.Equal(t, "user", m["origin"])
}
