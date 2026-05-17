package tasks

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseShorthandStrict_RejectsKeyValueScope closes UAT-K2 HIGH-K2-01.
// The legacy ParseShorthand silently accepted `@ns=value` (user habit
// from kubectl), producing a rule with NamespaceScope="ns=value" that
// never matched anything — the operator thought they had a guardrail,
// they didn't. The strict parser rejects hard with a clear pointer at
// the correct shape.
func TestParseShorthandStrict_RejectsKeyValueScope(t *testing.T) {
	cases := []struct {
		in   string
		want string // substring that must appear in the error
	}{
		{"pods:*@ns=prod-billing", "ns=prod-billing"},
		{"pods:*@namespace=prod", "namespace=prod"},
		{"pods:get@prod#name=api-*", "name=api-*"},
		{"pods:*@prod_underscore", "prod_underscore"},
		{"pods:*@PROD", "PROD"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := ParseShorthandStrict(tc.in)
			require.Error(t, err, "input %q must be rejected", tc.in)
			var ve *ValidationError
			require.True(t, errors.As(err, &ve))
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestParseShorthandStrict_AcceptsCanonicalScope confirms the strict
// parser does NOT regress the happy path.
func TestParseShorthandStrict_AcceptsCanonicalScope(t *testing.T) {
	cases := []string{
		"pods:*",
		"pods:*@prod-billing",
		"pods:get@prod-*#api-*",
		"pods:get#api-*",
		"*:delete*",
		"pods:*@a", // single-char scope is valid
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := ParseShorthandStrict(in)
			require.NoError(t, err)
		})
	}
}

// TestParseShorthandListStrict_PropagatesError pins that the list
// variant surfaces the first per-item error rather than silently
// dropping the bad entry.
func TestParseShorthandListStrict_PropagatesError(t *testing.T) {
	_, err := ParseShorthandListStrict("pods:get,pods:*@ns=prod,other:list")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ns=prod")
}

// TestParseShorthand_LegacyShimSwallowsErrors confirms the back-compat
// ParseShorthand still returns a (zero-valued) ProxyRule rather than
// panicking on bad input — preserves the prior signature for any
// caller that doesn't yet check for errors.
func TestParseShorthand_LegacyShimSwallowsErrors(t *testing.T) {
	r := ParseShorthand("pods:*@ns=prod")
	// The bad input swallows; r will be the zero value of ProxyRule
	// because ParseShorthandStrict errored before producing a rule.
	assert.Empty(t, r.Pattern)
	assert.Empty(t, r.NamespaceScope)
}
