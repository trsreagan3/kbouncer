package tasks

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/rules"
)

func TestBuildScope_Happy(t *testing.T) {
	s, err := BuildScope(
		"investigate prod alert",
		[]rules.ProxyRule{{Pattern: "pods:get"}, {Pattern: "pods:list"}},
		[]rules.ProxyRule{{Pattern: "*:delete*"}},
		60,
		"alice",
		"",
	)
	require.NoError(t, err)
	assert.Equal(t, "investigate prod alert", s.Description)
	assert.Equal(t, "alice", s.StartedBy)
	assert.Equal(t, StatusActive, s.Status)
	assert.Len(t, s.AllowRules, 2)
	assert.Len(t, s.DenyRules, 1)
	// Effect coercion: allow_rules → allow even if Effect was zero.
	assert.Equal(t, rules.EffectAllow, s.AllowRules[0].Effect)
	assert.Equal(t, rules.EffectDeny, s.DenyRules[0].Effect)
	// Origin defaults to task.
	assert.Equal(t, rules.OriginTask, s.AllowRules[0].Origin)
	assert.NotEmpty(t, s.TaskID)
	assert.Len(t, s.TaskID, 12)
}

func TestBuildScope_RejectsEmptyDescription(t *testing.T) {
	_, err := BuildScope("", []rules.ProxyRule{{Pattern: "pods:*"}}, nil, 30, "alice", "")
	require.Error(t, err)
	var ve *ValidationError
	assert.True(t, errors.As(err, &ve))
}

func TestBuildScope_RejectsBadDuration(t *testing.T) {
	_, err := BuildScope("x", []rules.ProxyRule{{Pattern: "pods:*"}}, nil, -1, "alice", "")
	require.Error(t, err)
	_, err = BuildScope("x", []rules.ProxyRule{{Pattern: "pods:*"}}, nil, MaxDurationMinutes+1, "alice", "")
	require.Error(t, err)
}

func TestBuildScope_RequiresAtLeastOneRule(t *testing.T) {
	_, err := BuildScope("x", nil, nil, 30, "alice", "")
	require.Error(t, err)
}

func TestBuildScope_RejectsBadPattern(t *testing.T) {
	_, err := BuildScope("x", []rules.ProxyRule{{Pattern: "pods-get"}}, nil, 30, "alice", "")
	require.Error(t, err)
}

func TestBuildScope_DefaultsDurationToThirty(t *testing.T) {
	s, err := BuildScope("x", []rules.ProxyRule{{Pattern: "pods:*"}}, nil, 0, "alice", "")
	require.NoError(t, err)
	start, err1 := parseISO(s.StartedAt)
	exp, err2 := parseISO(s.ExpiresAt)
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.WithinDuration(t, start.Add(30*time.Minute), exp, 2*time.Second)
}

func TestScope_IsExpired(t *testing.T) {
	s, err := BuildScope("x", []rules.ProxyRule{{Pattern: "pods:*"}}, nil, 5, "alice", "")
	require.NoError(t, err)
	assert.False(t, s.IsExpired(time.Now().UTC()))
	// Synthesize a far-future "now" that's past the expiry.
	future, _ := parseISO(s.ExpiresAt)
	assert.True(t, s.IsExpired(future.Add(time.Minute)))
	// Non-active tasks are never "expired" (their lifecycle is settled).
	s.Status = StatusCompleted
	assert.False(t, s.IsExpired(future.Add(time.Minute)))
}

func TestScope_RuleSets(t *testing.T) {
	s, err := BuildScope(
		"x",
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		[]rules.ProxyRule{{Pattern: "pods:delete"}},
		30, "alice", "",
	)
	require.NoError(t, err)
	allow := s.AllowRuleSet()
	deny := s.DenyRuleSet()
	require.NotNil(t, allow)
	require.NotNil(t, deny)
	assert.Equal(t, 1, allow.Len())
	assert.Equal(t, 1, deny.Len())
}

func TestParseShorthand(t *testing.T) {
	r := ParseShorthand("pods:*@prod-billing")
	assert.Equal(t, "pods:*", r.Pattern)
	assert.Equal(t, "prod-billing", r.NamespaceScope)
	assert.Equal(t, "", r.ResourceScope)

	r = ParseShorthand("pods:get@prod-*#api-*")
	assert.Equal(t, "pods:get", r.Pattern)
	assert.Equal(t, "prod-*", r.NamespaceScope)
	assert.Equal(t, "api-*", r.ResourceScope)

	r = ParseShorthand("pods:get#api-*")
	assert.Equal(t, "pods:get", r.Pattern)
	assert.Equal(t, "", r.NamespaceScope)
	assert.Equal(t, "api-*", r.ResourceScope)

	r = ParseShorthand("*:delete*")
	assert.Equal(t, "*:delete*", r.Pattern)
	assert.Empty(t, r.NamespaceScope)
	assert.Empty(t, r.ResourceScope)
}

func TestParseShorthandList(t *testing.T) {
	got := ParseShorthandList("pods:get,pods:list@prod-billing , *:delete*")
	require.Len(t, got, 3)
	assert.Equal(t, "pods:get", got[0].Pattern)
	assert.Equal(t, "pods:list", got[1].Pattern)
	assert.Equal(t, "prod-billing", got[1].NamespaceScope)
	assert.Equal(t, "*:delete*", got[2].Pattern)

	assert.Nil(t, ParseShorthandList(""))
	assert.Nil(t, ParseShorthandList("   "))
}

func TestScope_ToMap_RoundTrip(t *testing.T) {
	s, err := BuildScope(
		"x",
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		[]rules.ProxyRule{{Pattern: "pods:delete"}},
		30, "alice", "session-1",
	)
	require.NoError(t, err)
	m := s.ToMap()
	assert.Equal(t, "x", m["description"])
	assert.Equal(t, "alice", m["started_by"])
	assert.Equal(t, "active", m["status"])
	assert.Equal(t, "session-1", m["owner"])
	allowList, ok := m["allow_rules"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, allowList, 1)
	assert.Equal(t, "pods:get", allowList[0]["pattern"])
}
