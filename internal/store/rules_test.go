package store

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/tasks"
)

func TestAddRule_RoundTrip(t *testing.T) {
	s := freshDB(t)
	id, err := s.AddRule(rules.ProxyRule{
		Pattern:        "pods:create",
		Effect:         rules.EffectDeny,
		NamespaceScope: "prod-*",
		Note:           "no creating in prod",
	})
	require.NoError(t, err)
	assert.Positive(t, int64(id))

	got, err := s.GetRule(id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "pods:create", got.Pattern)
	assert.Equal(t, rules.EffectDeny, got.Effect)
	assert.Equal(t, "prod-*", got.NamespaceScope)
	assert.Equal(t, rules.OriginUser, got.Origin)
}

func TestAddRule_RejectsMalformedPattern(t *testing.T) {
	s := freshDB(t)
	_, err := s.AddRule(rules.ProxyRule{Pattern: "pods-create", Effect: rules.EffectAllow})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRule))
}

func TestAddRule_RejectsBadEffect(t *testing.T) {
	s := freshDB(t)
	_, err := s.AddRule(rules.ProxyRule{Pattern: "pods:get", Effect: "maybe"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRule))
}

func TestListRules_Order(t *testing.T) {
	s := freshDB(t)
	for _, pat := range []string{"pods:get", "pods:list", "secrets:get"} {
		_, err := s.AddRule(rules.ProxyRule{Pattern: pat, Effect: rules.EffectAllow})
		require.NoError(t, err)
	}
	got, err := s.ListRules()
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "pods:get", got[0].Rule.Pattern)
	assert.Equal(t, "pods:list", got[1].Rule.Pattern)
	assert.Equal(t, "secrets:get", got[2].Rule.Pattern)
}

func TestRemoveRule(t *testing.T) {
	s := freshDB(t)
	id, err := s.AddRule(rules.ProxyRule{Pattern: "pods:get", Effect: rules.EffectAllow})
	require.NoError(t, err)
	ok, err := s.RemoveRule(id)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = s.RemoveRule(id)
	require.NoError(t, err)
	assert.False(t, ok, "second remove should return false")
}

func TestLoadRuleSet_EvaluatesCorrectly(t *testing.T) {
	s := freshDB(t)
	_, err := s.AddRule(rules.ProxyRule{Pattern: "pods:*", Effect: rules.EffectAllow})
	require.NoError(t, err)
	_, err = s.AddRule(rules.ProxyRule{Pattern: "pods:delete", Effect: rules.EffectDeny})
	require.NoError(t, err)

	rs, err := s.LoadRuleSet()
	require.NoError(t, err)
	require.NotNil(t, rs)
	assert.Equal(t, 2, rs.Len())

	got := rs.Evaluate(&rules.ParsedRequest{Verb: "get", Resource: "pods"})
	require.NotNil(t, got)
	assert.Equal(t, rules.EffectAllow, got.Effect)

	got = rs.Evaluate(&rules.ParsedRequest{Verb: "delete", Resource: "pods"})
	require.NotNil(t, got)
	assert.Equal(t, rules.EffectDeny, got.Effect, "deny-beats-allow")
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

func makeScope(t *testing.T, desc, owner string, durationMin int) *tasks.Scope {
	t.Helper()
	sc, err := tasks.BuildScope(
		desc,
		[]rules.ProxyRule{{Pattern: "pods:get"}, {Pattern: "pods:list"}},
		[]rules.ProxyRule{{Pattern: "*:delete*"}},
		durationMin,
		"alice",
		owner,
	)
	require.NoError(t, err)
	return sc
}

func TestAddTask_Then_GetActive(t *testing.T) {
	s := freshDB(t)
	sc := makeScope(t, "investigate alert", "", 30)
	require.NoError(t, s.AddTask(sc))

	got, err := s.GetActiveTask("")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, sc.TaskID, got.TaskID)
	assert.Equal(t, tasks.StatusActive, got.Status)
	assert.Len(t, got.AllowRules, 2)
	assert.Len(t, got.DenyRules, 1)
	// JSON round-trip preserved Effect coercion.
	assert.Equal(t, rules.EffectAllow, got.AllowRules[0].Effect)
	assert.Equal(t, rules.EffectDeny, got.DenyRules[0].Effect)
}

func TestAddTask_RejectsSecondActiveSameOwner(t *testing.T) {
	s := freshDB(t)
	require.NoError(t, s.AddTask(makeScope(t, "first", "", 30)))
	err := s.AddTask(makeScope(t, "second", "", 30))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrActiveTaskExists))
}

func TestAddTask_AllowsDifferentOwners(t *testing.T) {
	s := freshDB(t)
	require.NoError(t, s.AddTask(makeScope(t, "alice's task", "alice-session", 30)))
	require.NoError(t, s.AddTask(makeScope(t, "bob's task", "bob-session", 30)))
}

func TestEndTask(t *testing.T) {
	s := freshDB(t)
	sc := makeScope(t, "x", "", 30)
	require.NoError(t, s.AddTask(sc))

	ok, err := s.EndTask(sc.TaskID, "alice", "done", tasks.StatusCompleted)
	require.NoError(t, err)
	assert.True(t, ok)

	// Second end is a no-op.
	ok, err = s.EndTask(sc.TaskID, "alice", "done", tasks.StatusCompleted)
	require.NoError(t, err)
	assert.False(t, ok)

	got, err := s.GetActiveTask("")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestEndTask_RejectsInvalidStatus(t *testing.T) {
	s := freshDB(t)
	_, err := s.EndTask("any", "alice", "x", tasks.StatusActive)
	require.Error(t, err)
}

func TestGetActiveTask_AutoExpires(t *testing.T) {
	s := freshDB(t)
	// Build a scope and then rewrite ExpiresAt to the past before insert.
	sc := makeScope(t, "to-expire", "", 30)
	sc.ExpiresAt = time.Now().Add(-1 * time.Minute).UTC().Format("2006-01-02T15:04:05Z")
	require.NoError(t, s.AddTask(sc))

	got, err := s.GetActiveTask("")
	require.NoError(t, err)
	assert.Nil(t, got, "expired task should auto-mark + return nil")

	// Status should now be expired.
	row, err := s.GetTask(sc.TaskID)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, tasks.StatusExpired, row.Status)
}

func TestListTasks_NewestFirstWithFilter(t *testing.T) {
	s := freshDB(t)
	a := makeScope(t, "first", "", 30)
	require.NoError(t, s.AddTask(a))
	_, err := s.EndTask(a.TaskID, "alice", "done", tasks.StatusCompleted)
	require.NoError(t, err)
	b := makeScope(t, "second", "", 30)
	require.NoError(t, s.AddTask(b))

	all, err := s.ListTasks("", 0)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, b.TaskID, all[0].TaskID, "newest first")

	completed, err := s.ListTasks("completed", 0)
	require.NoError(t, err)
	require.Len(t, completed, 1)
	assert.Equal(t, a.TaskID, completed[0].TaskID)
}

func TestTaskReviewSummary(t *testing.T) {
	s := freshDB(t)
	sc := makeScope(t, "review me", "", 30)
	require.NoError(t, s.AddTask(sc))

	// Insert some decisions linked to the task.
	for i, v := range []string{"allow", "allow", "deny"} {
		_, err := s.RecordDecision(DecisionRow{
			At:              time.Date(2026, 5, 17, 12, i, 0, 0, time.UTC),
			Method:          "GET",
			Path:            "/api/v1/pods",
			ParsedVerb:      "get",
			ParsedResource:  "pods",
			ParsedName:      "p-" + string(rune('a'+i)),
			DecisionVerdict: v,
			DecisionReason:  "test",
			ModeAtDecision:  "transparent",
			TaskID:          sc.TaskID,
		})
		require.NoError(t, err)
	}

	review, err := s.TaskReviewSummary(sc.TaskID)
	require.NoError(t, err)
	require.NotNil(t, review)
	assert.Equal(t, sc.TaskID, review.TaskID)
	assert.Equal(t, 3, review.DecisionCount)
	assert.Equal(t, 2, review.AllowCount)
	assert.Equal(t, 1, review.DenyCount)
	require.Len(t, review.DeniedCalls, 1)
	assert.Equal(t, "pods", review.DeniedCalls[0].Resource)
}

func TestTaskReviewSummary_MissingTask(t *testing.T) {
	s := freshDB(t)
	review, err := s.TaskReviewSummary("nonexistent")
	require.NoError(t, err)
	assert.Nil(t, review)
}
