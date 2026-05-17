// K-Slice 3 composition-order tests.
//
// These tests pin down the LOAD-BEARING invariant of the whole gating
// product: profile-deny > task-deny > task-allow > global-rule
// (deny-beats-allow) > default-policy. If a change weakens any of
// these orderings, the tests here are the canary.
//
// Symmetric to the Python iam-jit-bouncer's tests/bouncer/test_decisions.py
// + test_tasks.py — same scenarios, K8s-translated request shape.
package proxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/parser"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
	"github.com/trsreagan3/kbouncer/internal/tasks"
)

func mustStartTask(t *testing.T, st *store.Store, allow, deny []rules.ProxyRule) *tasks.Scope {
	t.Helper()
	sc, err := tasks.BuildScope(
		"test task", allow, deny, 30, "alice", "",
	)
	require.NoError(t, err)
	require.NoError(t, st.AddTask(sc))
	return sc
}

func mustAddRule(t *testing.T, st *store.Store, r rules.ProxyRule) {
	t.Helper()
	_, err := st.AddRule(r)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Global rule engine
// ---------------------------------------------------------------------------

func TestGlobalRule_AllowMatch(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{Pattern: "pods:get", Effect: rules.EffectAllow})

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyDeny)
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceGlobal, obs.DecisionSource)
	assert.Contains(t, obs.DecisionReason, "explicit-allow")
}

func TestGlobalRule_DenyMatch(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{Pattern: "pods:delete", Effect: rules.EffectDeny})

	req := parser.MustParseTestURL(http.MethodDelete, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceGlobal, obs.DecisionSource)
	assert.True(t, obs.Enforced)
}

func TestGlobalRule_DenyBeatsAllow(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{Pattern: "pods:*", Effect: rules.EffectAllow})
	mustAddRule(t, st, rules.ProxyRule{Pattern: "pods:delete", Effect: rules.EffectDeny})

	req := parser.MustParseTestURL(http.MethodDelete, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict, "explicit deny beats explicit allow")
	assert.Equal(t, SourceGlobal, obs.DecisionSource)
}

// ---------------------------------------------------------------------------
// Task scope composition
// ---------------------------------------------------------------------------

func TestTaskAllow_NarrowsTraffic(t *testing.T) {
	st := freshStore(t)
	mustStartTask(t, st,
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		nil,
	)
	// pods:get should match the task-allow → ALLOW source=task.
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceTask, obs.DecisionSource)
}

func TestTaskActive_UnmatchedFalls_DenyOutOfScope(t *testing.T) {
	st := freshStore(t)
	mustStartTask(t, st,
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		nil,
	)
	// secrets:get is NOT in the task allow + no global rule covers it →
	// out-of-task-scope deny.
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/secrets/s")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceTask, obs.DecisionSource)
	assert.Contains(t, obs.DecisionReason, "out-of-task-scope")
}

func TestTaskActive_GlobalAllowStillFires(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{Pattern: "namespaces:list", Effect: rules.EffectAllow})
	mustStartTask(t, st,
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		nil,
	)
	// namespaces:list isn't in the task scope but the global allow rule
	// covers it — the call should go through (so infra calls keep working).
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyDeny)
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceGlobal, obs.DecisionSource)
	assert.Contains(t, obs.DecisionReason, "not declared in task")
}

func TestTaskDeny_BeatsGlobalAllow(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{Pattern: "pods:*", Effect: rules.EffectAllow})
	mustStartTask(t, st,
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		[]rules.ProxyRule{{Pattern: "pods:delete"}},
	)
	// Global allow says "any pod verb"; task-deny says "no pods:delete".
	// Task-deny must win.
	req := parser.MustParseTestURL(http.MethodDelete, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceTask, obs.DecisionSource)
	assert.Contains(t, obs.DecisionReason, "task-explicit-deny")
}

func TestGlobalDeny_BeatsTaskAllow(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{Pattern: "secrets:*", Effect: rules.EffectDeny})
	mustStartTask(t, st,
		[]rules.ProxyRule{{Pattern: "secrets:get"}, {Pattern: "pods:get"}},
		nil,
	)
	// Global deny says "no secrets at all"; task tries to allow them.
	// Global deny is the admin's baseline + must win.
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/secrets/s")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceGlobal, obs.DecisionSource)
}

// ---------------------------------------------------------------------------
// Profile composition
// ---------------------------------------------------------------------------

func TestProfileDeny_BeatsTaskAllow(t *testing.T) {
	st := freshStore(t)
	mustStartTask(t, st,
		[]rules.ProxyRule{{Pattern: "pods:*"}},
		nil,
	)
	// staging-work profile: any "prod" keyword in namespace/name denies.
	stagingWork := &profile.Profile{
		Name:         "staging-work",
		DenyKeywords: []string{"prod"},
	}
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/prod-billing/pods/p")
	obs := EvaluateRequestWithProfile(
		req, st, ModeTransparent, DefaultPolicyAllow,
		stagingWork, "",
	)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceProfile, obs.DecisionSource,
		"profile deny is a hard floor — task-allow cannot lift it")
}

// ---------------------------------------------------------------------------
// Namespace + name scoping
// ---------------------------------------------------------------------------

func TestRule_NamespaceScope_Matches(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{
		Pattern:        "pods:*",
		Effect:         rules.EffectDeny,
		NamespaceScope: "prod-*",
	})
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/prod-billing/pods/p")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	assert.Equal(t, SourceGlobal, obs.DecisionSource)
}

func TestRule_NamespaceScope_DoesNotMatchOtherNamespace(t *testing.T) {
	st := freshStore(t)
	mustAddRule(t, st, rules.ProxyRule{
		Pattern:        "pods:*",
		Effect:         rules.EffectDeny,
		NamespaceScope: "prod-*",
	})
	// staging is NOT under the namespace scope → rule abstains → fall
	// through to default-policy.
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/staging/pods/p")
	obs := EvaluateRequest(req, st, ModeTransparent, DefaultPolicyAllow)
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceDefault, obs.DecisionSource)
}

// ---------------------------------------------------------------------------
// Audit log carries task_id when a task is active
// ---------------------------------------------------------------------------

func TestAudit_TaskAllowDecisionCarriesTaskID(t *testing.T) {
	st := freshStore(t)
	sc := mustStartTask(t, st,
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		nil,
	)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	_ = EvaluateRequest(req, st, ModeTransparent, DefaultPolicyDeny)

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Equal(t, sc.TaskID, rows[0].TaskID, "audit row should carry the active task id")
	assert.Equal(t, SourceTask, rows[0].DecisionSource)
}

// ---------------------------------------------------------------------------
// Task TTL auto-expiry — proxy treats expired task as no-active-task
// ---------------------------------------------------------------------------

func TestTaskAutoExpiry_FallsThroughToDefault(t *testing.T) {
	st := freshStore(t)
	sc, err := tasks.BuildScope(
		"to-expire",
		[]rules.ProxyRule{{Pattern: "pods:get"}},
		nil,
		30, "alice", "",
	)
	require.NoError(t, err)
	// Mutate the scope so it's already past its expiry on insert.
	sc.ExpiresAt = "2000-01-01T00:00:00Z"
	require.NoError(t, st.AddTask(sc))

	// With the task auto-expired, the proxy should fall through to
	// default-policy (allow here) since no rule matches.
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequest(req, st, ModeCooperative, DefaultPolicyAllow)
	assert.Equal(t, VerdictAllow, obs.DecisionVerdict)
	assert.Equal(t, SourceDefault, obs.DecisionSource)
}
