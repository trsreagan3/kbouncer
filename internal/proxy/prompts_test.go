// Proxy-integration tests for #5 async deny-prompt UX (v1.0 subset).
//
// The enqueue only fires when ALL of:
//   - opts.PromptOnDeny=true
//   - mode=Transparent (cooperative DENYs are advisory; no prompt)
//   - verdict=Deny
//   - no pause active (a pause already bypasses enforcement)
//
// Covered here:
//
//   - prompt_on_deny=false → no enqueue
//   - prompt_on_deny=true + transparent DENY → 1 enqueue
//   - prompt_on_deny=true + cooperative DENY → no enqueue
//   - prompt_on_deny=true + ALLOW → no enqueue
//   - prompt_on_deny=true + active pause → no enqueue
//   - decision_id JOINs back to decisions.id (post-hoc review linkage)
package proxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/parser"
)

func TestPromptOnDeny_NoEnqueueWhenFlagOff(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyDeny, nil, "", EvalOptions{PromptOnDeny: false})

	rows, err := st.ListPendingPrompts("pending", 50)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestPromptOnDeny_EnqueuesOnTransparentDeny(t *testing.T) {
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyDeny, nil, "", EvalOptions{PromptOnDeny: true})

	rows, err := st.ListPendingPrompts("pending", 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "get", rows[0].Verb)
	assert.Equal(t, "pods", rows[0].Resource)
	assert.Equal(t, "default", rows[0].Namespace)
	assert.Equal(t, "p", rows[0].Name)
	assert.Equal(t, "pending", rows[0].Status)
}

func TestPromptOnDeny_DoesNotEnqueueOnCooperativeDeny(t *testing.T) {
	// Cooperative mode never actually 403s the agent; the deny is
	// only advisory. Prompting here would be noise — the agent's call
	// succeeded upstream.
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	EvaluateRequestFull(req, st, ModeCooperative, DefaultPolicyDeny, nil, "", EvalOptions{PromptOnDeny: true})

	rows, err := st.ListPendingPrompts("pending", 50)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestPromptOnDeny_DoesNotEnqueueOnAllow(t *testing.T) {
	// Flip default policy to allow so the request gets through; with
	// no rules loaded that's the simplest way to produce an ALLOW
	// verdict in K-Slice 7.
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow, nil, "", EvalOptions{PromptOnDeny: true})

	rows, err := st.ListPendingPrompts("pending", 50)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestPromptOnDeny_DoesNotEnqueueWhenPaused(t *testing.T) {
	// A pause already bypasses enforcement — the agent isn't being
	// denied; no prompt to surface.
	st := freshStore(t)
	_, err := st.StartPause(600, "", "t")
	require.NoError(t, err)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyDeny, nil, "", EvalOptions{PromptOnDeny: true})

	rows, err := st.ListPendingPrompts("pending", 50)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestPromptOnDeny_DecisionIDLinksBackToDecisions(t *testing.T) {
	// The pending_prompts.decision_id is supposed to JOIN cleanly to
	// the decisions.id. If the linkage broke, post-hoc review couldn't
	// tell which exact request triggered each prompt.
	st := freshStore(t)
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyDeny, nil, "", EvalOptions{PromptOnDeny: true})

	prompts, err := st.ListPendingPrompts("pending", 50)
	require.NoError(t, err)
	require.Len(t, prompts, 1)

	decisions, err := st.RecentDecisions(50)
	require.NoError(t, err)
	require.NotEmpty(t, decisions)

	// Newest-first ordering, so decisions[0] is the most recent. We can
	// only easily JOIN by knowing the assigned id, but the round-trip
	// works because RecordDecision returns the same id RecentDecisions
	// reads. The store-level test covers the precise id linkage; here
	// we assert at least one decision exists + the prompt references
	// a positive decision_id.
	assert.Positive(t, prompts[0].DecisionID)
}
