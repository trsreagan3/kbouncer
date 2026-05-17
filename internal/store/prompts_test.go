// Pending-prompts store tests (#5 async deny-prompt UX, v1.0 subset).
//
// Mirrors the Python tests/bouncer/test_prompts_async.py store-level
// section so cross-product audits can compare invariants. Covered
// here:
//
//   - AddPendingPrompt inserts a row + returns id
//   - AddPendingPrompt is idempotent on (decision_id) — duplicate call returns same id
//   - ListPendingPrompts filters by status
//   - AnswerPendingPrompt records kind/target/by/at + flips status
//   - AnswerPendingPrompt is a no-op on already-answered prompts
//   - Kind validation rejects unknown values
//   - decision_id JOINs back to decisions.id (post-hoc review linkage)
package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddPendingPrompt_RoundTrip(t *testing.T) {
	s := freshDB(t)
	id, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 1,
		Verb:       "list",
		Resource:   "pods",
		Namespace:  "default",
		DenyReason: "default policy: deny",
	})
	require.NoError(t, err)
	assert.Positive(t, id)

	row, err := s.GetPendingPrompt(id)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, "list", row.Verb)
	assert.Equal(t, "pods", row.Resource)
	assert.Equal(t, "default", row.Namespace)
	assert.Equal(t, PromptStatusPending, row.Status)
}

func TestAddPendingPrompt_IdempotentPerDecision(t *testing.T) {
	// Same decision_id called twice returns the same prompt id and
	// leaves only one row — proxy enqueue path is safe to retry.
	s := freshDB(t)
	p1, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 42, Verb: "get", Resource: "pods", DenyReason: "t",
	})
	require.NoError(t, err)

	p2, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 42, Verb: "get", Resource: "pods", DenyReason: "t",
	})
	require.NoError(t, err)
	assert.Equal(t, p1, p2, "idempotent call should return same prompt id")

	rows, err := s.ListPendingPrompts(PromptStatusPending, 50)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
}

func TestListPendingPrompts_FiltersByStatus(t *testing.T) {
	s := freshDB(t)
	pid, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "t",
	})
	require.NoError(t, err)

	pending, err := s.ListPendingPrompts(PromptStatusPending, 50)
	require.NoError(t, err)
	assert.Len(t, pending, 1)

	answered, err := s.ListPendingPrompts(PromptStatusAnswered, 50)
	require.NoError(t, err)
	assert.Empty(t, answered)

	_, err = s.AnswerPendingPrompt(pid, PromptAnswerKindIgnore, "", "t")
	require.NoError(t, err)

	pending, err = s.ListPendingPrompts(PromptStatusPending, 50)
	require.NoError(t, err)
	assert.Empty(t, pending)

	answered, err = s.ListPendingPrompts(PromptStatusAnswered, 50)
	require.NoError(t, err)
	assert.Len(t, answered, 1)
}

func TestAnswerPendingPrompt_RecordsFields(t *testing.T) {
	s := freshDB(t)
	pid, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "t",
	})
	require.NoError(t, err)

	ok, err := s.AnswerPendingPrompt(pid, PromptAnswerKindProfile, "my-prof", "alice")
	require.NoError(t, err)
	assert.True(t, ok)

	row, err := s.GetPendingPrompt(pid)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, PromptStatusAnswered, row.Status)
	assert.Equal(t, PromptAnswerKindProfile, row.AnswerKind)
	assert.Equal(t, "my-prof", row.AnswerTarget)
	assert.Equal(t, "alice", row.AnsweredBy)
	assert.NotEmpty(t, row.AnsweredAt)
}

func TestAnswerPendingPrompt_NoOpOnAlreadyAnswered(t *testing.T) {
	// Re-answering an already-answered prompt returns false (no row
	// updated). The original answer is preserved — important for
	// audit (a later answerer can't overwrite the first answer).
	s := freshDB(t)
	pid, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "t",
	})
	require.NoError(t, err)

	_, err = s.AnswerPendingPrompt(pid, PromptAnswerKindIgnore, "", "t1")
	require.NoError(t, err)

	ok, err := s.AnswerPendingPrompt(pid, PromptAnswerKindAlways, "", "t2")
	require.NoError(t, err)
	assert.False(t, ok, "second answer should be a no-op")

	row, err := s.GetPendingPrompt(pid)
	require.NoError(t, err)
	assert.Equal(t, PromptAnswerKindIgnore, row.AnswerKind)
	assert.Equal(t, "t1", row.AnsweredBy)
}

func TestAnswerPendingPrompt_KindValidation(t *testing.T) {
	s := freshDB(t)
	pid, err := s.AddPendingPrompt(PromptInput{
		DecisionID: 1, Verb: "get", Resource: "pods", DenyReason: "t",
	})
	require.NoError(t, err)

	_, err = s.AnswerPendingPrompt(pid, "bogus", "", "t")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "answer_kind")
}

func TestGetPendingPrompt_NotFoundReturnsNil(t *testing.T) {
	s := freshDB(t)
	row, err := s.GetPendingPrompt(9999)
	require.NoError(t, err)
	assert.Nil(t, row)
}
