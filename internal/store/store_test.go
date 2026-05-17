package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func freshDB(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "kbouncer-test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAndMigrate(t *testing.T) {
	s := freshDB(t)
	// Opening it a second time on the same file should be idempotent.
	again, err := Open(s.Path())
	require.NoError(t, err)
	require.NoError(t, again.Close())
}

func TestRecordDecision_RoundTrip(t *testing.T) {
	s := freshDB(t)
	at := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	id, err := s.RecordDecision(DecisionRow{
		At:               at,
		Method:           "GET",
		Path:             "/api/v1/namespaces/default/pods/my-pod",
		ParsedVerb:       "get",
		ParsedVersion:    "v1",
		ParsedResource:   "pods",
		ParsedNamespace:  "default",
		ParsedName:       "my-pod",
		DecisionVerdict:  "allow",
		DecisionReason:   "default policy: allow",
		ModeAtDecision:   "cooperative",
	})
	require.NoError(t, err)
	assert.Positive(t, id, "INSERT should return a positive row id")

	n, err := s.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestRecordDecision_AutoTimestampWhenZero(t *testing.T) {
	s := freshDB(t)
	_, err := s.RecordDecision(DecisionRow{
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedVersion:   "v1",
		ParsedResource:  "pods",
		DecisionVerdict: "allow",
		DecisionReason:  "test",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err, "zero-At should not fail; store fills in time.Now()")
}

func TestRecordDecision_PreservesNullables(t *testing.T) {
	s := freshDB(t)
	id := int64(42)
	_, err := s.RecordDecision(DecisionRow{
		Method:          "POST",
		Path:            "/api/v1/namespaces/default/pods/p/exec",
		ParsedVerb:      "exec",
		ParsedResource:  "pods",
		ParsedNamespace: "default",
		ParsedName:      "p",
		ParsedSubresource: "exec",
		DecisionVerdict: "deny",
		DecisionReason:  "test",
		ModeAtDecision:  "transparent",
		Enforced:        true,
		MatchedRuleID:   &id,
		TaskID:          "task-abc",
	})
	require.NoError(t, err)
}

func TestDefaultDBPath_HonorsEnvOverride(t *testing.T) {
	t.Setenv("KBOUNCER_DB", "/tmp/kbouncer-override.db")
	p, err := DefaultDBPath()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/kbouncer-override.db", p)
}

func TestRecentDecisions_EmptyDBReturnsEmpty(t *testing.T) {
	s := freshDB(t)
	rows, err := s.RecentDecisions(0)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestRecentDecisions_NewestFirstWithCapAndDefault(t *testing.T) {
	s := freshDB(t)
	// Insert 5 rows
	for i := 0; i < 5; i++ {
		_, err := s.RecordDecision(DecisionRow{
			At:              time.Date(2026, 5, 17, 12, i, 0, 0, time.UTC),
			Method:          "GET",
			Path:            "/api/v1/namespaces/default/pods/p",
			ParsedVerb:      "get",
			ParsedResource:  "pods",
			DecisionVerdict: "allow",
			DecisionReason:  "n",
			ModeAtDecision:  "cooperative",
			DecisionSource:  "global",
		})
		require.NoError(t, err)
	}
	// limit=0 → default 50; only 5 exist → returns 5
	rows, err := s.RecentDecisions(0)
	require.NoError(t, err)
	require.Len(t, rows, 5)
	// Newest first → first row should be the LAST inserted
	assert.Equal(t, "12:04:00", rows[0].At.Format("15:04:05"))
	assert.Equal(t, "12:00:00", rows[4].At.Format("15:04:05"))
	// Decision-source round-trip preserved
	assert.Equal(t, "global", rows[0].DecisionSource)

	// limit=2 honored
	rows, err = s.RecentDecisions(2)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	// limit=99999 → clamped to 1000
	rows, err = s.RecentDecisions(99999)
	require.NoError(t, err)
	require.Len(t, rows, 5)  // only 5 exist, but no error from clamp
}

func TestRecentDecisions_PreservesProfileNameAndRuleID(t *testing.T) {
	s := freshDB(t)
	ruleID := int64(17)
	_, err := s.RecordDecision(DecisionRow{
		Method:          "DELETE",
		Path:            "/api/v1/namespaces/prod/pods/p",
		ParsedVerb:      "delete",
		ParsedResource:  "pods",
		ParsedNamespace: "prod",
		DecisionVerdict: "deny",
		DecisionReason:  "profile staging-work matched keyword prod",
		ModeAtDecision:  "transparent",
		Enforced:        true,
		MatchedRuleID:   &ruleID,
		TaskID:          "task-7",
		DecisionSource:  "profile",
		ProfileName:     "staging-work",
	})
	require.NoError(t, err)

	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	r := rows[0]
	assert.Equal(t, "profile", r.DecisionSource)
	assert.Equal(t, "staging-work", r.ProfileName)
	assert.Equal(t, "task-7", r.TaskID)
	require.NotNil(t, r.MatchedRuleID)
	assert.Equal(t, int64(17), *r.MatchedRuleID)
	assert.True(t, r.Enforced)
}
