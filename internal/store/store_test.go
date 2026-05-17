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
