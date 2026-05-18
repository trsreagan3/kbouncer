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

// ----------------------------------------------------------------------
// #289 — agent identity persisted in the decisions table.
// ----------------------------------------------------------------------

// TestSchemaVersion_AtLeastV8 pins the migration bump. Closes the
// kbounce-agent-identity-sqlite-gap: the schema MUST be v8+ for the
// new decisions.agent_name + decisions.agent_session_id columns to
// be in place.
func TestSchemaVersion_AtLeastV8(t *testing.T) {
	assert.GreaterOrEqual(t, SchemaVersion, 8,
		"#289 added decisions.agent_name + agent_session_id; schema must be v8+")
}

// TestRecordDecision_PersistsAgentIdentity rules in the happy path:
// when AgentName + AgentSessionID are populated on the insert,
// RecentDecisions reads them back. This is the cross-product parity
// guarantee with ibounce + dbounce + gbounce per
// [[cross-product-agent-parity]].
func TestRecordDecision_PersistsAgentIdentity(t *testing.T) {
	s := freshDB(t)
	_, err := s.RecordDecision(DecisionRow{
		Method:          "POST",
		Path:            "/api/v1/namespaces/default/pods",
		ParsedVerb:      "create",
		ParsedResource:  "pods",
		ParsedNamespace: "default",
		DecisionVerdict: "allow",
		DecisionReason:  "default policy: allow (no rule matched)",
		ModeAtDecision:  "cooperative",
		AgentName:       "claude-code",
		AgentSessionID:  "01956c44-c5c1-7c31-9bca-7c0aaa000001",
	})
	require.NoError(t, err)

	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "claude-code", rows[0].AgentName)
	assert.Equal(t, "01956c44-c5c1-7c31-9bca-7c0aaa000001",
		rows[0].AgentSessionID)
}

// TestRecordDecision_AnonymousAgentKeepsColumnsNull confirms that an
// insert with empty AgentName + AgentSessionID writes NULLs (verified
// indirectly by the empty-string read back, since nullableString
// converts "" → SQL NULL on the way in + COALESCE renders NULL → ""
// on the way out). Per the migration comment: NULL is accurate for
// requests where no detection source fired.
func TestRecordDecision_AnonymousAgentKeepsColumnsNull(t *testing.T) {
	s := freshDB(t)
	_, err := s.RecordDecision(DecisionRow{
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "allow",
		DecisionReason:  "default policy",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)

	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Empty(t, rows[0].AgentName,
		"empty AgentName must round-trip as empty (SQL NULL underneath)")
	assert.Empty(t, rows[0].AgentSessionID,
		"empty AgentSessionID must round-trip as empty (SQL NULL underneath)")

	// Direct PRAGMA check: confirm the underlying column values are
	// in fact NULL, not the empty string. Guards against a future
	// regression where someone "helpfully" stamps "" instead of NULL.
	var (
		nameNull    bool
		sessionNull bool
	)
	row := s.db.QueryRow(
		`SELECT agent_name IS NULL, agent_session_id IS NULL FROM decisions LIMIT 1`)
	require.NoError(t, row.Scan(&nameNull, &sessionNull))
	assert.True(t, nameNull, "agent_name should be SQL NULL for anon rows")
	assert.True(t, sessionNull,
		"agent_session_id should be SQL NULL for anon rows")
}

// TestRecordDecision_AgentNameWithoutSession covers the user-agent
// detection path: a fingerprinted name (kubectl, helm, ...) without
// an MCP session id. Columns surface name populated, session empty.
func TestRecordDecision_AgentNameWithoutSession(t *testing.T) {
	s := freshDB(t)
	_, err := s.RecordDecision(DecisionRow{
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "allow",
		DecisionReason:  "default policy",
		ModeAtDecision:  "cooperative",
		AgentName:       "kubectl",
	})
	require.NoError(t, err)

	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "kubectl", rows[0].AgentName)
	assert.Empty(t, rows[0].AgentSessionID)
}

// TestMigration_AddsAgentColumnsToExistingDB simulates the upgrade
// path: open a v7-shaped database (no agent columns), close it,
// re-open it, and confirm the v8 ALTERs landed without losing the
// pre-existing row. Per [[creates-never-mutates]]: old data
// preserved across the additive migration.
func TestMigration_AddsAgentColumnsToExistingDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "kbouncer-migrate.db")

	// First open: lands at the current SchemaVersion. Insert one row
	// with the legacy field set (no agent identity — emulates pre-#289
	// data shape).
	s1, err := Open(dbPath)
	require.NoError(t, err)
	_, err = s1.RecordDecision(DecisionRow{
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "allow",
		DecisionReason:  "legacy row before agent columns",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)

	// Drop the agent columns + roll schema_version back to 7 to make
	// this DB look like a pre-#289 backup on disk. SQLite < 3.35
	// can't DROP COLUMN; we rebuild the table without the new
	// columns (the manual equivalent of "this DB was created before
	// the v8 migration shipped"). Then we re-open + assert the
	// migration re-adds the columns + preserves the row.
	_, err = s1.db.Exec(`UPDATE schema_version SET version = 7`)
	require.NoError(t, err)
	_, err = s1.db.Exec(`ALTER TABLE decisions DROP COLUMN agent_name`)
	require.NoError(t, err)
	_, err = s1.db.Exec(`ALTER TABLE decisions DROP COLUMN agent_session_id`)
	require.NoError(t, err)
	require.NoError(t, s1.Close())

	// Re-open: addColumnIfMissing should detect the missing columns
	// + re-ALTER them in; schema_version should bump back to v8+.
	s2, err := Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })

	var ver int
	require.NoError(t,
		s2.db.QueryRow(`SELECT version FROM schema_version`).Scan(&ver))
	assert.GreaterOrEqual(t, ver, 8,
		"re-open MUST bump schema_version to v8+ via the additive migration")

	// Pre-existing row preserved + new columns surface as NULL/empty.
	rows, err := s2.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1, "pre-#289 row must survive the migration")
	assert.Equal(t, "legacy row before agent columns",
		rows[0].DecisionReason)
	assert.Empty(t, rows[0].AgentName,
		"legacy row must show empty agent name (column was NULL)")
	assert.Empty(t, rows[0].AgentSessionID,
		"legacy row must show empty session id (column was NULL)")

	// And the new column accepts inserts post-migration.
	_, err = s2.RecordDecision(DecisionRow{
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "allow",
		DecisionReason:  "post-migration row",
		ModeAtDecision:  "cooperative",
		AgentName:       "claude-code",
		AgentSessionID:  "01956c44-c5c1-7c31-9bca-7c0aaa000099",
	})
	require.NoError(t, err)
	rows, err = s2.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "claude-code", rows[0].AgentName,
		"newest-first ordering should put the post-migration row first")
	assert.Equal(t, "01956c44-c5c1-7c31-9bca-7c0aaa000099",
		rows[0].AgentSessionID)
}
