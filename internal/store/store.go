// Package store wraps a local SQLite database used by kbouncer for
// rule storage and decision audit logging.
//
// The schema is intentionally parallel to the Python iam-jit-bouncer's
// store so future tooling (cross-product audit-log scrapers, joint
// review UIs) can join across both databases without translation.
//
// K-Slice 1 ships the minimum needed for the proxy to land:
//   - decisions table: one row per evaluated request
//   - rules table: empty in K-Slice 1, scaffolded for K-Slice 3
//   - tasks table: empty in K-Slice 1, scaffolded for K-Slice 3
//   - schema_version table: monotonic migration tracker
//
// Driver: modernc.org/sqlite (pure Go; no CGO). A single binary builds
// cleanly for every platform — critical because kbouncer is shipped as
// a one-file install on the user's laptop or as a sidecar in cluster.
//
// Concurrency: standard database/sql connection pool. SQLite uses
// per-DB file locking; the proxy is single-process so we don't need
// WAL+busy-retry tuning yet. If a future Enterprise daemon goes
// multi-process we'll flip PRAGMA journal_mode=WAL and add retry-on-busy.
//
// Path: defaults to ~/.kbouncer/state.db. Override with the KBOUNCER_DB
// env var or by passing an explicit path to Open. Distinct from
// iam-jit-bouncer's ~/.iam-jit/bouncer/state.db so the two products
// don't share file locks.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SchemaVersion is bumped whenever the on-disk schema changes. Migrations
// are additive only (CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN);
// no destructive changes once we ship v1.
//
// Version log:
//
//	1 — initial: decisions + rules + tasks tables (K-Slice 1)
//	2 — add decisions.decision_source + decisions.profile_name (K-Slice 7)
const SchemaVersion = 2

// DefaultDBPath returns the path the store opens when no explicit path
// is supplied. Honors KBOUNCER_DB for tests and CI sandboxes that
// want a scratch location.
func DefaultDBPath() (string, error) {
	if override := os.Getenv("KBOUNCER_DB"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("kbouncer: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".kbouncer", "state.db"), nil
}

// Store wraps a sql.DB plus the migration state. Safe for concurrent
// use from multiple goroutines (sql.DB handles its own pooling).
type Store struct {
	db   *sql.DB
	path string
}

// Open initializes (creating if needed) the SQLite database at path.
// If path is "", DefaultDBPath() is consulted. Parent directories are
// created with 0o700 to keep the audit log private to the user.
func Open(path string) (*Store, error) {
	if path == "" {
		p, err := DefaultDBPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	// Ensure the parent dir exists and is private. We chmod 0o700 so a
	// shared-machine user can't read another user's decision history.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("kbouncer: mkdir %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("kbouncer: sql.Open: %w", err)
	}
	// modernc sqlite supports only one writer at a time per file; a
	// small connection cap keeps contention predictable and matches the
	// single-process proxy shape.
	db.SetMaxOpenConns(4)

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the on-disk path of the SQLite file, useful for log
// messages and tests.
func (s *Store) Path() string { return s.path }

// migrate runs the additive schema for the current SchemaVersion.
// Safe to call on an existing database; CREATE TABLE IF NOT EXISTS
// makes it idempotent.
func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY
		)`,
		// Decisions: one row per proxy evaluation. Mirrors the Python
		// iam-jit-bouncer schema column-by-column where the concepts
		// overlap; K8s-specific fields (verb/group/resource/...) are
		// added alongside.
		`CREATE TABLE IF NOT EXISTS decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			parsed_verb TEXT,
			parsed_group TEXT,
			parsed_version TEXT,
			parsed_resource TEXT,
			parsed_namespace TEXT,
			parsed_name TEXT,
			parsed_subresource TEXT,
			is_watch INTEGER NOT NULL DEFAULT 0,
			is_dry_run INTEGER NOT NULL DEFAULT 0,
			decision_verdict TEXT NOT NULL,
			decision_reason TEXT NOT NULL,
			mode_at_decision TEXT NOT NULL,
			enforced INTEGER NOT NULL DEFAULT 0,
			matched_rule_id INTEGER,
			task_id TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_at ON decisions(at)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_verdict ON decisions(decision_verdict)`,
		// Rules: scaffolded for K-Slice 3's rule engine. Empty in K-Slice 1
		// but defined now so the schema doesn't churn when the engine
		// ships.
		`CREATE TABLE IF NOT EXISTS rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pattern TEXT NOT NULL,
			effect TEXT NOT NULL,
			namespace_scope TEXT,
			resource_scope TEXT,
			verb_scope TEXT,
			note TEXT,
			origin TEXT NOT NULL DEFAULT 'user',
			created_at TEXT NOT NULL
		)`,
		// Tasks: scaffolded for K-Slice 3's task-scope feature, mirroring
		// the iam-jit-bouncer tasks table shape so the cross-product
		// review UI can compose without translation.
		`CREATE TABLE IF NOT EXISTS tasks (
			task_id TEXT PRIMARY KEY,
			description TEXT NOT NULL,
			allow_rules_json TEXT NOT NULL,
			deny_rules_json TEXT NOT NULL,
			started_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			started_by TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			ended_at TEXT,
			ended_by TEXT,
			end_reason TEXT,
			owner TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("kbouncer: migrate: %w (stmt=%q)", err, q)
		}
	}

	// K-Slice 7 additive columns. ALTER TABLE ADD COLUMN is idempotent-
	// equivalent only if we detect the column first; SQLite errors on
	// duplicate ADD COLUMN. addColumnIfMissing checks PRAGMA table_info
	// so re-opening an existing v2 DB doesn't panic.
	if err := s.addColumnIfMissing("decisions", "decision_source", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("decisions", "profile_name", "TEXT"); err != nil {
		return err
	}

	// Stamp the schema version. INSERT-or-UPDATE pattern keeps it
	// idempotent on re-open.
	var ver int
	row := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`)
	switch err := row.Scan(&ver); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES (?)`, SchemaVersion); err != nil {
			return fmt.Errorf("kbouncer: stamp schema_version: %w", err)
		}
	case err != nil:
		return fmt.Errorf("kbouncer: read schema_version: %w", err)
	default:
		if ver < SchemaVersion {
			if _, err := s.db.Exec(`UPDATE schema_version SET version = ?`, SchemaVersion); err != nil {
				return fmt.Errorf("kbouncer: bump schema_version: %w", err)
			}
		}
	}
	return nil
}

// DecisionRow is the input to RecordDecision. Mirrors the proxy
// package's RequestObservation but kept here as a plain struct so
// store/ doesn't depend on proxy/ (would create an import cycle).
type DecisionRow struct {
	At                time.Time
	Method            string
	Path              string
	ParsedVerb        string
	ParsedGroup       string
	ParsedVersion     string
	ParsedResource    string
	ParsedNamespace   string
	ParsedName        string
	ParsedSubresource string
	IsWatch           bool
	IsDryRun          bool
	DecisionVerdict   string
	DecisionReason    string
	ModeAtDecision    string
	Enforced          bool
	MatchedRuleID     *int64
	TaskID            string
	// DecisionSource added in K-Slice 7. Names the rule layer that
	// produced the verdict ("profile", "task", "global", "default",
	// "unclassifiable"). Empty string means a pre-K-Slice-7 row.
	DecisionSource string
	// ProfileName added in K-Slice 7. The active profile at decision
	// time, or "" when no profile was active.
	ProfileName string
}

// RecordDecision appends one row to the decisions audit log and
// returns the assigned row id. Failures bubble to the caller; the
// proxy logs them and keeps serving (per the same policy as
// iam-jit-bouncer — audit-write failure must not crash the proxy).
func (s *Store) RecordDecision(d DecisionRow) (int64, error) {
	atStr := d.At.UTC().Format("2006-01-02T15:04:05Z")
	if d.At.IsZero() {
		atStr = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	res, err := s.db.Exec(
		`INSERT INTO decisions(
			at, method, path,
			parsed_verb, parsed_group, parsed_version, parsed_resource,
			parsed_namespace, parsed_name, parsed_subresource,
			is_watch, is_dry_run,
			decision_verdict, decision_reason, mode_at_decision, enforced,
			matched_rule_id, task_id,
			decision_source, profile_name
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		atStr, d.Method, d.Path,
		d.ParsedVerb, d.ParsedGroup, d.ParsedVersion, d.ParsedResource,
		d.ParsedNamespace, d.ParsedName, d.ParsedSubresource,
		boolToInt(d.IsWatch), boolToInt(d.IsDryRun),
		d.DecisionVerdict, d.DecisionReason, d.ModeAtDecision, boolToInt(d.Enforced),
		nullableInt(d.MatchedRuleID), nullableString(d.TaskID),
		d.DecisionSource, nullableString(d.ProfileName),
	)
	if err != nil {
		return 0, fmt.Errorf("kbouncer: record decision: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("kbouncer: last insert id: %w", err)
	}
	return id, nil
}

// CountDecisions returns the total decision rows recorded so far.
// Used by tests; later slices will expose richer query/listing APIs.
func (s *Store) CountDecisions() (int64, error) {
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decisions`).Scan(&n); err != nil {
		return 0, fmt.Errorf("kbouncer: count decisions: %w", err)
	}
	return n, nil
}

// addColumnIfMissing is an idempotent ALTER TABLE ADD COLUMN. SQLite
// errors on a duplicate ADD; we check PRAGMA table_info first so a
// reopen of an already-migrated DB is a no-op.
func (s *Store) addColumnIfMissing(table, column, decl string) error {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("kbouncer: pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("kbouncer: scan table_info: %w", err)
		}
		if name == column {
			return nil // already present
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("kbouncer: rows.Err: %w", err)
	}
	stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl)
	if _, err := s.db.Exec(stmt); err != nil {
		return fmt.Errorf("kbouncer: add column %s.%s: %w", table, column, err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
