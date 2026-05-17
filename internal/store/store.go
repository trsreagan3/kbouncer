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
//	3 — add pause_events + decisions.pause_id (#6a timed escape hatch)
//	4 — add pending_prompts (#5 async deny-prompt UX, v1.0 subset)
//	5 — add decisions.is_stream + decisions.stream_kind (K-Slice 5)
const SchemaVersion = 5

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
		// pause_events: #6a timed escape hatch. Each pause is its own
		// audit row (intentionally a separate table from decisions/
		// config_events so reviewers can find "what windows did the
		// operator open" with a single query). Per [[safety-mode-lean-
		// permissive]]: the audit trail does the work; the bypass is
		// acceptable precisely because every call during it is logged
		// with pause_id linkage + the pause itself is its own row.
		`CREATE TABLE IF NOT EXISTS pause_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			started_at TEXT NOT NULL,
			ends_at TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			started_by TEXT NOT NULL,
			ended_at_actual TEXT,
			end_kind TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pause_events_ends_at ON pause_events(ends_at)`,
		// pending_prompts: #5 async deny-prompt UX (v1.0 subset).
		// When transparent-mode DENY fires AND the operator opted into
		// prompt_on_deny, the deny is also written here so the operator
		// can later answer (always-allow / add-to-profile / ignore).
		// Async v1.0 flow: agent gets denied immediately; operator
		// answers via `kbouncer prompts answer`; future calls use the
		// new rule. The sync v1.1 flow will REUSE this table by having
		// the proxy poll status briefly before returning.
		//
		// K8s column naming: verb/group/version/resource/namespace/name
		// mirrors the parser shape (vs the Python bouncer's
		// service/action). decision_id JOINs cleanly back to decisions.id
		// so post-hoc review can pull the full request URL by joining
		// the two tables.
		`CREATE TABLE IF NOT EXISTS pending_prompts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,
			decision_id INTEGER NOT NULL,
			verb TEXT NOT NULL DEFAULT '',
			group_name TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '',
			resource TEXT NOT NULL DEFAULT '',
			namespace TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			deny_reason TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			answer_kind TEXT,
			answer_target TEXT,
			answered_by TEXT,
			answered_at TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_prompts_status ON pending_prompts(status)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_prompts_created_at ON pending_prompts(created_at)`,
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

	// v3 additive migration: link each decision to the pause event that
	// was active at decision time (if any). Lets post-hoc review answer
	// "which decisions happened inside pause N?" with a single JOIN.
	// NULL when no pause active.
	if err := s.addColumnIfMissing("decisions", "pause_id", "INTEGER"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_decisions_pause_id ON decisions(pause_id)`); err != nil {
		return fmt.Errorf("kbouncer: create idx_decisions_pause_id: %w", err)
	}

	// v5 additive migration (K-Slice 5): mark streaming decisions so
	// audit-log readers can answer "did this open a long-lived stream?"
	// without re-parsing the request URL. ONE row per stream (not one
	// per chunk) — the decision happens at stream start; bytes flowing
	// during the stream are not recorded as separate decisions.
	//
	// is_stream defaults 0 to keep existing rows backward-compatible.
	// stream_kind is one of: "watch", "spdy", "" (not streaming).
	if err := s.addColumnIfMissing("decisions", "is_stream", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("decisions", "stream_kind", "TEXT NOT NULL DEFAULT ''"); err != nil {
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
	// PauseID added by #6a. Set when an operator-initiated pause window
	// was active at decision time so reviewers can ask "what calls
	// happened inside pause N?" with a single JOIN. NULL otherwise.
	PauseID *int64
	// IsStream added in K-Slice 5. True when the decision opened a
	// long-lived stream (watch, exec, port-forward, attach, follow-log).
	// One audit row per STREAM, not per chunk — the byte flow during
	// the stream is not separately audited.
	IsStream bool
	// StreamKind added in K-Slice 5. One of: "watch", "spdy", "" (not
	// streaming). Lets a reviewer filter the audit log to just the
	// streaming events without re-parsing URL shapes.
	StreamKind string
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
			decision_source, profile_name, pause_id,
			is_stream, stream_kind
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		atStr, d.Method, d.Path,
		d.ParsedVerb, d.ParsedGroup, d.ParsedVersion, d.ParsedResource,
		d.ParsedNamespace, d.ParsedName, d.ParsedSubresource,
		boolToInt(d.IsWatch), boolToInt(d.IsDryRun),
		d.DecisionVerdict, d.DecisionReason, d.ModeAtDecision, boolToInt(d.Enforced),
		nullableInt(d.MatchedRuleID), nullableString(d.TaskID),
		d.DecisionSource, nullableString(d.ProfileName), nullableInt(d.PauseID),
		boolToInt(d.IsStream), d.StreamKind,
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

// RecentDecisions returns the N most recently recorded decisions,
// newest first. Used by `kbouncer audit tail`. Bounded query — pass
// 0 or a negative limit to get the implicit default of 50; capped
// at 1000 so a runaway --limit doesn't OOM on a long-lived DB.
func (s *Store) RecentDecisions(limit int) ([]DecisionRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT
		at, method, path,
		parsed_verb, parsed_group, parsed_version, parsed_resource,
		parsed_namespace, parsed_name, parsed_subresource,
		is_watch, is_dry_run,
		decision_verdict, decision_reason, mode_at_decision, enforced,
		matched_rule_id, task_id,
		COALESCE(decision_source, ''), COALESCE(profile_name, ''),
		pause_id,
		COALESCE(is_stream, 0), COALESCE(stream_kind, '')
		FROM decisions
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("kbouncer: recent decisions query: %w", err)
	}
	defer rows.Close()
	out := make([]DecisionRow, 0, limit)
	for rows.Next() {
		var (
			d        DecisionRow
			atStr    string
			isWatch  int
			isDryRun int
			enforced int
			ruleID   sql.NullInt64
			taskID   sql.NullString
			pauseID  sql.NullInt64
			isStream int
		)
		if err := rows.Scan(
			&atStr, &d.Method, &d.Path,
			&d.ParsedVerb, &d.ParsedGroup, &d.ParsedVersion, &d.ParsedResource,
			&d.ParsedNamespace, &d.ParsedName, &d.ParsedSubresource,
			&isWatch, &isDryRun,
			&d.DecisionVerdict, &d.DecisionReason, &d.ModeAtDecision, &enforced,
			&ruleID, &taskID,
			&d.DecisionSource, &d.ProfileName, &pauseID,
			&isStream, &d.StreamKind,
		); err != nil {
			return nil, fmt.Errorf("kbouncer: recent decisions scan: %w", err)
		}
		if t, perr := time.Parse("2006-01-02T15:04:05Z", atStr); perr == nil {
			d.At = t
		}
		d.IsWatch = isWatch != 0
		d.IsDryRun = isDryRun != 0
		d.Enforced = enforced != 0
		if ruleID.Valid {
			rid := ruleID.Int64
			d.MatchedRuleID = &rid
		}
		if taskID.Valid {
			d.TaskID = taskID.String
		}
		if pauseID.Valid {
			pid := pauseID.Int64
			d.PauseID = &pid
		}
		d.IsStream = isStream != 0
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kbouncer: recent decisions iterate: %w", err)
	}
	return out, nil
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

// ---------------------------------------------------------------------------
// Pauses (#6a — timed bypass / escape hatch)
// ---------------------------------------------------------------------------

// PauseRow is one row from pause_events. Returned by GetActivePause and
// ListRecentPauses. Optional fields use sql.NullString so callers can
// distinguish "not set" from "empty string."
type PauseRow struct {
	ID            int64
	StartedAt     string
	EndsAt        string
	Reason        string
	StartedBy     string
	EndedAtActual string // empty when pause is still active
	EndKind       string // "" while live; "expired" or "resumed_early" after end
}

// MaxPauseDurationSeconds caps how long a single pause may run. Per
// [[safety-mode-lean-permissive]]: short windows + audit trail does the
// work. A multi-day pause is an "I don't want the proxy" signal — the
// operator should stop the daemon instead.
const MaxPauseDurationSeconds int64 = 24 * 3600

// StartPause opens a new pause window. Returns the new pause id.
//
// Refuses (returns error) if another pause is already active — nested
// pauses are deliberately rejected so the audit trail always has a
// clean "started at X, ended at Y" pairing. To extend, resume + start
// a new one (each extension is its own row).
//
// Also refuses durationSeconds <= 0 (nonsense) and > 24h (cap; see
// MaxPauseDurationSeconds).
func (s *Store) StartPause(durationSeconds int64, reason, startedBy string) (int64, error) {
	if durationSeconds <= 0 {
		return 0, fmt.Errorf("kbouncer: pause duration must be > 0 seconds")
	}
	if durationSeconds > MaxPauseDurationSeconds {
		return 0, fmt.Errorf(
			"kbouncer: pause duration cannot exceed 24h; for longer windows " +
				"stop the proxy and restart later")
	}
	now := time.Now().UTC()
	ends := now.Add(time.Duration(durationSeconds) * time.Second)
	// Lazy-GC + active-check under the same connection so a racing
	// caller can't slip past. The active-pause query inside
	// GetActivePause writes back expired rows so this read sees the
	// current truth.
	active, err := s.GetActivePause()
	if err != nil {
		return 0, err
	}
	if active != nil {
		return 0, fmt.Errorf(
			"kbouncer: a pause is already active (id=%d, ends_at=%s); "+
				"resume first to start a new one",
			active.ID, active.EndsAt)
	}
	res, err := s.db.Exec(
		`INSERT INTO pause_events(started_at, ends_at, reason, started_by) VALUES (?, ?, ?, ?)`,
		now.Format("2006-01-02T15:04:05Z"),
		ends.Format("2006-01-02T15:04:05Z"),
		reason,
		startedBy,
	)
	if err != nil {
		return 0, fmt.Errorf("kbouncer: start pause: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("kbouncer: start pause last insert id: %w", err)
	}
	return id, nil
}

// EndPause closes the currently-active pause. Returns the ended pause
// id, or nil if no pause was active. Sets end_kind = "resumed_early"
// so post-hoc review can distinguish operator-initiated ends from
// auto-expiry.
//
// endedBy names the actor for the audit trail (typically "cli" or a
// username).
func (s *Store) EndPause(endedBy string) (*int64, error) {
	active, err := s.GetActivePause()
	if err != nil {
		return nil, err
	}
	if active == nil {
		return nil, nil
	}
	_, err = s.db.Exec(
		`UPDATE pause_events SET ended_at_actual = ?, end_kind = ? WHERE id = ? AND ended_at_actual IS NULL`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"resumed_early",
		active.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("kbouncer: end pause: %w", err)
	}
	// Note: endedBy is recorded by the CLI layer in a future audit-
	// event table; the pause_events row itself tracks lifecycle, not
	// the actor who ended it. (Mirrors the Python store.)
	_ = endedBy
	return &active.ID, nil
}

// GetActivePause returns the currently-active pause (started, not yet
// expired, not yet ended). Returns nil when no pause is active.
//
// Lazy garbage-collect: marks any pause whose ends_at is past as
// 'expired' before reading. This is the auto-revert mechanism — no
// background timer required; works in tests, in serverless,
// anywhere. The first read past ends_at flips the pause to expired.
func (s *Store) GetActivePause() (*PauseRow, error) {
	nowStr := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if _, err := s.db.Exec(
		`UPDATE pause_events SET ended_at_actual = ends_at, end_kind = 'expired'
		 WHERE ended_at_actual IS NULL AND ends_at <= ?`,
		nowStr,
	); err != nil {
		return nil, fmt.Errorf("kbouncer: gc expired pauses: %w", err)
	}
	row := s.db.QueryRow(
		`SELECT id, started_at, ends_at, reason, started_by,
		       COALESCE(ended_at_actual, ''), COALESCE(end_kind, '')
		 FROM pause_events
		 WHERE ended_at_actual IS NULL
		 ORDER BY id DESC LIMIT 1`,
	)
	var p PauseRow
	err := row.Scan(&p.ID, &p.StartedAt, &p.EndsAt, &p.Reason, &p.StartedBy, &p.EndedAtActual, &p.EndKind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kbouncer: get active pause: %w", err)
	}
	return &p, nil
}

// ListRecentPauses returns the N most recent pause rows for
// `kbouncer pause history`. Default limit when <=0: 20.
func (s *Store) ListRecentPauses(limit int) ([]PauseRow, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(
		`SELECT id, started_at, ends_at, reason, started_by,
		        COALESCE(ended_at_actual, ''), COALESCE(end_kind, '')
		 FROM pause_events ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("kbouncer: list pauses: %w", err)
	}
	defer rows.Close()
	out := make([]PauseRow, 0, limit)
	for rows.Next() {
		var p PauseRow
		if err := rows.Scan(&p.ID, &p.StartedAt, &p.EndsAt, &p.Reason, &p.StartedBy, &p.EndedAtActual, &p.EndKind); err != nil {
			return nil, fmt.Errorf("kbouncer: list pauses scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kbouncer: list pauses iterate: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Pending prompts (#5 — async deny-prompt UX, v1.0 subset)
// ---------------------------------------------------------------------------

// PromptRow is one row from pending_prompts. K8s column shape: the
// parsed verb/group/version/resource/namespace/name from the proxy
// (mirrors the iam-jit-bouncer service+action equivalents).
type PromptRow struct {
	ID           int64
	CreatedAt    string
	DecisionID   int64
	Verb         string
	Group        string
	Version      string
	Resource     string
	Namespace    string
	Name         string
	DenyReason   string
	Status       string
	AnswerKind   string
	AnswerTarget string
	AnsweredBy   string
	AnsweredAt   string
}

// PromptInput is the input to AddPendingPrompt. Keeping a struct
// (rather than a long positional arg list) so the call site stays
// readable + future fields are additive.
type PromptInput struct {
	DecisionID int64
	Verb       string
	Group      string
	Version    string
	Resource   string
	Namespace  string
	Name       string
	DenyReason string
}

// AddPendingPrompt inserts a pending-prompt row for a transparent-mode
// DENY the operator has opted in to be notified about. Returns the
// new prompt id.
//
// Idempotent on (decision_id) — re-calling with the same decision_id
// is a no-op + returns the existing id. This makes the proxy's
// enqueue path safe to retry on transient failures.
func (s *Store) AddPendingPrompt(p PromptInput) (int64, error) {
	// Idempotency: if a prompt already exists for this decision_id,
	// return its id without inserting again. The proxy's audit-log
	// invariant is "one decision -> at-most-one prompt".
	var prior int64
	row := s.db.QueryRow(`SELECT id FROM pending_prompts WHERE decision_id = ?`, p.DecisionID)
	if err := row.Scan(&prior); err == nil {
		return prior, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("kbouncer: lookup pending prompt: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT INTO pending_prompts(
			created_at, decision_id, verb, group_name, version, resource,
			namespace, name, deny_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		p.DecisionID, p.Verb, p.Group, p.Version, p.Resource,
		p.Namespace, p.Name, p.DenyReason,
	)
	if err != nil {
		return 0, fmt.Errorf("kbouncer: add pending prompt: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("kbouncer: add pending prompt last insert id: %w", err)
	}
	return id, nil
}

// PromptStatusPending / PromptStatusAnswered / PromptStatusIgnored are
// the canonical status values surfaced by ListPendingPrompts +
// AnswerPendingPrompt.
const (
	PromptStatusPending  = "pending"
	PromptStatusAnswered = "answered"
	PromptStatusIgnored  = "ignored"
)

// ListPendingPrompts returns prompts with the given status, newest
// first. Default limit when <=0: 50.
func (s *Store) ListPendingPrompts(status string, limit int) ([]PromptRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if status == "" {
		status = PromptStatusPending
	}
	rows, err := s.db.Query(
		`SELECT id, created_at, decision_id, verb, group_name, version,
		        resource, namespace, name, deny_reason, status,
		        COALESCE(answer_kind, ''), COALESCE(answer_target, ''),
		        COALESCE(answered_by, ''), COALESCE(answered_at, '')
		 FROM pending_prompts WHERE status = ?
		 ORDER BY id DESC LIMIT ?`, status, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("kbouncer: list pending prompts: %w", err)
	}
	defer rows.Close()
	out := make([]PromptRow, 0, limit)
	for rows.Next() {
		var p PromptRow
		if err := rows.Scan(
			&p.ID, &p.CreatedAt, &p.DecisionID, &p.Verb, &p.Group, &p.Version,
			&p.Resource, &p.Namespace, &p.Name, &p.DenyReason, &p.Status,
			&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt,
		); err != nil {
			return nil, fmt.Errorf("kbouncer: list pending prompts scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kbouncer: list pending prompts iterate: %w", err)
	}
	return out, nil
}

// GetPendingPrompt returns the prompt with the given id, or nil if it
// doesn't exist.
func (s *Store) GetPendingPrompt(id int64) (*PromptRow, error) {
	row := s.db.QueryRow(
		`SELECT id, created_at, decision_id, verb, group_name, version,
		        resource, namespace, name, deny_reason, status,
		        COALESCE(answer_kind, ''), COALESCE(answer_target, ''),
		        COALESCE(answered_by, ''), COALESCE(answered_at, '')
		 FROM pending_prompts WHERE id = ?`, id,
	)
	var p PromptRow
	err := row.Scan(
		&p.ID, &p.CreatedAt, &p.DecisionID, &p.Verb, &p.Group, &p.Version,
		&p.Resource, &p.Namespace, &p.Name, &p.DenyReason, &p.Status,
		&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kbouncer: get pending prompt: %w", err)
	}
	return &p, nil
}

// PromptAnswerKindAlways / Profile / Ignore are the canonical answer
// kinds accepted by AnswerPendingPrompt.
const (
	PromptAnswerKindAlways  = "always"
	PromptAnswerKindProfile = "profile"
	PromptAnswerKindIgnore  = "ignore"
)

// AnswerPendingPrompt records an answer on a pending prompt. Returns
// true if the prompt was found + pending; false if it was already
// answered or doesn't exist.
//
// Validates kind ∈ {always, profile, ignore} — unknown kinds return
// an error (NOT false) so callers can distinguish a bad request from
// an already-answered prompt.
//
// Side-effects (rule add / profile edit) are the CLI's responsibility
// — store just records intent.
func (s *Store) AnswerPendingPrompt(id int64, kind, target, answeredBy string) (bool, error) {
	switch kind {
	case PromptAnswerKindAlways, PromptAnswerKindProfile, PromptAnswerKindIgnore:
		// ok
	default:
		return false, fmt.Errorf(
			"kbouncer: answer_kind must be one of: always, profile, ignore (got %q)",
			kind)
	}
	res, err := s.db.Exec(
		`UPDATE pending_prompts SET status = 'answered',
		        answer_kind = ?, answer_target = ?, answered_by = ?, answered_at = ?
		 WHERE id = ? AND status = 'pending'`,
		kind, nullableString(target), answeredBy,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		id,
	)
	if err != nil {
		return false, fmt.Errorf("kbouncer: answer pending prompt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("kbouncer: answer pending prompt rows affected: %w", err)
	}
	return n > 0, nil
}
