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
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
//	6 — add pending_prompts.sync_wait_id (#203 synchronous deny-prompt v1.1)
//	7 — add rules.expires_at + rules.created_by + bulk-answer state tables
//	    (bulk-prompt-answer-ux: burst events + profile-switch reload signal)
//	8 — add decisions.agent_name + decisions.agent_session_id (#289 closes
//	    the kbounce-agent-identity-sqlite-gap with the existing parity
//	    shape used by ibounce / dbounce / gbounce — both columns NULL on
//	    pre-#289 rows, which the read path surfaces as the default
//	    {name:"unknown", detected_from:"unknown"} agent block; old data
//	    is preserved per [[creates-never-mutates]])
//	9 — #320 / §A18: add decisions.detected_from TEXT NOT NULL DEFAULT
//	    'unknown' so the HTTP /audit/events endpoint can surface the
//	    REAL detection source (http_header, http_header_name_only,
//	    user_agent, mcp_clientinfo, process_tree, unknown) instead of
//	    the agentInfoFromDecisionRow heuristic that always rendered
//	    `detected_from=mcp_clientinfo` whenever an agent_session_id
//	    was present. UAT 2026-05-22 verified the heuristic mis-
//	    labelled http_header-detected events as mcp_clientinfo —
//	    breaks SIEM filters that distinguish "agent declared itself
//	    via HTTP header" from "agent surfaced via MCP handshake".
//	    Pre-#320 rows get 'unknown' via the schema-level DEFAULT —
//	    historical events stay accurate (we don't synthesize a
//	    detection source we didn't actually observe). Mirrors
//	    dbounce v7 + gbounce + ibounce per
//	    [[cross-product-agent-parity]].
const SchemaVersion = 9

// DefaultDBPath returns the path the store opens when no explicit path
// is supplied. Honors KBOUNCER_DB for tests and CI sandboxes that
// want a scratch location.
func DefaultDBPath() (string, error) {
	if override := os.Getenv("KBOUNCER_DB"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("kbounce: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".kbouncer", "state.db"), nil
}

// Store wraps a sql.DB plus the migration state. Safe for concurrent
// use from multiple goroutines (sql.DB handles its own pooling).
//
// The store also owns the in-memory waiter map used by #203's
// synchronous deny-prompt flow (sync_wait_id -> chan PromptDecision).
// The map lives ONLY in memory: on proxy restart, any in-flight sync
// prompts are lost (the request goroutine is dead too). This is the
// expected behavior — sync prompts are RUNTIME state, not persisted
// state.
type Store struct {
	db   *sql.DB
	path string

	syncMu      sync.Mutex
	syncWaiters map[string]chan PromptDecision
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
			return nil, fmt.Errorf("kbounce: mkdir %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("kbounce: sql.Open: %w", err)
	}
	// modernc sqlite supports only one writer at a time per file; a
	// small connection cap keeps contention predictable and matches the
	// single-process proxy shape.
	db.SetMaxOpenConns(4)

	s := &Store{
		db:          db,
		path:        path,
		syncWaiters: make(map[string]chan PromptDecision),
	}
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
			return fmt.Errorf("kbounce: migrate: %w (stmt=%q)", err, q)
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
		return fmt.Errorf("kbounce: create idx_decisions_pause_id: %w", err)
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

	// v6 additive migration (#203 synchronous deny-prompt v1.1):
	// sync_wait_id tags a pending_prompts row that has an active
	// in-process waiter — i.e. a proxy request goroutine is blocked
	// waiting for the operator's answer before returning to the agent.
	// NULL/empty when the prompt is purely async (the v1.0 flow).
	//
	// Column is TEXT (UUID-shaped); no NOT NULL because the legacy
	// async path inserts NULL. SQLite UNIQUE allows multiple NULL
	// rows, which is exactly what we want.
	if err := s.addColumnIfMissing("pending_prompts", "sync_wait_id", "TEXT"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_prompts_sync_wait_id
		ON pending_prompts(sync_wait_id) WHERE sync_wait_id IS NOT NULL`); err != nil {
		return fmt.Errorf("kbounce: create idx_pending_prompts_sync_wait_id: %w", err)
	}

	// v7 additive migration ([[bulk-prompt-answer-ux]] memo):
	// - rules.expires_at: NULL = permanent (existing behavior); non-NULL
	//   timestamp = the row is honored by LoadRuleSet only while
	//   wall-clock < expires_at. Per [[creates-never-mutates]] the row
	//   is NEVER deleted at expiry — the audit trail keeps the full
	//   history of "what was allowed when." LoadRuleSet filters; the
	//   row stays in the table.
	// - rules.created_by: actor that added the rule (operator name /
	//   "bulk-answer" / "mcp"). Lets bulk-answer rows be enumerated
	//   without re-parsing the note field.
	// - burst_events: one row per BURST_DETECTED event the proxy emits.
	//   Read by `kbounce prompts bulk-answer` (CLI surfaces "n prompts
	//   in m seconds; how to handle?") + by the bulk-answer MCP tool
	//   so an agent can introspect the same burst state. Persisting
	//   the event (rather than an in-memory shape) lets cross-process
	//   `kbounce prompts bulk-answer` see what the running proxy
	//   detected.
	// - profile_reload_signal: cross-process channel for the
	//   profile-switch bulk-answer option. The CLI / MCP writes the
	//   desired profile name; the running proxy's poll loop picks it
	//   up + hot-swaps its active profile pointer. Single-row table
	//   (pk=1) so writes are idempotent overwrites.
	if err := s.addColumnIfMissing("rules", "expires_at", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("rules", "created_by", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_rules_expires_at ON rules(expires_at)`); err != nil {
		return fmt.Errorf("kbounce: create idx_rules_expires_at: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS burst_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		detected_at TEXT NOT NULL,
		prompt_count INTEGER NOT NULL,
		window_seconds INTEGER NOT NULL,
		resolved_at TEXT,
		resolution_kind TEXT
	)`); err != nil {
		return fmt.Errorf("kbounce: create burst_events: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_burst_events_resolved_at ON burst_events(resolved_at)`); err != nil {
		return fmt.Errorf("kbounce: create idx_burst_events_resolved_at: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS profile_reload_signal (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		profile_name TEXT NOT NULL,
		requested_at TEXT NOT NULL,
		requested_by TEXT NOT NULL,
		applied_at TEXT
	)`); err != nil {
		return fmt.Errorf("kbounce: create profile_reload_signal: %w", err)
	}

	// v8 additive migration (#289 — close the kbounce-agent-identity-
	// sqlite-gap): persist the agent name + per-MCP-session id alongside
	// every decision row. The JSONL audit log + HTTPS webhook already
	// carry these (bound in memory at proxy hot-path); SQLite was the
	// one channel that dropped them, which made anything reading SQLite
	// directly (audit-tail, investigate, /audit/events, the web UI)
	// always render `agent.name="unknown"` even when the in-memory
	// identity was high-fidelity.
	//
	// Both columns nullable: pre-#289 rows stay NULL and the read path
	// (RecentDecisions → decisionRowsToEvents → FromDecision) treats
	// empty AgentInfo as "fall through to the default unknown block"
	// — which is the ACCURATE label for rows that were recorded before
	// we had the identity to store. NO backfill — synthesizing a fake
	// identity for retroactive rows would violate
	// [[scorer-is-ground-truth]] (pretending to know is not honest).
	//
	// Closes the cross-product parity gap with ibounce + dbounce +
	// gbounce per [[cross-product-agent-parity]].
	if err := s.addColumnIfMissing("decisions", "agent_name", "TEXT"); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("decisions", "agent_session_id", "TEXT"); err != nil {
		return err
	}

	// v9 additive migration (#320 / §A18 — close the /audit/events
	// wire-shape parity gap): replace the read-time
	// `agentInfoFromDecisionRow` heuristic (which guessed
	// `detected_from=mcp_clientinfo` whenever a session_id was
	// persisted, mis-labelling http_header-detected events) with a
	// stored column populated at write time from the SAME source the
	// in-memory exporter pipeline already records. NOT NULL DEFAULT
	// 'unknown' so pre-#320 rows surface the canonical "we don't
	// know" value instead of synthesizing a fake detection source.
	// Mirrors dbounce v7 + gbounce + ibounce per
	// [[cross-product-agent-parity]].
	if err := s.addColumnIfMissing("decisions", "detected_from", "TEXT NOT NULL DEFAULT 'unknown'"); err != nil {
		return err
	}

	// Stamp the schema version. INSERT-or-UPDATE pattern keeps it
	// idempotent on re-open.
	var ver int
	row := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`)
	switch err := row.Scan(&ver); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES (?)`, SchemaVersion); err != nil {
			return fmt.Errorf("kbounce: stamp schema_version: %w", err)
		}
	case err != nil:
		return fmt.Errorf("kbounce: read schema_version: %w", err)
	default:
		if ver < SchemaVersion {
			if _, err := s.db.Exec(`UPDATE schema_version SET version = ?`, SchemaVersion); err != nil {
				return fmt.Errorf("kbounce: bump schema_version: %w", err)
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
	// AgentName added in #289 (closes the kbounce-agent-identity-sqlite-
	// gap). The fingerprinted agent name at decision time ("claude-code",
	// "kubectl", "client-go", "unknown", ...). Empty when no detection
	// source fired AND for rows recorded before #289 — both surface as
	// the default {name:"unknown", detected_from:"unknown"} agent block
	// when wrapped by FromDecision. Mirrors the column written by
	// ibounce + dbounce + gbounce per [[cross-product-agent-parity]].
	AgentName string
	// AgentSessionID added in #289. The per-MCP-connection UUID v7 bound
	// at the MCP handshake; empty for proxy-observed traffic that wasn't
	// routed through an MCP connection (bare kubectl, ad-hoc scripts).
	AgentSessionID string
	// DetectedFrom added in v9 (#320 / §A18). Names the signal that
	// produced the AgentName + AgentSessionID values: one of
	// "http_header", "http_header_name_only", "user_agent",
	// "mcp_clientinfo", "process_tree", "unknown". Empty string is
	// treated as "unknown" on the read path so handler code never has
	// to nil-check. Replaces the read-time heuristic that mis-labelled
	// http_header-detected events as mcp_clientinfo whenever a
	// session_id was present. Mirrors the column written by dbounce +
	// ibounce + gbounce per [[cross-product-agent-parity]].
	DetectedFrom string
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
	// #320 / §A18: default DetectedFrom to "unknown" so a row written
	// without an explicit detection source still satisfies the NOT
	// NULL constraint + reads back as the canonical fall-through.
	detectedFrom := d.DetectedFrom
	if detectedFrom == "" {
		detectedFrom = "unknown"
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
			is_stream, stream_kind,
			agent_name, agent_session_id, detected_from
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		atStr, d.Method, d.Path,
		d.ParsedVerb, d.ParsedGroup, d.ParsedVersion, d.ParsedResource,
		d.ParsedNamespace, d.ParsedName, d.ParsedSubresource,
		boolToInt(d.IsWatch), boolToInt(d.IsDryRun),
		d.DecisionVerdict, d.DecisionReason, d.ModeAtDecision, boolToInt(d.Enforced),
		nullableInt(d.MatchedRuleID), nullableString(d.TaskID),
		d.DecisionSource, nullableString(d.ProfileName), nullableInt(d.PauseID),
		boolToInt(d.IsStream), d.StreamKind,
		nullableString(d.AgentName), nullableString(d.AgentSessionID), detectedFrom,
	)
	if err != nil {
		return 0, fmt.Errorf("kbounce: record decision: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("kbounce: last insert id: %w", err)
	}
	return id, nil
}

// CountDecisions returns the total decision rows recorded so far.
// Used by tests; later slices will expose richer query/listing APIs.
func (s *Store) CountDecisions() (int64, error) {
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decisions`).Scan(&n); err != nil {
		return 0, fmt.Errorf("kbounce: count decisions: %w", err)
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
		COALESCE(is_stream, 0), COALESCE(stream_kind, ''),
		COALESCE(agent_name, ''), COALESCE(agent_session_id, ''),
		COALESCE(detected_from, 'unknown')
		FROM decisions
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("kbounce: recent decisions query: %w", err)
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
			&d.AgentName, &d.AgentSessionID, &d.DetectedFrom,
		); err != nil {
			return nil, fmt.Errorf("kbounce: recent decisions scan: %w", err)
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
		return nil, fmt.Errorf("kbounce: recent decisions iterate: %w", err)
	}
	return out, nil
}

// addColumnIfMissing is an idempotent ALTER TABLE ADD COLUMN. SQLite
// errors on a duplicate ADD; we check PRAGMA table_info first so a
// reopen of an already-migrated DB is a no-op.
func (s *Store) addColumnIfMissing(table, column, decl string) error {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("kbounce: pragma table_info(%s): %w", table, err)
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
			return fmt.Errorf("kbounce: scan table_info: %w", err)
		}
		if name == column {
			return nil // already present
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("kbounce: rows.Err: %w", err)
	}
	stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl)
	if _, err := s.db.Exec(stmt); err != nil {
		return fmt.Errorf("kbounce: add column %s.%s: %w", table, column, err)
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
		return 0, fmt.Errorf("kbounce: pause duration must be > 0 seconds")
	}
	if durationSeconds > MaxPauseDurationSeconds {
		return 0, fmt.Errorf(
			"kbounce: pause duration cannot exceed 24h; for longer windows " +
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
			"kbounce: a pause is already active (id=%d, ends_at=%s); "+
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
		return 0, fmt.Errorf("kbounce: start pause: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("kbounce: start pause last insert id: %w", err)
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
		return nil, fmt.Errorf("kbounce: end pause: %w", err)
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
		return nil, fmt.Errorf("kbounce: gc expired pauses: %w", err)
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
		return nil, fmt.Errorf("kbounce: get active pause: %w", err)
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
		return nil, fmt.Errorf("kbounce: list pauses: %w", err)
	}
	defer rows.Close()
	out := make([]PauseRow, 0, limit)
	for rows.Next() {
		var p PauseRow
		if err := rows.Scan(&p.ID, &p.StartedAt, &p.EndsAt, &p.Reason, &p.StartedBy, &p.EndedAtActual, &p.EndKind); err != nil {
			return nil, fmt.Errorf("kbounce: list pauses scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kbounce: list pauses iterate: %w", err)
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
	// SyncWaitID is the UUID-shaped key for the in-memory waiter
	// channel that the proxy goroutine is blocked on. Empty for
	// purely-async (v1.0) prompts. When non-empty, AnswerPendingPrompt
	// wakes the in-process waiter so the request goroutine can return
	// the right response to the agent.
	SyncWaitID string
}

// PromptDecision is what AnswerPendingPrompt sends to a waiting proxy
// goroutine through the sync-wait channel. Distinct from the on-disk
// answer_kind because the proxy only cares about the binary
// allow/deny outcome — "always" + "profile" both mean ALLOW; "ignore"
// means DENY. Mirrors the "answer integration" section of the #203
// shared UX spec.
type PromptDecision struct {
	// Allow is true when the operator's answer resolves to "let this
	// request through" (kind in {always, profile}); false when it
	// resolves to "keep denying" (kind=ignore) or on timeout.
	Allow bool
	// Kind echoes the operator's answer kind so the audit row + the
	// proxy's debug logs can record exactly which path was taken.
	// Empty when the decision came from a timeout / context cancel.
	Kind string
	// AnsweredBy carries the actor recorded on the answer row, when
	// available; empty for timeout decisions.
	AnsweredBy string
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
		return 0, fmt.Errorf("kbounce: lookup pending prompt: %w", err)
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
		return 0, fmt.Errorf("kbounce: add pending prompt: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("kbounce: add pending prompt last insert id: %w", err)
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
		        COALESCE(answered_by, ''), COALESCE(answered_at, ''),
		        COALESCE(sync_wait_id, '')
		 FROM pending_prompts WHERE status = ?
		 ORDER BY id DESC LIMIT ?`, status, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("kbounce: list pending prompts: %w", err)
	}
	defer rows.Close()
	out := make([]PromptRow, 0, limit)
	for rows.Next() {
		var p PromptRow
		if err := rows.Scan(
			&p.ID, &p.CreatedAt, &p.DecisionID, &p.Verb, &p.Group, &p.Version,
			&p.Resource, &p.Namespace, &p.Name, &p.DenyReason, &p.Status,
			&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt,
			&p.SyncWaitID,
		); err != nil {
			return nil, fmt.Errorf("kbounce: list pending prompts scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kbounce: list pending prompts iterate: %w", err)
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
		        COALESCE(answered_by, ''), COALESCE(answered_at, ''),
		        COALESCE(sync_wait_id, '')
		 FROM pending_prompts WHERE id = ?`, id,
	)
	var p PromptRow
	err := row.Scan(
		&p.ID, &p.CreatedAt, &p.DecisionID, &p.Verb, &p.Group, &p.Version,
		&p.Resource, &p.Namespace, &p.Name, &p.DenyReason, &p.Status,
		&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt,
		&p.SyncWaitID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kbounce: get pending prompt: %w", err)
	}
	return &p, nil
}

// GetPendingPromptBySyncWaitID returns the prompt row keyed by its
// sync_wait_id, or nil if no row matches. Used by the proxy's cross-
// process poll fallback in handleSyncPromptDeny: when `kbounce run` +
// `kbounce prompts answer` execute in DIFFERENT processes (the typical
// operator workflow), AnswerPendingPrompt's in-memory channel wake
// fires in the answerer's process — invisible to the proxy. The proxy
// goroutine polls this lookup on a 200ms cadence to detect the
// persisted status change. Indexed via idx_pending_prompts_sync_wait_id.
func (s *Store) GetPendingPromptBySyncWaitID(id string) (*PromptRow, error) {
	if id == "" {
		return nil, nil
	}
	row := s.db.QueryRow(
		`SELECT id, created_at, decision_id, verb, group_name, version,
		        resource, namespace, name, deny_reason, status,
		        COALESCE(answer_kind, ''), COALESCE(answer_target, ''),
		        COALESCE(answered_by, ''), COALESCE(answered_at, ''),
		        COALESCE(sync_wait_id, '')
		 FROM pending_prompts WHERE sync_wait_id = ?`, id,
	)
	var p PromptRow
	err := row.Scan(
		&p.ID, &p.CreatedAt, &p.DecisionID, &p.Verb, &p.Group, &p.Version,
		&p.Resource, &p.Namespace, &p.Name, &p.DenyReason, &p.Status,
		&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt,
		&p.SyncWaitID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kbounce: get pending prompt by sync_wait_id: %w", err)
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
//
// #203 sync flow: if the prompt has a sync_wait_id, the in-memory
// waiter channel is looked up + sent the resolved PromptDecision so
// the proxy request goroutine can return the right response to the
// agent. The wake is best-effort — a missing waiter (proxy restarted
// after the row was written) is a no-op, NOT an error.
func (s *Store) AnswerPendingPrompt(id int64, kind, target, answeredBy string) (bool, error) {
	switch kind {
	case PromptAnswerKindAlways, PromptAnswerKindProfile, PromptAnswerKindIgnore:
		// ok
	default:
		return false, fmt.Errorf(
			"kbounce: answer_kind must be one of: always, profile, ignore (got %q)",
			kind)
	}
	// Read the prompt FIRST so we can fish out the sync_wait_id (if any)
	// before flipping its status. Reading after the UPDATE would race
	// with another goroutine that calls GetPendingPrompt at the same
	// instant — not a correctness problem (the wake is best-effort)
	// but cleaner to read first.
	prior, err := s.GetPendingPrompt(id)
	if err != nil {
		return false, err
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
		return false, fmt.Errorf("kbounce: answer pending prompt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("kbounce: answer pending prompt rows affected: %w", err)
	}
	ok := n > 0
	if ok && prior != nil && prior.SyncWaitID != "" {
		decision := PromptDecision{
			Allow:      kind == PromptAnswerKindAlways || kind == PromptAnswerKindProfile,
			Kind:       kind,
			AnsweredBy: answeredBy,
		}
		s.wakeSyncWaiter(prior.SyncWaitID, decision)
	}
	return ok, nil
}

// ---------------------------------------------------------------------------
// Synchronous pending prompts (#203 — synchronous deny-prompt v1.1)
// ---------------------------------------------------------------------------

// newSyncWaitID returns a URL-safe random 16-byte hex string used as
// the in-memory waiter key (the column is TEXT; the column is unique
// when populated). Collision probability is negligible (128 bits).
func newSyncWaitID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("kbounce: read random sync_wait_id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// AddSyncPendingPrompt is the #203 sync-flow variant of
// AddPendingPrompt. It inserts a pending_prompts row tagged with a
// fresh sync_wait_id, registers an in-memory waiter channel keyed by
// that id, and returns the channel for the caller (a proxy request
// goroutine) to select on.
//
// The returned channel is BUFFERED (cap 1) so AnswerPendingPrompt
// never blocks even if the waiter has already given up + moved on
// (timeout / context cancel paths drain the channel via the store's
// wakeSyncWaiter / forgetSyncWaiter pair).
//
// Idempotency: NOT idempotent on decision_id like AddPendingPrompt is.
// Each sync call gets its own row + its own waiter — the proxy
// request goroutine is single-shot, and re-using a row from an earlier
// async enqueue would let an old answer wake a NEW request, which is
// the wrong audit story.
//
// Caller MUST call ForgetSyncWaiter(sync_wait_id) when it's done
// waiting (on any outcome — answer received, timeout, ctx cancel) so
// the in-memory map doesn't leak.
func (s *Store) AddSyncPendingPrompt(p PromptInput) (string, <-chan PromptDecision, error) {
	syncID, err := newSyncWaitID()
	if err != nil {
		return "", nil, err
	}
	ch := make(chan PromptDecision, 1)

	// Register the waiter BEFORE the INSERT so an unlikely race where
	// the operator answers in the gap can't be lost (Answer looks up
	// the in-memory waiter; if it's not there, the answer is purely
	// async and the agent will see it on the next call of the same
	// shape — same behavior as the v1.0 path).
	s.syncMu.Lock()
	s.syncWaiters[syncID] = ch
	s.syncMu.Unlock()

	res, err := s.db.Exec(
		`INSERT INTO pending_prompts(
			created_at, decision_id, verb, group_name, version, resource,
			namespace, name, deny_reason, sync_wait_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		p.DecisionID, p.Verb, p.Group, p.Version, p.Resource,
		p.Namespace, p.Name, p.DenyReason, syncID,
	)
	if err != nil {
		// Roll back the waiter registration so we don't leak.
		s.ForgetSyncWaiter(syncID)
		return "", nil, fmt.Errorf("kbounce: add sync pending prompt: %w", err)
	}
	if _, err := res.LastInsertId(); err != nil {
		s.ForgetSyncWaiter(syncID)
		return "", nil, fmt.Errorf("kbounce: add sync pending prompt last insert id: %w", err)
	}
	return syncID, ch, nil
}

// wakeSyncWaiter sends decision on the channel registered for syncID
// (if any) without blocking. The channel is buffered cap-1 so a single
// send always succeeds; subsequent sends are dropped (a waiter only
// reads one decision). Safe to call when no waiter is registered
// (crash-restart-after-row-written; the answer falls through to the
// purely-async semantic).
func (s *Store) wakeSyncWaiter(syncID string, decision PromptDecision) {
	s.syncMu.Lock()
	ch, ok := s.syncWaiters[syncID]
	if ok {
		// Remove from the map under the same lock so a second wake
		// (e.g. operator re-answers via another path) is a no-op.
		delete(s.syncWaiters, syncID)
	}
	s.syncMu.Unlock()
	if !ok {
		return
	}
	// Non-blocking send: the channel is buffered cap-1; if the waiter
	// already drained it (timeout path) we drop the value. close() is
	// deliberately NOT used so a stale call to wakeSyncWaiter (test
	// shutdown ordering) can't panic with "send on closed channel."
	select {
	case ch <- decision:
	default:
	}
}

// WakeSyncPendingPrompt is the exported wrapper around wakeSyncWaiter,
// used by tests that want to simulate an operator answer without
// going through AnswerPendingPrompt's DB write.
func (s *Store) WakeSyncPendingPrompt(syncID string, decision PromptDecision) {
	s.wakeSyncWaiter(syncID, decision)
}

// ForgetSyncWaiter removes the in-memory waiter entry for syncID.
// MUST be called by the waiting goroutine when it returns (timeout /
// ctx cancel / received decision) so the map doesn't leak. A duplicate
// call is a no-op.
func (s *Store) ForgetSyncWaiter(syncID string) {
	s.syncMu.Lock()
	delete(s.syncWaiters, syncID)
	s.syncMu.Unlock()
}

// ListWaitingSyncPrompts returns the pending_prompts rows that
// currently have an in-process waiter registered — i.e. the subset of
// pending sync prompts the running proxy is actively blocked on.
//
// Determinism: SQL query against pending_prompts.sync_wait_id IS NOT
// NULL AND status = 'pending', INNER JOIN-style filtered against the
// in-memory waiter map. A row whose proxy has died (waiter map empty)
// is NOT returned by this function — that row is purely a leftover
// audit record at that point and won't ever resolve through the sync
// path.
//
// Surfaced by the kbounce_pending_sync_prompts MCP tool. Newest first.
// Default limit when <=0: 50; capped at 1000.
func (s *Store) ListWaitingSyncPrompts(limit int) ([]PromptRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(
		`SELECT id, created_at, decision_id, verb, group_name, version,
		        resource, namespace, name, deny_reason, status,
		        COALESCE(answer_kind, ''), COALESCE(answer_target, ''),
		        COALESCE(answered_by, ''), COALESCE(answered_at, ''),
		        COALESCE(sync_wait_id, '')
		 FROM pending_prompts
		 WHERE sync_wait_id IS NOT NULL AND status = 'pending'
		 ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("kbounce: list waiting sync prompts: %w", err)
	}
	defer rows.Close()
	candidates := make([]PromptRow, 0, limit)
	for rows.Next() {
		var p PromptRow
		if err := rows.Scan(
			&p.ID, &p.CreatedAt, &p.DecisionID, &p.Verb, &p.Group, &p.Version,
			&p.Resource, &p.Namespace, &p.Name, &p.DenyReason, &p.Status,
			&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt,
			&p.SyncWaitID,
		); err != nil {
			return nil, fmt.Errorf("kbounce: list waiting sync prompts scan: %w", err)
		}
		candidates = append(candidates, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kbounce: list waiting sync prompts iterate: %w", err)
	}
	// Filter to rows whose waiter is still registered. Lock once + read
	// many — the map mutations elsewhere take the same mutex.
	s.syncMu.Lock()
	out := make([]PromptRow, 0, len(candidates))
	for _, p := range candidates {
		if _, ok := s.syncWaiters[p.SyncWaitID]; ok {
			out = append(out, p)
		}
	}
	s.syncMu.Unlock()
	return out, nil
}

// SyncWaiterCount returns the number of in-memory waiters currently
// registered. Test-only helper for leak detection + healthz future use.
func (s *Store) SyncWaiterCount() int {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	return len(s.syncWaiters)
}
