// Bulk-answer state: burst events + profile-reload signal.
//
// Per the [[bulk-prompt-answer-ux]] memo: when the proxy's burst detector
// (internal/proxy/burst.go) trips, it records a row here so the operator's
// next `kbounce prompts bulk-answer` invocation has something to surface.
// The CLI / MCP bulk-answer path then:
//
//   - reads the most-recent unresolved BurstEvent
//   - reads the set of currently-pending prompts
//   - applies the operator's chosen disposition (session / 3h / 10min /
//     profile / none)
//   - calls ResolveBurstEvent to bookend the audit row
//
// The profile-reload-signal table is a single-row cross-process channel:
// the CLI / MCP writes the desired profile name; the running proxy's
// poll loop picks it up + hot-swaps its active-profile pointer (see
// proxy.Server's profile-reload watcher). One row only (CHECK id=1)
// so writes are idempotent overwrites — a second profile switch
// supersedes the first.
//
// Kept in a separate file so the bulk-answer surface is reviewable
// independently of the K-Slice 1/2 store foundation.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BurstEvent is one row from burst_events. Recorded by the proxy's
// burst detector when N pending prompts accumulate within T seconds.
// The CLI / MCP `prompts bulk-answer` flow reads the most-recent
// unresolved row + resolves it after applying the operator's chosen
// disposition.
type BurstEvent struct {
	ID             int64
	DetectedAt     string
	PromptCount    int
	WindowSeconds  int
	ResolvedAt     string // empty while unresolved
	ResolutionKind string // empty while unresolved
}

// Bulk-answer resolution kinds. Stable enum so audit-review tooling +
// the MCP surface can color-code which option fired.
const (
	BulkResolutionSession      = "session"      // until proxy restart
	BulkResolution3h           = "3h"           // 3-hour TTL on resulting rule
	BulkResolution10min        = "10min"        // 10-minute TTL on resulting rule
	BulkResolutionProfile      = "profile"      // operator picked a different profile
	BulkResolutionNone         = "none"         // option (5) — leave pending
	BulkResolutionAutoExpired  = "auto_expired" // never resolved; aged out
)

// IsValidBulkResolution returns true for the canonical resolution
// kinds. Callers (CLI flag parse, MCP tool arg parse) gate on this so
// a typo surfaces eagerly.
func IsValidBulkResolution(kind string) bool {
	switch kind {
	case BulkResolutionSession, BulkResolution3h, BulkResolution10min,
		BulkResolutionProfile, BulkResolutionNone, BulkResolutionAutoExpired:
		return true
	}
	return false
}

// RecordBurstEvent inserts a new BURST_DETECTED row. Returns the new id.
// promptCount + windowSeconds describe the burst the detector observed;
// the row stays in `unresolved` state until a `prompts bulk-answer`
// invocation calls ResolveBurstEvent.
func (s *Store) RecordBurstEvent(promptCount, windowSeconds int) (int64, error) {
	if promptCount <= 0 || windowSeconds <= 0 {
		return 0, fmt.Errorf(
			"kbounce: burst event must have positive prompt_count + window_seconds (got %d, %d)",
			promptCount, windowSeconds)
	}
	res, err := s.db.Exec(
		`INSERT INTO burst_events(detected_at, prompt_count, window_seconds) VALUES (?, ?, ?)`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		promptCount, windowSeconds,
	)
	if err != nil {
		return 0, fmt.Errorf("kbounce: record burst event: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("kbounce: record burst event last insert id: %w", err)
	}
	return id, nil
}

// LatestUnresolvedBurst returns the most recent BURST_DETECTED row whose
// resolved_at is NULL, or (nil, nil) when none exists. Used by the CLI
// + MCP bulk-answer flow to confirm there's a burst to act on before
// prompting the operator.
func (s *Store) LatestUnresolvedBurst() (*BurstEvent, error) {
	row := s.db.QueryRow(
		`SELECT id, detected_at, prompt_count, window_seconds,
		        COALESCE(resolved_at, ''), COALESCE(resolution_kind, '')
		 FROM burst_events
		 WHERE resolved_at IS NULL
		 ORDER BY id DESC LIMIT 1`,
	)
	var b BurstEvent
	err := row.Scan(&b.ID, &b.DetectedAt, &b.PromptCount, &b.WindowSeconds,
		&b.ResolvedAt, &b.ResolutionKind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kbounce: latest unresolved burst: %w", err)
	}
	return &b, nil
}

// ListRecentBurstEvents returns burst events newest-first (resolved or
// not). Default limit when <=0: 20; capped at 1000. Surfaced by the
// audit-review CLI + MCP introspection tool.
func (s *Store) ListRecentBurstEvents(limit int) ([]BurstEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 1000 {
		limit = 1000
	}
	rs, err := s.db.Query(
		`SELECT id, detected_at, prompt_count, window_seconds,
		        COALESCE(resolved_at, ''), COALESCE(resolution_kind, '')
		 FROM burst_events ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("kbounce: list recent burst events: %w", err)
	}
	defer rs.Close()
	out := make([]BurstEvent, 0, limit)
	for rs.Next() {
		var b BurstEvent
		if err := rs.Scan(&b.ID, &b.DetectedAt, &b.PromptCount, &b.WindowSeconds,
			&b.ResolvedAt, &b.ResolutionKind); err != nil {
			return nil, fmt.Errorf("kbounce: list recent burst events scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("kbounce: list recent burst events iterate: %w", err)
	}
	return out, nil
}

// ResolveBurstEvent stamps resolved_at + resolution_kind on a burst row.
// Returns true when a row was updated (i.e. the burst existed + was
// still unresolved). Idempotent on already-resolved rows (returns false
// without erroring) so two racing bulk-answer calls don't trip on
// each other.
func (s *Store) ResolveBurstEvent(id int64, resolutionKind string) (bool, error) {
	if !IsValidBulkResolution(resolutionKind) {
		return false, fmt.Errorf(
			"kbounce: unknown bulk resolution kind %q (want session|3h|10min|profile|none|auto_expired)",
			resolutionKind)
	}
	res, err := s.db.Exec(
		`UPDATE burst_events SET resolved_at = ?, resolution_kind = ?
		 WHERE id = ? AND resolved_at IS NULL`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		resolutionKind, id,
	)
	if err != nil {
		return false, fmt.Errorf("kbounce: resolve burst event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("kbounce: resolve burst event rows affected: %w", err)
	}
	return n > 0, nil
}

// PromptAnswerKindBulk is the answer_kind written on pending_prompts
// when a bulk-answer call applies. Distinct from always/profile/ignore
// so audit review can isolate "this prompt was bulk-resolved" vs
// "this prompt was individually answered." answer_target carries the
// resolution kind (session / 3h / ...) for the same reason.
const PromptAnswerKindBulk = "bulk"

// BulkAnswerPendingPrompts marks every currently-pending prompt as
// answered with kind=bulk + target=resolutionKind. Returns the count
// of rows actually flipped (rows that raced into 'answered' between
// the operator's list-pending + the call here are NOT counted; ok).
//
// Resolves in-process sync waiters too: any pending_prompts row with a
// non-empty sync_wait_id has its waiter woken with the appropriate
// PromptDecision (Allow=true for session/3h/10min/profile, Allow=false
// for none/auto_expired). Mirrors the AnswerPendingPrompt one-shot
// wake semantics so the proxy goroutines that were blocked on sync
// answers don't hang when the operator chose bulk-allow.
//
// Wraps a single UPDATE — SQLite serializes writes per-DB; no explicit
// transaction needed. The wake fan-out is best-effort (per
// wakeSyncWaiter contract).
func (s *Store) BulkAnswerPendingPrompts(resolutionKind, actor string) (int64, error) {
	if !IsValidBulkResolution(resolutionKind) {
		return 0, fmt.Errorf(
			"kbounce: unknown bulk resolution kind %q", resolutionKind)
	}
	// Collect sync waiters BEFORE the UPDATE so the row read sees them
	// while status is still 'pending' (the UPDATE flips status).
	rs, err := s.db.Query(
		`SELECT COALESCE(sync_wait_id, '') FROM pending_prompts
		 WHERE status = 'pending' AND sync_wait_id IS NOT NULL`,
	)
	if err != nil {
		return 0, fmt.Errorf("kbounce: collect sync waiters for bulk: %w", err)
	}
	waiters := make([]string, 0, 8)
	for rs.Next() {
		var wid string
		if err := rs.Scan(&wid); err != nil {
			rs.Close()
			return 0, fmt.Errorf("kbounce: scan sync waiter: %w", err)
		}
		if wid != "" {
			waiters = append(waiters, wid)
		}
	}
	rs.Close()

	res, err := s.db.Exec(
		`UPDATE pending_prompts SET status = 'answered',
		        answer_kind = ?, answer_target = ?, answered_by = ?, answered_at = ?
		 WHERE status = 'pending'`,
		PromptAnswerKindBulk, resolutionKind, actor,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	)
	if err != nil {
		return 0, fmt.Errorf("kbounce: bulk answer pending prompts: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("kbounce: bulk answer rows affected: %w", err)
	}
	// Wake any sync waiters. Allow = true for the dispositions that
	// install a permissive rule (or hot-swap a broader profile); false
	// for none / auto_expired (the original 403 stands).
	allow := false
	switch resolutionKind {
	case BulkResolutionSession, BulkResolution3h, BulkResolution10min, BulkResolutionProfile:
		allow = true
	}
	decision := PromptDecision{
		Allow:      allow,
		Kind:       PromptAnswerKindBulk,
		AnsweredBy: actor,
	}
	for _, wid := range waiters {
		s.wakeSyncWaiter(wid, decision)
	}
	return n, nil
}

// PendingPromptShape is the (verb, resource) tuple a bulk-allow rule
// covers. Used by SnapshotPendingPromptShapes so the bulk-answer flow
// knows what rules to install + so the audit row can carry the union
// of observed verbs+resources from the burst window.
type PendingPromptShape struct {
	Verb     string
	Resource string
	Count    int
}

// SnapshotPendingPromptShapes returns the deduplicated (verb, resource)
// tuples observed across all currently-pending prompts. The bulk-answer
// flow uses this to install one time-bounded ALLOW rule per tuple. Empty
// slice when nothing is pending.
//
// Ordering: most-frequent first (so audit log + UI surfaces the
// dominant burst pattern at the top); tiebreak by (verb, resource)
// for determinism in tests.
func (s *Store) SnapshotPendingPromptShapes() ([]PendingPromptShape, error) {
	rs, err := s.db.Query(
		`SELECT COALESCE(verb, ''), COALESCE(resource, ''), COUNT(*)
		 FROM pending_prompts
		 WHERE status = 'pending'
		 GROUP BY verb, resource
		 ORDER BY COUNT(*) DESC, verb, resource`,
	)
	if err != nil {
		return nil, fmt.Errorf("kbounce: snapshot pending prompt shapes: %w", err)
	}
	defer rs.Close()
	out := make([]PendingPromptShape, 0, 8)
	for rs.Next() {
		var sh PendingPromptShape
		if err := rs.Scan(&sh.Verb, &sh.Resource, &sh.Count); err != nil {
			return nil, fmt.Errorf("kbounce: snapshot scan: %w", err)
		}
		// Skip rows where the parser produced no verb / resource — a
		// bulk rule with pattern ":" is invalid; the operator can still
		// drop the prompts via BulkResolutionNone.
		if sh.Verb == "" || sh.Resource == "" {
			continue
		}
		out = append(out, sh)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("kbounce: snapshot iterate: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// profile_reload_signal — cross-process channel for the profile-switch
// bulk-answer option.
// ---------------------------------------------------------------------------

// ProfileReloadSignal is the row from profile_reload_signal. The proxy's
// reload watcher polls GetProfileReloadSignal on a low cadence; when the
// requested_at > the last-applied timestamp it hot-swaps + calls
// AckProfileReloadSignal.
type ProfileReloadSignal struct {
	ProfileName string
	RequestedAt string
	RequestedBy string
	AppliedAt   string // empty until the proxy has picked it up
}

// SetProfileReloadSignal writes (upserts) the single profile_reload_signal
// row. Returns nil on success. The running proxy's reload watcher polls
// GetProfileReloadSignal + hot-swaps when it sees an unacked request.
//
// Idempotent: writing the same profile name twice in a row is harmless
// (the second write resets requested_at, which is what we want — the
// proxy sees a fresh request).
func (s *Store) SetProfileReloadSignal(profileName, requestedBy string) error {
	if profileName == "" {
		return errors.New("kbounce: SetProfileReloadSignal: profile_name required")
	}
	_, err := s.db.Exec(
		`INSERT INTO profile_reload_signal(id, profile_name, requested_at, requested_by, applied_at)
		 VALUES (1, ?, ?, ?, NULL)
		 ON CONFLICT(id) DO UPDATE SET
		   profile_name = excluded.profile_name,
		   requested_at = excluded.requested_at,
		   requested_by = excluded.requested_by,
		   applied_at   = NULL`,
		profileName,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		requestedBy,
	)
	if err != nil {
		return fmt.Errorf("kbounce: set profile reload signal: %w", err)
	}
	return nil
}

// GetProfileReloadSignal returns the current signal row, or (nil, nil)
// when none exists.
func (s *Store) GetProfileReloadSignal() (*ProfileReloadSignal, error) {
	row := s.db.QueryRow(
		`SELECT profile_name, requested_at, requested_by, COALESCE(applied_at, '')
		 FROM profile_reload_signal WHERE id = 1`,
	)
	var p ProfileReloadSignal
	err := row.Scan(&p.ProfileName, &p.RequestedAt, &p.RequestedBy, &p.AppliedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kbounce: get profile reload signal: %w", err)
	}
	return &p, nil
}

// AckProfileReloadSignal stamps applied_at on the current signal row so
// the proxy's reload watcher doesn't re-fire on the same request. Safe
// to call when no row exists (no-op).
func (s *Store) AckProfileReloadSignal() error {
	_, err := s.db.Exec(
		`UPDATE profile_reload_signal SET applied_at = ? WHERE id = 1 AND applied_at IS NULL`,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	)
	if err != nil {
		return fmt.Errorf("kbounce: ack profile reload signal: %w", err)
	}
	return nil
}
