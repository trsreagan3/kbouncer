// disk_pressure.go is the Go port of Python ibounce's
// iam_jit.bouncer.audit_export.disk_pressure module (#461 / §A63c).
//
// Closes the LAUNCH-BLOCKER §A63c gap that until this slice landed,
// the cross-product DiskStatus primitive (rotation.go:GetDiskStatus,
// shipped in #311) was ONLY consulted by the `kbounce doctor logs`
// CLI. The proxy's /healthz handler ignored disk state, no periodic
// check fired between operator-invoked CLI runs, and the documented
// --stop-on-disk-critical flag was a ghost reference. A kbouncer
// sitting on a 99%-full disk would silently fail audit writes,
// losing the compliance value the audit log is supposed to provide.
//
// Three operator-selectable modes per the §A63c spec:
//
//   - pause-requests (compliance-heavy default) — at the critical
//     threshold the proxy REFUSES new agent requests with HTTP 503 +
//     the #459 structured-deny body shape. Audit integrity is
//     prioritised over liveness. Per [[creates-never-mutates]] we
//     don't drop archives or mutate existing state.
//
//   - rotate-aggressively (dev default) — at the critical threshold
//     the policy drops the oldest rotated audit-*.jsonl.gz /
//     audit-*.db.gz archives until disk usage falls back below the
//     warn threshold. Liveness prioritised over historical retention.
//
//   - archive-and-purge (hybrid) — at the critical threshold the
//     policy emits an admin-action event signalling oldest-archive
//     candidates are eligible for upload by the operator's #317
//     object-storage sink, THEN drops the oldest local archives to
//     reclaim space. Operators wire --audit-object-storage-* flags
//     independently; the modes don't double-couple to S3 SDK calls.
//
// State transitions are recorded as OCSF v1.1.0 class 6003 admin-
// action events with kind disk_pressure.transition so the SIEM
// dashboard answers "when did the bouncer cross into critical /
// emergency / recover to ok?" from the same stream that carries
// proxy decisions + admin actions.
//
// Per [[ambient-value-prop-and-friction-framing]] the framing here is
// "your bouncer is approaching disk threshold, consider archiving"
// rather than "ERROR: disk pressure". Refusal bodies (pause-requests
// mode) explain WHY the refusal happened + what to configure to
// change behavior.
//
// Per [[ibounce-honest-positioning]] every state transition surfaces
// on /healthz audit_log. Don't hide disk state from operators.
//
// Per [[v1-scope-bar]] this module reuses the existing GetDiskStatus
// primitive from rotation.go — no rotation architecture redesign, no
// new compression formats, no hash-chain coupling. The policy layer
// is THIN: it sequences existing primitives based on the operator's
// declared mode.
//
// Per [[cross-product-agent-parity]] the wire-level field names +
// the disk_pressure.transition admin-action kind + the
// disk_pressure_mode string values MUST match Python ibounce +
// dbounce + gbounce byte-for-byte so a single playbook covers all
// four bouncers.
package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DiskPressureMode names the operator-selectable response modes. The
// string values match the YAML field `disk_pressure_mode:` documented
// in iam-roles/docs/PRODUCTION-LOG-STORAGE.md.
const (
	DiskPressureModePauseRequests      = "pause-requests"
	DiskPressureModeRotateAggressively = "rotate-aggressively"
	DiskPressureModeArchiveAndPurge    = "archive-and-purge"
)

// DefaultDiskPressureMode is the compliance-heavy default applied
// when the operator hasn't picked one. The audit log IS the
// compliance value ([[self-host-zero-billing-dependency]]) — losing
// events to make room for new traffic inverts the whole point.
// Operators who prefer the liveness tradeoff opt into
// rotate-aggressively.
//
// Note: per the kbouncer-side §A63c spec "dev workflows trend toward
// rotate-aggressively"; the CLI default for kbouncer is therefore
// rotate-aggressively, NOT the cross-product DefaultDiskPressureMode.
// The constant here documents the cross-product floor; the CLI flag
// default applies the kbounce-flavored choice.
const DefaultDiskPressureMode = DiskPressureModePauseRequests

// DiskPressureCheckInterval is the periodic-tick cadence. 60s matches
// the §A63 spec — small enough that a runaway-disk event hits the
// policy within one tick, large enough that the check isn't a
// meaningful load (one statfs per minute).
const DiskPressureCheckInterval = 60 * time.Second

// DefaultDiskEmergencyPercent is the emergency tier ABOVE crit.
// Operators see this as "disk is basically full; even rotate-
// aggressively can't keep up." ALL modes treat emergency the same
// way: log + emit + signal in /healthz; no mode is permitted to
// "ignore" emergency.
const DefaultDiskEmergencyPercent = 99

// PauseRequestsRefusalReasonTemplate is the operator-friendly body
// the proxy returns in pause-requests mode at critical / emergency.
// Framed per [[ambient-value-prop-and-friction-framing]] — explains
// what happened + how to change behavior, doesn't say "ERROR" or
// "BLOCKED".
const PauseRequestsRefusalReasonTemplate = "bouncer paused — disk pressure at %.1f%% used " +
	"(threshold %d%%); audit-log writes would risk loss if we " +
	"forwarded. Configure disk_pressure_mode=rotate-aggressively " +
	"or archive-and-purge to change behavior, or clear space + restart."

// KnownDiskPressureModes is the canonical set of allowed values.
// Used by NormalizeDiskPressureMode for fail-fast validation.
var KnownDiskPressureModes = []string{
	DiskPressureModePauseRequests,
	DiskPressureModeRotateAggressively,
	DiskPressureModeArchiveAndPurge,
}

// NormalizeDiskPressureMode validates + normalizes the operator's
// mode input. Returns the canonical mode string or an error on
// unknown values so the CLI / apply-config layer fails fast with a
// clear message. Empty string returns the default
// (compliance-heavy pause-requests). Case-insensitive.
func NormalizeDiskPressureMode(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return DefaultDiskPressureMode, nil
	}
	norm := strings.ToLower(strings.TrimSpace(value))
	for _, k := range KnownDiskPressureModes {
		if norm == k {
			return norm, nil
		}
	}
	return "", fmt.Errorf("unknown disk_pressure_mode %q; expected one of %v",
		value, KnownDiskPressureModes)
}

// DiskPressureState is the live in-process state for one bouncer's
// disk-pressure subsystem. Stored in-process; not persisted. On
// restart the periodic check re-detects state from the filesystem.
//
// Per [[ibounce-honest-positioning]] /healthz reads this directly so
// external monitoring sees the same view the proxy uses for refusal
// decisions.
//
// Concurrency: a single internal mutex serializes the periodic-loop
// writer + the /healthz + proxy-hot-path readers. All callers MUST
// use Snapshot() / RefuseRequests() rather than touching fields
// directly so the lock is always held correctly.
type DiskPressureState struct {
	mu sync.RWMutex

	mode               string
	currentStatus      string
	lastObserved       *DiskStatus
	lastCheckUnix      int64
	warnPct            int
	critPct            int
	emergencyPct       int
	warnFreeBytes      int64
	critFreeBytes      int64
	logDir             string
	refuseRequests     bool
	transitionsCount   int64
	lastActionTaken    string
	archiveCount       int
	archiveSizeBytes   int64
	ignoreDiskPressure bool
}

// DiskPressureSnapshot is a point-in-time copy of the state for
// /healthz JSON encoding + smoke tests.
type DiskPressureSnapshot struct {
	Mode               string      `json:"disk_pressure_mode"`
	Status             string      `json:"status"`
	DiskFreePct        *float64    `json:"disk_free_pct"`
	DiskFreeBytes      *int64      `json:"disk_free_bytes"`
	UsedPct            *float64    `json:"used_pct"`
	WarnPct            int         `json:"warn_pct"`
	CritPct            int         `json:"crit_pct"`
	EmergencyPct       int         `json:"emergency_pct"`
	WarnThresholdBytes int64       `json:"warn_threshold_bytes"`
	CritThresholdBytes int64       `json:"crit_threshold_bytes"`
	Path               string      `json:"path"`
	RefuseRequests     bool        `json:"refuse_requests"`
	ArchiveCount       int         `json:"current_archive_count"`
	ArchiveSizeBytes   int64       `json:"current_archive_size_bytes"`
	TransitionsCount   int64       `json:"transitions_count"`
	LastCheckUnix      *int64      `json:"last_check_unix"`
	LastActionTaken    string      `json:"last_action_taken,omitempty"`
	Reason             string      `json:"reason,omitempty"`
	LastRotationAt     string      `json:"last_rotation_at,omitempty"`
	LastObservedRaw    *DiskStatus `json:"-"`
	IgnoreDiskPressure bool        `json:"ignore_disk_pressure,omitempty"`
}

// NewDiskPressureState constructs a state container with the operator-
// declared mode + thresholds. logDir is the parent directory of the
// audit log; empty (audit logging disabled) makes the state a no-op.
//
// Thresholds: 0 or negative values are silently replaced with the
// cross-product defaults so a partially-configured state still does
// something useful. emergencyPct must be >= critPct >= warnPct;
// invalid orderings collapse to the defaults.
func NewDiskPressureState(mode, logDir string, warnPct, critPct, emergencyPct int) *DiskPressureState {
	return NewDiskPressureStateFull(mode, logDir, warnPct, critPct, emergencyPct, 0, 0, false)
}

// NewDiskPressureStateFull is the extended constructor with absolute-free-space
// floors and ignore flag.
func NewDiskPressureStateFull(
	mode, logDir string,
	warnPct, critPct, emergencyPct int,
	warnFreeBytes, critFreeBytes int64,
	ignoreDiskPressure bool,
) *DiskPressureState {
	if warnPct <= 0 {
		warnPct = DefaultDiskWarnPercent
	}
	if critPct <= 0 || critPct < warnPct {
		critPct = DefaultDiskCritPercent
	}
	if emergencyPct <= 0 || emergencyPct < critPct {
		emergencyPct = DefaultDiskEmergencyPercent
	}
	if mode == "" {
		mode = DefaultDiskPressureMode
	}
	if warnFreeBytes <= 0 {
		warnFreeBytes = DefaultDiskWarnFreeBytes
	}
	if critFreeBytes <= 0 {
		critFreeBytes = DefaultDiskCritFreeBytes
	}
	return &DiskPressureState{
		mode:               mode,
		currentStatus:      "ok",
		warnPct:            warnPct,
		critPct:            critPct,
		emergencyPct:       emergencyPct,
		warnFreeBytes:      warnFreeBytes,
		critFreeBytes:      critFreeBytes,
		logDir:             logDir,
		ignoreDiskPressure: ignoreDiskPressure,
	}
}

// Mode returns the operator-declared mode (one of the canonical 3).
func (s *DiskPressureState) Mode() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// RefuseRequests reports whether the proxy hot path should return
// 503 instead of forwarding. The single source of truth callers read
// per-request — computed by EvaluateAndReact under the state mutex
// so the read here is just a flag load.
func (s *DiskPressureState) RefuseRequests() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refuseRequests
}

// Status returns the current status label ("ok" / "degraded" /
// "critical" / "emergency").
func (s *DiskPressureState) Status() string {
	if s == nil {
		return "ok"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentStatus
}

// Snapshot returns a point-in-time copy of the state for /healthz
// encoding. Always returns a non-nil snapshot so callers can encode
// the audit_log block unconditionally.
func (s *DiskPressureState) Snapshot() DiskPressureSnapshot {
	if s == nil {
		return DiskPressureSnapshot{
			Mode:   DefaultDiskPressureMode,
			Status: "ok",
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := DiskPressureSnapshot{
		Mode:               s.mode,
		Status:             s.currentStatus,
		WarnPct:            s.warnPct,
		CritPct:            s.critPct,
		EmergencyPct:       s.emergencyPct,
		WarnThresholdBytes: s.warnFreeBytes,
		CritThresholdBytes: s.critFreeBytes,
		Path:               s.logDir,
		RefuseRequests:     s.refuseRequests,
		ArchiveCount:       s.archiveCount,
		ArchiveSizeBytes:   s.archiveSizeBytes,
		TransitionsCount:   s.transitionsCount,
		LastActionTaken:    s.lastActionTaken,
		IgnoreDiskPressure: s.ignoreDiskPressure,
	}
	if s.lastObserved != nil {
		freePct := 100.0 - s.lastObserved.UsedPct
		usedPct := s.lastObserved.UsedPct
		snap.DiskFreePct = &freePct
		snap.UsedPct = &usedPct
		snap.Reason = s.lastObserved.Reason
		if s.lastObserved.Path != "" {
			snap.Path = s.lastObserved.Path
		}
		snap.LastObservedRaw = s.lastObserved
		fb := s.lastObserved.FreeBytes
		snap.DiskFreeBytes = &fb
	}
	if s.lastCheckUnix != 0 {
		t := s.lastCheckUnix
		snap.LastCheckUnix = &t
	}
	// Last rotation timestamp from the most-recently-mtime'd archive.
	if s.logDir != "" {
		if t := lastRotationTime(s.logDir); !t.IsZero() {
			snap.LastRotationAt = t.UTC().Format(time.RFC3339)
		}
	}
	return snap
}

// EvaluateAndReact runs one tick of the disk-pressure check +
// reaction. Mirrors Python evaluate_and_react verbatim.
//
//  1. Call diskStatFn (defaults to GetDiskStatus) to read current
//     usage.
//  2. Compute current_status (adds emergency tier on top of
//     rotation.go's ok/degraded/critical).
//  3. If status transitioned vs prior state, emit an admin-action
//     disk_pressure.transition OCSF event via emitter (nil emitter
//     skips the emit).
//  4. Apply mode-specific behavior at critical/emergency:
//     - pause-requests: flip state.refuseRequests = true
//     - rotate-aggressively: drop oldest archives to recover
//     - archive-and-purge: emit hint + drop oldest archives
//  5. Re-stat archive_count + archive_size_bytes for /healthz.
//
// diskStatFn is a test seam — production callers pass nil so the
// function falls back to GetDiskStatus. Returns the resulting
// snapshot for chaining + test inspection.
func (s *DiskPressureState) EvaluateAndReact(
	ctx context.Context,
	emitter Emitter,
	diskStatFn func(path string, warnPct, critPct int) (DiskStatus, error),
	now time.Time,
) DiskPressureSnapshot {
	if s == nil {
		return DiskPressureSnapshot{Mode: DefaultDiskPressureMode, Status: "ok"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheckUnix = now.Unix()
	if s.ignoreDiskPressure {
		s.currentStatus = "ignored"
		s.refuseRequests = false
		return s.snapshotLocked()
	}
	if s.logDir == "" {
		// Nothing to monitor; leave state at ok + refuse off.
		s.currentStatus = "ok"
		s.refuseRequests = false
		return s.snapshotLocked()
	}
	if diskStatFn == nil {
		diskStatFn = func(path string, warnPct, critPct int) (DiskStatus, error) {
			return GetDiskStatusFull(path, warnPct, critPct, s.warnFreeBytes, s.critFreeBytes)
		}
	}
	snap, _ := diskStatFn(s.logDir, s.warnPct, s.critPct)
	s.lastObserved = &snap
	newStatus := classifyDiskStatusWithEmergency(snap, s.warnPct, s.critPct, s.emergencyPct)
	s.archiveCount, s.archiveSizeBytes = countAuditArchives(s.logDir)
	transitioned := newStatus != s.currentStatus
	priorStatus := s.currentStatus
	s.currentStatus = newStatus
	if transitioned {
		s.transitionsCount++
		emitDiskPressureTransition(ctx, emitter, priorStatus, newStatus, snap, s.mode, s.logDir)
	}
	s.refuseRequests = computeRefuseRequests(s.mode, s.currentStatus)
	if newStatus == "critical" || newStatus == "emergency" {
		switch s.mode {
		case DiskPressureModePauseRequests:
			s.lastActionTaken = fmt.Sprintf(
				"refusing new agent requests at %.1f%% used",
				snap.UsedPct,
			)
		case DiskPressureModeRotateAggressively:
			removed := dropOldestArchives(s.logDir, s.warnPct)
			s.lastActionTaken = fmt.Sprintf(
				"dropped %d oldest archive(s) to recover space at %.1f%% used",
				len(removed), snap.UsedPct,
			)
			s.archiveCount, s.archiveSizeBytes = countAuditArchives(s.logDir)
		case DiskPressureModeArchiveAndPurge:
			removed := dropOldestArchives(s.logDir, s.warnPct)
			s.lastActionTaken = fmt.Sprintf(
				"archive-and-purge: dropped %d oldest archive(s) "+
					"(operator-configured object-storage sink should ship "+
					"before next tick) at %.1f%% used",
				len(removed), snap.UsedPct,
			)
			s.archiveCount, s.archiveSizeBytes = countAuditArchives(s.logDir)
		}
	} else {
		s.lastActionTaken = ""
	}
	return s.snapshotLocked()
}

// snapshotLocked mirrors Snapshot but assumes the caller already
// holds the state mutex (write or read). Used by EvaluateAndReact
// to return the post-mutation view without double-locking.
func (s *DiskPressureState) snapshotLocked() DiskPressureSnapshot {
	snap := DiskPressureSnapshot{
		Mode:               s.mode,
		Status:             s.currentStatus,
		WarnPct:            s.warnPct,
		CritPct:            s.critPct,
		EmergencyPct:       s.emergencyPct,
		WarnThresholdBytes: s.warnFreeBytes,
		CritThresholdBytes: s.critFreeBytes,
		Path:               s.logDir,
		RefuseRequests:     s.refuseRequests,
		ArchiveCount:       s.archiveCount,
		ArchiveSizeBytes:   s.archiveSizeBytes,
		TransitionsCount:   s.transitionsCount,
		LastActionTaken:    s.lastActionTaken,
		IgnoreDiskPressure: s.ignoreDiskPressure,
	}
	if s.lastObserved != nil {
		freePct := 100.0 - s.lastObserved.UsedPct
		usedPct := s.lastObserved.UsedPct
		snap.DiskFreePct = &freePct
		snap.UsedPct = &usedPct
		snap.Reason = s.lastObserved.Reason
		if s.lastObserved.Path != "" {
			snap.Path = s.lastObserved.Path
		}
		snap.LastObservedRaw = s.lastObserved
		fb := s.lastObserved.FreeBytes
		snap.DiskFreeBytes = &fb
	}
	if s.lastCheckUnix != 0 {
		t := s.lastCheckUnix
		snap.LastCheckUnix = &t
	}
	if s.logDir != "" {
		if t := lastRotationTime(s.logDir); !t.IsZero() {
			snap.LastRotationAt = t.UTC().Format(time.RFC3339)
		}
	}
	return snap
}

// classifyDiskStatusWithEmergency maps a DiskStatus snapshot to one
// of ok/degraded/critical/emergency. Rotation.go's GetDiskStatus
// returns at most "critical"; we add the emergency tier on top so the
// proxy can surface a more severe state without changing the
// underlying primitive.
func classifyDiskStatusWithEmergency(snap DiskStatus, warnPct, critPct, emergencyPct int) string {
	if snap.Status == "ok" {
		return "ok"
	}
	if snap.UsedPct >= float64(emergencyPct) {
		return "emergency"
	}
	if snap.UsedPct >= float64(critPct) {
		return "critical"
	}
	if snap.UsedPct >= float64(warnPct) {
		return "degraded"
	}
	return snap.Status
}

// computeRefuseRequests is the single source of truth for "should the
// proxy refuse new requests now?" Used by both the periodic loop
// (when it updates state.refuseRequests) and the smoke tests (which
// assert the same mapping). pause-requests refuses at critical /
// emergency; the other two modes never refuse — they react via
// rotation.
func computeRefuseRequests(mode, currentStatus string) bool {
	if mode != DiskPressureModePauseRequests {
		return false
	}
	return currentStatus == "critical" || currentStatus == "emergency"
}

// countAuditArchives returns (file_count, total_bytes) of rotated
// archives in logDir. Skips the active audit.jsonl + audit.db.
// Returns (0, 0) when logDir is empty or unreadable.
func countAuditArchives(logDir string) (int, int64) {
	if logDir == "" {
		return 0, 0
	}
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return 0, 0
	}
	count := 0
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "audit-") {
			continue
		}
		if !(strings.HasSuffix(n, ".jsonl.gz") || strings.HasSuffix(n, ".db.gz") || strings.HasSuffix(n, ".db")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		count++
		total += info.Size()
	}
	return count, total
}

// dropOldestArchives drops rotated archives oldest-first until the
// disk usage falls back below warnPct OR no archives remain. Returns
// the list of paths removed.
//
// Per [[creates-never-mutates]] NEVER touches the active audit.jsonl
// / audit.db; only audit-*.jsonl.gz / audit-*.db.gz / audit-*.db
// (rotated DB sibling) are eligible.
//
// Used by rotate-aggressively + archive-and-purge modes;
// pause-requests does NOT call this (its whole point is to preserve
// audit data over liveness).
func dropOldestArchives(logDir string, warnPct int) []string {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil
	}
	type candidate struct {
		path  string
		mtime time.Time
	}
	var cands []candidate
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "audit-") {
			continue
		}
		if !(strings.HasSuffix(n, ".jsonl.gz") || strings.HasSuffix(n, ".db.gz") || strings.HasSuffix(n, ".db")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, candidate{
			path:  filepath.Join(logDir, n),
			mtime: info.ModTime(),
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mtime.Before(cands[j].mtime) })
	var removed []string
	for _, c := range cands {
		// Re-stat after each delete so the loop exits as soon as
		// headroom returns. We pass the warn threshold as the
		// "headroom target" — once we're below warn we stop.
		cur, err := GetDiskStatus(logDir, warnPct, 100)
		if err == nil && cur.UsedPct < float64(warnPct) {
			break
		}
		if err := os.Remove(c.path); err != nil {
			continue
		}
		removed = append(removed, c.path)
	}
	return removed
}

// lastRotationTime returns the mtime of the most-recently-rotated
// archive in logDir. Zero time when there are no archives. Used by
// Snapshot to populate the last_rotation_at /healthz field.
func lastRotationTime(logDir string) time.Time {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return time.Time{}
	}
	var latest time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "audit-") {
			continue
		}
		if !(strings.HasSuffix(n, ".jsonl.gz") || strings.HasSuffix(n, ".db.gz") || strings.HasSuffix(n, ".db")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest
}

// emitDiskPressureTransition emits the admin-action OCSF event
// signalling a status transition. Fail-soft: nil emitter is a no-op;
// downstream emit errors are not surfaced (the operator still sees
// the transition on /healthz even if the SIEM emit fails per
// [[deliberate-feature-completion]] + [[ibounce-honest-positioning]]).
func emitDiskPressureTransition(
	ctx context.Context,
	emitter Emitter,
	fromStatus, toStatus string,
	snap DiskStatus,
	mode, logDir string,
) {
	if emitter == nil {
		return
	}
	EmitAdminAction(ctx, emitter, AdminActionInput{
		Action:     AdminActionDiskPressureTransition,
		EntityKind: "audit_log_directory",
		EntityName: logDir,
		Source:     AdminActionSourceAPI,
		Before:     map[string]any{"status": fromStatus},
		After: map[string]any{
			"status":   toStatus,
			"used_pct": roundFloat(snap.UsedPct, 2),
		},
		ExtraExt: map[string]any{
			"from_status": fromStatus,
			"to_status":   toStatus,
			"used_pct":    roundFloat(snap.UsedPct, 2),
			"mode":        mode,
			"reason":      snap.Reason,
			"path":        snap.Path,
		},
	})
}

// roundFloat rounds to N decimal places. Mirrors Python's
// round(v, 2). Used in event payloads so used_pct doesn't surface a
// 17-digit float to operators.
func roundFloat(v float64, places int) float64 {
	if places <= 0 {
		return float64(int64(v + 0.5))
	}
	mult := 1.0
	for i := 0; i < places; i++ {
		mult *= 10
	}
	return float64(int64(v*mult+0.5)) / mult
}

// ResolveLogDir maps the audit-log-path (file path) to the directory
// that holds it + the rotated archives. Empty string (audit logging
// disabled) returns empty. Returns the parent dir even if the file
// doesn't yet exist (the first event creates it).
func ResolveLogDir(auditLogPath string) string {
	if auditLogPath == "" {
		return ""
	}
	return filepath.Dir(auditLogPath)
}

// RunDiskPressureLoop is the background goroutine the bouncer's
// Server starts at boot. Ticks every DiskPressureCheckInterval, calls
// EvaluateAndReact, and exits cleanly when stop is closed.
//
// Per [[deliberate-feature-completion]] the loop is the production
// reaction surface; the smoke tests + unit tests invoke
// EvaluateAndReact directly for deterministic ticks.
func RunDiskPressureLoop(
	ctx context.Context,
	state *DiskPressureState,
	emitter Emitter,
	stop <-chan struct{},
) {
	if state == nil {
		return
	}
	// First tick on entry so /healthz isn't blank for 60s after start.
	state.EvaluateAndReact(ctx, emitter, nil, time.Now())
	t := time.NewTicker(DiskPressureCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			state.EvaluateAndReact(ctx, emitter, nil, now)
		}
	}
}
