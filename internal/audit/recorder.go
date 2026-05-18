// Package audit — per-session NDJSON recording (#285).
//
// Recording captures every audit event into a per-session file at
// {dir}/{agent.session_id}.ndjson. The format is identical across the
// four Bounce products (ibounce / kbounce / dbounce / gbounce) so the
// cross-product `iam-jit session replay <FILE>` CLI consumes any
// product's recordings uniformly per [[cross-product-agent-parity]].
//
// File layout:
//
//	first line: `{"_meta": {...}}` header carrying recording_schema_
//	            version, session_id, agent_name, bouncer_product,
//	            recording_started_at.
//	remaining:  one OCSF event per line, append-only.
//
// File suffix is `.ndjson.partial` while the session is in-flight; the
// recorder renames atomically to `.ndjson` on a clean Close OR on the
// heartbeat-timeout finalisation tick. SIGKILL leaves a `.partial`; the
// next Start() finalises any stale `.partial` older than the heartbeat
// timeout.
//
// File mode is 0o600 — recordings carry agent identity + operation
// details and must not be world-readable.
//
// Per [[creates-never-mutates]] the recorder is additive: it tees the
// existing event stream and writes a flat NDJSON file. Per [[self-host-
// zero-billing-dependency]] there are no network calls; entirely local
// filesystem.
package audit

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RecordingSchemaVersion is bumped when the on-disk shape changes in a
// way that older replay CLIs can't consume. The `_meta` header carries
// this value so the replay CLI can surface a clear error rather than
// silently ignoring unknown fields.
const RecordingSchemaVersion = "1.0"

// RecordingPartialSuffix marks an in-flight recording. The recorder
// renames atomically (drops the suffix) on a clean stop OR on heartbeat-
// timeout finalisation.
const RecordingPartialSuffix = ".partial"

// RecordingFileMode — owner read+write only. Recording files carry
// agent identity + operation details; treat as sensitive by default.
const RecordingFileMode = 0o600

// DefaultRecorderHeartbeatTimeout matches the Python recorder's 5-min
// session-idle threshold. Sessions whose last event is older than this
// are considered ended and their `.partial` files are renamed.
const DefaultRecorderHeartbeatTimeout = 5 * time.Minute

// sessionIDRe is the validator for session_id filenames. UUIDs +
// dashes + alphanumerics only — defence in depth against an event
// whose `agent.session_id` got mangled upstream from letting us write
// outside the recording dir.
var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// IsValidSessionID reports whether the given string is a safe filename
// fragment for use as a recording-file name.
func IsValidSessionID(s string) bool {
	return sessionIDRe.MatchString(s)
}

// ExtractSessionID pulls the agent.session_id out of an Event.
// Returns "" when the event has no agent block, no session id, or a
// session id that fails validation.
func ExtractSessionID(ev Event) string {
	if ev.Unmapped.IAMJIT.Agent == nil {
		return ""
	}
	sid := ev.Unmapped.IAMJIT.Agent.SessionID
	if !IsValidSessionID(sid) {
		return ""
	}
	return sid
}

// SessionRecorder tees every audit event to a per-session NDJSON
// file. Default off; only constructed when the operator passes
// `--record-sessions-dir`. The Manager's Emit fans every event to the
// recorder (when wired) alongside the JSONL log + webhook channels.
//
// SessionRecorder is goroutine-safe: a single recorder instance handles
// concurrent Emit calls from the proxy hot-path; per-session file fds
// are protected by an internal mutex. The implementation is deliberately
// synchronous (one write per event, no queue) because the on-disk
// append is fast and per-session files mean no cross-session
// serialization is required.
type SessionRecorder struct {
	dir              string
	bouncerProduct   string
	heartbeatTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*recorderSession

	// Stats — mirrors LogWriter's Status() shape so callers reading
	// `kbounce audit-export status` can see recorder health uniformly.
	total          atomic.Int64
	dropped        atomic.Int64
	lastErr        atomic.Value // string
	lastErrAtMilli atomic.Int64

	started atomic.Bool
}

type recorderSession struct {
	fd          *os.File
	partialPath string
	finalPath   string
	lastEventAt time.Time
	eventCount  int64
}

// SessionRecorderOptions configures a SessionRecorder.
type SessionRecorderOptions struct {
	// Dir is the recordings directory. Created on Start() if missing.
	Dir string

	// BouncerProduct is recorded in every `_meta` header so the replay
	// CLI can route what-if-profile lookups to the right product. Must
	// be one of "ibounce", "kbouncer", "dbounce", "gbounce".
	BouncerProduct string

	// HeartbeatTimeout — sessions idle longer than this are considered
	// ended (no event in 5 minutes by default → finalise).
	HeartbeatTimeout time.Duration
}

// NewSessionRecorder constructs a SessionRecorder. Call Start before
// the first Record; Stop on shutdown to finalise any open sessions.
func NewSessionRecorder(opts SessionRecorderOptions) (*SessionRecorder, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("audit: session recorder requires a non-empty dir")
	}
	if opts.BouncerProduct == "" {
		return nil, fmt.Errorf("audit: session recorder requires a bouncer product name")
	}
	timeout := opts.HeartbeatTimeout
	if timeout <= 0 {
		timeout = DefaultRecorderHeartbeatTimeout
	}
	r := &SessionRecorder{
		dir:              opts.Dir,
		bouncerProduct:   opts.BouncerProduct,
		heartbeatTimeout: timeout,
		sessions:         map[string]*recorderSession{},
	}
	r.lastErr.Store("")
	return r, nil
}

// Start creates the recordings dir (if missing) and finalises any
// `.partial` files left behind by a previous SIGKILL.
func (r *SessionRecorder) Start() error {
	if r.started.Load() {
		return nil
	}
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		r.recordError(fmt.Sprintf("mkdir %q: %v", r.dir, err))
		return err
	}
	// Best-effort directory perm tightening. Ignore failure (tests +
	// some container filesystems refuse chmod after the fact).
	_ = os.Chmod(r.dir, 0o700)
	r.finaliseStalePartials()
	r.started.Store(true)
	return nil
}

// Stop finalises every still-open session + closes fds. Idempotent.
func (r *SessionRecorder) Stop() {
	if r == nil || !r.started.Load() {
		return
	}
	r.mu.Lock()
	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		r.finaliseSession(id)
	}
	r.started.Store(false)
}

// Record appends `ev` to its session's recording file. Called by the
// Manager's Emit when a SessionRecorder is wired. Events without a
// resolvable session_id (raw API calls without an MCP session, mangled
// agent block) are dropped silently; the dropped counter is bumped so
// the operator can spot misconfiguration.
//
// Fail-soft: filesystem errors are recorded on the status counter but
// never propagate into the proxy hot path.
func (r *SessionRecorder) Record(ev Event) {
	if r == nil || !r.started.Load() {
		return
	}
	sid := ExtractSessionID(ev)
	if sid == "" {
		r.dropped.Add(1)
		return
	}
	if err := r.writeEvent(sid, ev); err != nil {
		r.recordError(fmt.Sprintf("write %s: %v", sid, err))
		return
	}
	r.total.Add(1)
}

// FinaliseIdle finalises any session whose last event is older than the
// heartbeat threshold. Returns the list of finalised session ids. The
// proxy should call this periodically (the heartbeat tick is a natural
// fit). Tests pass a fixed `now` to bypass the wall clock.
func (r *SessionRecorder) FinaliseIdle(now time.Time) []string {
	if r == nil || !r.started.Load() {
		return nil
	}
	r.mu.Lock()
	stale := []string{}
	for id, sess := range r.sessions {
		if now.Sub(sess.lastEventAt) > r.heartbeatTimeout {
			stale = append(stale, id)
		}
	}
	r.mu.Unlock()
	for _, id := range stale {
		r.finaliseSession(id)
	}
	return stale
}

// Status snapshots the recorder counters for the MCP audit-export
// status tool. Goroutine-safe.
type SessionRecorderStatus struct {
	Configured      bool   `json:"configured"`
	Dir             string `json:"dir"`
	BouncerProduct  string `json:"bouncer_product"`
	ActiveSessions  int    `json:"active_sessions"`
	TotalEvents     int64  `json:"total_events"`
	DroppedEvents   int64  `json:"dropped_events"`
	LastError       string `json:"last_error,omitempty"`
	LastErrorMillis int64  `json:"last_error_unix_milli,omitempty"`
}

// Status returns a snapshot of the recorder's runtime counters.
func (r *SessionRecorder) Status() SessionRecorderStatus {
	if r == nil {
		return SessionRecorderStatus{}
	}
	r.mu.Lock()
	active := len(r.sessions)
	r.mu.Unlock()
	s := SessionRecorderStatus{
		Configured:     true,
		Dir:            r.dir,
		BouncerProduct: r.bouncerProduct,
		ActiveSessions: active,
		TotalEvents:    r.total.Load(),
		DroppedEvents:  r.dropped.Load(),
	}
	if v, ok := r.lastErr.Load().(string); ok {
		s.LastError = v
	}
	s.LastErrorMillis = r.lastErrAtMilli.Load()
	return s
}

// writeEvent appends one event to the per-session `.partial` file.
// Opens + writes the `_meta` header on first event for a session.
func (r *SessionRecorder) writeEvent(sid string, ev Event) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	line = append(line, '\n')

	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.sessions[sid]
	if !ok {
		sess, err = r.openSessionLocked(sid, ev)
		if err != nil {
			return err
		}
	}
	if _, err := sess.fd.Write(line); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	sess.lastEventAt = time.Now()
	sess.eventCount++
	return nil
}

type recordingMeta struct {
	RecordingSchemaVersion string `json:"recording_schema_version"`
	SessionID              string `json:"session_id"`
	AgentName              string `json:"agent_name"`
	BouncerProduct         string `json:"bouncer_product"`
	RecordingStartedAt     string `json:"recording_started_at"`
}

type recordingMetaWrapper struct {
	Meta recordingMeta `json:"_meta"`
}

// openSessionLocked opens the per-session .partial file + writes the
// `_meta` header. Must be called with r.mu held.
func (r *SessionRecorder) openSessionLocked(sid string, first Event) (*recorderSession, error) {
	if !IsValidSessionID(sid) {
		return nil, fmt.Errorf("invalid session_id for filename: %q", sid)
	}
	finalPath := filepath.Join(r.dir, sid+".ndjson")
	partialPath := finalPath + RecordingPartialSuffix
	fd, err := os.OpenFile(
		partialPath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		RecordingFileMode,
	)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", partialPath, err)
	}
	// Best-effort tightening — if the file pre-existed wider, clamp to
	// 0o600. Failure is non-fatal (test env / container fs may refuse).
	_ = fd.Chmod(RecordingFileMode)

	agentName := "unknown"
	if first.Unmapped.IAMJIT.Agent != nil && first.Unmapped.IAMJIT.Agent.Name != "" {
		agentName = first.Unmapped.IAMJIT.Agent.Name
	}
	header := recordingMetaWrapper{Meta: recordingMeta{
		RecordingSchemaVersion: RecordingSchemaVersion,
		SessionID:              sid,
		AgentName:              agentName,
		BouncerProduct:         r.bouncerProduct,
		RecordingStartedAt:     time.Now().UTC().Format(time.RFC3339),
	}}
	headerLine, _ := json.Marshal(header)
	headerLine = append(headerLine, '\n')
	if _, err := fd.Write(headerLine); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}
	sess := &recorderSession{
		fd:          fd,
		partialPath: partialPath,
		finalPath:   finalPath,
		lastEventAt: time.Now(),
	}
	r.sessions[sid] = sess
	return sess, nil
}

// finaliseSession closes the fd + atomic-renames .partial -> .ndjson.
// Idempotent.
func (r *SessionRecorder) finaliseSession(sid string) {
	r.mu.Lock()
	sess, ok := r.sessions[sid]
	if ok {
		delete(r.sessions, sid)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	_ = sess.fd.Close()
	if _, err := os.Stat(sess.partialPath); err == nil {
		if err := os.Rename(sess.partialPath, sess.finalPath); err != nil {
			r.recordError(fmt.Sprintf("finalise %s: %v", sid, err))
		}
	}
}

// finaliseStalePartials scans the recordings dir on Start() and
// renames any `.partial` file older than the heartbeat threshold.
// Catches SIGKILL'd processes; younger `.partial` files are left
// alone (they might belong to a sibling process or a session about to
// receive its next event).
func (r *SessionRecorder) finaliseStalePartials() {
	threshold := time.Now().Add(-r.heartbeatTimeout)
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, RecordingPartialSuffix) {
			continue
		}
		full := filepath.Join(r.dir, name)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.ModTime().After(threshold) {
			continue
		}
		final := strings.TrimSuffix(full, RecordingPartialSuffix)
		if err := os.Rename(full, final); err != nil {
			r.recordError(fmt.Sprintf("finalise stale %s: %v", name, err))
		}
	}
}

func (r *SessionRecorder) recordError(msg string) {
	r.lastErr.Store(msg)
	r.lastErrAtMilli.Store(time.Now().UnixMilli())
	log.Printf("session recorder error: %s", msg)
}

// ----------------------------------------------------------------------
// Read / listing helpers — power `kbounce session list / show / export`
// and the cross-product `iam-jit session replay`. Same on-disk shape
// across products so the replay CLI consumes any product's files.
// ----------------------------------------------------------------------

// SessionRow is the row shape `session list` produces.
type SessionRow struct {
	SessionID              string `json:"session_id"`
	AgentName              string `json:"agent_name"`
	BouncerProduct         string `json:"bouncer_product"`
	RecordingSchemaVersion string `json:"recording_schema_version"`
	RecordingStartedAt     string `json:"recording_started_at,omitempty"`
	EventCount             int64  `json:"event_count"`
	StartMS                int64  `json:"start_ms,omitempty"`
	EndMS                  int64  `json:"end_ms,omitempty"`
	IsPartial              bool   `json:"is_partial"`
	Path                   string `json:"path"`
}

// ListSessions enumerates the recording files in dir. Empty / missing
// dir returns nil (not an error); unreadable files are silently skipped.
func ListSessions(dir string) ([]SessionRow, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	rows := make([]SessionRow, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		isPartial := false
		switch {
		case strings.HasSuffix(name, ".ndjson"):
		case strings.HasSuffix(name, ".ndjson"+RecordingPartialSuffix):
			isPartial = true
		default:
			continue
		}
		full := filepath.Join(dir, name)
		row, err := summariseRecording(full, isPartial)
		if err != nil {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func summariseRecording(path string, isPartial bool) (SessionRow, error) {
	meta, events, err := ReadSessionFile(path)
	if err != nil {
		return SessionRow{}, err
	}
	row := SessionRow{
		SessionID:              meta.SessionID,
		AgentName:              meta.AgentName,
		BouncerProduct:         meta.BouncerProduct,
		RecordingSchemaVersion: meta.RecordingSchemaVersion,
		RecordingStartedAt:     meta.RecordingStartedAt,
		EventCount:             int64(len(events)),
		IsPartial:              isPartial,
		Path:                   path,
	}
	if row.SessionID == "" {
		row.SessionID = strings.TrimSuffix(
			strings.TrimSuffix(filepath.Base(path), RecordingPartialSuffix),
			".ndjson",
		)
	}
	for i, ev := range events {
		if i == 0 {
			row.StartMS = ev.Time
		}
		row.EndMS = ev.Time
	}
	return row, nil
}

// RecordingMeta is the public alias for the `_meta` header shape so
// callers (CLI + replay) can read it without importing the unexported
// type.
type RecordingMeta = recordingMeta

// ReadSession loads a single recording from the recordings dir by
// session_id. Returns the meta header + the events.
func ReadSession(dir, sessionID string) (RecordingMeta, []Event, error) {
	if !IsValidSessionID(sessionID) {
		return RecordingMeta{}, nil, fmt.Errorf("invalid session_id: %q", sessionID)
	}
	final := filepath.Join(dir, sessionID+".ndjson")
	partial := final + RecordingPartialSuffix
	for _, p := range []string{final, partial} {
		if _, err := os.Stat(p); err == nil {
			return ReadSessionFile(p)
		}
	}
	return RecordingMeta{}, nil, fmt.Errorf("no recording for session %s in %s", sessionID, dir)
}

// ReadSessionFile loads a recording by direct path. The replay CLI
// calls this so an operator can replay a recording shared from another
// box without requiring it live inside a recordings dir.
func ReadSessionFile(path string) (RecordingMeta, []Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RecordingMeta{}, nil, err
	}
	var meta RecordingMeta
	events := []Event{}
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if i == 0 && strings.Contains(line, `"_meta"`) {
			var wrap recordingMetaWrapper
			if err := json.Unmarshal([]byte(line), &wrap); err != nil {
				return meta, events, fmt.Errorf("corrupt meta header: %w", err)
			}
			meta = wrap.Meta
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return meta, events, fmt.Errorf("corrupt event at line %d: %w", i+1, err)
		}
		events = append(events, ev)
	}
	return meta, events, nil
}

// EventCountByType groups events by activity_name for `session show`.
func EventCountByType(events []Event) map[string]int {
	out := map[string]int{}
	for _, ev := range events {
		key := ev.ActivityName
		if key == "" {
			key = ev.ClassName
		}
		if key == "" {
			key = "unknown"
		}
		out[key]++
	}
	return out
}

// PurgeOlderThan removes `.ndjson` files whose mtime is older than
// `olderThan`. Returns the list of removed paths. `.partial` files are
// skipped — those belong to active or recently-killed sessions and the
// recorder's Start() recovery path is the right place to deal with
// them. Operator owns retention by default; this is the explicit
// cleanup surface.
func PurgeOlderThan(dir string, olderThan time.Duration, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	threshold := now.Add(-olderThan)
	removed := []string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".ndjson") {
			continue
		}
		full := filepath.Join(dir, name)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.ModTime().After(threshold) {
			continue
		}
		if err := os.Remove(full); err != nil {
			continue
		}
		removed = append(removed, full)
	}
	return removed, nil
}

// DetectionFinding is the OCSF-shaped wrapper `session export` emits.
// Matches the #273 investigate-with-claude evidence shape so an
// exported session is portable into the same Claude-driven
// investigation flow.
type DetectionFinding struct {
	Metadata     OCSFMetadata `json:"metadata"`
	ClassUID     int          `json:"class_uid"`
	ClassName    string       `json:"class_name"`
	CategoryUID  int          `json:"category_uid"`
	CategoryName string       `json:"category_name"`
	ActivityID   int          `json:"activity_id"`
	ActivityName string       `json:"activity_name"`
	TypeUID      int          `json:"type_uid"`
	TypeName     string       `json:"type_name"`
	SeverityID   int          `json:"severity_id"`
	Severity     string       `json:"severity"`
	Time         int64        `json:"time"`
	StartTime    int64        `json:"start_time,omitempty"`
	EndTime      int64        `json:"end_time,omitempty"`
	FindingInfo  struct {
		Title string `json:"title"`
		UID   string `json:"uid"`
	} `json:"finding_info"`
	Unmapped struct {
		IAMJIT struct {
			Session struct {
				SessionID              string  `json:"session_id"`
				AgentName              string  `json:"agent_name"`
				BouncerProduct         string  `json:"bouncer_product"`
				RecordingSchemaVersion string  `json:"recording_schema_version"`
				RecordingStartedAt     string  `json:"recording_started_at"`
				EventCount             int     `json:"event_count"`
				Events                 []Event `json:"events"`
			} `json:"session"`
		} `json:"iam_jit"`
	} `json:"unmapped"`
}

// DetectionFindingFromSession wraps a recording into an OCSF Detection
// Finding envelope.
func DetectionFindingFromSession(meta RecordingMeta, events []Event) DetectionFinding {
	var startMS, endMS int64
	for i, ev := range events {
		if i == 0 {
			startMS = ev.Time
		}
		endMS = ev.Time
	}
	f := DetectionFinding{
		Metadata: OCSFMetadata{
			Version: "1.1.0",
			Product: OCSFProduct{
				Name:       meta.BouncerProduct,
				VendorName: "iam-jit.com",
			},
		},
		ClassUID:     2004,
		ClassName:    "Detection Finding",
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: "Create",
		TypeUID:      200401,
		TypeName:     "Detection Finding: Create",
		SeverityID:   1,
		Severity:     "Informational",
		Time:         endMS,
		StartTime:    startMS,
		EndTime:      endMS,
	}
	f.FindingInfo.Title = fmt.Sprintf("session recording: %s", meta.SessionID)
	f.FindingInfo.UID = meta.SessionID
	f.Unmapped.IAMJIT.Session.SessionID = meta.SessionID
	f.Unmapped.IAMJIT.Session.AgentName = meta.AgentName
	f.Unmapped.IAMJIT.Session.BouncerProduct = meta.BouncerProduct
	f.Unmapped.IAMJIT.Session.RecordingSchemaVersion = meta.RecordingSchemaVersion
	f.Unmapped.IAMJIT.Session.RecordingStartedAt = meta.RecordingStartedAt
	f.Unmapped.IAMJIT.Session.EventCount = len(events)
	f.Unmapped.IAMJIT.Session.Events = events
	return f
}
