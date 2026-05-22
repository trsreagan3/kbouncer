package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// LogWriter is the JSONL audit log writer. Append-only file with
// mode 0600; a worker goroutine drains a bounded channel so the
// proxy hot-path is never blocked on disk I/O.
//
// No rotation built in — operators are expected to point logrotate
// / Fluent Bit / Vector at the file. The CLI flag help spells this
// out so an operator isn't surprised when the file grows unbounded.
//
// Per [[scorer-is-ground-truth]] / [[no-nl-synthesis]] this writer
// emits raw decision events; no LLM enrichment, no derived fields
// beyond what FromDecision computes. Slice 2's rule engine emits
// SECURITY_ALERT events on the same writer but is otherwise
// orthogonal.
type LogWriter struct {
	path     string
	fsync    bool
	queue    chan Event
	done     chan struct{}
	wg       sync.WaitGroup
	total    atomic.Int64 // events successfully written
	dropped  atomic.Int64 // events dropped because the queue was full
	lastErr  atomic.Value // string — last write/marshal error message (empty when clean)
	closeOnce sync.Once

	// Per [[audit-export-failure-visibility]] health-surface
	// counters. writesOK is true when the most-recent attempt
	// succeeded (or none have happened yet); consecFailures is the
	// monotonically-increasing run of failed writes since the last
	// success; lastSuccessUnixNano is the wall-clock of the most-
	// recent successful write. All three power the F1-F8 visibility
	// table the CLI subcommand + /healthz + audit_export_degraded
	// alert rule all read.
	writesOK             atomic.Bool
	consecFailures       atomic.Int64
	lastSuccessUnixNano  atomic.Int64

	// #311 / §A10 rotation knobs + telemetry. maxSizeMB / maxAgeDays
	// gate the rotation trigger; rotations / rotationFailures /
	// partialBytesRecovered are surfaced by the MCP status tool and
	// `kbounce logs verify` so operators can confirm rotation is
	// firing without grepping for the admin-action.
	maxSizeMB              int64
	maxAgeDays             int
	rotations              atomic.Int64
	rotationFailures       atomic.Int64
	lastRotationUnixNano   atomic.Int64
	lastRotationPath       atomic.Value // string
	partialBytesRecovered  atomic.Int64
	// Callbacks fire on rotation success / failure / recovery; the
	// proxy wires admin-action emitters into these so the audit
	// channel records `audit.log.rotated` / `.rotation_failed` /
	// `.recovered_partial` lifecycle events.
	onRotation         func(archive string)
	onRotationFailure  func(reason string)
	onRecovery         func(bytes int64)
}

// LogWriterOptions configures a LogWriter. Path must be non-empty
// (the caller decides whether to construct a LogWriter at all
// based on whether --audit-log-path was passed).
type LogWriterOptions struct {
	Path  string
	Fsync bool
	// QueueDepth bounds the in-memory channel between the proxy hot-
	// path and the disk writer worker. Default 1000 matches the
	// webhook pusher default. A full queue triggers drop+count
	// rather than blocking the caller.
	QueueDepth int
	// #311 / §A10 rotation thresholds. Zero disables the respective
	// trigger; the writer never destroys data on its own — rotated
	// files are gzipped into the same dir and live until an explicit
	// `kbounce logs purge` reaps them.
	MaxSizeMB  int64
	MaxAgeDays int
	// Optional lifecycle callbacks for the admin-action audit
	// channel. Each fires off the worker goroutine; callers MUST NOT
	// block on the audit pipeline (would deadlock the worker).
	OnRotation        func(archive string)
	OnRotationFailure func(reason string)
	OnRecovery        func(bytes int64)
}

// NewLogWriter constructs + starts a LogWriter. The worker goroutine
// runs until ctx is cancelled or Close() is called.
//
// Opens the file in O_APPEND|O_CREATE|O_WRONLY with perm 0600
// (owner-read-write only) — kbounce holds inbound bearer tokens long
// enough to forward; a 0644 audit log would expose decision rows
// to any local user, which is a defensible concern for a security-
// team audit feature.
func NewLogWriter(ctx context.Context, opts LogWriterOptions) (*LogWriter, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("audit: log writer requires a non-empty path")
	}
	depth := opts.QueueDepth
	if depth <= 0 {
		depth = 1000
	}
	// #311 / §A10 — crash recovery before opening for append. If the
	// previous process died mid-write, the trailing line may be
	// partial; truncate it so the next O_APPEND lands clean.
	recovered, recErr := RecoverPartialTail(opts.Path)
	f, err := os.OpenFile(opts.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log file %q: %w", opts.Path, err)
	}
	lw := &LogWriter{
		path:              opts.Path,
		fsync:             opts.Fsync,
		queue:             make(chan Event, depth),
		done:              make(chan struct{}),
		maxSizeMB:         opts.MaxSizeMB,
		maxAgeDays:        opts.MaxAgeDays,
		onRotation:        opts.OnRotation,
		onRotationFailure: opts.OnRotationFailure,
		onRecovery:        opts.OnRecovery,
	}
	lw.lastErr.Store("")
	lw.lastRotationPath.Store("")
	if recErr != nil {
		lw.lastErr.Store(fmt.Sprintf("recover partial tail: %v", recErr))
	}
	if recovered > 0 {
		lw.partialBytesRecovered.Add(recovered)
		if opts.OnRecovery != nil {
			go opts.OnRecovery(recovered)
		}
	}
	// Newly-constructed writer starts in the "healthy, no attempts
	// yet" shape — a startup-time /healthz probe that lands before
	// any decisions should not flag the channel as degraded just
	// because the success counter is still zero.
	lw.writesOK.Store(true)
	lw.wg.Add(1)
	go lw.run(ctx, f)
	return lw, nil
}

// Write enqueues an event for the worker to append. Non-blocking:
// if the queue is full the event is dropped + the dropped counter
// incremented. Callers (proxy hot-path) must NEVER be blocked on a
// slow audit sink.
//
// Returns nil on enqueue success; an error wrapping the drop reason
// when the queue is full (so the caller can decide whether to log
// the drop). The decision row in SQLite is the canonical source of
// truth anyway — the JSONL is a shipping convenience, not the
// primary audit surface.
func (lw *LogWriter) Write(_ context.Context, ev Event) error {
	if lw == nil {
		return nil
	}
	select {
	case lw.queue <- ev:
		return nil
	default:
		lw.dropped.Add(1)
		// Queue-full drop counts as a failed write for the visibility
		// surface — the operator wanted this event written + the writer
		// could not. Recorded under the same consec-failures counter
		// the worker uses on disk I/O errors so a single threshold
		// captures both failure shapes.
		lw.writesOK.Store(false)
		lw.consecFailures.Add(1)
		lw.lastErr.Store(fmt.Sprintf("audit log queue full (depth=%d); event dropped", cap(lw.queue)))
		return fmt.Errorf("audit log queue full (depth=%d); event dropped", cap(lw.queue))
	}
}

// run is the worker goroutine. Exits when ctx is cancelled, when
// done is closed (Close call), or when an unrecoverable file I/O
// error fires.
//
// The file handle + encoder are stored in worker-local pointers so
// the rotation guard (called after each successful write) can swap
// them when it renames + reopens the active log.
func (lw *LogWriter) run(ctx context.Context, f *os.File) {
	defer lw.wg.Done()
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	enc := json.NewEncoder(f)
	for {
		select {
		case <-ctx.Done():
			lw.drainRemaining(f, enc)
			return
		case <-lw.done:
			lw.drainRemaining(f, enc)
			return
		case ev := <-lw.queue:
			lw.writeOne(f, enc, ev)
			// #311 / §A10 — rotation guard. Cheap when no trigger
			// fires (a single Stat); on rotation we swap f + enc.
			if newF, newEnc := lw.maybeRotate(f); newF != nil {
				f = newF
				enc = newEnc
			}
		}
	}
}

// maybeRotate runs the size + age check; on a trigger it fsyncs +
// closes the active fd, calls Rotate, then re-opens. Returns (nil,
// nil) when no rotation happened. On rotation failure the active fd
// is re-opened so writes continue; the failure is recorded.
func (lw *LogWriter) maybeRotate(f *os.File) (*os.File, *json.Encoder) {
	if !ShouldRotateBySize(lw.path, lw.maxSizeMB) &&
		!ShouldRotateByAge(lw.path, lw.maxAgeDays, time.Now()) {
		return nil, nil
	}
	_ = f.Sync()
	_ = f.Close()
	archive, rotErr := Rotate(lw.path, time.Now())
	if rotErr != nil {
		lw.rotationFailures.Add(1)
		lw.lastErr.Store(fmt.Sprintf("rotate: %v", rotErr))
		if lw.onRotationFailure != nil {
			go lw.onRotationFailure(rotErr.Error())
		}
	}
	newF, err := os.OpenFile(lw.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		lw.lastErr.Store(fmt.Sprintf("reopen after rotate: %v", err))
		return nil, nil
	}
	if archive != "" {
		lw.rotations.Add(1)
		lw.lastRotationUnixNano.Store(time.Now().UnixNano())
		lw.lastRotationPath.Store(archive)
		if lw.onRotation != nil {
			go lw.onRotation(archive)
		}
	}
	return newF, json.NewEncoder(newF)
}

// drainRemaining flushes anything left in the channel on shutdown.
// Best-effort — we don't want shutdown to hang forever if the
// channel is large, but a final drain is cheap if the queue is
// near-empty (the common case).
func (lw *LogWriter) drainRemaining(f *os.File, enc *json.Encoder) {
	for {
		select {
		case ev := <-lw.queue:
			lw.writeOne(f, enc, ev)
		default:
			return
		}
	}
}

// writeOne marshals + appends a single event. Errors are recorded
// in lastErr so /healthz + the MCP status tool can surface them; no
// retry (the file path is local + retry on disk-full just delays
// the inevitable).
func (lw *LogWriter) writeOne(f *os.File, enc *json.Encoder, ev Event) {
	if err := enc.Encode(ev); err != nil {
		lw.lastErr.Store(fmt.Sprintf("encode event id=%d: %v", ev.DecisionID, err))
		lw.writesOK.Store(false)
		lw.consecFailures.Add(1)
		return
	}
	if lw.fsync {
		if err := f.Sync(); err != nil {
			lw.lastErr.Store(fmt.Sprintf("fsync: %v", err))
			lw.writesOK.Store(false)
			lw.consecFailures.Add(1)
			return
		}
	}
	lw.total.Add(1)
	lw.lastErr.Store("")
	// Reset the failure run on success + record the wall-clock so
	// the watchdog can flag "no write has landed in the last 5
	// minutes" even when no explicit error is recorded (the worker
	// may be wedged on a downstream operation that never errors).
	lw.writesOK.Store(true)
	lw.consecFailures.Store(0)
	lw.lastSuccessUnixNano.Store(time.Now().UTC().UnixNano())
}

// Close stops the worker goroutine + closes the underlying file.
// Idempotent — safe to call multiple times. Blocks until the worker
// has drained any remaining queued events.
func (lw *LogWriter) Close() {
	if lw == nil {
		return
	}
	lw.closeOnce.Do(func() {
		close(lw.done)
		lw.wg.Wait()
	})
}

// Total returns the cumulative count of events successfully written.
// Used by the MCP status tool + tests.
func (lw *LogWriter) Total() int64 {
	if lw == nil {
		return 0
	}
	return lw.total.Load()
}

// Dropped returns the cumulative count of events dropped because
// the bounded queue was full.
func (lw *LogWriter) Dropped() int64 {
	if lw == nil {
		return 0
	}
	return lw.dropped.Load()
}

// Path returns the configured file path. Surfaced by the MCP status
// tool so an operator can confirm the running proxy is writing where
// they expect.
func (lw *LogWriter) Path() string {
	if lw == nil {
		return ""
	}
	return lw.path
}

// LastError returns the last write/encode/fsync error message, or
// "" when no error has occurred (or the most recent write succeeded).
func (lw *LogWriter) LastError() string {
	if lw == nil {
		return ""
	}
	if v, ok := lw.lastErr.Load().(string); ok {
		return v
	}
	return ""
}

// WritesOK reports whether the most-recent write attempt succeeded.
// True on a fresh writer with no attempts yet (so a startup-time
// health probe does not flag a brand-new export channel as degraded).
// Flips to false on any failed write (queue-full, encode-error,
// fsync-error) and stays false until the next successful write.
//
// Per [[audit-export-failure-visibility]]: read by /healthz, the MCP
// status tool, the `kbounce audit-export health` CLI subcommand, and
// the audit_export_degraded alert-rule predicate.
func (lw *LogWriter) WritesOK() bool {
	if lw == nil {
		return true
	}
	return lw.writesOK.Load()
}

// ConsecutiveFailures returns the count of consecutive failed writes
// since the last successful write. 0 on a fresh writer + reset to 0
// on each success. The /healthz 503 trigger fires at > 3 (per the
// memo's threshold table).
func (lw *LogWriter) ConsecutiveFailures() int64 {
	if lw == nil {
		return 0
	}
	return lw.consecFailures.Load()
}

// LastSuccess returns the wall-clock of the most-recent successful
// write. Zero time when no successful write has happened yet
// (newly-constructed writer pre-first-write). Read by the watchdog
// to flag "no write has landed in the last 5 minutes" stalls even
// when no explicit error is recorded.
func (lw *LogWriter) LastSuccess() time.Time {
	if lw == nil {
		return time.Time{}
	}
	v := lw.lastSuccessUnixNano.Load()
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(0, v).UTC()
}

// Rotations returns the cumulative count of successful rotations
// since startup. Surfaced via the MCP status tool + the doctor
// logs subcommand so operators can confirm rotation cadence.
func (lw *LogWriter) Rotations() int64 {
	if lw == nil {
		return 0
	}
	return lw.rotations.Load()
}

// RotationFailures returns the cumulative count of rotation
// attempts that failed (gzip error, rename error, etc.). A
// non-zero value should fire an alert; the active log keeps
// growing until the operator intervenes.
func (lw *LogWriter) RotationFailures() int64 {
	if lw == nil {
		return 0
	}
	return lw.rotationFailures.Load()
}

// LastRotationPath returns the archive path of the most-recent
// rotation, "" when none has happened.
func (lw *LogWriter) LastRotationPath() string {
	if lw == nil {
		return ""
	}
	v, _ := lw.lastRotationPath.Load().(string)
	return v
}

// PartialBytesRecovered returns the total bytes trimmed by the
// startup partial-tail recovery. Non-zero indicates a previous
// process died mid-write.
func (lw *LogWriter) PartialBytesRecovered() int64 {
	if lw == nil {
		return 0
	}
	return lw.partialBytesRecovered.Load()
}

// MaxSizeMB returns the configured size threshold; 0 == disabled.
func (lw *LogWriter) MaxSizeMB() int64 {
	if lw == nil {
		return 0
	}
	return lw.maxSizeMB
}

// MaxAgeDays returns the configured age threshold; 0 == disabled.
func (lw *LogWriter) MaxAgeDays() int {
	if lw == nil {
		return 0
	}
	return lw.maxAgeDays
}
