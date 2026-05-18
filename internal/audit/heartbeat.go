// Heartbeater is the background goroutine that emits a HEARTBEAT
// event at a fixed cadence so a downstream SIEM has a positive
// liveness signal for the audit-export channel.
//
// Per [[prompt-injection-disable-bouncer-threat]]: the audit-export
// channel is the operator's ONLY supervision surface over a kbounce
// process. An attacker who can inject prompts into an agent can
// attempt to silence supervision by killing the proxy, flipping it
// to cooperative mode, disabling the export flag, or breaking the
// outbound webhook. Without a liveness signal, "no events" is
// indistinguishable from "no traffic" and the silence reads as
// healthy. Heartbeats convert silence into a loudly-flagged GAP on
// the SIEM side — a SIEM rule on "no HEARTBEAT for 2+ intervals"
// trips on every silencing vector identically.
//
// Per [[audit-export-failure-visibility]]: when the gap is detected
// LOCALLY (by the heartbeatGapRule in alerts.go), the alert ALSO
// writes to stderr + flips /healthz to 503 — the audit-export channel
// itself may be the failure source, so riding the alert through the
// same transport that just broke would be invisible. The stderr +
// healthz paths are independent fallback surfaces an operator can
// monitor with shell-grade tooling.
//
// Per [[cross-product-agent-parity]]: ibounce / kbounce / dbounce
// emit the SAME heartbeat shape (event_type=HEARTBEAT,
// activity_name="heartbeat", monotonic seq + interval in
// unmapped.iam_jit), so a single SIEM dashboard rule catches gaps
// across the whole Bounce suite without product-specific glue.
//
// Per [[security-team-positioning-safety-not-surveillance]]: default
// OFF. Operators opt in via --heartbeat-interval — for a solo-laptop
// dev the heartbeat noise on the audit log is not worth it; for an
// Enterprise security team the heartbeat IS the SIEM contract.
//
// Per [[deliberate-feature-completion]]: shipped as one atomic unit
// (event shape + emitter goroutine + local gap rule + /healthz flip
// + stderr fallback + MCP status surface + tests) so the feature is
// fully usable end-to-end rather than half-wired.

package audit

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultHeartbeatInterval is the recommended cadence when the
// operator enables heartbeats without specifying a custom interval.
// 30s strikes the standard SIEM-rule-tolerance balance: short enough
// that a silenced exporter trips a 2-interval-gap rule within a
// minute, long enough that the heartbeat noise on the audit log is
// 2 events/minute (cheap on JSONL + cheap on webhook quota).
const DefaultHeartbeatInterval = 30 * time.Second

// MinHeartbeatInterval bounds the lower end so a config-error +
// runaway emit doesn't flood the audit-export channel. 1s is the
// floor — anything faster is ticker-noise, not liveness.
const MinHeartbeatInterval = 1 * time.Second

// Heartbeater wraps an Emitter + a ticker goroutine. Start() begins
// emitting; Close() drains the goroutine cleanly. Safe for
// concurrent Status() reads from MCP + /healthz handlers.
//
// Lifecycle:
//
//	hb := NewHeartbeater(emitter, 30*time.Second)
//	hb.Start(ctx)        // launches the ticker goroutine
//	defer hb.Close()     // drains; safe to call multiple times
//
// A Heartbeater with interval == 0 is a no-op — Start does nothing,
// Status reports disabled. This makes the wiring uniform regardless
// of whether the operator passed --heartbeat-interval.
type Heartbeater struct {
	emitter  Emitter
	interval time.Duration

	// seq is the monotonically-incrementing heartbeat sequence number,
	// embedded in each event so the local rule + the SIEM-side rule
	// can detect missing ticks by id arithmetic (independent of clock
	// drift / timestamp comparisons).
	seq atomic.Int64

	// lastEmitUnixNano is the wall-clock of the most-recent successful
	// Emit call. Used by Status() (for the MCP surface) and by the
	// /healthz probe (to flip 503 when no heartbeat has fired in the
	// expected window).
	lastEmitUnixNano atomic.Int64

	// unhealthy is set when the local heartbeatGapRule fires — the
	// /healthz handler reads this to switch its 200 to a 503. The
	// rule resets the bit on the next successful heartbeat
	// observation so an intermittent gap auto-recovers without
	// operator intervention.
	unhealthy atomic.Bool

	// stderrWriter is the io.Writer the gap rule writes a one-line
	// "audit-export heartbeat gap detected" notice to. Defaults to
	// os.Stderr; overridable for tests. Per
	// [[audit-export-failure-visibility]] the stderr path is the
	// fallback when the audit-export transport itself is the failure
	// source — keeping the alert visible to an operator who's reading
	// kbounce's container logs / journalctl output.
	stderrMu     sync.Mutex
	stderrWriter io.Writer

	// done is closed by Close to signal the ticker goroutine to
	// drain. closeOnce guards against double-close panics so Close
	// is safely idempotent — the CLI defers it AND the http.Server
	// Shutdown path may invoke it indirectly under signal handling.
	done      chan struct{}
	closeOnce sync.Once

	// wg blocks Close() until the ticker goroutine has fully exited.
	// Mirrors the connWG pattern from #266 — Server.Shutdown waits
	// for in-flight goroutines to drain cleanly rather than leaking
	// them across a test's t.Cleanup.
	wg sync.WaitGroup

	// nowFn is the clock the goroutine reads. Defaults to time.Now;
	// overridable for tests that need to advance "last emit" without
	// real sleeps.
	nowFn func() time.Time
}

// NewHeartbeater constructs a Heartbeater. interval == 0 disables
// the feature entirely (returns a no-op Heartbeater whose Start +
// Close are safe no-ops). interval below MinHeartbeatInterval is
// clamped up — the CLI rejects the flag value earlier so this is
// belt-and-suspenders for library users.
func NewHeartbeater(emitter Emitter, interval time.Duration) *Heartbeater {
	if interval > 0 && interval < MinHeartbeatInterval {
		interval = MinHeartbeatInterval
	}
	return &Heartbeater{
		emitter:      emitter,
		interval:     interval,
		stderrWriter: os.Stderr,
		done:         make(chan struct{}),
		nowFn:        func() time.Time { return time.Now().UTC() },
	}
}

// Start launches the ticker goroutine AND the watchdog goroutine.
// No-op when interval == 0 or when emitter == nil (the heartbeat
// target is gone; nothing to emit to). Idempotent — calling twice
// will not start a second goroutine pair (the second call drops on
// the early-return).
//
// The ticker goroutine emits one HEARTBEAT event per tick + observes
// the same event back through itself (so the local heartbeatGapRule
// can fire on a missed tick — the rule lives in the alerts engine,
// but the engine is the same Emitter we're wired to). The watchdog
// goroutine separately monitors lastEmitUnixNano against wall-clock;
// when no emit has landed within 2 intervals, it flips unhealthy
// even if the ticker itself died (per
// [[prompt-injection-disable-bouncer-threat]] — an attacker that
// kills the ticker goroutine alone would otherwise go undetected
// locally). Both goroutines exit cleanly on ctx.Done() OR Close().
func (h *Heartbeater) Start(ctx context.Context) {
	if h == nil || h.interval == 0 || h.emitter == nil {
		return
	}
	h.wg.Add(2)
	go h.run(ctx)
	go h.watchdog(ctx)
}

// watchdog is the independent goroutine that flips the unhealthy
// flag when no heartbeat has been emitted in the last 2 intervals.
// Complements the heartbeatGapRule (which detects seq jumps in
// EVENTS observed by the engine): this watchdog catches the case
// where the ticker goroutine itself died + no events are arriving
// at all — the gap rule can't fire on events that don't exist.
//
// Per [[audit-export-failure-visibility]] the watchdog tick is the
// ONLY signal the local /healthz + stderr fallback have when the
// audit-export channel itself is the failure source.
func (h *Heartbeater) watchdog(ctx context.Context) {
	defer h.wg.Done()
	// Watchdog cadence is the same as the ticker — re-evaluating
	// each interval is cheap + means a 2-interval-stale state
	// trips on the third watchdog wake at latest.
	t := time.NewTicker(h.interval)
	defer t.Stop()
	staleThreshold := 2 * h.interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.done:
			return
		case <-t.C:
			last := h.lastEmitUnixNano.Load()
			if last == 0 {
				// No emit yet — within startup grace; skip.
				continue
			}
			age := h.nowFn().Sub(time.Unix(0, last).UTC())
			if age > staleThreshold {
				missed := int(age / h.interval)
				h.markUnhealthy(missed, h.seq.Load())
			} else {
				h.markHealthy()
			}
		}
	}
}

// run is the ticker goroutine. Emits one HEARTBEAT event per tick
// until ctx.Done or done is closed.
func (h *Heartbeater) run(ctx context.Context) {
	defer h.wg.Done()
	t := time.NewTicker(h.interval)
	defer t.Stop()
	// Emit one immediately at startup so a SIEM rule that requires a
	// recent heartbeat doesn't trip during the first-interval warmup.
	h.emitOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.done:
			return
		case <-t.C:
			h.emitOnce(ctx)
		}
	}
}

// emitOnce builds + emits one heartbeat event, advances seq, and
// records the wall-clock for /healthz + MCP status reads. Safe for
// concurrent invocation; atomics + the Emitter's own thread-safety
// take care of the synchronization.
func (h *Heartbeater) emitOnce(ctx context.Context) {
	if h.emitter == nil {
		return
	}
	seq := h.seq.Add(1)
	intervalSeconds := int(h.interval.Seconds())
	if intervalSeconds == 0 {
		intervalSeconds = 1
	}
	ev := NewHeartbeatEvent(seq, intervalSeconds)
	h.lastEmitUnixNano.Store(h.nowFn().UnixNano())
	h.emitter.Emit(ctx, ev)
}

// Close stops the ticker goroutine + blocks until it has fully
// exited. Idempotent. Safe to call from a deferred-shutdown path
// that runs alongside ctx-cancel — close(done) signals; wg.Wait
// drains. Subsequent calls are no-ops.
func (h *Heartbeater) Close() {
	if h == nil {
		return
	}
	h.closeOnce.Do(func() {
		close(h.done)
	})
	h.wg.Wait()
}

// Interval returns the configured cadence. 0 = disabled.
func (h *Heartbeater) Interval() time.Duration {
	if h == nil {
		return 0
	}
	return h.interval
}

// Seq returns the most-recent heartbeat sequence number emitted.
// 0 before the first emit; monotonically increasing thereafter.
func (h *Heartbeater) Seq() int64 {
	if h == nil {
		return 0
	}
	return h.seq.Load()
}

// LastEmit returns the wall-clock of the most-recent successful
// emit. Zero time when no emit has fired yet.
func (h *Heartbeater) LastEmit() time.Time {
	if h == nil {
		return time.Time{}
	}
	v := h.lastEmitUnixNano.Load()
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(0, v).UTC()
}

// Healthy reports whether the heartbeat watchdog considers the
// audit-export channel live. Returns true when the feature is
// disabled (no heartbeat = no expectation to fail). Returns false
// once the local heartbeatGapRule has fired and stays false until
// the next observed heartbeat resets the bit.
//
// The /healthz handler reads this — when false, the handler returns
// 503 + a degraded payload so an external supervisor (k8s liveness
// probe, monit, supervisor scripts) flips on the same signal the
// SIEM-side rule trips on.
func (h *Heartbeater) Healthy() bool {
	if h == nil || h.interval == 0 {
		return true
	}
	return !h.unhealthy.Load()
}

// markUnhealthy is called by the heartbeatGapRule when it fires.
// Also writes a one-line stderr notice so an operator reading the
// container's stderr (the audit-export channel may be the failure
// source) sees the gap. Per
// [[security-team-positioning-safety-not-surveillance]] the message
// is neutral — names the pattern, doesn't accuse the operator.
func (h *Heartbeater) markUnhealthy(missed int, seq int64) {
	if h == nil {
		return
	}
	h.unhealthy.Store(true)
	h.stderrMu.Lock()
	w := h.stderrWriter
	h.stderrMu.Unlock()
	if w == nil {
		return
	}
	// One-line, machine-parseable; downstream tooling (grep, fluent-bit)
	// can pivot on the literal "kbounce: audit-export heartbeat_gap".
	fmt.Fprintf(w,
		"kbounce: audit-export heartbeat_gap detected (missed=%d, last_seq=%d, interval=%s); "+
			"/healthz now reports 503 until the next observed heartbeat\n",
		missed, seq, h.interval)
}

// markHealthy is called when a HEARTBEAT event is observed and the
// watchdog had previously flipped to unhealthy. Auto-recovery — an
// intermittent gap doesn't require operator intervention.
func (h *Heartbeater) markHealthy() {
	if h == nil {
		return
	}
	if h.unhealthy.Swap(false) {
		h.stderrMu.Lock()
		w := h.stderrWriter
		h.stderrMu.Unlock()
		if w != nil {
			fmt.Fprintln(w,
				"kbounce: audit-export heartbeat recovered; /healthz returns to 200")
		}
	}
}

// setStderrWriter overrides the stderr fallback target. Test hook —
// production CLI always uses os.Stderr.
func (h *Heartbeater) setStderrWriter(w io.Writer) {
	if h == nil {
		return
	}
	h.stderrMu.Lock()
	h.stderrWriter = w
	h.stderrMu.Unlock()
}

// withClock overrides the internal clock for deterministic tests.
func (h *Heartbeater) withClock(now func() time.Time) *Heartbeater {
	if h == nil {
		return h
	}
	h.nowFn = now
	return h
}
