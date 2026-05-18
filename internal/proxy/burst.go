// Burst detector for the [[bulk-prompt-answer-ux]] memo.
//
// When N pending DENY prompts accumulate within T seconds, the
// detector emits a BURST_DETECTED event so the operator's next
// `kbounce prompts bulk-answer` invocation has a burst to act on.
// The event is persisted to the store (cross-process visibility: the
// proxy + the CLI + the MCP server may be three different processes;
// in-memory state in the proxy wouldn't reach the CLI) and the
// in-memory detector tracks a sliding window + a cool-down period to
// avoid emitting a fresh burst on every additional prompt during the
// window.
//
// Defaults per the memo: N=5 prompts within T=60s; cool-down 5min.
// The values are tunable via the constructor so a future --burst-*
// flag set on `kbounce run` can override without rewriting the
// detector.
//
// Per [[safety-mode-lean-permissive]] + [[ibounce-honest-positioning]]:
// the burst detector is part of the UX-deterrent path that prevents
// "block-happy = uninstalled" failure mode. It is NOT a security
// boundary — an adversarial agent that could trigger N benign-looking
// DENY prompts could drive a bulk-allow. The audit row + bulk_answer
// resolution kind keep the operator-decision trail intact.
//
// Per [[creates-never-mutates]]: this file only OBSERVES + records;
// it never mutates existing rules. The bulk-answer CLI/MCP layer
// creates new time-bounded ALLOW rules (which auto-expire).

package proxy

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/kbouncer/internal/store"
)

// BurstThresholdDefault is the prompt-count threshold the detector uses
// when not overridden. Per [[bulk-prompt-answer-ux]] memo.
const BurstThresholdDefault = 5

// BurstWindowDefault is the sliding-window length over which the
// detector counts prompts. Per [[bulk-prompt-answer-ux]] memo.
const BurstWindowDefault = 60 * time.Second

// BurstCooldownDefault is how long the detector stays silent after
// emitting an event before it can fire again. Prevents one big burst
// from emitting dozens of identical events. Per [[bulk-prompt-answer-
// ux]] memo: 5 minutes.
const BurstCooldownDefault = 5 * time.Minute

// BurstDetector counts prompt-emit events in a sliding window + emits
// a BURST_DETECTED event (recorded to the store) when the count crosses
// the threshold. Safe for concurrent use.
//
// One detector per running proxy. Use NewBurstDetector to construct;
// use OnPromptEnqueued from the prompt-enqueue path to feed it.
type BurstDetector struct {
	threshold int
	window    time.Duration
	cooldown  time.Duration

	st *store.Store

	mu           sync.Mutex
	timestamps   []time.Time // recent prompt-emit times within `window`
	cooldownEnds time.Time   // zero = detector armed; >now = silenced
	lastEvent    int64       // store id of the most-recent BURST_DETECTED row
}

// BurstDetectorOptions tunes the detector at construction. Zero values
// fall back to the BurstThresholdDefault / BurstWindowDefault /
// BurstCooldownDefault constants.
type BurstDetectorOptions struct {
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
}

// NewBurstDetector constructs a detector wired to the given store. A
// nil store disables emission (the detector still tracks counts so
// tests can introspect, but never calls RecordBurstEvent).
func NewBurstDetector(st *store.Store, opts BurstDetectorOptions) *BurstDetector {
	d := &BurstDetector{
		threshold: opts.Threshold,
		window:    opts.Window,
		cooldown:  opts.Cooldown,
		st:        st,
	}
	if d.threshold <= 0 {
		d.threshold = BurstThresholdDefault
	}
	if d.window <= 0 {
		d.window = BurstWindowDefault
	}
	if d.cooldown <= 0 {
		d.cooldown = BurstCooldownDefault
	}
	d.timestamps = make([]time.Time, 0, d.threshold*2)
	return d
}

// OnPromptEnqueued is called by the prompt-enqueue path right after
// a pending_prompts row is written. Records the timestamp, prunes the
// sliding window, and emits a BURST_DETECTED row when the count first
// crosses the threshold. Re-arms after the cool-down passes.
//
// Returns the burst event id when one was emitted (positive int64), or
// 0 when the call was a normal sub-threshold prompt-enqueue. Tests use
// the return value to assert exactly-once emission within a window.
func (d *BurstDetector) OnPromptEnqueued() int64 {
	if d == nil {
		return 0
	}
	return d.onPromptAt(time.Now().UTC())
}

// onPromptAt is the test-injectable version of OnPromptEnqueued. Tests
// pass a deterministic clock + verify exactly-once emission within
// the window without relying on real time.
func (d *BurstDetector) onPromptAt(now time.Time) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Cool-down: silenced until cooldownEnds. Prune the window so the
	// next post-cooldown burst restarts from a clean count rather than
	// inheriting stale timestamps.
	if !d.cooldownEnds.IsZero() && now.Before(d.cooldownEnds) {
		// Still keep the rolling window pruned so the post-cooldown
		// re-arm sees the true rate, not 30 stale entries.
		d.pruneLocked(now)
		return 0
	}
	if !d.cooldownEnds.IsZero() && !now.Before(d.cooldownEnds) {
		// Cooldown expired — re-arm + reset the window so we start
		// counting from zero. Without this, a sustained burst would
		// trip again immediately on the first post-cooldown event.
		d.cooldownEnds = time.Time{}
		d.timestamps = d.timestamps[:0]
	}
	d.timestamps = append(d.timestamps, now)
	d.pruneLocked(now)
	if len(d.timestamps) < d.threshold {
		return 0
	}
	// Threshold crossed. Record the event + arm the cool-down.
	d.cooldownEnds = now.Add(d.cooldown)
	count := len(d.timestamps)
	if d.st == nil {
		return 0
	}
	id, err := d.st.RecordBurstEvent(count, int(d.window.Seconds()))
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: burst-event record failed")
		return 0
	}
	d.lastEvent = id
	log.Info().
		Int("prompt_count", count).
		Int("window_seconds", int(d.window.Seconds())).
		Int64("burst_id", id).
		Msg("kbounce: BURST_DETECTED")
	return id
}

// pruneLocked drops timestamps older than `window` from the head of
// the slice. Caller must hold d.mu.
func (d *BurstDetector) pruneLocked(now time.Time) {
	cutoff := now.Add(-d.window)
	// Common case: head is recent, no work to do.
	if len(d.timestamps) == 0 || !d.timestamps[0].Before(cutoff) {
		return
	}
	// Find the first index that is NOT before cutoff. Bounded linear
	// scan; the slice is small (capped near threshold*2 in steady
	// state).
	cut := 0
	for i, ts := range d.timestamps {
		if !ts.Before(cutoff) {
			cut = i
			break
		}
		cut = i + 1
	}
	d.timestamps = d.timestamps[cut:]
}

// ResetForResolution clears the in-memory window + the cool-down so the
// next sub-threshold prompt-enqueue starts counting from zero. Called
// by the bulk-answer flow after it resolves the burst — without this,
// the post-resolution prompts would still be inside the same sliding
// window + a single additional prompt would re-trip the threshold,
// surfacing a phantom burst the operator already addressed.
func (d *BurstDetector) ResetForResolution() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.timestamps = d.timestamps[:0]
	d.cooldownEnds = time.Time{}
}

// Snapshot returns the current window count + the cool-down state for
// tests + /healthz introspection. Safe for concurrent calls.
type BurstSnapshot struct {
	WindowCount   int
	Threshold     int
	WindowSeconds int
	Cooldown      bool
	LastEventID   int64
}

// Snapshot returns a copy of the detector's internal counters. Test +
// healthz surface.
func (d *BurstDetector) Snapshot() BurstSnapshot {
	if d == nil {
		return BurstSnapshot{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(time.Now().UTC())
	return BurstSnapshot{
		WindowCount:   len(d.timestamps),
		Threshold:     d.threshold,
		WindowSeconds: int(d.window.Seconds()),
		Cooldown:      !d.cooldownEnds.IsZero() && time.Now().UTC().Before(d.cooldownEnds),
		LastEventID:   d.lastEvent,
	}
}
