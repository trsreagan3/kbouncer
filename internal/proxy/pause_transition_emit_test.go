// Proxy hot-path coverage for the synthetic EventTypeAdminFallbackGrant
// + EventTypePauseEnd emit wiring per #270 + [[security-team-audit-
// export]]. The proxy is the single observer with the audit emitter
// wired, so pause state mutations from the one-shot
// `kbouncer pause start` / `kbouncer pause stop` CLI commands get
// audit-exported through the next inbound request rather than needing
// CLI-side emitter plumbing.
//
// Coverage focuses on the transition detector:
//
//   - Open edge (0 → N): synthetic admin_fallback_grant fires exactly
//     once.
//   - Close edge (N → 0): synthetic pause_end fires exactly once with
//     the persisted end_kind ("resumed_early" vs "expired").
//   - Steady-state (N → N): no duplicate emit on subsequent requests
//     in the same pause window.
//   - No audit emitter wired: detector is a no-op (no panic).
package proxy

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/parser"
)

// capturePauseEmitter is a test-only audit.Emitter that records every
// emitted event in arrival order under a mutex (the proxy hot-path
// may call Emit from multiple goroutines, though these tests are
// single-threaded; the mutex is cheap insurance).
type capturePauseEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *capturePauseEmitter) Emit(_ context.Context, ev audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *capturePauseEmitter) Status() audit.Status { return audit.Status{} }

func (c *capturePauseEmitter) byType(et audit.EventType) []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []audit.Event
	for _, ev := range c.events {
		if ev.EventType == et {
			out = append(out, ev)
		}
	}
	return out
}

// runProbe sends a representative inbound request through the Server's
// pause-transition observer. The probe request is benign (a GET against
// a known path) so the proxy's decision flow is reproducible — the
// test asserts on synthetic events the observer emits, not on the
// decision events themselves.
func runProbe(t *testing.T, s *Server) {
	t.Helper()
	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	// Drive the same path handle() exercises: look up the active pause
	// + invoke the transition observer. Skip the full handle() so the
	// test doesn't need a TCP listener.
	active, err := s.store.GetActivePause()
	require.NoError(t, err)
	s.observePauseTransition(active)
	_ = req // referenced for documentation; the observer is the unit under test
}

func TestObservePauseTransition_OpenEdgeEmitsGrant(t *testing.T) {
	st := freshStore(t)
	emitter := &capturePauseEmitter{}
	s := NewServer(Config{AuditEmitter: emitter}, st)

	// Pre-pause: no transition; no emit.
	runProbe(t, s)
	assert.Empty(t, emitter.events,
		"no pause active + no prior state → observer must not emit")

	// Operator opens a pause window (simulating `kbounce pause start`).
	pid, err := st.StartPause(600, "incident response", "alice")
	require.NoError(t, err)

	runProbe(t, s)

	grants := emitter.byType(audit.EventTypeAdminFallbackGrant)
	require.Len(t, grants, 1,
		"first request after `pause start` MUST emit the synthetic grant event")
	ev := grants[0]
	assert.Equal(t, pid, ev.Unmapped.IAMJIT.Ext["pause_id"])
	assert.Equal(t, "incident response", ev.Unmapped.IAMJIT.Ext["pause_reason"])
	assert.Equal(t, "alice", ev.Unmapped.IAMJIT.Ext["pause_started_by"])

	// Steady-state: subsequent requests must NOT re-emit while the
	// same pause window is active (otherwise every request inside a
	// long pause window would generate one grant event per request).
	runProbe(t, s)
	runProbe(t, s)
	grants = emitter.byType(audit.EventTypeAdminFallbackGrant)
	assert.Len(t, grants, 1,
		"steady-state inside a pause window must NOT re-emit the grant event")
}

func TestObservePauseTransition_CloseEdgeEmitsResumedEarly(t *testing.T) {
	st := freshStore(t)
	emitter := &capturePauseEmitter{}
	s := NewServer(Config{AuditEmitter: emitter}, st)

	pid, err := st.StartPause(600, "incident response", "alice")
	require.NoError(t, err)
	runProbe(t, s) // open-edge emit

	// Operator runs `kbounce pause stop`.
	endedID, err := st.EndPause("alice")
	require.NoError(t, err)
	require.NotNil(t, endedID)
	assert.Equal(t, pid, *endedID)

	runProbe(t, s) // close-edge emit

	ends := emitter.byType(audit.EventTypePauseEnd)
	require.Len(t, ends, 1, "first request after `pause stop` MUST emit pause_end")
	ev := ends[0]
	assert.Equal(t, pid, ev.Unmapped.IAMJIT.Ext["pause_id"])
	assert.Equal(t, "resumed_early", ev.Unmapped.IAMJIT.Ext["pause_end_kind"],
		"operator-initiated close MUST surface as resumed_early so a SIEM "+
			"can distinguish it from auto-expiry")

	// Steady-state after close: no further emit.
	runProbe(t, s)
	runProbe(t, s)
	assert.Len(t, emitter.byType(audit.EventTypePauseEnd), 1,
		"no further pause_end emit once the close edge has fired")
}

func TestObservePauseTransition_AutoExpiryEmitsExpired(t *testing.T) {
	st := freshStore(t)
	emitter := &capturePauseEmitter{}
	s := NewServer(Config{AuditEmitter: emitter}, st)

	// 1-second pause → the GetActivePause lazy-GC inside runProbe will
	// flip it to 'expired' after the wall-clock window passes. Mirrors
	// TestGetActivePause_AutoExpiresPastPauses in the store package
	// (the store has no DB() accessor for backdating the row, so brief
	// sleep is the canonical fixture pattern).
	_, err := st.StartPause(1, "short window", "bob")
	require.NoError(t, err)
	runProbe(t, s) // open-edge emit

	time.Sleep(1100 * time.Millisecond)
	runProbe(t, s) // close-edge emit (lazy-GC flips end_kind to "expired")

	ends := emitter.byType(audit.EventTypePauseEnd)
	require.Len(t, ends, 1, "auto-expiry MUST emit pause_end")
	assert.Equal(t, "expired", ends[0].Unmapped.IAMJIT.Ext["pause_end_kind"],
		"auto-revert MUST surface as expired so a SIEM can distinguish it "+
			"from operator-initiated closure")
}

func TestObservePauseTransition_NoEmitterIsNoOp(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{ /* AuditEmitter intentionally nil */ }, st)

	_, err := st.StartPause(600, "no audit wired", "ops")
	require.NoError(t, err)
	// Must not panic.
	runProbe(t, s)
	runProbe(t, s)
}
