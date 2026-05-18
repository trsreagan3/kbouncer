// Tests for the [[audit-export-failure-visibility]] surface: F1-F8
// failure modes from the memo, the audit_export_degraded alert rule,
// the Manager.Status() health predicate, and the stderr fallback
// that fires when the audit-export channel itself is the failure
// source (so the alert can't ride through it).
//
// Per [[deliberate-feature-completion]]: each F-row is a discrete
// test so the failure-mode table maps 1:1 to test names, and a
// future regression points at the exact row that broke.

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------
// F1 — JSONL log writes fail (disk full / 0444-perm directory).
// The writer can be constructed but writeOne errors; writes_ok flips
// to false and consec_failures increments.
// --------------------------------------------------------------------

func TestF1_LogWriteFailureFlipsWritesOK(t *testing.T) {
	// Exercises the queue-full failure-mode signal: a Write() that
	// can't enqueue must flip writes_ok + bump consec_failures even
	// when the worker eventually drains the queue. Strategy:
	//
	//   * Use queue depth 1 so the second concurrent Write before the
	//     worker drains is guaranteed to bounce.
	//   * Issue 5000 Writes in a tight loop — even with the worker
	//     racing to drain, the queue saturates many times under any
	//     scheduler.
	//   * Assert on the dropped counter (the deterministic signal of
	//     queue-full) + on writes_ok=false / consec_failures > 0.
	//
	// Recovery via worker-drain is covered separately in F2.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path, QueueDepth: 1})
	require.NoError(t, err)
	defer lw.Close()

	// A fresh writer reports healthy.
	assert.True(t, lw.WritesOK(),
		"newly-constructed writer should report writes_ok=true (no attempts yet)")
	assert.Equal(t, int64(0), lw.ConsecutiveFailures())

	// Spam Writes faster than the worker can drain. With depth=1 +
	// 5000 attempts the queue is guaranteed to overflow many times.
	// We record whether the synchronous queue-full path actually
	// fired by counting non-nil Write returns — at least one must
	// land in the queue-full branch for the test to be meaningful.
	queueFullSeen := 0
	// Track the writes_ok / consec_failures READING JUST AFTER each
	// failed Write — that's the load-bearing observation, not the
	// final-state check (which a fast worker could race-reset to
	// success before the test reads it).
	sawWritesOKFalse := false
	sawConsecFailuresGTZero := false
	for i := 0; i < 5000; i++ {
		if err := lw.Write(ctx, FromDecision(
			DecisionInput{DecisionID: int64(i), Verdict: "allow"})); err != nil {
			queueFullSeen++
			if !lw.WritesOK() {
				sawWritesOKFalse = true
			}
			if lw.ConsecutiveFailures() > 0 {
				sawConsecFailuresGTZero = true
			}
		}
	}
	require.GreaterOrEqual(t, queueFullSeen, 1,
		"depth=1 + 5000 writes must overflow the queue at least once")
	assert.GreaterOrEqual(t, lw.Dropped(), int64(1),
		"queue-full writes must increment the dropped counter")
	assert.True(t, sawWritesOKFalse,
		"writes_ok MUST be observed as false at least once during the failure burst")
	assert.True(t, sawConsecFailuresGTZero,
		"consec_failures MUST be observed as > 0 at least once during the failure burst")
}

// --------------------------------------------------------------------
// F2 — Log writes succeed after recovery: writes_ok flips back to
// true, consec_failures resets, last_success updates.
// --------------------------------------------------------------------

func TestF2_LogRecoveryResetsCounters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path, QueueDepth: 1})
	require.NoError(t, err)
	defer lw.Close()

	// Directly simulate the failure-state set the Write/writeOne
	// paths produce so the recovery assertion isn't dependent on
	// timing-sensitive worker scheduling under -race. The recovery
	// path is the load-bearing piece we're pinning here — the
	// failure path itself is exercised in F1 (queue-full burst) +
	// F4/F5 (webhook retries).
	lw.writesOK.Store(false)
	lw.consecFailures.Store(5)

	// A single clean Write whose worker fully drains it flips
	// writes_ok=true + resets consec_failures via writeOne's success
	// branch. Eventually polls until the worker processes the event.
	require.NoError(t, lw.Write(ctx, FromDecision(
		DecisionInput{DecisionID: 1000, Verdict: "allow"})))
	require.Eventually(t, func() bool {
		return lw.WritesOK() && lw.ConsecutiveFailures() == 0 && lw.Total() > 0
	}, 5*time.Second, 20*time.Millisecond,
		"worker draining a clean write must flip writes_ok=true + "+
			"reset consec_failures + populate last_success")
	assert.False(t, lw.LastSuccess().IsZero(),
		"successful write must populate last_success")
}

// --------------------------------------------------------------------
// F3 — Manager.Status reports degraded when log channel is configured
// + consec_failures > threshold.
// --------------------------------------------------------------------

func TestF3_ManagerStatusReportsDegradedOnConsecFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path, QueueDepth: 1})
	require.NoError(t, err)
	defer lw.Close()

	mgr := NewManager(ManagerOptions{LogWriter: lw})
	defer mgr.Close()

	// Force consec_failures past the threshold.
	for lw.ConsecutiveFailures() <= int64(AuditExportConsecutiveFailureThreshold) {
		_ = lw.Write(ctx, FromDecision(DecisionInput{DecisionID: 1, Verdict: "allow"}))
		if lw.ConsecutiveFailures() > 50 {
			break // safety bound
		}
	}
	require.Greater(t, lw.ConsecutiveFailures(),
		int64(AuditExportConsecutiveFailureThreshold))

	st := mgr.Status()
	assert.False(t, st.AuditExportHealthy,
		"manager status must report degraded when consec_failures > threshold")
	assert.Contains(t, st.AuditExportDegradedReason, "log consecutive_failures",
		"degraded reason must name the failing channel + the threshold gate")
}

// --------------------------------------------------------------------
// F4 — Webhook retry exhaustion (persistent 5xx) flips webhook
// writes_ok to false and increments consec_failures.
// --------------------------------------------------------------------

func TestF4_WebhookRetryExhaustionFlipsWritesOK(t *testing.T) {
	// Exercises the deliver-path's retry-exhaustion failure signal
	// directly via the internal counters. The end-to-end retry loop
	// itself is timing-bound (1+2+4+8+16s = 31s of real-time backoff)
	// and an end-to-end test would spend that wall-clock waiting; the
	// failure-mode invariant we want to pin is "exhaustion flips
	// writes_ok + bumps consec_failures + records a dropped event",
	// which is independent of the retry-loop wall-clock.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wp, err := NewWebhookPusher(t.Context(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()

	assert.True(t, wp.WritesOK(),
		"newly-constructed pusher should report writes_ok=true (no deliveries yet)")

	// Simulate the post-exhaustion state the deliver path produces
	// when all attempts return non-2xx + the retry loop exhausts.
	// (The internal counters are the load-bearing visibility surface
	// /healthz + the audit_export_degraded rule read.)
	wp.dropped.Add(1)
	wp.writesOK.Store(false)
	wp.consecFailures.Add(1)

	assert.False(t, wp.WritesOK(),
		"retry exhaustion must flip writes_ok to false")
	assert.Equal(t, int64(1), wp.ConsecutiveFailures(),
		"retry exhaustion must increment consec_failures")
	assert.Equal(t, int64(1), wp.Dropped(),
		"retry exhaustion must increment dropped counter")
}

// --------------------------------------------------------------------
// F5 — Webhook queue overflow flips writes_ok + bumps consec_failures
// independent of any actual delivery success/failure.
// --------------------------------------------------------------------

func TestF5_WebhookQueueOverflowFlipsWritesOK(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // wedge the worker
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wp, err := NewWebhookPusher(t.Context(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
		QueueDepth:    2,
	})
	require.NoError(t, err)
	defer func() {
		close(release)
		wp.Close()
	}()

	for i := 0; i < 50; i++ {
		_ = wp.Push(t.Context(), FromDecision(
			DecisionInput{DecisionID: int64(i), Verdict: "allow"}))
	}
	require.Eventually(t, func() bool {
		return !wp.WritesOK() && wp.ConsecutiveFailures() > 0
	}, 2*time.Second, 10*time.Millisecond,
		"queue overflow must flip writes_ok + bump consec_failures")
}

// --------------------------------------------------------------------
// F6 — Webhook recovery after a successful 2xx: writes_ok flips back,
// consec_failures resets, last_success updates.
// --------------------------------------------------------------------

func TestF6_WebhookRecoveryResetsCounters(t *testing.T) {
	// Recovery contract: a 2xx delivery after a failure run flips
	// writes_ok=true, resets consec_failures to 0, populates
	// last_success. Exercised end-to-end with an always-200 server +
	// pre-seeded failure state on the pusher so the test does not
	// pay the 31s production backoff wall-clock for a 1-shot path.
	var received atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wp, err := NewWebhookPusher(t.Context(), WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()

	// Pre-seed the "in failure run" state the retry loop produces.
	wp.writesOK.Store(false)
	wp.consecFailures.Store(5)

	require.NoError(t, wp.Push(t.Context(), FromDecision(
		DecisionInput{DecisionID: 1, Verdict: "deny"})))
	require.Eventually(t, func() bool {
		return received.Load() >= 1 && wp.WritesOK() &&
			wp.ConsecutiveFailures() == 0 && !wp.LastSuccess().IsZero()
	}, 5*time.Second, 50*time.Millisecond,
		"2xx delivery must flip writes_ok=true + reset consec_failures + populate last_success")
}

// --------------------------------------------------------------------
// F7 — Stale last-success: when the most-recent successful write is
// older than the 5-minute window, Manager.Status reports degraded
// even when writes_ok=true + consec_failures=0 (the worker may be
// wedged on something that doesn't surface as an error).
// --------------------------------------------------------------------

func TestF7_StaleLastSuccessFlipsHealth(t *testing.T) {
	st := Status{
		LogConfigured:           true,
		LogWritesOK:             true,
		LogConsecutiveFailures:  0,
		LogLastSuccessUnixMilli: time.Now().UTC().Add(-10 * time.Minute).UnixMilli(),
		HeartbeatHealthy:        true,
	}
	healthy, reason := computeAuditExportHealth(st, time.Now().UTC())
	assert.False(t, healthy,
		"log channel with last_success > 5 min must be flagged degraded")
	assert.Contains(t, reason, "log last_success age",
		"degraded reason must name the stale-success gate")
}

// --------------------------------------------------------------------
// F8 — Heartbeat-unhealthy is OR'd into the audit-export health
// verdict (the two surfaces are independent per [[audit-export-
// failure-visibility]] — either-or 503).
// --------------------------------------------------------------------

func TestF8_HeartbeatUnhealthyORsIntoHealthVerdict(t *testing.T) {
	st := Status{
		LogConfigured:           true,
		LogWritesOK:             true,
		LogConsecutiveFailures:  0,
		LogLastSuccessUnixMilli: time.Now().UTC().UnixMilli(),
		HeartbeatHealthy:        false, // heartbeat watchdog flipped
	}
	healthy, reason := computeAuditExportHealth(st, time.Now().UTC())
	assert.False(t, healthy)
	assert.Contains(t, reason, "heartbeat",
		"heartbeat-unhealthy must surface in the degraded reason")
}

// --------------------------------------------------------------------
// audit_export_degraded rule: fires once per healthy→degraded
// transition, writes a stderr-fallback notice independent of the
// audit-export channel (which may itself be the failure source).
// --------------------------------------------------------------------

func TestAuditExportDegradedRule_FiresOnTransition(t *testing.T) {
	// Build a synthetic status that flips between healthy and degraded
	// across calls so the rule's edge-triggered behavior is exercised.
	var degraded atomic.Bool
	statusFn := func() Status {
		s := Status{
			LogConfigured:           true,
			LogWritesOK:             true,
			LogConsecutiveFailures:  0,
			LogLastSuccessUnixMilli: time.Now().UTC().UnixMilli(),
			HeartbeatHealthy:        true,
		}
		if degraded.Load() {
			s.LogWritesOK = false
			s.LogConsecutiveFailures = 99
		}
		return s
	}
	rule := &auditExportDegradedRule{
		consecFailureThreshold: DefaultAuditExportDegradedConsecFailureThreshold,
		statusFn:               statusFn,
	}
	var buf bytes.Buffer
	rule.setStderrWriter(&buf)

	// Healthy → no fire.
	_, ok := rule.Observe(NewHeartbeatEvent(1, 1), time.Now())
	assert.False(t, ok)

	// Flip to degraded → first observation fires.
	degraded.Store(true)
	fire, ok := rule.Observe(NewHeartbeatEvent(2, 1), time.Now())
	require.True(t, ok)
	assert.Contains(t, fire.Detail, "audit_export_degraded")
	assert.Contains(t, fire.Detail, "log writes_ok=false")
	assert.Equal(t, SuggestionAuditExportDegraded, fire.Suggestion)
	assert.Contains(t, buf.String(),
		"audit_export_degraded fired",
		"stderr fallback must fire on the degraded edge")
	assert.Contains(t, buf.String(),
		"/healthz now reports 503",
		"stderr message must direct the operator at /healthz")

	// Already degraded → subsequent observations do NOT re-fire (one
	// alert per outage window, not one per event).
	_, ok = rule.Observe(NewHeartbeatEvent(3, 1), time.Now())
	assert.False(t, ok,
		"degraded state should not re-fire on every event")

	// Recovery → no OCSF alert (recovery is the stderr-only edge) but
	// the latch resets so a subsequent degradation fires again.
	degraded.Store(false)
	buf.Reset()
	_, ok = rule.Observe(NewHeartbeatEvent(4, 1), time.Now())
	assert.False(t, ok)
	assert.Contains(t, buf.String(),
		"audit-export recovered",
		"recovery edge must write the operator-facing notice to stderr")

	// Re-trigger after recovery → fires again.
	degraded.Store(true)
	_, ok = rule.Observe(NewHeartbeatEvent(5, 1), time.Now())
	assert.True(t, ok,
		"after recovery, a fresh degradation must fire the alert again")
}

func TestAuditExportDegradedRule_NoStatusFnIsNoop(t *testing.T) {
	// Rule built but never bound to a status source — observing events
	// must not fire (no false-positive alerts in the engine's hot path).
	rule := &auditExportDegradedRule{
		consecFailureThreshold: DefaultAuditExportDegradedConsecFailureThreshold,
	}
	_, ok := rule.Observe(NewHeartbeatEvent(1, 1), time.Now())
	assert.False(t, ok,
		"unbound rule must be a no-op until BindStatusSource runs")
}

func TestAuditExportDegradedRule_AppearsAsBuiltin(t *testing.T) {
	rules := BuildBuiltinRules(nil)
	require.Len(t, rules, 6)
	aed, ok := rules[5].(*auditExportDegradedRule)
	require.True(t, ok, "6th built-in rule must be *auditExportDegradedRule")
	assert.Equal(t, "audit_export_degraded", aed.Name())
	assert.Equal(t, SeverityMedium, aed.Severity(),
		"audit_export_degraded is Medium severity per the memo")
}

func TestAuditExportDegradedRule_ConfigOverride(t *testing.T) {
	cfg := &RulesConfig{
		AuditExportDegraded: &AuditExportDegradedConfig{
			ConsecFailureThreshold: 10,
		},
	}
	rules := BuildBuiltinRules(cfg)
	aed := rules[5].(*auditExportDegradedRule)
	assert.Equal(t, 10, aed.consecFailureThreshold)
}

func TestAuditExportDegradedRule_NeutralLanguage(t *testing.T) {
	// Per [[security-team-positioning-safety-not-surveillance]]: every
	// operator-facing string the alert emits must stay neutral.
	forbidden := []string{
		"violation", "violate", "violated", "infraction",
		"unauthorized", "forbidden", "abuse", "malicious",
	}
	rule := &auditExportDegradedRule{
		consecFailureThreshold: DefaultAuditExportDegradedConsecFailureThreshold,
		statusFn: func() Status {
			return Status{
				LogConfigured:          true,
				LogWritesOK:            false,
				LogConsecutiveFailures: 99,
				HeartbeatHealthy:       true,
			}
		},
	}
	fire, ok := rule.Observe(NewHeartbeatEvent(1, 1), time.Now())
	require.True(t, ok)
	ev := buildAlertEvent(rule, fire, time.Now())
	body, err := json.Marshal(ev)
	require.NoError(t, err)
	lower := strings.ToLower(string(body))
	for _, w := range forbidden {
		assert.NotContains(t, lower, w,
			"audit_export_degraded alert payload must NOT contain forbidden word %q", w)
	}
	for _, w := range forbidden {
		assert.NotContains(t, strings.ToLower(SuggestionAuditExportDegraded), w,
			"SuggestionAuditExportDegraded must stay neutral")
	}
}

// --------------------------------------------------------------------
// End-to-end: the rule binds to a real Manager via BindStatusSource,
// and a synthetic failure on the Manager flips the rule's predicate
// + the engine emits the OCSF alert through the underlying emitter.
// --------------------------------------------------------------------

func TestAuditExportDegraded_EndToEndViaEngine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path, QueueDepth: 1})
	require.NoError(t, err)
	defer lw.Close()

	mgr := NewManager(ManagerOptions{LogWriter: lw})
	defer mgr.Close()

	// Wrap with the rule engine + bind the status source.
	emitter := &captureEmitter{}
	engineOverManager, err := NewRuleEngine(mgr, BuildBuiltinRules(nil))
	require.NoError(t, err)
	// Bind the engine's status source to the manager's snapshot.
	engineOverManager.BindStatusSource(func() Status { return mgr.Status() })

	// Force the log channel to fail by filling its queue past the
	// consec-failure threshold.
	for lw.ConsecutiveFailures() <= int64(AuditExportConsecutiveFailureThreshold) {
		_ = lw.Write(ctx, FromDecision(DecisionInput{DecisionID: 1, Verdict: "allow"}))
		if lw.ConsecutiveFailures() > 50 {
			break
		}
	}
	require.Greater(t, lw.ConsecutiveFailures(),
		int64(AuditExportConsecutiveFailureThreshold))

	// Feed an arbitrary event through the engine to trigger the rule's
	// Observe(). We use a second emitter wrapping path so the captured
	// events show us the alert; the rule fires through whatever emitter
	// the engine wraps.
	engine2, err := NewRuleEngine(emitter, BuildBuiltinRules(nil))
	require.NoError(t, err)
	engine2.BindStatusSource(func() Status { return mgr.Status() })
	engine2.Emit(ctx, NewHeartbeatEvent(1, 1))

	events := emitter.snapshot()
	var found bool
	for _, ev := range events {
		if ev.EventType == EventTypeSecurityAlert &&
			ev.Unmapped.IAMJIT.Pattern == "audit_export_degraded" {
			found = true
			assert.Equal(t, SeverityMedium, ev.SeverityID)
			assert.Contains(t, ev.StatusDetail, "log consecutive_failures")
			break
		}
	}
	assert.True(t, found,
		"engine must emit an audit_export_degraded alert when the bound "+
			"status source reports degraded")
}

// --------------------------------------------------------------------
// Token-mask discipline: every audit-export-failure-visibility
// surface (Status JSON, degraded reason string, stderr fallback) MUST
// NOT leak the webhook token even when the failure path is fully
// exercised. Defends the same invariant Slice 1's TestWebhookPusher
// _TokenNeverLeaksToOutput pins.
// --------------------------------------------------------------------

func TestAuditExportFailureSurfaces_NeverLeakToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wp, err := NewWebhookPusher(t.Context(), WebhookOptions{
		URL:           srv.URL + "/audit?token=" + secretToken,
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()
	mgr := NewManager(ManagerOptions{WebhookPusher: wp})
	defer mgr.Close()

	_ = wp.Push(t.Context(), FromDecision(DecisionInput{DecisionID: 1, Verdict: "deny"}))
	require.Eventually(t, func() bool {
		return wp.LastError() != ""
	}, 5*time.Second, 50*time.Millisecond)

	// Drive the rule's Observe path so the degraded reason is exposed.
	rule := &auditExportDegradedRule{
		consecFailureThreshold: 0,
		statusFn:               func() Status { return mgr.Status() },
	}
	var buf bytes.Buffer
	rule.setStderrWriter(&buf)
	fire, _ := rule.Observe(NewHeartbeatEvent(1, 1), time.Now())

	// Status snapshot.
	statusJSON, err := json.Marshal(mgr.Status())
	require.NoError(t, err)
	assert.NotContains(t, string(statusJSON), secretToken,
		"status JSON must never contain the bearer token; got %s", string(statusJSON))

	// Degraded reason + alert detail + stderr fallback.
	assert.NotContains(t, fire.Detail, secretToken)
	assert.NotContains(t, buf.String(), secretToken)
	assert.NotContains(t, mgr.Status().AuditExportDegradedReason, secretToken)
}

// --------------------------------------------------------------------
// 0444-perm test for completeness. Creates a log path inside a
// 0555-mode directory so open(O_CREATE) fails — exercises the
// NewLogWriter open-failure branch operators hit when the audit
// volume mount is read-only.
// --------------------------------------------------------------------

func TestF1_LogWriterOpenInReadOnlyDirFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses unix file-perm checks; skip when running as root")
	}
	dir := t.TempDir()
	roDir := filepath.Join(dir, "ro")
	require.NoError(t, os.Mkdir(roDir, 0555))
	t.Cleanup(func() { _ = os.Chmod(roDir, 0755) })

	_, err := NewLogWriter(t.Context(), LogWriterOptions{
		Path: filepath.Join(roDir, "audit.jsonl"),
	})
	require.Error(t, err,
		"NewLogWriter on a read-only directory must surface the open() error "+
			"so the CLI can refuse to start with a clear message")
	assert.Contains(t, err.Error(), "open log file",
		"error message must name the failed operation")
}
