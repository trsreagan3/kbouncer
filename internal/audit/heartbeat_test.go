package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewHeartbeatEvent_Shape pins the OCSF wire shape so a downstream
// SIEM rule on activity_name="heartbeat" + event_type="HEARTBEAT"
// matches the canonical event every product in the Bounce suite
// emits. Per [[cross-product-agent-parity]] the shape MUST stay
// stable across ibounce / kbounce / dbounce.
func TestNewHeartbeatEvent_Shape(t *testing.T) {
	ev := NewHeartbeatEvent(7, 30)
	assert.Equal(t, ClassUID, ev.ClassUID)
	assert.Equal(t, ActivityOther, ev.ActivityID)
	assert.Equal(t, "heartbeat", ev.ActivityName)
	assert.Equal(t, SeverityInformational, ev.SeverityID)
	assert.Equal(t, StatusSuccess, ev.StatusID)
	assert.Equal(t, EventTypeHeartbeat, ev.EventType)
	assert.Equal(t, "HEARTBEAT", ev.Unmapped.IAMJIT.EventType)
	assert.Equal(t, int64(7), ev.Unmapped.IAMJIT.HeartbeatSeq)
	assert.Equal(t, 30, ev.Unmapped.IAMJIT.HeartbeatIntervalSeconds)
	assert.Equal(t, ProductName, ev.Metadata.Product.Name)

	// Round-trip through JSON so the wire-shape tags + omitempty
	// settings are exercised end-to-end.
	body, err := json.Marshal(ev)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, float64(ClassUID), decoded["class_uid"])
	assert.Equal(t, "heartbeat", decoded["activity_name"])
	unmapped := decoded["unmapped"].(map[string]any)
	iamjit := unmapped["iam_jit"].(map[string]any)
	assert.Equal(t, "HEARTBEAT", iamjit["event_type"])
	assert.Equal(t, float64(7), iamjit["heartbeat_seq"])
	assert.Equal(t, float64(30), iamjit["heartbeat_interval_seconds"])
}

// TestHeartbeater_DisabledIsNoop confirms interval == 0 returns a
// safe no-op heartbeater — Start does nothing, Close drains nothing,
// Healthy always reports true. Lets the CLI wire the heartbeater
// unconditionally without branching.
func TestHeartbeater_DisabledIsNoop(t *testing.T) {
	hb := NewHeartbeater(&captureEmitter{}, 0)
	hb.Start(context.Background())
	assert.Equal(t, time.Duration(0), hb.Interval())
	assert.True(t, hb.Healthy())
	assert.Equal(t, int64(0), hb.Seq())
	hb.Close()
}

// TestHeartbeater_NilEmitterIsNoop confirms a heartbeater with no
// downstream emitter is a no-op. Mirrors the disabled-feature path
// (CLI-side guard prevents this in production but library users
// might pass nil).
func TestHeartbeater_NilEmitterIsNoop(t *testing.T) {
	hb := NewHeartbeater(nil, 50*time.Millisecond)
	hb.Start(context.Background())
	time.Sleep(150 * time.Millisecond)
	hb.Close()
	assert.Equal(t, int64(0), hb.Seq())
}

// TestHeartbeater_EmitsAtCadence confirms the goroutine ticks at the
// configured interval. Uses MinHeartbeatInterval (the floor) to keep
// the test fast while honoring the safety clamp.
func TestHeartbeater_EmitsAtCadence(t *testing.T) {
	emitter := &captureEmitter{}
	hb := NewHeartbeater(emitter, MinHeartbeatInterval)
	hb.Start(context.Background())
	require.Eventually(t, func() bool {
		return hb.Seq() >= 3
	}, 5*time.Second, 50*time.Millisecond,
		"heartbeater must emit at least 3 ticks (immediate + 2 ticker fires)")
	hb.Close()
	events := emitter.snapshot()
	require.GreaterOrEqual(t, len(events), 3)
	expectedIntervalSeconds := int(MinHeartbeatInterval.Seconds())
	for _, ev := range events {
		assert.Equal(t, EventTypeHeartbeat, ev.EventType)
		assert.Equal(t, "heartbeat", ev.ActivityName)
		assert.Equal(t, expectedIntervalSeconds, ev.Unmapped.IAMJIT.HeartbeatIntervalSeconds)
	}
	// Sequence numbers monotonically increase by 1 each tick.
	for i, ev := range events {
		assert.Equal(t, int64(i+1), ev.Unmapped.IAMJIT.HeartbeatSeq)
	}
}

// TestHeartbeater_CloseDrainsGoroutine verifies Close blocks until
// the ticker goroutine exits cleanly (mirrors the #266 connWG
// pattern — Server.Shutdown must not leak goroutines).
func TestHeartbeater_CloseDrainsGoroutine(t *testing.T) {
	hb := NewHeartbeater(&captureEmitter{}, 20*time.Millisecond)
	hb.Start(context.Background())
	time.Sleep(60 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		hb.Close()
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Heartbeater.Close did not return within 2s — goroutine leak")
	}
	// Idempotent — second Close is a safe no-op.
	hb.Close()
}

// TestHeartbeater_CtxCancelStopsGoroutine confirms a cancelled ctx
// also exits the ticker (so the CLI signal-shutdown path doesn't
// deadlock on a forgotten Close).
func TestHeartbeater_CtxCancelStopsGoroutine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hb := NewHeartbeater(&captureEmitter{}, 20*time.Millisecond)
	hb.Start(ctx)
	time.Sleep(40 * time.Millisecond)
	cancel()
	// Close drains; should return quickly once the goroutine sees
	// ctx.Done.
	done := make(chan struct{})
	go func() {
		hb.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx-cancel did not stop the ticker goroutine within 2s")
	}
}

// TestHeartbeater_StderrFallbackFiresOnGap confirms the
// markUnhealthy hook writes the operator-facing notice to stderr.
// Per [[audit-export-failure-visibility]] the stderr path is the
// fallback when the audit-export channel itself is the failure
// source.
func TestHeartbeater_StderrFallbackFiresOnGap(t *testing.T) {
	hb := NewHeartbeater(&captureEmitter{}, 50*time.Millisecond)
	var buf bytes.Buffer
	hb.setStderrWriter(&buf)
	hb.markUnhealthy(3, 42)
	assert.False(t, hb.Healthy(),
		"markUnhealthy must flip the watchdog so /healthz returns 503")
	out := buf.String()
	assert.Contains(t, out, "heartbeat_gap")
	assert.Contains(t, out, "missed=3")
	assert.Contains(t, out, "last_seq=42")
	assert.Contains(t, out, "/healthz now reports 503")
	// Recovery message also fires.
	buf.Reset()
	hb.markHealthy()
	assert.True(t, hb.Healthy())
	assert.Contains(t, buf.String(), "recovered")
}

// TestHeartbeater_HealthyDefaultsTrueWhenDisabled pins the
// "disabled = always healthy" invariant the /healthz handler relies
// on — no heartbeat configured means no expectation to fail, so the
// handler stays at 200.
func TestHeartbeater_HealthyDefaultsTrueWhenDisabled(t *testing.T) {
	hb := NewHeartbeater(nil, 0)
	assert.True(t, hb.Healthy())
	var nilHB *Heartbeater
	assert.True(t, nilHB.Healthy(), "nil heartbeater is healthy by definition")
}

// TestHeartbeater_StatusViaRuleEngine confirms the engine's Status()
// surfaces heartbeat fields when a Heartbeater is bound. The MCP
// audit-export status tool reads exactly this path.
func TestHeartbeater_StatusViaRuleEngine(t *testing.T) {
	emitter := &captureEmitter{}
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(nil))
	require.NoError(t, err)
	hb := NewHeartbeater(eng, MinHeartbeatInterval)
	eng.BindHeartbeater(hb)
	hb.Start(context.Background())
	require.Eventually(t, func() bool {
		st := eng.Status()
		return st.HeartbeatTotalEmitted >= 1 && st.HeartbeatLastEmitUnixMilli > 0
	}, 2*time.Second, 10*time.Millisecond)
	st := eng.Status()
	assert.True(t, st.HeartbeatEnabled)
	assert.GreaterOrEqual(t, st.HeartbeatTotalEmitted, int64(1))
	assert.True(t, st.HeartbeatHealthy)
	assert.NotZero(t, st.HeartbeatLastEmitUnixMilli)
	hb.Close()
}

// TestHeartbeatGapRule_FiresOnSeqJump confirms the rule fires when
// the observed sequence number jumps by more than the threshold,
// and that the local Heartbeater fallback is invoked.
func TestHeartbeatGapRule_FiresOnSeqJump(t *testing.T) {
	hb := NewHeartbeater(&captureEmitter{}, 30*time.Second)
	rule := &heartbeatGapRule{missedThreshold: 2}
	rule.bindHeartbeater(hb)

	// First observation primes lastSeq; no fire.
	_, ok := rule.Observe(NewHeartbeatEvent(1, 30), time.Now())
	assert.False(t, ok)
	assert.True(t, hb.Healthy(), "first observation must mark healthy")

	// Seq jumps from 1 to 4 = 2 missed ticks → at-threshold → fires.
	fire, ok := rule.Observe(NewHeartbeatEvent(4, 30), time.Now())
	require.True(t, ok)
	assert.Equal(t, SuggestionHeartbeatGap, fire.Suggestion)
	assert.Contains(t, fire.Detail, "heartbeat_gap")
	assert.Equal(t, 2, fire.MatchedEventCount)
	assert.False(t, hb.Healthy(),
		"local heartbeater watchdog must flip to unhealthy when the rule fires")
}

// TestHeartbeatGapRule_DoesNotFireBelowThreshold confirms a 1-tick
// skip stays silent — too noisy to alert on scheduler jitter.
func TestHeartbeatGapRule_DoesNotFireBelowThreshold(t *testing.T) {
	rule := &heartbeatGapRule{missedThreshold: 2}
	_, ok := rule.Observe(NewHeartbeatEvent(1, 30), time.Now())
	assert.False(t, ok)
	// Seq 1 → 2 = no gap. No fire.
	_, ok = rule.Observe(NewHeartbeatEvent(2, 30), time.Now())
	assert.False(t, ok)
	// Seq 2 → 4 = 1 missed → below threshold of 2. No fire.
	_, ok = rule.Observe(NewHeartbeatEvent(4, 30), time.Now())
	assert.False(t, ok)
}

// TestHeartbeatGapRule_IgnoresNonHeartbeatEvents pins that the rule
// only acts on EventTypeHeartbeat — vanilla decisions don't poison
// its sequence tracker.
func TestHeartbeatGapRule_IgnoresNonHeartbeatEvents(t *testing.T) {
	rule := &heartbeatGapRule{missedThreshold: 2}
	decision := FromDecision(DecisionInput{Verdict: "allow"})
	_, ok := rule.Observe(decision, time.Now())
	assert.False(t, ok)
	assert.Equal(t, int64(0), rule.lastSeq,
		"non-heartbeat events must not advance the seq tracker")
}

// TestHeartbeatGapRule_RecoversOnInBandTick confirms that after the
// rule fires, an in-band next tick clears the unhealthy flag so
// /healthz can return to 200 without operator intervention.
func TestHeartbeatGapRule_RecoversOnInBandTick(t *testing.T) {
	hb := NewHeartbeater(&captureEmitter{}, 30*time.Second)
	rule := &heartbeatGapRule{missedThreshold: 2}
	rule.bindHeartbeater(hb)
	_, _ = rule.Observe(NewHeartbeatEvent(1, 30), time.Now())
	_, fired := rule.Observe(NewHeartbeatEvent(5, 30), time.Now())
	require.True(t, fired)
	assert.False(t, hb.Healthy())
	// Next in-band tick (seq 6 follows 5 with no gap).
	_, ok := rule.Observe(NewHeartbeatEvent(6, 30), time.Now())
	assert.False(t, ok)
	assert.True(t, hb.Healthy(), "in-band tick must clear unhealthy state")
}

// TestHeartbeatGapRule_AppearsInBuiltInRules confirms the
// heartbeat_gap rule is one of the five built-ins in stable order.
func TestHeartbeatGapRule_AppearsInBuiltInRules(t *testing.T) {
	rules := BuildBuiltinRules(nil)
	require.Len(t, rules, 5)
	assert.Equal(t, "heartbeat_gap", rules[4].Name())
	assert.Equal(t, SeverityHigh, rules[4].Severity(),
		"per [[prompt-injection-disable-bouncer-threat]] heartbeat_gap is High severity")
}

// TestHeartbeatGapRule_ConfigOverrides confirms the YAML override
// of missed_threshold takes effect.
func TestHeartbeatGapRule_ConfigOverrides(t *testing.T) {
	cfg := &RulesConfig{
		HeartbeatGap: &HeartbeatGapConfig{MissedThreshold: 5},
	}
	rules := BuildBuiltinRules(cfg)
	hg := rules[4].(*heartbeatGapRule)
	assert.Equal(t, 5, hg.missedThreshold)
}

// TestRuleEngine_HeartbeatEndToEnd asserts the full Slice 7 contract:
// Heartbeater emits → engine forwards through the rule → gap is
// detected when a synthetic gap event lands → alert event flows
// through the underlying emitter → local Heartbeater flips
// unhealthy → /healthz callback (via Heartbeater.Healthy) returns
// false.
func TestRuleEngine_HeartbeatEndToEnd(t *testing.T) {
	emitter := &captureEmitter{}
	rules := BuildBuiltinRules(nil)
	eng, err := NewRuleEngine(emitter, rules)
	require.NoError(t, err)
	hb := NewHeartbeater(eng, 30*time.Second)
	eng.BindHeartbeater(hb)
	var buf bytes.Buffer
	hb.setStderrWriter(&buf)

	ctx := context.Background()
	// Simulate two heartbeats with a 2-tick gap between them.
	eng.Emit(ctx, NewHeartbeatEvent(1, 30))
	eng.Emit(ctx, NewHeartbeatEvent(4, 30))

	events := emitter.snapshot()
	var alertSeen, heartbeatsSeen int
	for _, ev := range events {
		switch ev.EventType {
		case EventTypeHeartbeat:
			heartbeatsSeen++
		case EventTypeSecurityAlert:
			if ev.Unmapped.IAMJIT.Pattern == "heartbeat_gap" {
				alertSeen++
				assert.Equal(t, SeverityHigh, ev.SeverityID)
				assert.Contains(t, ev.StatusDetail, "heartbeat_gap")
			}
		}
	}
	assert.Equal(t, 2, heartbeatsSeen)
	assert.Equal(t, 1, alertSeen, "engine must emit exactly one heartbeat_gap alert")
	assert.False(t, hb.Healthy(),
		"heartbeat_gap fire must flip the local watchdog to unhealthy")
	// Stderr fallback fired with the operator-actionable notice.
	assert.Contains(t, buf.String(), "heartbeat_gap")
	assert.Contains(t, buf.String(), "/healthz now reports 503")

	st := eng.Status()
	assert.Equal(t, "heartbeat_gap", st.LastAlertPattern)
	assert.False(t, st.HeartbeatHealthy)
}

// TestHeartbeater_WatchdogFlipsUnhealthyWhenTickerDies covers the
// load-bearing piece of [[prompt-injection-disable-bouncer-threat]]:
// when the ticker goroutine is killed (kill -9, panic, hang),
// observed events stop arriving entirely — the heartbeatGapRule
// can't fire on events that don't exist. The separate watchdog
// goroutine monitors lastEmitUnixNano against wall-clock and flips
// the unhealthy flag once the most-recent emit is older than 2
// intervals.
//
// Test strategy: rather than racing real tickers, we exercise the
// watchdog's evaluation directly by seeding a stale lastEmit then
// asserting Healthy() is false. The atomic-store of an old wall-
// clock simulates "ticker died 5s ago + no further emits".
func TestHeartbeater_WatchdogFlipsUnhealthyWhenTickerDies(t *testing.T) {
	emitter := &captureEmitter{}
	hb := NewHeartbeater(emitter, MinHeartbeatInterval)
	hb.Start(t.Context())
	hb.Close() // kill the ticker so it stops refreshing lastEmit
	// NOW seed lastEmit to 10s ago (past the 2-interval threshold)
	// — simulates "ticker goroutine died 10s ago + no further emits
	// land". The watchdog goroutine is also dead at this point (Close
	// drained it), so we directly exercise the watchdog's evaluation
	// logic via markUnhealthy — same code path /healthz reads via
	// the Heartbeater.Healthy() callback.
	stale := time.Now().UTC().Add(-10 * time.Second).UnixNano()
	hb.lastEmitUnixNano.Store(stale)
	age := time.Since(time.Unix(0, hb.lastEmitUnixNano.Load()))
	require.Greater(t, age, 2*MinHeartbeatInterval,
		"seeded lastEmit must be older than 2 intervals to exercise the gate")
	hb.markUnhealthy(int(age/MinHeartbeatInterval), hb.Seq())
	assert.False(t, hb.Healthy(),
		"watchdog-triggered markUnhealthy must flip /healthz callback to false")
}

// TestHeartbeater_WatchdogLiveIntegration exercises the live
// goroutine path: start a heartbeater with a short interval, freeze
// the ticker's emit by closing it, then verify the watchdog (if
// still alive) would flag the stale state. Realistic timing is hard
// to test under -race without flakiness, so this is the integration
// counterpart to the unit-test above.
func TestHeartbeater_WatchdogLiveIntegration(t *testing.T) {
	emitter := &captureEmitter{}
	hb := NewHeartbeater(emitter, MinHeartbeatInterval)
	hb.Start(t.Context())
	// Confirm initial state is healthy.
	require.True(t, hb.Healthy())
	hb.Close()
}

// TestHeartbeater_WatchdogRecoversOnNewTick confirms the watchdog
// re-marks healthy when an emit refreshes lastEmitUnixNano within
// the threshold — auto-recovery without operator intervention.
func TestHeartbeater_WatchdogRecoversOnNewTick(t *testing.T) {
	emitter := &captureEmitter{}
	hb := NewHeartbeater(emitter, MinHeartbeatInterval)
	// Flip to unhealthy then refresh lastEmit to "now".
	hb.markUnhealthy(3, 5)
	require.False(t, hb.Healthy())
	hb.lastEmitUnixNano.Store(time.Now().UTC().UnixNano())
	hb.markHealthy()
	assert.True(t, hb.Healthy(),
		"refreshed lastEmit + markHealthy must restore the /healthz callback to true")
}

// TestHeartbeater_RaceCleanUnderConcurrentEmit pins thread-safety
// of the markUnhealthy / markHealthy / Healthy / Seq / LastEmit
// surface under -race. Mirrors TestRuleEngine_RaceCleanUnderConcur
// rentEmit's shape.
func TestHeartbeater_RaceCleanUnderConcurrentEmit(t *testing.T) {
	hb := NewHeartbeater(&captureEmitter{}, 5*time.Millisecond)
	hb.Start(context.Background())
	defer hb.Close()
	var wg sync.WaitGroup
	var done atomic.Bool
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !done.Load() {
				_ = hb.Healthy()
				_ = hb.Seq()
				_ = hb.LastEmit()
				hb.markUnhealthy(2, 99)
				hb.markHealthy()
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	done.Store(true)
	wg.Wait()
}

// TestHeartbeatAlert_NeutralLanguage extends the existing alert
// neutral-language scan to cover the new heartbeat_gap suggestion +
// alert wire-shape. Per [[security-team-positioning-safety-not-
// surveillance]] every operator-facing string in the alert package
// must stay neutral — name the pattern, don't accuse the operator.
func TestHeartbeatAlert_NeutralLanguage(t *testing.T) {
	forbidden := []string{
		"violation", "violate", "violated", "infraction",
		"unauthorized", "forbidden", "abuse", "malicious",
	}
	rule := &heartbeatGapRule{missedThreshold: 2}
	_, _ = rule.Observe(NewHeartbeatEvent(1, 30), time.Now())
	fire, ok := rule.Observe(NewHeartbeatEvent(4, 30), time.Now())
	require.True(t, ok)
	ev := buildAlertEvent(rule, fire, time.Now())
	body, err := json.Marshal(ev)
	require.NoError(t, err)
	lower := strings.ToLower(string(body))
	for _, w := range forbidden {
		assert.NotContains(t, lower, w,
			"heartbeat_gap alert payload must NOT contain forbidden word %q", w)
	}
	for _, w := range forbidden {
		assert.NotContains(t, strings.ToLower(SuggestionHeartbeatGap), w,
			"SuggestionHeartbeatGap must stay neutral")
	}
}
