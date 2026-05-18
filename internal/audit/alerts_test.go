package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------

// adminFallbackEvent builds a decision event marked as a pause-bypass
// / admin-fallback grant. Used by admin_fallback_burst + pause_long
// rule tests so the per-rule predicate fires.
func adminFallbackEvent(at time.Time) Event {
	return FromDecision(DecisionInput{
		At:            at,
		DecisionID:    1,
		Mode:          "cooperative",
		Verdict:       "deny",
		Reason:        "rule-X",
		Profile:       "safe-default",
		ParsedVerb:    "delete",
		AdminFallback: true,
	})
}

// vanillaDecisionEvent builds a plain decision event (no admin-fallback,
// no high-risk subresource) so rules that should NOT fire stay silent.
func vanillaDecisionEvent(at time.Time) Event {
	return FromDecision(DecisionInput{
		At:         at,
		DecisionID: 2,
		Mode:       "cooperative",
		Verdict:    "allow",
		ParsedVerb: "get",
	})
}

// transparentDenyEvent builds an enforced transparent-mode DENY event
// with the given subresource / resource fields populated so the
// unusual_high_risk_action rule has something to match against.
func transparentDenyEvent(subresource, verb, resource, namespace, name string) Event {
	return FromDecision(DecisionInput{
		At:                time.Now().UTC(),
		DecisionID:        99,
		Mode:              "transparent",
		Verdict:           "deny",
		Reason:            "rule-Y",
		Enforced:          true,
		ParsedVerb:        verb,
		ParsedResource:    resource,
		ParsedNamespace:   namespace,
		ParsedName:        name,
		ParsedSubresource: subresource,
	})
}

// profileSourceEvent builds an event whose active profile was
// installed from the given URL.
func profileSourceEvent(profileName, source string) Event {
	return FromDecision(DecisionInput{
		At:            time.Now().UTC(),
		DecisionID:    7,
		Mode:          "cooperative",
		Verdict:       "allow",
		Profile:       profileName,
		ProfileSource: source,
		ParsedVerb:    "get",
	})
}

// ---------------------------------------------------------------------
// admin_fallback_burst rule
// ---------------------------------------------------------------------

func TestAdminFallbackBurst_FiresAboveThreshold(t *testing.T) {
	r := &adminFallbackBurstRule{
		threshold: DefaultAdminFallbackBurstThreshold,
		window:    DefaultAdminFallbackBurstWindow,
	}
	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	// First 3 events do NOT fire (threshold is "more than 3").
	for i := 0; i < 3; i++ {
		_, ok := r.Observe(adminFallbackEvent(base.Add(time.Duration(i)*time.Minute)), base.Add(time.Duration(i)*time.Minute))
		assert.False(t, ok, "event %d should not fire", i)
	}
	// 4th event fires.
	fire, ok := r.Observe(adminFallbackEvent(base.Add(3*time.Minute)), base.Add(3*time.Minute))
	require.True(t, ok, "4th admin-fallback event in 5min window should fire")
	assert.Equal(t, 4, fire.MatchedEventCount)
	assert.Equal(t, 300, fire.WindowSeconds)
	assert.Contains(t, fire.Detail, "admin_fallback_burst")
	assert.Contains(t, fire.Suggestion, "broader scope")
}

func TestAdminFallbackBurst_SlidingWindowDropsOldEvents(t *testing.T) {
	r := &adminFallbackBurstRule{
		threshold: DefaultAdminFallbackBurstThreshold,
		window:    DefaultAdminFallbackBurstWindow,
	}
	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	// 3 events in window.
	for i := 0; i < 3; i++ {
		_, _ = r.Observe(adminFallbackEvent(base.Add(time.Duration(i)*time.Minute)), base.Add(time.Duration(i)*time.Minute))
	}
	// Jump forward past the window. New event should be the only one in
	// the active set; rule must NOT fire.
	later := base.Add(20 * time.Minute)
	_, ok := r.Observe(adminFallbackEvent(later), later)
	assert.False(t, ok, "events outside the 5min window must be dropped")
}

func TestAdminFallbackBurst_IgnoresNonAdminFallbackEvents(t *testing.T) {
	r := &adminFallbackBurstRule{
		threshold: DefaultAdminFallbackBurstThreshold,
		window:    DefaultAdminFallbackBurstWindow,
	}
	for i := 0; i < 100; i++ {
		_, ok := r.Observe(vanillaDecisionEvent(time.Now()), time.Now())
		require.False(t, ok)
	}
}

func TestAdminFallbackBurst_ResetsAfterFire(t *testing.T) {
	r := &adminFallbackBurstRule{
		threshold: DefaultAdminFallbackBurstThreshold,
		window:    DefaultAdminFallbackBurstWindow,
	}
	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		_, _ = r.Observe(adminFallbackEvent(base.Add(time.Duration(i)*time.Second)), base.Add(time.Duration(i)*time.Second))
	}
	// Now the next 3 events should NOT immediately re-fire (buffer reset).
	for i := 0; i < 3; i++ {
		_, ok := r.Observe(adminFallbackEvent(base.Add(time.Duration(10+i)*time.Second)), base.Add(time.Duration(10+i)*time.Second))
		assert.False(t, ok, "event %d post-fire reset should not refire", i)
	}
}

// ---------------------------------------------------------------------
// pause_long rule
// ---------------------------------------------------------------------

func TestPauseLong_FiresAboveThresholdSpan(t *testing.T) {
	r := &pauseLongRule{
		threshold: DefaultPauseLongThreshold,
		window:    DefaultPauseLongWindow,
	}
	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	_, ok := r.Observe(adminFallbackEvent(base), base)
	require.False(t, ok, "first admin-fallback event should not fire")
	// 31 minutes later: span exceeds 30min threshold.
	later := base.Add(31 * time.Minute)
	fire, ok := r.Observe(adminFallbackEvent(later), later)
	require.True(t, ok, "pause window spanning >30min must fire")
	assert.Contains(t, fire.Detail, "pause_long")
	assert.Contains(t, fire.Ext, "observed_pause_seconds")
	assert.GreaterOrEqual(t, fire.Ext["observed_pause_seconds"].(int), 30*60)
}

func TestPauseLong_DoesNotFireBelowThreshold(t *testing.T) {
	r := &pauseLongRule{
		threshold: DefaultPauseLongThreshold,
		window:    DefaultPauseLongWindow,
	}
	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	_, _ = r.Observe(adminFallbackEvent(base), base)
	later := base.Add(5 * time.Minute)
	_, ok := r.Observe(adminFallbackEvent(later), later)
	assert.False(t, ok, "5min pause span must not fire 30min threshold")
}

func TestPauseLong_NonFallbackEventResetsTracking(t *testing.T) {
	r := &pauseLongRule{
		threshold: DefaultPauseLongThreshold,
		window:    DefaultPauseLongWindow,
	}
	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	_, _ = r.Observe(adminFallbackEvent(base), base)
	// Vanilla event in the middle — the pause window is "interrupted".
	_, _ = r.Observe(vanillaDecisionEvent(base.Add(5*time.Minute)), base.Add(5*time.Minute))
	// Now a fallback at +31min: firstAt got reset, so this is the new
	// "first" — should NOT fire.
	_, ok := r.Observe(adminFallbackEvent(base.Add(31*time.Minute)), base.Add(31*time.Minute))
	assert.False(t, ok, "vanilla event must reset the tracked pause window")
}

// ---------------------------------------------------------------------
// non_org_profile_install rule
// ---------------------------------------------------------------------

func TestNonOrgProfileInstall_FiresOnNonAllowlistedURL(t *testing.T) {
	r := &nonOrgProfileInstallRule{
		approved: map[string]struct{}{
			"https://approved.example/profiles.yaml": {},
		},
		fired: map[string]struct{}{},
	}
	ev := profileSourceEvent("rogue", "https://untrusted.example/p.yaml")
	fire, ok := r.Observe(ev, time.Now())
	require.True(t, ok)
	assert.Contains(t, fire.Detail, "non_org_profile_install")
	assert.Equal(t, "https://untrusted.example/p.yaml", fire.Ext["observed_profile_source"])
	assert.Equal(t, "rogue", fire.Ext["observed_profile_name"])
}

func TestNonOrgProfileInstall_DoesNotFireOnAllowlistedURL(t *testing.T) {
	r := &nonOrgProfileInstallRule{
		approved: map[string]struct{}{
			"https://approved.example/profiles.yaml": {},
		},
		fired: map[string]struct{}{},
	}
	ev := profileSourceEvent("org-blessed", "https://approved.example/profiles.yaml")
	_, ok := r.Observe(ev, time.Now())
	assert.False(t, ok)
}

func TestNonOrgProfileInstall_DoesNotFireOnLocalProfile(t *testing.T) {
	r := &nonOrgProfileInstallRule{
		approved: map[string]struct{}{},
		fired:    map[string]struct{}{},
	}
	// Source = "" (default user-edited) → no fire.
	_, ok := r.Observe(vanillaDecisionEvent(time.Now()), time.Now())
	assert.False(t, ok)
	// Source = "local" → no fire.
	ev := profileSourceEvent("user", "local")
	_, ok = r.Observe(ev, time.Now())
	assert.False(t, ok)
}

func TestNonOrgProfileInstall_DedupesPerProfileSource(t *testing.T) {
	r := &nonOrgProfileInstallRule{
		approved: map[string]struct{}{},
		fired:    map[string]struct{}{},
	}
	ev := profileSourceEvent("rogue", "https://untrusted.example/p.yaml")
	_, ok := r.Observe(ev, time.Now())
	require.True(t, ok, "first observation should fire")
	for i := 0; i < 10; i++ {
		_, ok := r.Observe(ev, time.Now())
		assert.False(t, ok, "repeat observations of same (profile, source) must dedupe")
	}
}

// ---------------------------------------------------------------------
// unusual_high_risk_action rule
// ---------------------------------------------------------------------

func TestUnusualHighRiskAction_FiresOnExecDeny(t *testing.T) {
	r := &unusualHighRiskActionRule{
		subresources:     stringSet(DefaultK8sHighRiskSubresources),
		clusterMutations: stringSet(DefaultK8sHighRiskClusterMutations),
	}
	ev := transparentDenyEvent("exec", "create", "pods", "prod", "db-0")
	fire, ok := r.Observe(ev, time.Now())
	require.True(t, ok)
	assert.Contains(t, fire.Detail, "unusual_high_risk_action")
	assert.Equal(t, "subresource", fire.Ext["observed_kind"])
	assert.Equal(t, "exec", fire.Ext["observed_subresource"])
}

func TestUnusualHighRiskAction_FiresOnClusterRoleBindingDelete(t *testing.T) {
	r := &unusualHighRiskActionRule{
		subresources:     stringSet(DefaultK8sHighRiskSubresources),
		clusterMutations: stringSet(DefaultK8sHighRiskClusterMutations),
	}
	ev := transparentDenyEvent("", "delete", "clusterrolebindings", "", "bind-admin")
	fire, ok := r.Observe(ev, time.Now())
	require.True(t, ok)
	assert.Equal(t, "cluster_mutation", fire.Ext["observed_kind"])
	assert.Equal(t, "clusterrolebindings", fire.Ext["observed_resource"])
}

func TestUnusualHighRiskAction_DoesNotFireOnCooperativeDeny(t *testing.T) {
	r := &unusualHighRiskActionRule{
		subresources:     stringSet(DefaultK8sHighRiskSubresources),
		clusterMutations: stringSet(DefaultK8sHighRiskClusterMutations),
	}
	ev := FromDecision(DecisionInput{
		Mode:              "cooperative",
		Verdict:           "deny",
		Enforced:          false,
		ParsedVerb:        "create",
		ParsedResource:    "pods",
		ParsedSubresource: "exec",
	})
	_, ok := r.Observe(ev, time.Now())
	assert.False(t, ok, "cooperative-mode advisory DENY must not fire")
}

func TestUnusualHighRiskAction_DoesNotFireOnLowRiskResource(t *testing.T) {
	r := &unusualHighRiskActionRule{
		subresources:     stringSet(DefaultK8sHighRiskSubresources),
		clusterMutations: stringSet(DefaultK8sHighRiskClusterMutations),
	}
	ev := transparentDenyEvent("", "get", "pods", "prod", "db-0")
	_, ok := r.Observe(ev, time.Now())
	assert.False(t, ok)
}

func TestUnusualHighRiskAction_DoesNotFireOnNamespacedDelete(t *testing.T) {
	r := &unusualHighRiskActionRule{
		subresources:     stringSet(DefaultK8sHighRiskSubresources),
		clusterMutations: stringSet(DefaultK8sHighRiskClusterMutations),
	}
	// `delete pods` in a namespace is not in the cluster-mutation set.
	ev := transparentDenyEvent("", "delete", "pods", "default", "p1")
	_, ok := r.Observe(ev, time.Now())
	assert.False(t, ok)
}

// ---------------------------------------------------------------------
// YAML config loading
// ---------------------------------------------------------------------

func TestLoadRulesConfig_EmptyPathOK(t *testing.T) {
	cfg, err := LoadRulesConfig("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Nil(t, cfg.AdminFallbackBurst)
}

func TestLoadRulesConfig_ParsesOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	yaml := `
admin_fallback_burst:
  threshold: 10
  window_seconds: 600
pause_long:
  threshold_seconds: 900
non_org_profile_install:
  approved_urls:
    - https://internal.example/profiles.yaml
    - https://internal.example/staging.yaml
unusual_high_risk_action:
  high_risk_subresources:
    - exec
    - portforward
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	cfg, err := LoadRulesConfig(path)
	require.NoError(t, err)
	require.NotNil(t, cfg.AdminFallbackBurst)
	assert.Equal(t, 10, cfg.AdminFallbackBurst.Threshold)
	assert.Equal(t, 600, cfg.AdminFallbackBurst.WindowSeconds)
	require.NotNil(t, cfg.PauseLong)
	assert.Equal(t, 900, cfg.PauseLong.ThresholdSeconds)
	require.NotNil(t, cfg.NonOrgProfileInstall)
	assert.Len(t, cfg.NonOrgProfileInstall.ApprovedURLs, 2)
	require.NotNil(t, cfg.UnusualHighRiskAction)
	assert.Equal(t, []string{"exec", "portforward"}, cfg.UnusualHighRiskAction.HighRiskSubresources)
}

func TestLoadRulesConfig_MalformedYAMLErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("not: valid: yaml: ::"), 0o600))
	_, err := LoadRulesConfig(path)
	require.Error(t, err)
}

func TestLoadRulesConfig_MissingFileErrors(t *testing.T) {
	_, err := LoadRulesConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.Error(t, err)
}

func TestBuildBuiltinRules_AppliesOverrides(t *testing.T) {
	cfg := &RulesConfig{
		AdminFallbackBurst: &AdminFallbackBurstConfig{
			Threshold:     10,
			WindowSeconds: 600,
		},
		NonOrgProfileInstall: &NonOrgProfileInstallConfig{
			ApprovedURLs: []string{"https://approved.example/p.yaml"},
		},
	}
	rules := BuildBuiltinRules(cfg)
	require.Len(t, rules, 4)

	// admin_fallback_burst now requires 11+ events to fire.
	afb := rules[0].(*adminFallbackBurstRule)
	assert.Equal(t, 10, afb.threshold)
	assert.Equal(t, 10*time.Minute, afb.window)

	// non_org_profile_install allowlist populated.
	npi := rules[2].(*nonOrgProfileInstallRule)
	_, present := npi.approved["https://approved.example/p.yaml"]
	assert.True(t, present)
}

func TestBuildBuiltinRules_NilConfigUsesDefaults(t *testing.T) {
	rules := BuildBuiltinRules(nil)
	require.Len(t, rules, 4)
	afb := rules[0].(*adminFallbackBurstRule)
	assert.Equal(t, DefaultAdminFallbackBurstThreshold, afb.threshold)
	assert.Equal(t, DefaultAdminFallbackBurstWindow, afb.window)
}

// ---------------------------------------------------------------------
// RuleEngine + end-to-end via httptest webhook
// ---------------------------------------------------------------------

// captureEmitter is a test Emitter that records every event it
// receives so end-to-end engine tests can assert on the resulting
// alert payloads.
type captureEmitter struct {
	mu     sync.Mutex
	events []Event
}

func (c *captureEmitter) Emit(_ context.Context, ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *captureEmitter) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{TotalEvents: int64(len(c.events))}
}

func (c *captureEmitter) snapshot() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, len(c.events))
	copy(out, c.events)
	return out
}

func TestRuleEngine_NilEmitterRejected(t *testing.T) {
	_, err := NewRuleEngine(nil, BuildBuiltinRules(nil))
	require.Error(t, err)
}

func TestRuleEngine_ForwardsDecisionAndEmitsAlert(t *testing.T) {
	emitter := &captureEmitter{}
	rules := BuildBuiltinRules(nil)
	eng, err := NewRuleEngine(emitter, rules)
	require.NoError(t, err)

	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	eng = eng.withClock(func() time.Time { return base })
	ctx := context.Background()
	// 4 admin-fallback events → triggers admin_fallback_burst.
	for i := 0; i < 4; i++ {
		eng.Emit(ctx, adminFallbackEvent(base))
	}

	events := emitter.snapshot()
	// Underlying emitter must see all 4 decisions + the 1 alert.
	require.GreaterOrEqual(t, len(events), 5, "engine must forward decisions + emit alert")

	var alertFound bool
	for _, ev := range events {
		if ev.EventType == EventTypeSecurityAlert {
			alertFound = true
			assert.Equal(t, AlertActivityName, ev.ActivityName)
			assert.Equal(t, ClassUID, ev.ClassUID)
			assert.Equal(t, ActivityOther, ev.ActivityID)
			assert.Equal(t, ClassUID*100+ActivityOther, ev.TypeUID)
			assert.Equal(t, StatusOther, ev.StatusID)
			assert.Equal(t, SeverityMedium, ev.SeverityID)
			assert.Equal(t, "admin_fallback_burst", ev.Unmapped.IAMJIT.Pattern)
			assert.Equal(t, "ANOMALY_DETECTED", ev.Unmapped.IAMJIT.EventType)
		}
	}
	assert.True(t, alertFound, "engine must emit a SECURITY_ALERT event")

	// Status counters updated.
	st := eng.Status()
	assert.True(t, st.AlertsEnabled)
	assert.GreaterOrEqual(t, st.AlertsFiredCount, int64(1))
	assert.Equal(t, "admin_fallback_burst", st.LastAlertPattern)
}

func TestRuleEngine_DoesNotRecurseOnAlertEvents(t *testing.T) {
	emitter := &captureEmitter{}
	rules := BuildBuiltinRules(nil)
	eng, err := NewRuleEngine(emitter, rules)
	require.NoError(t, err)

	alert := buildAlertEvent(&adminFallbackBurstRule{
		threshold: 1,
		window:    time.Minute,
	}, AlertFire{Detail: "test"}, time.Now())
	eng.Emit(context.Background(), alert)

	events := emitter.snapshot()
	require.Len(t, events, 1, "alert events MUST NOT trigger more rules")
}

func TestRuleEngine_RuleNamesExposed(t *testing.T) {
	emitter := &captureEmitter{}
	rules := BuildBuiltinRules(nil)
	eng, err := NewRuleEngine(emitter, rules)
	require.NoError(t, err)
	names := eng.RuleNames()
	assert.Equal(t, []string{
		"admin_fallback_burst",
		"pause_long",
		"non_org_profile_install",
		"unusual_high_risk_action",
	}, names)
}

// TestRuleEngine_EndToEndWebhook is the slice-2 end-to-end contract:
// a sequence of admin-fallback decisions flows through the engine +
// the webhook pusher, and the resulting alert event reaches a real
// HTTPS collector with the expected OCSF shape.
func TestRuleEngine_EndToEndWebhook(t *testing.T) {
	const token = "test-bearer-token-1234567890"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var received atomic.Int64
	var bodies sync.Map // index → string body
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAllBody(r)
		idx := received.Add(1)
		bodies.Store(idx, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wp, err := NewWebhookPusher(ctx, WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         token,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	defer wp.Close()
	mgr := NewManager(ManagerOptions{WebhookPusher: wp})
	defer mgr.Close()

	eng, err := NewRuleEngine(mgr, BuildBuiltinRules(nil))
	require.NoError(t, err)

	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	eng = eng.withClock(func() time.Time { return base })

	for i := 0; i < 4; i++ {
		eng.Emit(ctx, adminFallbackEvent(base))
	}

	// Expect 4 decision events + 1 alert event = 5 webhook POSTs.
	require.Eventually(t, func() bool {
		return received.Load() >= 5
	}, 3*time.Second, 10*time.Millisecond, "webhook must receive decisions + alert")

	// Locate the alert body.
	var alertBody string
	bodies.Range(func(_, v any) bool {
		body := v.(string)
		if strings.Contains(body, "anomaly_detected") {
			alertBody = body
			return false
		}
		return true
	})
	require.NotEmpty(t, alertBody, "must find alert body among delivered events")

	// Token never appears in the alert payload.
	assert.NotContains(t, alertBody, token,
		"alert event body must NEVER contain the webhook Bearer token")

	// Sample-alert-event-shape assertion.
	var arr []map[string]any
	require.NoError(t, json.Unmarshal([]byte(alertBody), &arr))
	require.Len(t, arr, 1)
	alert := arr[0]
	assert.Equal(t, float64(ClassUID), alert["class_uid"])
	assert.Equal(t, float64(ActivityOther), alert["activity_id"])
	assert.Equal(t, AlertActivityName, alert["activity_name"])
	unmapped, ok := alert["unmapped"].(map[string]any)
	require.True(t, ok)
	iamjit, ok := unmapped["iam_jit"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "admin_fallback_burst", iamjit["pattern"])
	assert.Equal(t, "ANOMALY_DETECTED", iamjit["event_type"])
}

// readAllBody slurps an httptest request body fully.
func readAllBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 1024)
	for {
		n, err := r.Body.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			if errors.Is(err, http.ErrBodyReadAfterClose) || err.Error() == "EOF" {
				return buf, nil
			}
			return buf, nil
		}
	}
}

// ---------------------------------------------------------------------
// Concurrency / race
// ---------------------------------------------------------------------

func TestRuleEngine_RaceCleanUnderConcurrentEmit(t *testing.T) {
	emitter := &captureEmitter{}
	rules := BuildBuiltinRules(nil)
	eng, err := NewRuleEngine(emitter, rules)
	require.NoError(t, err)
	ctx := context.Background()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				eng.Emit(ctx, adminFallbackEvent(time.Now()))
				eng.Emit(ctx, vanillaDecisionEvent(time.Now()))
				eng.Emit(ctx, transparentDenyEvent("exec", "create", "pods", "default", "p"))
				eng.Emit(ctx, profileSourceEvent("rogue", "https://untrusted.example/p.yaml"))
			}
		}()
	}
	wg.Wait()
	// Engine status must be queryable concurrent with emits.
	_ = eng.Status()
}

// ---------------------------------------------------------------------
// License-gate placeholder
// ---------------------------------------------------------------------

func TestErrAlertRulesLicenseRequired_ShapesMessage(t *testing.T) {
	require.Error(t, ErrAlertRulesLicenseRequired)
	msg := ErrAlertRulesLicenseRequired.Error()
	assert.Contains(t, msg, "Enterprise")
	assert.Contains(t, msg, "license")
	assert.Contains(t, msg, "#235")
}

// ---------------------------------------------------------------------
// Neutral-language scan per
// [[security-team-positioning-safety-not-surveillance]]
// ---------------------------------------------------------------------

// TestAlertPayload_NeutralLanguage asserts that no alert event body
// from any rule contains the forbidden surveillance-framing words.
// Per the memo, alert wire-shape language stays neutral: we name the
// pattern + report the observation, never accuse the operator of
// "violating" / "infracting" / acting "unauthorized".
func TestAlertPayload_NeutralLanguage(t *testing.T) {
	forbidden := []string{
		"violation",
		"violate",
		"violated",
		"infraction",
		"unauthorized",
		"forbidden",
		"abuse",
		"malicious",
	}

	emitter := &captureEmitter{}
	rules := BuildBuiltinRules(&RulesConfig{
		NonOrgProfileInstall: &NonOrgProfileInstallConfig{},
	})
	eng, err := NewRuleEngine(emitter, rules)
	require.NoError(t, err)
	base := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	eng = eng.withClock(func() time.Time { return base })
	ctx := context.Background()

	// Trigger every rule at least once.
	for i := 0; i < 4; i++ {
		eng.Emit(ctx, adminFallbackEvent(base))
	}
	eng.Emit(ctx, adminFallbackEvent(base.Add(31*time.Minute)))
	eng.Emit(ctx, transparentDenyEvent("exec", "create", "pods", "prod", "db-0"))
	eng.Emit(ctx, profileSourceEvent("rogue", "https://untrusted.example/p.yaml"))

	events := emitter.snapshot()
	var alertsChecked int
	for _, ev := range events {
		if ev.EventType != EventTypeSecurityAlert {
			continue
		}
		alertsChecked++
		body, err := json.Marshal(ev)
		require.NoError(t, err)
		lower := strings.ToLower(string(body))
		for _, w := range forbidden {
			assert.NotContains(t, lower, w,
				"alert event payload must NOT contain forbidden word %q (got %s)", w, string(body))
		}
	}
	require.GreaterOrEqual(t, alertsChecked, 3, "must check at least 3 alert payloads")

	// Also scan static suggestion strings (cheap belt-and-suspenders).
	for _, s := range []string{
		SuggestionAdminFallbackBurst,
		SuggestionPauseLong,
		SuggestionNonOrgProfileInstall,
		SuggestionUnusualHighRiskAction,
	} {
		lower := strings.ToLower(s)
		for _, w := range forbidden {
			assert.NotContains(t, lower, w,
				"suggestion string must stay neutral; %q contains forbidden word %q", s, w)
		}
	}
}

// TestAlertEvent_OmitsTokenLeak — defense-in-depth: build an alert
// directly + assert no field surfaces anything resembling a webhook
// token. The webhook layer's token-masking is asserted separately;
// this guards the alert builder specifically.
func TestAlertEvent_OmitsTokenLeak(t *testing.T) {
	r := &adminFallbackBurstRule{threshold: 1, window: time.Minute}
	fire := AlertFire{
		Detail:            "test detail",
		WindowSeconds:     300,
		MatchedEventCount: 4,
		Suggestion:        SuggestionAdminFallbackBurst,
	}
	ev := buildAlertEvent(r, fire, time.Now())
	body, err := json.Marshal(ev)
	require.NoError(t, err)
	for _, suspicious := range []string{
		"bearer", "Bearer", "Token", "Authorization",
	} {
		assert.NotContains(t, string(body), suspicious,
			"alert event body must not contain credential-shaped field %q", suspicious)
	}
}

// TestRuleEngine_ForwardsAuditDroppedWithoutObserve guards the
// transport-marker bypass: AUDIT_DROPPED events must reach the
// downstream emitter (so consumers see the gap) but MUST NOT trigger
// rule evaluation (they're not decisions).
func TestRuleEngine_ForwardsAuditDroppedWithoutObserve(t *testing.T) {
	emitter := &captureEmitter{}
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(nil))
	require.NoError(t, err)
	dropped := NewDroppedMarker(7)
	eng.Emit(context.Background(), dropped)
	events := emitter.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, EventTypeAuditDropped, events[0].EventType)
}
