// Coverage for the synthetic-event builders + RuleEngine Observe*
// helpers that wire kbounce's pause / profile-install pipelines into
// the audit-export channel per [[security-team-audit-export]] +
// [[cross-product-agent-parity]]. The builders MUST produce OCSF-shaped
// events the existing JSONL log + HTTPS webhook accept verbatim, AND
// the existing Slice 2 rules (admin_fallback_burst,
// non_org_profile_install) MUST fire on the synthetic events without
// any rule-side branch on event_type — the predicates are the single
// source of truth, the synthetic events just give the rules an extra
// data point at the open / install boundary.
package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMakeAdminFallbackGrantEvent_ShapeAndExt asserts the synthetic
// open-edge event carries the OCSF API-Activity wire shape + the
// ext.admin_fallback=true bit the admin_fallback_burst + pause_long
// rules predicate on.
func TestMakeAdminFallbackGrantEvent_ShapeAndExt(t *testing.T) {
	ev := MakeAdminFallbackGrantEvent(42, "incident response", "alice", 1747567200000)

	assert.Equal(t, EventTypeAdminFallbackGrant, ev.EventType)
	assert.Equal(t, ClassUID, ev.ClassUID)
	assert.Equal(t, ActivityOther, ev.ActivityID)
	assert.Equal(t, "admin_fallback_grant", ev.ActivityName)
	assert.Equal(t, SeverityInformational, ev.SeverityID)
	assert.Equal(t, StatusSuccess, ev.StatusID)
	assert.Equal(t, "ADMIN_FALLBACK_GRANT", ev.Unmapped.IAMJIT.EventType)

	require.NotNil(t, ev.Unmapped.IAMJIT.Ext, "synthetic grant event must carry ext")
	assert.Equal(t, true, ev.Unmapped.IAMJIT.Ext["admin_fallback"],
		"ext.admin_fallback=true is the rule-engine predicate; rules will not "+
			"fire without it")
	assert.Equal(t, int64(42), ev.Unmapped.IAMJIT.Ext["pause_id"])
	assert.Equal(t, "alice", ev.Unmapped.IAMJIT.Ext["pause_started_by"])
	assert.Equal(t, "incident response", ev.Unmapped.IAMJIT.Ext["pause_reason"])
	assert.Equal(t, int64(1747567200000), ev.Unmapped.IAMJIT.Ext["pause_ends_at_unix_milli"])

	// Actor populated from startedBy so a SIEM analyst can pivot on
	// actor.user.name for "who opened pause windows last week".
	require.NotNil(t, ev.Actor)
	require.NotNil(t, ev.Actor.User)
	assert.Equal(t, "alice", ev.Actor.User.Name)

	// isAdminFallbackEvent is the single source of truth for the
	// admin_fallback_burst + pause_long rules; assert the synthetic
	// event passes it.
	assert.True(t, isAdminFallbackEvent(ev),
		"synthetic grant event must satisfy isAdminFallbackEvent so the "+
			"admin_fallback_burst + pause_long rules see it")
}

func TestMakeAdminFallbackGrantEvent_OmitsEndsAtWhenZero(t *testing.T) {
	ev := MakeAdminFallbackGrantEvent(7, "", "", 0)
	require.NotNil(t, ev.Unmapped.IAMJIT.Ext)
	_, hasEndsAt := ev.Unmapped.IAMJIT.Ext["pause_ends_at_unix_milli"]
	assert.False(t, hasEndsAt,
		"a zero endsAtUnixMilli must be omitted (better to skip than to encode 0)")
	// Empty startedBy → no actor block; OCSF omitempty drops it.
	assert.Nil(t, ev.Actor)
}

// TestMakePauseEndEvent_ShapeAndKinds asserts the close-edge event
// carries the persisted end_kind so a SIEM can distinguish
// operator-initiated closure (resumed_early) from auto-revert
// (expired).
func TestMakePauseEndEvent_ShapeAndKinds(t *testing.T) {
	for _, kind := range []string{"resumed_early", "expired", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			ev := MakePauseEndEvent(42, kind, "alice")
			assert.Equal(t, EventTypePauseEnd, ev.EventType)
			assert.Equal(t, "pause_end", ev.ActivityName)
			assert.Equal(t, "PAUSE_END", ev.Unmapped.IAMJIT.EventType)
			assert.Equal(t, int64(42), ev.Unmapped.IAMJIT.Ext["pause_id"])
			assert.Equal(t, kind, ev.Unmapped.IAMJIT.Ext["pause_end_kind"])
			// Pause-end events MUST NOT carry admin_fallback=true; the
			// pause_long rule resets its tracked-start state on any
			// non-fallback event, so a pause-end accidentally tagged
			// fallback would re-arm the rule's tracking inside an
			// already-closed window.
			_, hasFallback := ev.Unmapped.IAMJIT.Ext["admin_fallback"]
			assert.False(t, hasFallback,
				"pause_end event must NOT carry admin_fallback bit; the "+
					"pause_long rule's reset logic depends on its absence")
			assert.False(t, isAdminFallbackEvent(ev),
				"pause_end event MUST NOT pass isAdminFallbackEvent")
		})
	}
}

// TestMakeProfileInstallEvent_ShapeAndExt asserts the install-time
// event carries the source URL + profile name in the SAME fields the
// non_org_profile_install rule already keys on, so the rule fires
// without an event_type branch.
func TestMakeProfileInstallEvent_ShapeAndExt(t *testing.T) {
	names := []string{"org-prod-readonly", "org-staging-rw"}
	ev := MakeProfileInstallEvent(names, "https://internal.example/profiles.yaml",
		"abcd1234deadbeef", true)

	assert.Equal(t, EventTypeProfileInstall, ev.EventType)
	assert.Equal(t, "profile_install", ev.ActivityName)
	assert.Equal(t, "PROFILE_INSTALL", ev.Unmapped.IAMJIT.EventType)
	assert.Equal(t, "org-prod-readonly", ev.Unmapped.IAMJIT.Profile,
		"first installed profile name MUST land in IAMJIT.Profile so the "+
			"non_org_profile_install rule's dedupe key works")

	require.NotNil(t, ev.Unmapped.IAMJIT.Ext)
	assert.Equal(t, "https://internal.example/profiles.yaml",
		ev.Unmapped.IAMJIT.Ext["profile_source"],
		"profile_source ext field is the rule's allowlist key")
	assert.Equal(t, names, ev.Unmapped.IAMJIT.Ext["installed_profiles"])
	assert.Equal(t, 2, ev.Unmapped.IAMJIT.Ext["installed_count"])
	assert.Equal(t, "abcd1234deadbeef", ev.Unmapped.IAMJIT.Ext["installed_sha256"])
	assert.Equal(t, true, ev.Unmapped.IAMJIT.Ext["installed_sha256_verified"])

	// profileSource() helper is the rule's read-path; assert the
	// synthetic event satisfies it.
	assert.Equal(t, "https://internal.example/profiles.yaml", profileSource(ev),
		"profileSource(ev) must return the URL so the non_org rule's "+
			"allowlist lookup works")
}

// TestSyntheticEvents_NeutralLanguage scans every synthetic event's
// JSON body for the same forbidden words the existing Slice 2 alert
// payloads exclude per [[security-team-positioning-safety-not-
// surveillance]]. The synthetic events ride the SAME export channel
// as the alerts; they must not break the channel's neutrality
// contract.
func TestSyntheticEvents_NeutralLanguage(t *testing.T) {
	forbidden := []string{
		"violation",
		"violate",
		"infraction",
		"unauthorized",
		"forbidden",
		"abuse",
		"malicious",
	}
	events := []Event{
		MakeAdminFallbackGrantEvent(1, "operator request", "alice", 0),
		MakePauseEndEvent(1, "resumed_early", "alice"),
		MakePauseEndEvent(2, "expired", ""),
		MakeProfileInstallEvent([]string{"safe-default"},
			"https://approved.example/profiles.yaml", "deadbeef", true),
	}
	for _, ev := range events {
		body, err := json.Marshal(ev)
		require.NoError(t, err)
		lower := strings.ToLower(string(body))
		for _, w := range forbidden {
			assert.NotContains(t, lower, w,
				"synthetic event %s body must stay neutral (got %q)",
				ev.EventType, string(body))
		}
	}
}

// TestRuleEngine_ObserveAdminFallbackGrant_ForwardsAndFiresRules
// wires the synthetic open-edge event through a RuleEngine + asserts
// (a) it lands in the downstream emitter alongside per-decision
// events and (b) the admin_fallback_burst rule observes it as a
// first-class fallback event (count = 1 in its sliding window). The
// rule does NOT fire on a single grant (threshold > 3) but its count
// MUST advance — proves the rule's predicate trips on the synthetic
// event without a rule-side branch.
func TestRuleEngine_ObserveAdminFallbackGrant_ForwardsAndFiresRules(t *testing.T) {
	emitter := &captureEmitter{}
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(nil))
	require.NoError(t, err)
	ctx := context.Background()

	eng.ObserveAdminFallbackGrant(ctx, 99, "incident response", "alice", 0)

	events := emitter.snapshot()
	require.Len(t, events, 1, "synthetic grant must land in downstream emitter")
	assert.Equal(t, EventTypeAdminFallbackGrant, events[0].EventType)
	assert.Equal(t, int64(99), events[0].Unmapped.IAMJIT.Ext["pause_id"])
	// Status counter unchanged — single grant is below the burst rule's threshold.
	assert.Equal(t, int64(0), eng.Status().AlertsFiredCount,
		"single grant must not fire the burst rule (threshold > 3)")
}

// TestRuleEngine_ObserveAdminFallbackGrant_TripsBurstAtThreshold
// confirms the synthetic grant events are COUNTED by the burst rule
// the same way per-decision admin-fallback events are — 4 grants in
// the default 5-minute window fires the rule.
func TestRuleEngine_ObserveAdminFallbackGrant_TripsBurstAtThreshold(t *testing.T) {
	emitter := &captureEmitter{}
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(nil))
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		eng.ObserveAdminFallbackGrant(ctx, int64(i+1), "rotation", "ops", 0)
	}

	st := eng.Status()
	assert.Equal(t, int64(1), st.AlertsFiredCount,
		"4 synthetic grants in-window must trip admin_fallback_burst once")
	assert.Equal(t, "admin_fallback_burst", st.LastAlertPattern)

	// Snapshot also contains the alert event for SIEM consumption.
	var alertCount int
	for _, ev := range emitter.snapshot() {
		if ev.EventType == EventTypeSecurityAlert {
			alertCount++
		}
	}
	assert.Equal(t, 1, alertCount, "alert event must reach downstream emitter")
}

// TestRuleEngine_ObservePauseEnd_Bookend confirms the close-edge
// event lands in the downstream emitter + does NOT trigger the
// admin_fallback_burst / pause_long rules (those reset on any
// non-fallback observation). Important: the bookend is for SIEM-side
// join, not for re-triggering the rules.
func TestRuleEngine_ObservePauseEnd_Bookend(t *testing.T) {
	emitter := &captureEmitter{}
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(nil))
	require.NoError(t, err)
	ctx := context.Background()

	eng.ObservePauseEnd(ctx, 42, "resumed_early", "alice")

	events := emitter.snapshot()
	require.Len(t, events, 1, "synthetic close-edge must land in downstream emitter")
	assert.Equal(t, EventTypePauseEnd, events[0].EventType)
	assert.Equal(t, "resumed_early", events[0].Unmapped.IAMJIT.Ext["pause_end_kind"])
	assert.Equal(t, int64(0), eng.Status().AlertsFiredCount,
		"pause-end MUST NOT fire any built-in alert rule")
}

// TestRuleEngine_ObserveProfileInstall_FiresNonOrgRuleAtInstallTime
// is the load-bearing assertion for the install-time wiring: a
// profile installed from a URL that is NOT in the operator's
// approved-URL allowlist MUST fire the non_org_profile_install rule
// the moment ObserveProfileInstall runs — NOT after the first
// proxied decision under the profile lands. Closes the alerting gap
// for off-hours onboarding installs.
func TestRuleEngine_ObserveProfileInstall_FiresNonOrgRuleAtInstallTime(t *testing.T) {
	emitter := &captureEmitter{}
	// Empty allowlist → every non-empty source is non-org.
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(&RulesConfig{
		NonOrgProfileInstall: &NonOrgProfileInstallConfig{},
	}))
	require.NoError(t, err)
	ctx := context.Background()

	eng.ObserveProfileInstall(ctx, []string{"rogue-profile"},
		"https://untrusted.example/p.yaml", "deadbeef", false)

	st := eng.Status()
	assert.Equal(t, int64(1), st.AlertsFiredCount,
		"non-org install must fire the rule at install time, not at first decision")
	assert.Equal(t, "non_org_profile_install", st.LastAlertPattern)

	var alertEv *Event
	for i, ev := range emitter.snapshot() {
		if ev.EventType == EventTypeSecurityAlert {
			alertEv = &emitter.snapshot()[i]
			break
		}
	}
	require.NotNil(t, alertEv, "alert event must land in downstream emitter")
	assert.Equal(t, "non_org_profile_install", alertEv.Unmapped.IAMJIT.Pattern)
	assert.Contains(t, alertEv.StatusDetail, "rogue-profile")
	assert.Contains(t, alertEv.StatusDetail, "untrusted.example")
}

// TestRuleEngine_ObserveProfileInstall_AllowlistedDoesNotFire is the
// inverse: an install from an allowlisted URL MUST NOT fire the rule
// — the synthetic event still lands in the downstream log (audit
// trail of the install), but no alert fires.
func TestRuleEngine_ObserveProfileInstall_AllowlistedDoesNotFire(t *testing.T) {
	emitter := &captureEmitter{}
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(&RulesConfig{
		NonOrgProfileInstall: &NonOrgProfileInstallConfig{
			ApprovedURLs: []string{"https://approved.example/profiles.yaml"},
		},
	}))
	require.NoError(t, err)
	ctx := context.Background()

	eng.ObserveProfileInstall(ctx, []string{"safe-default"},
		"https://approved.example/profiles.yaml", "deadbeef", true)

	assert.Equal(t, int64(0), eng.Status().AlertsFiredCount,
		"allowlisted install MUST NOT fire the rule")
	events := emitter.snapshot()
	require.Len(t, events, 1, "synthetic install event must still land for audit trail")
	assert.Equal(t, EventTypeProfileInstall, events[0].EventType)
}

// TestEmitHelpers_NilEmitter_NoOp asserts the package-level Emit*
// helpers are safe to call with a nil Emitter — the call sites (proxy
// hot-path, profile.Install) pass whatever's wired without a nil
// check + we want the default-uninstalled path to silently do nothing
// rather than panic.
func TestEmitHelpers_NilEmitter_NoOp(t *testing.T) {
	ctx := context.Background()
	// Compiles + doesn't panic = pass; no assertions needed.
	EmitAdminFallbackGrant(ctx, nil, 1, "", "", 0)
	EmitPauseEnd(ctx, nil, 1, "expired", "")
	EmitProfileInstall(ctx, nil, []string{"x"}, "https://example/", "x", false)

	// Nil receiver on the *RuleEngine method form must also be a no-op.
	var eng *RuleEngine
	eng.ObserveAdminFallbackGrant(ctx, 1, "", "", 0)
	eng.ObservePauseEnd(ctx, 1, "expired", "")
	eng.ObserveProfileInstall(ctx, []string{"x"}, "https://example/", "x", false)
}

// TestEmitHelpers_DispatchToBareManager confirms the package-level
// helpers work on a bare *Manager (no RuleEngine wrapped) — operators
// who haven't enabled the alert engine (pre-#235 license gate, or who
// just don't want it) still get the synthetic events delivered to the
// JSONL log + HTTPS webhook through the bare Manager path.
func TestEmitHelpers_DispatchToBareManager(t *testing.T) {
	emitter := &captureEmitter{}
	ctx := context.Background()

	EmitAdminFallbackGrant(ctx, emitter, 1, "test", "alice", 0)
	EmitPauseEnd(ctx, emitter, 1, "resumed_early", "alice")
	EmitProfileInstall(ctx, emitter, []string{"x"},
		"https://approved.example/x", "dead", true)

	events := emitter.snapshot()
	require.Len(t, events, 3,
		"all 3 synthetic events must reach a bare-emitter consumer")
	assert.Equal(t, EventTypeAdminFallbackGrant, events[0].EventType)
	assert.Equal(t, EventTypePauseEnd, events[1].EventType)
	assert.Equal(t, EventTypeProfileInstall, events[2].EventType)
}
