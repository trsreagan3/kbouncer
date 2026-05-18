// Coverage for the admin-action OCSF event builder + emit helpers
// per [[basic-app-hygiene-features]] TIER 1 + [[security-team-audit-
// export]].
//
// Asserts: every action type maps to the right activity_id +
// activity_name + severity; before/after hashes are deterministic +
// sensitive to mutation; the license.install event NEVER carries the
// license bytes; the events ride the existing audit-export transport
// (the captureEmitter doubles as the JSONL log / webhook for
// assertion purposes — the real transport tests live in log_test.go +
// webhook_test.go and don't care about event shape).
package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminActionActivityIDMapping pins the activity_id mapping for
// every action type the spec ships. Locked-in test — changing the
// mapping is a wire-shape break for downstream SIEM rules.
func TestAdminActionActivityIDMapping(t *testing.T) {
	cases := []struct {
		action AdminAction
		want   int
	}{
		{AdminActionProfileInstall, ActivityCreate},
		{AdminActionProfileDelete, ActivityDelete},
		{AdminActionRuleAdd, ActivityCreate},
		{AdminActionRuleRemove, ActivityDelete},
		{AdminActionPauseStart, ActivityUpdate},
		{AdminActionPauseStop, ActivityUpdate},
		{AdminActionPresetApply, ActivityCreate},
		{AdminActionLicenseInstall, ActivityCreate},
		{AdminActionAlertRuleEdit, ActivityUpdate},
		{AdminActionProfileAssign, ActivityUpdate},
		{AdminActionConfigImport, ActivityCreate},
		{AdminActionConfigExport, ActivityOther},
	}
	for _, c := range cases {
		t.Run(string(c.action), func(t *testing.T) {
			assert.Equal(t, c.want, AdminActionActivityID(c.action))
		})
	}
}

// TestAdminActionSeverity_DefaultIsInformational_LicenseAndAssignAreHigh
// pins the severity mapping: license + assignment changes are High
// (security-team-paging-worthy); everything else is Informational
// (SIEM-ingest-worthy without alert noise).
func TestAdminActionSeverity_DefaultIsInformational_LicenseAndAssignAreHigh(t *testing.T) {
	for _, a := range []AdminAction{
		AdminActionProfileInstall,
		AdminActionProfileDelete,
		AdminActionRuleAdd,
		AdminActionRuleRemove,
		AdminActionPauseStart,
		AdminActionPauseStop,
		AdminActionPresetApply,
		AdminActionAlertRuleEdit,
		AdminActionConfigImport,
		AdminActionConfigExport,
	} {
		t.Run("informational/"+string(a), func(t *testing.T) {
			sev, _ := AdminActionSeverity(a)
			assert.Equal(t, SeverityInformational, sev,
				"default admin actions stay Informational so a routine `rules add` "+
					"doesn't page the security team")
		})
	}
	for _, a := range []AdminAction{AdminActionLicenseInstall, AdminActionProfileAssign} {
		t.Run("high/"+string(a), func(t *testing.T) {
			sev, label := AdminActionSeverity(a)
			assert.Equal(t, SeverityHigh, sev,
				"license + assignment changes are High — they alter the enforcement "+
					"floor for privileged actors")
			assert.Equal(t, "High", label)
		})
	}
}

// TestMakeAdminActionEvent_ShapeAndExt asserts the core wire shape: the
// event is OCSF class 6003, the action lands in activity_name, and the
// config_change block carries the source + before/after hashes the
// tamper-detection rule keys on.
func TestMakeAdminActionEvent_ShapeAndExt(t *testing.T) {
	ev := MakeAdminActionEvent(AdminActionInput{
		Action:     AdminActionRuleAdd,
		Actor:      "alice",
		ActorUID:   "uid-1",
		Before:     map[string]any{"rules": []string{"pods:get"}},
		After:      map[string]any{"rules": []string{"pods:get", "secrets:get"}},
		EntityName: "secrets:get",
		EntityKind: "rule",
		Source:     AdminActionSourceCLI,
		ExtraExt:   map[string]any{"rule_id": int64(42)},
	})

	assert.Equal(t, ClassUID, ev.ClassUID)
	assert.Equal(t, CategoryUID, ev.CategoryUID)
	assert.Equal(t, ActivityCreate, ev.ActivityID)
	assert.Equal(t, "rule.add", ev.ActivityName)
	assert.Equal(t, SeverityInformational, ev.SeverityID)
	assert.Equal(t, StatusSuccess, ev.StatusID)
	assert.Equal(t, EventType("ADMIN_ACTION"), ev.EventType)
	assert.Equal(t, "ADMIN_ACTION", ev.Unmapped.IAMJIT.EventType)

	require.NotNil(t, ev.Actor)
	require.NotNil(t, ev.Actor.User)
	assert.Equal(t, "alice", ev.Actor.User.Name)
	assert.Equal(t, "uid-1", ev.Actor.User.UID)

	cfg, ok := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
	require.True(t, ok, "config_change block must be a map")
	assert.Equal(t, "rule.add", cfg["type"])
	assert.Equal(t, "cli", cfg["source"])
	assert.Equal(t, "rule", cfg["entity_kind"])
	assert.Equal(t, "secrets:get", cfg["entity"])

	beforeHash, _ := cfg["before_hash"].(string)
	afterHash, _ := cfg["after_hash"].(string)
	require.Len(t, beforeHash, 64, "before_hash must be a 64-char hex sha256")
	require.Len(t, afterHash, 64, "after_hash must be a 64-char hex sha256")
	assert.NotEqual(t, beforeHash, afterHash,
		"before/after hashes must differ when state mutates — tamper-detection "+
			"depends on this distinction")

	extraExt, _ := cfg["ext"].(map[string]any)
	require.NotNil(t, extraExt)
	assert.Equal(t, int64(42), extraExt["rule_id"])
}

// TestMakeAdminActionEvent_OmitsHashWhenInputNil — a nil Before /
// After must be ABSENT from the wire shape, not encoded as a hash of
// "null". Lets analysts distinguish "we didn't capture before-state"
// from "the state was the empty value".
func TestMakeAdminActionEvent_OmitsHashWhenInputNil(t *testing.T) {
	ev := MakeAdminActionEvent(AdminActionInput{
		Action: AdminActionPauseStop,
		Actor:  "alice",
		// Before/After both nil — wire shape must drop them.
	})
	cfg := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
	_, hasBefore := cfg["before_hash"]
	_, hasAfter := cfg["after_hash"]
	assert.False(t, hasBefore, "nil Before must omit before_hash; observed=%v", cfg)
	assert.False(t, hasAfter, "nil After must omit after_hash; observed=%v", cfg)
}

// TestHashState_DeterministicAcrossEquivalentInputs is the load-
// bearing tamper-detection invariant: structurally-equivalent inputs
// MUST hash identically across runs, regardless of how the caller
// assembled them. Tests struct + map paths.
func TestHashState_DeterministicAcrossEquivalentInputs(t *testing.T) {
	type rule struct {
		Pattern string `json:"pattern"`
		Effect  string `json:"effect"`
	}
	a := rule{Pattern: "pods:get", Effect: "allow"}
	b := rule{Pattern: "pods:get", Effect: "allow"}
	ha, okA := HashState(a)
	hb, okB := HashState(b)
	require.True(t, okA)
	require.True(t, okB)
	assert.Equal(t, ha, hb,
		"equivalent struct values must hash identically — tamper-detection "+
			"compares hashes across runs")

	// Map ordering must not change the hash (encoding/json emits sorted
	// keys).
	m1 := map[string]any{"a": 1, "b": 2}
	m2 := map[string]any{"b": 2, "a": 1}
	h1, _ := HashState(m1)
	h2, _ := HashState(m2)
	assert.Equal(t, h1, h2,
		"map-key ordering must not perturb the hash; encoding/json sorts keys")
}

// TestHashState_NilReturnsNoCapture — a nil input MUST signal "not
// captured" rather than hashing to a sentinel. The wire shape uses
// the `ok` return to omit the field entirely.
func TestHashState_NilReturnsNoCapture(t *testing.T) {
	h, ok := HashState(nil)
	assert.Equal(t, "", h)
	assert.False(t, ok,
		"nil input must signal 'not captured' so MakeAdminActionEvent omits "+
			"the field; distinct from EmptyStateHash() which IS a real hash of "+
			"the empty value")
}

// TestEmptyStateHash_NonEmptyAndStable — EmptyStateHash returns the
// SHA of "null"; lets callers explicitly signal "the state WAS the
// empty value" without that being indistinguishable from
// "we didn't capture state".
func TestEmptyStateHash_NonEmptyAndStable(t *testing.T) {
	h := EmptyStateHash()
	require.Len(t, h, 64, "empty-state hash must be a 64-char hex sha256")
	assert.Equal(t, h, EmptyStateHash(), "must be stable across calls")
	// Distinct from any HashState() output on a non-nil input.
	h2, _ := HashState(map[string]any{"x": 1})
	assert.NotEqual(t, h, h2)
}

// TestMakeAdminActionEvent_LicenseContentNotExposed is the token-
// leak invariant: a caller who passes license content / signed bytes
// in ExtraExt MUST NOT see those bytes in the OCSF wire shape. Only
// metadata (issuer, expiry, license_id, content_sha256) passes
// through. The strip is silent — the audit-export channel never
// carries the signed material even if a caller forgot to redact.
func TestMakeAdminActionEvent_LicenseContentNotExposed(t *testing.T) {
	leakedBytes := "----- BEGIN LICENSE ----- SECRET-LICENSE-BYTES ----- END LICENSE -----"
	ev := MakeAdminActionEvent(AdminActionInput{
		Action:     AdminActionLicenseInstall,
		Actor:      "ops",
		EntityKind: "license",
		EntityName: "ent-1",
		ExtraExt: map[string]any{
			"license_id":      "ent-1",
			"issuer":          "iam-jit.com",
			"expiry_iso":      "2027-05-18T00:00:00Z",
			"content_sha256": "abcd1234",
			// These keys MUST be stripped before the event is built.
			"license_content":     leakedBytes,
			"license_bytes":       leakedBytes,
			"license_pem":         leakedBytes,
			"license_private_key": leakedBytes,
			"license_token":       leakedBytes,
		},
	})
	body, err := json.Marshal(ev)
	require.NoError(t, err)
	bodyStr := string(body)
	assert.NotContains(t, bodyStr, "SECRET-LICENSE-BYTES",
		"license content MUST NOT appear in the OCSF wire shape — token-leak "+
			"invariant per [[security-team-audit-export]]")
	assert.NotContains(t, bodyStr, "license_content")
	assert.NotContains(t, bodyStr, "license_bytes")
	assert.NotContains(t, bodyStr, "license_pem")
	assert.NotContains(t, bodyStr, "license_private_key")
	assert.NotContains(t, bodyStr, "license_token")

	// Safe metadata DOES land in the event.
	assert.Contains(t, bodyStr, "ent-1")
	assert.Contains(t, bodyStr, "iam-jit.com")
	assert.Contains(t, bodyStr, "content_sha256")

	// Severity is High for license.install (security team should look).
	assert.Equal(t, SeverityHigh, ev.SeverityID)
}

// TestMakeAdminActionEvent_NeutralLanguage — admin-action events ride
// the same audit-export channel as the existing alert payloads; they
// must honor the same neutrality contract per [[security-team-
// positioning-safety-not-surveillance]].
func TestMakeAdminActionEvent_NeutralLanguage(t *testing.T) {
	forbidden := []string{
		"violation",
		"violate",
		"infraction",
		"unauthorized",
		"forbidden",
		"abuse",
		"malicious",
	}
	actions := []AdminAction{
		AdminActionProfileInstall, AdminActionProfileDelete,
		AdminActionRuleAdd, AdminActionRuleRemove,
		AdminActionPauseStart, AdminActionPauseStop,
		AdminActionPresetApply, AdminActionLicenseInstall,
		AdminActionAlertRuleEdit, AdminActionProfileAssign,
		AdminActionConfigImport, AdminActionConfigExport,
	}
	for _, a := range actions {
		t.Run(string(a), func(t *testing.T) {
			ev := MakeAdminActionEvent(AdminActionInput{
				Action: a, Actor: "alice", EntityName: "x", EntityKind: "y",
				Before: map[string]any{"a": 1}, After: map[string]any{"a": 2},
			})
			body, err := json.Marshal(ev)
			require.NoError(t, err)
			lower := strings.ToLower(string(body))
			for _, w := range forbidden {
				assert.NotContains(t, lower, w,
					"admin-action %s body must stay neutral", a)
			}
		})
	}
}

// TestEmitAdminAction_NilEmitterIsNoOp — package-level helper must be
// safe to call when no audit-export channel is wired (one-shot CLI
// subcommands that didn't pass --audit-log-path). Mirror of
// TestEmitHelpers_NilEmitter_NoOp.
func TestEmitAdminAction_NilEmitterIsNoOp(t *testing.T) {
	ctx := context.Background()
	// Compiles + doesn't panic = pass.
	EmitAdminAction(ctx, nil, AdminActionInput{Action: AdminActionRuleAdd})

	// Nil receiver on the *RuleEngine form must also be a no-op.
	var eng *RuleEngine
	eng.ObserveAdminAction(ctx, AdminActionInput{Action: AdminActionRuleAdd})
}

// TestEmitAdminAction_ReachesDownstreamEmitter — the synthetic event
// rides the SAME transport as DECISION events. We don't re-test the
// JSONL log or webhook here (those have their own tests); we assert
// the helper invokes Emit so a real LogWriter / WebhookPusher would
// pick it up.
func TestEmitAdminAction_ReachesDownstreamEmitter(t *testing.T) {
	emitter := &captureEmitter{}
	ctx := context.Background()

	EmitAdminAction(ctx, emitter, AdminActionInput{
		Action: AdminActionPresetApply, Actor: "alice",
		EntityName: "eks-cluster-survey", EntityKind: "preset",
		Before: map[string]any{"rules": 0},
		After:  map[string]any{"rules": 5},
	})

	events := emitter.snapshot()
	require.Len(t, events, 1)
	ev := events[0]
	assert.Equal(t, "preset.apply", ev.ActivityName)
	assert.Equal(t, "ADMIN_ACTION", ev.Unmapped.IAMJIT.EventType)
	cfg := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
	assert.Equal(t, "preset", cfg["entity_kind"])
	assert.Equal(t, "eks-cluster-survey", cfg["entity"])
}

// TestRuleEngine_ObserveAdminAction_ForwardsToDownstream — the engine-
// method form fans the admin-action event into the downstream emitter
// (same path the synthetic Observe* helpers use). The rule engine does
// NOT currently fire any rule on admin-action events — they're for the
// "who changed what" audit log, not anomaly detection — but future
// rules may key off them.
func TestRuleEngine_ObserveAdminAction_ForwardsToDownstream(t *testing.T) {
	emitter := &captureEmitter{}
	eng, err := NewRuleEngine(emitter, BuildBuiltinRules(nil))
	require.NoError(t, err)
	ctx := context.Background()

	eng.ObserveAdminAction(ctx, AdminActionInput{
		Action: AdminActionPauseStart, Actor: "alice",
		EntityKind: "pause_window", EntityName: "pause#42",
		Before: nil,
		After:  map[string]any{"pause_id": 42, "duration_seconds": 1800},
	})

	events := emitter.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, "pause.start", events[0].ActivityName)
	assert.Equal(t, int64(0), eng.Status().AlertsFiredCount,
		"admin-action events must NOT trip the built-in anomaly rules")
}

// TestStubWirePoints_AllReachDownstream confirms each of the stub
// wire-points (profile delete / license install / alert-rule edit /
// profile assign / config import / config export) actually publishes
// the right OCSF activity_name through the Emitter — proves the
// future feature PRs need only a one-line call site to land.
func TestStubWirePoints_AllReachDownstream(t *testing.T) {
	ctx := context.Background()
	emitter := &captureEmitter{}

	EmitProfileDelete(ctx, emitter, "alice", "rogue-profile",
		map[string]any{"name": "rogue-profile", "denied_keywords": []string{"prod"}})
	EmitLicenseInstall(ctx, emitter, "ops", "ent-42",
		map[string]any{"license_id": "ent-42", "issuer": "iam-jit.com"})
	EmitAlertRuleEdit(ctx, emitter, "alice", "/etc/kbouncer/alerts.yaml",
		map[string]any{"rules": 5}, map[string]any{"rules": 6})
	EmitProfileAssign(ctx, emitter, "admin", "bob@example.com", "safe-default",
		map[string]any{"profile": "full-user"}, map[string]any{"profile": "safe-default"})
	EmitConfigImport(ctx, emitter, "alice", "/tmp/kbouncer-export.yaml",
		nil, map[string]any{"profiles": 3, "rules": 12})
	EmitConfigExport(ctx, emitter, "alice", "/tmp/kbouncer-export.yaml",
		map[string]any{"profiles": 3, "rules": 12})

	events := emitter.snapshot()
	require.Len(t, events, 6,
		"all 6 stub wire-points must deliver an admin-action event")

	wantNames := []string{
		"profile.delete",
		"license.install",
		"alert-rule.edit",
		"profile.assign",
		"config.import",
		"config.export",
	}
	for i, want := range wantNames {
		assert.Equal(t, want, events[i].ActivityName,
			"stub wire-point #%d activity_name", i)
	}

	// license.install + profile.assign are HIGH severity.
	assert.Equal(t, SeverityHigh, events[1].SeverityID,
		"license.install severity must be High")
	assert.Equal(t, SeverityHigh, events[3].SeverityID,
		"profile.assign severity must be High")
}

// TestEmitLicenseInstall_MetadataInExtNotContent confirms the stub
// helper's metadata lands under config_change.ext but the license-
// content keys (if a future caller passes them by mistake) are
// stripped before the wire shape is built.
func TestEmitLicenseInstall_MetadataInExtNotContent(t *testing.T) {
	emitter := &captureEmitter{}
	EmitLicenseInstall(context.Background(), emitter, "ops", "ent-42", map[string]any{
		"license_id":      "ent-42",
		"issuer":          "iam-jit.com",
		"content_sha256":  "deadbeef",
		"license_content": "SECRET-LICENSE-PEM-BYTES",
	})
	events := emitter.snapshot()
	require.Len(t, events, 1)
	body, err := json.Marshal(events[0])
	require.NoError(t, err)
	assert.NotContains(t, string(body), "SECRET-LICENSE-PEM-BYTES",
		"license content keys must be stripped by the wire-shape builder")
	assert.Contains(t, string(body), "deadbeef",
		"content_sha256 metadata must pass through")
}

// TestMakeAdminActionEvent_AllWireActionsPresent — exhaustively builds
// each action type so coverage of the activity_name / activity_id /
// source / before/after-hash path is complete. Token-leak invariant
// already covered above; this assertion just confirms we shipped all
// 12 of the spec's named actions.
func TestMakeAdminActionEvent_AllWireActionsPresent(t *testing.T) {
	want := []AdminAction{
		AdminActionProfileInstall, AdminActionProfileDelete,
		AdminActionRuleAdd, AdminActionRuleRemove,
		AdminActionPauseStart, AdminActionPauseStop,
		AdminActionPresetApply, AdminActionLicenseInstall,
		AdminActionAlertRuleEdit, AdminActionProfileAssign,
		AdminActionConfigImport, AdminActionConfigExport,
	}
	require.Len(t, want, 12, "spec ships 12 action types")
	for _, a := range want {
		t.Run(string(a), func(t *testing.T) {
			ev := MakeAdminActionEvent(AdminActionInput{
				Action: a, Actor: "ops", EntityName: "x",
				Before: nil, After: map[string]any{"x": 1},
				Source: AdminActionSourceCLI,
			})
			assert.Equal(t, string(a), ev.ActivityName)
			assert.NotZero(t, ev.ActivityID,
				"activity_id must be set; ActivityUnknown is reserved")
			cfg := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
			assert.Equal(t, string(a), cfg["type"])
			assert.Equal(t, "cli", cfg["source"])
		})
	}
}
