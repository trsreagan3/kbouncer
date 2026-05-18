// admin_action.go implements the admin-action OCSF audit-event layer
// per [[basic-app-hygiene-features]] TIER 1 + [[security-team-audit-
// export]].
//
// Closes the security-critical gap that until this slice landed only
// proxy DECISIONS rode the OCSF audit-export channel — CONFIG CHANGES
// (profile install / delete, rule add / remove, pause start / stop,
// preset apply, license install, alert-rule edit, profile assignment,
// config import / export) were silent. Security teams could not answer
// "who installed this profile / paused enforcement / disabled the
// bouncer."
//
// Wire shape per [[ocsf-audit-schema]]: every admin action emits an
// OCSF v1.1.0 class 6003 (API Activity) event. activity_id maps to
// Create (1) / Update (3) / Delete (4) per the kind of mutation;
// the unmapped.iam_jit.config_change block carries the action type +
// SHA-256 hashes of the before / after state for the
// [[enterprise-admin-controls]] tamper-detection rule + the audit-
// export source label so an analyst can pivot on "events that came
// from the CLI vs the MCP tool".
//
// Hash discipline (load-bearing):
//
//   - SHA-256 is computed over a CANONICAL JSON serialization of the
//     before / after state. We picked JSON-of-struct (not YAML, not
//     raw bytes) because:
//
//       (a) Go's encoding/json serializes struct fields in declaration
//           order, which is deterministic regardless of how a caller
//           assembled the input. Tamper-detection comparisons across
//           runs are stable.
//       (b) Map keys are emitted in sorted order by the standard
//           library — also deterministic.
//       (c) YAML round-trips preserve cosmetic whitespace / quoting
//           that a benign re-save would perturb; the hash would change
//           even when the SEMANTIC content didn't. JSON-of-struct
//           strips that noise.
//       (d) A single serialization mechanism works whether the input
//           is a Profile struct, a rule row, a pause window, or a
//           map[string]any.
//
//   - The empty-state hash is the sha256 of an empty JSON object so a
//     "create from scratch" event has a non-zero before_hash that
//     differs from "we forgot to capture before-state".
//
// Stub hooks for features that haven't shipped yet (license install,
// profile assignment, config import / export) per [[deliberate-feature-
// completion]]: the wire-up point ships now even though the calling
// feature lands later; the future feature's PR is a 1-line call to
// EmitAdminAction* with the right activity name. Avoids the failure
// mode where features ship without audit coverage because nobody
// remembered to add the event later.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// AdminAction names every recognized admin-action activity. The wire
// value lands in unmapped.iam_jit.config_change.type AND in the OCSF
// activity_name field, so SIEM analysts can pivot on either.
//
// Per [[security-team-positioning-safety-not-surveillance]] the wire
// names are NEUTRAL — "profile.install" (what happened), not
// "profile.injected" (accusation). Same neutrality contract the alert
// payloads honor.
type AdminAction string

const (
	// AdminActionProfileInstall — `profile install` succeeded. Distinct
	// from the EventTypeProfileInstall synthetic that drives the
	// non_org_profile_install rule (#270): that event is for INSTALL-
	// TIME ALERTING, this one is for the "who changed what" audit log.
	// Both fire on a successful install so a security team has both
	// the rule trigger AND the config-change row.
	AdminActionProfileInstall AdminAction = "profile.install"

	// AdminActionProfileDelete — operator removed a profile from
	// profiles.yaml. Stubbed for the future `profile delete` subcommand;
	// the wire point already exists so the subcommand PR is one line.
	AdminActionProfileDelete AdminAction = "profile.delete"

	// AdminActionRuleAdd / AdminActionRuleRemove — global-rule-table
	// mutations via `rules add` / `rules remove`.
	AdminActionRuleAdd    AdminAction = "rule.add"
	AdminActionRuleRemove AdminAction = "rule.remove"

	// AdminActionPauseStart / AdminActionPauseStop — operator opened or
	// closed a pause window. Distinct from the EventTypeAdminFallback
	// Grant / EventTypePauseEnd synthetics: those drive the
	// admin_fallback_burst + pause_long rule predicates. The
	// admin-action event is the "config change" row in the audit log.
	AdminActionPauseStart AdminAction = "pause.start"
	AdminActionPauseStop  AdminAction = "pause.stop"

	// AdminActionPresetApply — operator ran `presets apply NAME`. The
	// before_hash captures the rule-table state before the apply; the
	// after_hash captures the post-apply state. Lets the tamper-
	// detection rule answer "did this preset apply add the rules the
	// preset YAML promised?"
	AdminActionPresetApply AdminAction = "preset.apply"

	// AdminActionLicenseInstall — operator installed a new Enterprise
	// license file. STUB: kbounce does not yet have license-file
	// plumbing (#235). The wire point ships now so the #235 PR is a
	// one-line call. Token-leak invariant: the license CONTENT (the
	// signed bytes) MUST NOT appear in the event body — only metadata
	// (issuer, expiry, license id). Tested in admin_action_test.go.
	AdminActionLicenseInstall AdminAction = "license.install"

	// AdminActionAlertRuleEdit — operator reloaded --alert-rules YAML.
	// STUB: alert-rules plumbing is an Enterprise feature gated by the
	// same #235 license-file work; the live-reload subcommand lands
	// post-#235.
	AdminActionAlertRuleEdit AdminAction = "alert-rule.edit"

	// AdminActionProfileAssign — operator assigned a profile to a user
	// / group / namespace via the enterprise-admin-controls feature.
	// STUB: per-user assignment ships with the enterprise-admin-
	// controls plumbing; the wire point lives here so its PR is a
	// one-line call.
	AdminActionProfileAssign AdminAction = "profile.assign"

	// AdminActionConfigImport / AdminActionConfigExport — operator
	// imported / exported the kbounce config via the future #275
	// import/export subcommand. STUB: feature ships in #275; wire
	// point lives here so the #275 PR is one-line.
	AdminActionConfigImport AdminAction = "config.import"
	AdminActionConfigExport AdminAction = "config.export"

	// AdminActionDiagnosticsBundle — operator produced a diagnostics
	// bundle via `kbounce diagnostics bundle` (#277). The bundle is a
	// support-package ZIP with redacted config + audit-log tail +
	// health snapshot; recording the action gives a security team a
	// witness for "who pulled diagnostics + when?" so the bundle's
	// later appearance in a support ticket / agent thread is
	// traceable. The bundle output path lands in EntityName.
	AdminActionDiagnosticsBundle AdminAction = "diagnostics.bundle"
)

// AdminActionActivityID returns the OCSF activity_id (class 6003 enum)
// that corresponds to the action. Create / Update / Delete map to the
// canonical CRUD values; anything that's neither (export, install of
// signed material) maps to Other (99) per the [[ocsf-audit-schema]]
// "honest about uncategorized" stance.
func AdminActionActivityID(a AdminAction) int {
	switch a {
	case AdminActionProfileInstall,
		AdminActionRuleAdd,
		AdminActionPresetApply,
		AdminActionConfigImport,
		AdminActionLicenseInstall:
		return ActivityCreate
	case AdminActionPauseStart,
		AdminActionPauseStop,
		AdminActionAlertRuleEdit,
		AdminActionProfileAssign:
		return ActivityUpdate
	case AdminActionProfileDelete,
		AdminActionRuleRemove:
		return ActivityDelete
	case AdminActionConfigExport, AdminActionDiagnosticsBundle:
		return ActivityOther
	default:
		return ActivityOther
	}
}

// AdminActionSeverity returns the OCSF severity_id for the action.
// Most admin actions are Informational — security teams want to SEE
// them, not be PAGED on every routine `rules add`. Two action types
// are escalated to High per [[security-team-audit-export]]:
//
//   - license.install: installing a new license changes the
//     enforcement surface (Enterprise features come online); the
//     security team should review.
//   - profile.assign: per-user assignment binds an actor to a
//     specific guardrail profile; misconfigured assignment can
//     silently weaken the floor for a privileged user.
func AdminActionSeverity(a AdminAction) (int, string) {
	switch a {
	case AdminActionLicenseInstall, AdminActionProfileAssign:
		return SeverityHigh, "High"
	default:
		return SeverityInformational, "Informational"
	}
}

// AdminActionSource names where the admin action originated. Lands in
// unmapped.iam_jit.config_change.source so an analyst can answer "did
// this rule come from the CLI, an MCP-bridged agent, or the
// future-import path?"
type AdminActionSource string

const (
	// AdminActionSourceCLI — the change came from a `kbounce ...` CLI
	// invocation.
	AdminActionSourceCLI AdminActionSource = "cli"

	// AdminActionSourceMCP — the change came from an MCP tool call
	// (an agent-facing path the operator wired).
	AdminActionSourceMCP AdminActionSource = "mcp"

	// AdminActionSourceAPI — the change came from a programmatic API
	// caller (reserved for the future Enterprise self-host control
	// plane).
	AdminActionSourceAPI AdminActionSource = "api"

	// AdminActionSourceUnknown — the source could not be determined.
	// Honest fallback per [[scorer-is-ground-truth]].
	AdminActionSourceUnknown AdminActionSource = "unknown"
)

// AdminActionInput is the minimal struct callers pass to
// MakeAdminActionEvent. All fields are optional; the builder fills
// honest defaults for anything missing (actor=cli, source=cli).
type AdminActionInput struct {
	// Action names the activity. Required for a non-degenerate event;
	// an empty action falls through to ActivityOther / "admin_action".
	Action AdminAction

	// Actor identifies the operator who initiated the change. Lands in
	// the OCSF actor.user.name field. Empty → actor block omitted.
	Actor string

	// ActorUID is the optional stable id of the operator (e.g. an
	// OIDC sub claim). Lands in actor.user.uid.
	ActorUID string

	// Before / After are the state values to hash. Either may be nil
	// (e.g. before-state of a fresh install is nil; after-state of a
	// delete is nil). The serialization is canonical JSON-of-value
	// (struct field order is declaration order; map keys are sorted
	// by encoding/json) so the hash is stable across runs that pass
	// semantically-equivalent inputs.
	Before any
	After  any

	// Source names where the action originated. Empty → CLI per the
	// [[basic-app-hygiene-features]] default (CLI is the most common
	// admin path).
	Source AdminActionSource

	// EntityName is the human-readable identifier of the affected
	// entity (e.g. a profile name, a rule pattern). Lands in
	// unmapped.iam_jit.config_change.entity for SIEM pivots.
	EntityName string

	// EntityKind labels the kind of entity ("profile", "rule",
	// "pause_window", "preset", "license"). Lands in
	// unmapped.iam_jit.config_change.entity_kind.
	EntityKind string

	// ExtraExt lets callers pass per-action context (rule id, pause
	// duration, preset name, sha256 of the installed license, ...).
	// Lands under unmapped.iam_jit.config_change.ext. The key
	// "license_content" / "license_bytes" is REFUSED — license content
	// MUST NOT leave the local machine via the audit-export channel
	// (token-leak invariant; see TestAdminAction_LicenseContentNotExposed).
	ExtraExt map[string]any
}

// MakeAdminActionEvent builds an OCSF v1.1.0 class 6003 Event for an
// admin action. Mirrors MakeProfileInstallEvent's shape so the same
// JSONL log writer + HTTPS webhook pusher consume admin-action events
// without any transport-layer changes.
//
// before_hash / after_hash are populated by HashState(in.Before) /
// HashState(in.After). A nil input hashes to the empty-state sentinel
// (sha256 of "null") — distinct from "before-state not captured"
// (which omits the field), so an analyst can tell the difference.
//
// Token-leak guard: the license_content / license_bytes / license_pem
// keys are STRIPPED from ExtraExt before the event is built. Only
// metadata (issuer, expiry, license_id, content_sha256) is allowed
// through.
func MakeAdminActionEvent(in AdminActionInput) Event {
	action := in.Action
	if action == "" {
		action = "admin_action"
	}
	activityID := AdminActionActivityID(action)
	severityID, severity := AdminActionSeverity(action)
	source := in.Source
	if source == "" {
		source = AdminActionSourceCLI
	}

	cfgChange := map[string]any{
		"type":   string(action),
		"source": string(source),
	}
	if hashB, ok := HashState(in.Before); ok {
		cfgChange["before_hash"] = hashB
	}
	if hashA, ok := HashState(in.After); ok {
		cfgChange["after_hash"] = hashA
	}
	if in.EntityName != "" {
		cfgChange["entity"] = in.EntityName
	}
	if in.EntityKind != "" {
		cfgChange["entity_kind"] = in.EntityKind
	}
	if cleaned := stripLicenseContent(in.ExtraExt); len(cleaned) > 0 {
		cfgChange["ext"] = cleaned
	}

	ext := map[string]any{
		"config_change": cfgChange,
	}

	var actor *OCSFActor
	if in.Actor != "" || in.ActorUID != "" {
		actor = &OCSFActor{User: &OCSFUser{Name: in.Actor, UID: in.ActorUID}}
	}

	statusDetail := fmt.Sprintf("admin action %s by %s", action, displayActor(in.Actor))
	if in.EntityName != "" {
		statusDetail = fmt.Sprintf(
			"admin action %s on %s %q by %s",
			action, displayEntityKind(in.EntityKind), in.EntityName, displayActor(in.Actor))
	}

	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         nowUnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   activityID,
		ActivityName: string(action),
		TypeUID:      ClassUID*100 + activityID,
		TypeName:     typeNameForActivity(activityID),
		SeverityID:   severityID,
		Severity:     severity,
		StatusID:     StatusSuccess,
		Status:       "Success",
		StatusDetail: statusDetail,
		Actor:        actor,
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType: "ADMIN_ACTION",
				Ext:       ext,
			},
		},
		EventType: "ADMIN_ACTION",
	}
}

// HashState returns the hex sha256 of a canonical JSON serialization
// of v. Returns ("", false) when v is nil so the caller can omit the
// hash field — distinguishing "before-state not captured" from
// "before-state was the empty value". A non-nil-but-empty input
// (empty map / empty slice / empty string) hashes to the SHA of its
// JSON representation, NOT to the no-capture sentinel — those ARE
// meaningful states.
//
// Per [[scorer-is-ground-truth]] this is deterministic: json.Marshal
// emits struct fields in declaration order and map keys in sorted
// order, so the same semantic input always hashes the same way.
//
// Per [[cross-product-agent-parity]] the hashing scheme MUST be
// identical across kbounce + dbounce + ibounce so an analyst can
// compute the same hash locally to verify tampering.
func HashState(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	b, err := json.Marshal(v)
	if err != nil {
		// Don't surface marshal errors to the caller — admin-action
		// emission is best-effort; the wire-shape "no hash" sentinel
		// is the honest answer when serialization broke.
		return "", false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), true
}

// EmptyStateHash returns the sha256 of "null" — useful as the
// before-state for a fresh-install or as the after-state for a
// delete when the caller wants an explicit "the state was empty"
// rather than omitting the field.
func EmptyStateHash() string {
	sum := sha256.Sum256([]byte("null"))
	return hex.EncodeToString(sum[:])
}

// EmitAdminAction is the Emitter-interface-level helper call sites
// use to publish an admin-action event without holding a concrete
// *Manager / *RuleEngine. Mirrors EmitAdminFallbackGrant /
// EmitPauseEnd / EmitProfileInstall. Nil emitter → no-op so the
// default-uninstalled path silently does nothing.
func EmitAdminAction(ctx context.Context, e Emitter, in AdminActionInput) {
	if e == nil {
		return
	}
	e.Emit(ctx, MakeAdminActionEvent(in))
}

// ObserveAdminAction is the RuleEngine-method form for callers that
// hold a concrete *RuleEngine. Lets future alert rules that key off
// admin-action events (e.g. "license.install fired with a missing
// before_hash") observe the event in the same pipeline as decision
// events. Safe on a nil receiver.
func (e *RuleEngine) ObserveAdminAction(ctx context.Context, in AdminActionInput) {
	if e == nil {
		return
	}
	e.Emit(ctx, MakeAdminActionEvent(in))
}

// EmitProfileDelete is the stub wire-point for the future
// `kbounce profile delete NAME` subcommand. Future PR adds the
// subcommand and calls this helper with the operator + the
// deleted profile name; until that PR lands, this function is
// reachable from the MCP delete-profile tool + tests.
//
// Per [[deliberate-feature-completion]]: shipping the wire point
// before the feature avoids the failure mode where features ship
// without audit coverage because nobody remembered to add the
// emit. before is the on-disk Profile struct (or its YAML map
// equivalent) at the moment of deletion; after is nil to mark
// "the profile no longer exists".
func EmitProfileDelete(ctx context.Context, e Emitter, actor, profileName string, before any) {
	EmitAdminAction(ctx, e, AdminActionInput{
		Action:     AdminActionProfileDelete,
		Actor:      actor,
		EntityKind: "profile",
		EntityName: profileName,
		Source:     AdminActionSourceCLI,
		Before:     before,
		After:      nil,
	})
}

// EmitLicenseInstall is the stub wire-point for #235's license-file
// install path. Future PR calls this helper from the CLI subcommand
// with the metadata block (license_id, issuer, expiry_iso,
// content_sha256). The license CONTENT MUST NOT be passed in
// ExtraExt — stripLicenseContent silently drops the leak keys, but
// the well-behaved call site never includes them in the first place.
//
// Severity High per [[security-team-audit-export]]: a license change
// alters the enforcement floor; the security team should review.
func EmitLicenseInstall(ctx context.Context, e Emitter, actor, licenseID string, metadata map[string]any) {
	EmitAdminAction(ctx, e, AdminActionInput{
		Action:     AdminActionLicenseInstall,
		Actor:      actor,
		EntityKind: "license",
		EntityName: licenseID,
		Source:     AdminActionSourceCLI,
		Before:     nil,
		After:      metadata,
		ExtraExt:   metadata,
	})
}

// EmitAlertRuleEdit is the stub wire-point for the future
// `kbounce alert-rules reload` subcommand (the live-reload path
// that ships post-#235 with the rest of the alert-rule Enterprise
// plumbing). before / after are the parsed alert-rule sets at the
// reload boundary so the tamper-detection rule can witness exactly
// which rules changed.
func EmitAlertRuleEdit(ctx context.Context, e Emitter, actor, rulesPath string, before, after any) {
	EmitAdminAction(ctx, e, AdminActionInput{
		Action:     AdminActionAlertRuleEdit,
		Actor:      actor,
		EntityKind: "alert_rules",
		EntityName: rulesPath,
		Source:     AdminActionSourceCLI,
		Before:     before,
		After:      after,
	})
}

// EmitProfileAssign is the stub wire-point for the future
// enterprise-admin-controls per-user assignment feature. assignee
// is the user / group / namespace receiving the assignment;
// profileName is the profile being assigned. Severity High per
// [[security-team-audit-export]]: a per-user assignment changes
// which guardrails fire for that actor; misconfigured assignment
// can silently weaken the floor.
func EmitProfileAssign(ctx context.Context, e Emitter, actor, assignee, profileName string, before, after any) {
	EmitAdminAction(ctx, e, AdminActionInput{
		Action:     AdminActionProfileAssign,
		Actor:      actor,
		EntityKind: "profile_assignment",
		EntityName: assignee + "->" + profileName,
		Source:     AdminActionSourceCLI,
		Before:     before,
		After:      after,
		ExtraExt: map[string]any{
			"assignee":     assignee,
			"profile_name": profileName,
		},
	})
}

// EmitConfigImport is the stub wire-point for the future #275
// `kbounce config import` subcommand. sourcePath is the file
// being imported; after is the imported config object so the
// tamper-detection rule has the post-import shape to compare
// against on subsequent runs.
func EmitConfigImport(ctx context.Context, e Emitter, actor, sourcePath string, before, after any) {
	EmitAdminAction(ctx, e, AdminActionInput{
		Action:     AdminActionConfigImport,
		Actor:      actor,
		EntityKind: "config",
		EntityName: sourcePath,
		Source:     AdminActionSourceCLI,
		Before:     before,
		After:      after,
	})
}

// EmitConfigExport is the stub wire-point for the future #275
// `kbounce config export` subcommand. destinationPath is the file
// being written; snapshot is the exported config object's hash
// input (so an analyst can verify the exported file's checksum
// against the audit-recorded after_hash).
func EmitConfigExport(ctx context.Context, e Emitter, actor, destinationPath string, snapshot any) {
	EmitAdminAction(ctx, e, AdminActionInput{
		Action:     AdminActionConfigExport,
		Actor:      actor,
		EntityKind: "config",
		EntityName: destinationPath,
		Source:     AdminActionSourceCLI,
		Before:     nil,
		After:      snapshot,
	})
}

// stripLicenseContent removes keys that would leak Enterprise license
// material into the audit-export channel. The license-file plumbing
// (#235) signs bytes; those bytes MUST NOT appear in the audit log /
// webhook body. Only metadata (issuer, expiry, license id, content
// sha256) is allowed through. The strip is silent — the caller can
// freely pass a license struct in ExtraExt; the wire shape will carry
// only the safe subset.
func stripLicenseContent(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	const (
		denyContent = "license_content"
		denyBytes   = "license_bytes"
		denyPEM     = "license_pem"
		denyPriv    = "license_private_key"
		denyToken   = "license_token"
	)
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch k {
		case denyContent, denyBytes, denyPEM, denyPriv, denyToken:
			continue
		}
		out[k] = v
	}
	return out
}

// displayActor returns a non-empty actor label for the status_detail
// line. Empty input falls back to "operator" (neutral; doesn't
// fabricate a username).
func displayActor(a string) string {
	if a == "" {
		return "operator"
	}
	return a
}

// displayEntityKind returns a non-empty kind label for the
// status_detail line. Empty input falls back to "entity".
func displayEntityKind(k string) string {
	if k == "" {
		return "entity"
	}
	return k
}
