// Package structureddeny is the Go port of the canonical Python
// iam_jit.structured_deny module (#459 / §A57b). It produces the
// structured-deny payload merged into kbouncer's 403 wire body so an
// agent receives the same shape it sees from ibounce — per
// [[cross-product-agent-parity]] every Bounce gets matching agent UX.
//
// Per [[ambient-value-prop-and-friction-framing]] every operator-facing
// string here LEADS with caught_by_bouncer framing — never "ERROR"
// / "DENIED" / "BLOCKED".
//
// Per [[ibounce-honest-positioning]] the Go bouncers ship a LOCAL
// heuristic classifier ONLY (no LLM round-trip). The classifier_hook
// field is set to "go-heuristic-only" so an operator can tell at a
// glance that this 403 was not classified by the LLM (which Python
// ibounce can call). A v1.1 enhancement may add an opt-in Python-
// classifier RPC; for v1.0 the heuristic is the honest backstop.
//
// Per [[creates-never-mutates]] the structured-deny fields are
// ADDITIVE — every legacy 403 body field the wire shape already
// emits is preserved unchanged; these fields ride alongside.
package structureddeny

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Recommended-action enum (mirrors Python RECOMMENDED_ACTION_*).
const (
	RecommendedActionEasyAllow     = "easy-allow"
	RecommendedActionHaltEscalate  = "halt+escalate"
	RecommendedActionRephraseRetry = "rephrase+retry"
)

// Injection-classification enum (mirrors Python INJECTION_*).
const (
	InjectionAppearsLegitimate = "appears_legitimate"
	InjectionAmbiguous         = "ambiguous"
	InjectionAppearsAdversarial = "appears_adversarial"
)

// SchemaVersion is the wire-protocol schema version surfaced on every
// structured-deny payload. Bumped only on additive-incompatible changes;
// readers MUST tolerate unknown fields.
const SchemaVersion = "1.0"

// ClassifierHookGoHeuristic is the value emitted in the
// classifier_hook field when the Go-side heuristic ran (which is
// always for Go bouncers in v1.0). Per [[ibounce-honest-positioning]]
// we explicitly mark this so operators don't conflate Go-heuristic
// classification with Python LLM-classifier output.
const ClassifierHookGoHeuristic = "go-heuristic-only"

// KnownAdversarialPatterns mirrors the destructive-verb backstop in
// iam_jit.structured_deny.response.classify_injection_likelihood. Kept
// in this kbouncer-shape file as lowercase substrings; matched against
// a lowercased action string. Keep this list in sync ACROSS all three
// Go bouncers (dbounce + gbounce) so the parity guarantee holds.
//
// Each entry catches a verb that almost-always signals a destructive
// action. Per [[safety-mode-lean-permissive]] this is a small list —
// we do NOT want to false-positive on routine reads.
var KnownAdversarialPatterns = []string{
	"delete",
	"destroy",
	"terminate",
	"remove",
	"drop",
	"stoploggingactivity",
	"putuserpolicy",
	"attachuserpolicy",
	"createaccesskey",
	"deactivatemfadevice",
	"passrole",
}

// StructuredDeny is the canonical structured-deny payload shape. JSON
// tags match the wire-protocol field names that Python ibounce emits
// (see iam_jit.bouncer.proxy.py:~3060). An agent consuming the 403
// body uses these field names regardless of which bouncer produced it.
type StructuredDeny struct {
	CaughtByBouncer                 string `json:"caught_by_bouncer"`
	IsLikelyInjectionClassification string `json:"is_likely_injection_classification"`
	SuggestedAllowCommand           string `json:"suggested_allow_command"`
	RecommendedAction               string `json:"recommended_action"`
	DenyEventID                     string `json:"deny_event_id"`
	ClassifierHook                  string `json:"classifier_hook"`
	DenySourceClassified            string `json:"deny_source_classified"`
	StructuredDenySchemaVersion     string `json:"structured_deny_schema_version"`
}

// AsMap returns the structured-deny payload as a map[string]any for
// merging into a legacy 403 wire body without breaking the existing
// JSON encoder caller pattern (e.g. json.NewEncoder(w).Encode(body)).
func (s StructuredDeny) AsMap() map[string]any {
	return map[string]any{
		"caught_by_bouncer":                  s.CaughtByBouncer,
		"is_likely_injection_classification": s.IsLikelyInjectionClassification,
		"suggested_allow_command":            s.SuggestedAllowCommand,
		"recommended_action":                 s.RecommendedAction,
		"deny_event_id":                      s.DenyEventID,
		"classifier_hook":                    s.ClassifierHook,
		"deny_source_classified":             s.DenySourceClassified,
		"structured_deny_schema_version":     s.StructuredDenySchemaVersion,
	}
}

// ClassifyHeuristic is the deterministic destructive-verb backstop
// shipped in Go. Mirrors the structural heuristic at the bottom of
// iam_jit.structured_deny.response.classify_injection_likelihood.
//
// Returns (classification, classifierHook). classifierHook is always
// ClassifierHookGoHeuristic to make the Go-vs-Python distinction
// explicit on the wire per [[ibounce-honest-positioning]].
func ClassifyHeuristic(action string) (string, string) {
	act := strings.ToLower(strings.TrimSpace(action))
	if act != "" {
		for _, marker := range KnownAdversarialPatterns {
			if strings.Contains(act, marker) {
				return InjectionAppearsAdversarial, ClassifierHookGoHeuristic
			}
		}
	}
	return InjectionAmbiguous, ClassifierHookGoHeuristic
}

// DeriveRecommendedAction picks one of easy-allow / halt+escalate /
// rephrase+retry. Mirrors the Python decision table in
// iam_jit.structured_deny.response.derive_recommended_action.
//
// Lean-permissive per [[safety-mode-lean-permissive]] — default to
// easy-allow on ambiguous and let the agent prompt the operator —
// EXCEPT when classification == appears_adversarial, in which case
// halt+escalate so the agent can't silently retry around it.
func DeriveRecommendedAction(denySource, classification, suggestedAllowCommand string) string {
	if classification == InjectionAppearsAdversarial {
		return RecommendedActionHaltEscalate
	}
	switch denySource {
	case "dynamic_deny", "profile_only_account_ids", "profile_only_regions":
		return RecommendedActionRephraseRetry
	}
	if trimmed := strings.TrimLeft(suggestedAllowCommand, " \t"); strings.HasPrefix(trimmed, "#") {
		return RecommendedActionRephraseRetry
	}
	return RecommendedActionEasyAllow
}

// BuildOptions are the inputs to Build. Bouncer is required; the rest
// are best-effort.
type BuildOptions struct {
	// Bouncer is the wire-level caught_by_bouncer string ("kbouncer" /
	// "dbounce" / "gbounce"). Required.
	Bouncer string

	// Action is the bouncer-shaped denied action — for kbouncer this is
	// "<group>/<resource>:<verb>" (e.g. "apps/deployments:delete").
	// Used by both the heuristic + the deny_event_id seed.
	Action string

	// Resource is the bouncer-shaped resource identifier — for kbouncer
	// this is "<namespace>/<name>" or "<namespace>" when no name.
	Resource string

	// DenyReason is the human-friendly reason string (e.g. the
	// existing DecisionReason). Carried as the seed of the
	// classified-source label.
	DenyReason string

	// DenySource is the existing decision-source label (e.g. "profile"
	// / "task" / "dynamic" / "default"). Optional.
	DenySource string

	// RuleIDIfDynamic is the dynamic-deny rule id when DenySource is
	// "dynamic"; empty otherwise.
	RuleIDIfDynamic string

	// SuggestedAllowCommand is the one-line shell-friendly allow
	// command the bouncer recommends. When empty the builder leaves
	// the field empty (callers MAY pre-populate it from a recommender).
	SuggestedAllowCommand string

	// When is the ISO-8601 timestamp; defaults to time.Now().UTC() in
	// RFC3339 format when empty.
	When string
}

// Build produces a fully-populated StructuredDeny from BuildOptions.
// Mirrors the Python build_structured_deny shape verbatim on the wire.
func Build(opts BuildOptions) StructuredDeny {
	bouncer := opts.Bouncer
	if bouncer == "" {
		bouncer = "unknown"
	}
	denySource := opts.DenySource
	if denySource == "" {
		denySource = "unknown"
	}

	classification, hook := ClassifyHeuristic(opts.Action)
	recommended := DeriveRecommendedAction(denySource, classification, opts.SuggestedAllowCommand)

	when := opts.When
	if when == "" {
		when = time.Now().UTC().Format(time.RFC3339)
	}

	eventID := synthDenyEventID(bouncer, when, opts.Action, opts.Resource, opts.RuleIDIfDynamic)

	return StructuredDeny{
		CaughtByBouncer:                 bouncer,
		IsLikelyInjectionClassification: classification,
		SuggestedAllowCommand:           opts.SuggestedAllowCommand,
		RecommendedAction:               recommended,
		DenyEventID:                     eventID,
		ClassifierHook:                  hook,
		DenySourceClassified:            denySource,
		StructuredDenySchemaVersion:     SchemaVersion,
	}
}

// synthDenyEventID mirrors iam_jit.structured_deny.response.
// _synth_deny_event_id — sha256 over a stable JSON payload of the
// load-bearing deny fields, truncated to 12 hex chars.
func synthDenyEventID(bouncer, when, action, resource, ruleID string) string {
	payload := map[string]string{
		"bouncer":  bouncer,
		"when":     when,
		"action":   action,
		"resource": resource,
		"rule":     ruleID,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// Defensive: marshal can fail on cyclic structures, which we
		// don't have here. Fall back to a timestamp-only seed.
		b = []byte(bouncer + ":" + when + ":" + action + ":" + resource + ":" + ruleID)
	}
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])[:12]
	return "evt_" + bouncer + "_" + sha
}
