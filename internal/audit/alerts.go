// Slice 2 of #252 — suspicious-activity alert rule engine. Sits
// between the proxy decision path and the audit Manager (the
// transport layer): every decision event is observed by the engine
// + then forwarded to the underlying Emitter; when a sliding-window
// rule fires, a synthetic alert event (EventTypeSecurityAlert) is
// emitted via the SAME transport so it lands in the JSONL log + the
// HTTPS webhook alongside the decision events that triggered it.
//
// Per [[security-team-audit-export]] the rule engine is deterministic
// (no LLM); per [[scorer-is-ground-truth]] no rule re-evaluates a
// decision's verdict — rules only count + classify what the scorer +
// proxy already decided. Per [[security-team-positioning-safety-not-
// surveillance]] every operator-facing string in this package uses
// NEUTRAL language; we name the rule + report the observation, never
// frame the operator as having "violated" anything. A test scans
// every alert payload for forbidden words to enforce that invariant.
//
// Cross-product parity per [[cross-product-agent-parity]]: ibounce
// + dbounce ship the SAME four built-in rule names + the SAME OCSF
// alert shape (class_uid 6003 / activity_id 99 / activity_name
// "anomaly_detected") so a single SIEM dashboard can pivot rule
// activity across all three Bounce products.

package audit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// AlertActivityName is the OCSF activity_name string every alert
// event carries. Pinned constant so downstream SIEMs can filter on
// it without product-specific glue.
const AlertActivityName = "anomaly_detected"

// Default rule thresholds. Override via the --alert-rules YAML file
// per the engine's RulesConfig loader.
const (
	DefaultAdminFallbackBurstThreshold = 3
	DefaultAdminFallbackBurstWindow    = 5 * time.Minute
	DefaultPauseLongThreshold          = 30 * time.Minute
	DefaultPauseLongWindow             = 2 * time.Hour // bound the per-event ring size
)

// DefaultK8sHighRiskSubresources is the built-in set of K8s
// subresources whose DENY in transparent mode triggers the
// unusual_high_risk_action rule. These are the verbs that move
// laterally / elevate / bypass admission — exec / portforward /
// proxy / bind / escalate / impersonate.
//
// Per [[scorer-is-ground-truth]] this is a flat lookup — the rule
// counts the event, the scorer already decided it was worth denying.
var DefaultK8sHighRiskSubresources = []string{
	"exec",
	"portforward",
	"proxy",
	"bind",
	"escalate",
	"impersonate",
}

// DefaultK8sHighRiskClusterMutations is the built-in set of
// cluster-scoped resources whose DELETE / mutating verb in
// transparent mode triggers the unusual_high_risk_action rule.
// Cluster-scoped because a namespace-scoped delete is less
// blast-radius-relevant than a clusterrole / clusterrolebinding /
// namespace delete.
var DefaultK8sHighRiskClusterMutations = []string{
	"clusterrolebindings",
	"clusterroles",
	"namespaces",
}

// ErrAlertRulesLicenseRequired is the error the CLI returns when
// an operator passes --alert-rules without an Enterprise license.
// Same placeholder shape as ErrLicenseRequired; the rule engine is
// Enterprise per [[security-team-audit-export]] (rule curation is
// a security-team workflow, not a solo-laptop one). Real license-
// file plumbing pending #235.
var ErrAlertRulesLicenseRequired = fmt.Errorf(
	"audit alert rules require Enterprise license (placeholder — " +
		"license-file plumbing not yet implemented for kbounce; see #235)")

// Suggestion strings — neutral phrasing per [[security-team-
// positioning-safety-not-surveillance]]. Each suggestion describes
// an action the OPERATOR can take, never frames the operator's
// past behavior as wrong.
const (
	SuggestionAdminFallbackBurst = "consider distributing a profile " +
		"with broader scope, or extending the active task scope, so the " +
		"operator does not need to re-enter a pause window"
	SuggestionPauseLong = "consider whether the long-running pause " +
		"reflects a workflow that would be better served by a scoped " +
		"task or a profile rule"
	SuggestionNonOrgProfileInstall = "review the profile source URL " +
		"and add it to the org-approved allowlist if appropriate"
	SuggestionUnusualHighRiskAction = "review the decision context to " +
		"confirm the denied action was intended; add an explicit allow " +
		"rule when appropriate"
)

// AlertRule is the interface every built-in (and future operator-
// supplied) sliding-window rule implements. Observe() is called once
// per decision event; the rule maintains its own internal state +
// returns a non-nil alert when the pattern fires. State is mutex-
// guarded by the engine; rules don't need their own locks.
//
// Rules MUST return alerts deterministically — the same sequence of
// events MUST produce the same alert sequence regardless of timing.
// Per [[scorer-is-ground-truth]] no rule re-evaluates verdict /
// severity; rules count + classify what the scorer + proxy decided.
type AlertRule interface {
	// Name is the stable rule identifier surfaced in alert events +
	// MCP status. Matches the YAML config key.
	Name() string
	// Description is a human-readable summary for `kbounce rules list`
	// + the YAML config doc-comment.
	Description() string
	// Severity is the OCSF severity_id (1-5) every alert from this
	// rule carries.
	Severity() int
	// Observe records the event in the rule's sliding-window state
	// and returns alert metadata when the pattern fires. The engine
	// builds the OCSF event from the returned fields. Returns ok=false
	// when no alert fires (the hot path).
	Observe(ev Event, now time.Time) (alert AlertFire, ok bool)
}

// AlertFire is the per-fire metadata the rule returns to the engine.
// The engine builds the OCSF alert Event from these fields + the
// rule's static Name / Description / Severity.
type AlertFire struct {
	// Detail is the human-readable status_detail string (already
	// composed with the matched-event count + window).
	Detail string
	// WindowSeconds is the sliding-window the rule evaluated over.
	WindowSeconds int
	// MatchedEventCount is the number of in-window events that
	// satisfied the rule's predicate.
	MatchedEventCount int
	// Suggestion is the neutral-language operator hint surfaced in
	// unmapped.iam_jit.suggestion.
	Suggestion string
	// Ext lets rules attach rule-specific fields (e.g. pause_seconds,
	// observed_url) under unmapped.iam_jit.ext for SIEM filters.
	Ext map[string]any
}

// RulesConfig is the on-disk YAML shape for --alert-rules. All
// fields optional; absent fields fall back to built-in defaults so
// an operator can override one threshold without re-declaring the
// rest.
type RulesConfig struct {
	AdminFallbackBurst    *AdminFallbackBurstConfig    `yaml:"admin_fallback_burst,omitempty"`
	PauseLong             *PauseLongConfig             `yaml:"pause_long,omitempty"`
	NonOrgProfileInstall  *NonOrgProfileInstallConfig  `yaml:"non_org_profile_install,omitempty"`
	UnusualHighRiskAction *UnusualHighRiskActionConfig `yaml:"unusual_high_risk_action,omitempty"`
}

// AdminFallbackBurstConfig tunes the admin_fallback_burst rule. A
// "BYPASS" verdict on a decision event corresponds to a pause-active
// fallback in the proxy hot-path — the operator-initiated escape
// hatch per [[safety-mode-lean-permissive]]. The rule fires when
// more than Threshold of those fire inside WindowSeconds.
type AdminFallbackBurstConfig struct {
	Threshold     int `yaml:"threshold,omitempty"`
	WindowSeconds int `yaml:"window_seconds,omitempty"`
}

// PauseLongConfig tunes the pause_long rule. The rule fires when
// the OBSERVED span of consecutive BYPASS events (the proxy's
// pause-bypass signal) exceeds ThresholdSeconds, indicating the
// operator has been in a pause window long enough to merit review.
type PauseLongConfig struct {
	ThresholdSeconds int `yaml:"threshold_seconds,omitempty"`
}

// NonOrgProfileInstallConfig tunes the non_org_profile_install rule.
// ApprovedURLs is the operator-curated allowlist; events emitted under
// a profile whose source URL is NON-empty AND NOT in this list trigger
// the rule. The rule fires AT MOST ONCE per (profile-name, profile-
// source) pair across the engine's lifetime to avoid alert storms.
type NonOrgProfileInstallConfig struct {
	ApprovedURLs []string `yaml:"approved_urls,omitempty"`
}

// UnusualHighRiskActionConfig tunes the unusual_high_risk_action rule.
// HighRiskSubresources + HighRiskClusterMutations override the built-
// in defaults when set; empty / nil falls back to the defaults.
type UnusualHighRiskActionConfig struct {
	HighRiskSubresources     []string `yaml:"high_risk_subresources,omitempty"`
	HighRiskClusterMutations []string `yaml:"high_risk_cluster_mutations,omitempty"`
}

// LoadRulesConfig reads + parses a YAML file at path. Returns a
// fully-populated config; missing fields keep their nil pointers so
// the engine builder can apply built-in defaults selectively.
func LoadRulesConfig(path string) (*RulesConfig, error) {
	if path == "" {
		return &RulesConfig{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit: read alert rules file: %w", err)
	}
	var cfg RulesConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("audit: parse alert rules file %q: %w", path, err)
	}
	return &cfg, nil
}

// BuildBuiltinRules constructs the four built-in alert rules from
// the loaded config (or empty config → all defaults). Returns rules
// in stable order so test output is deterministic.
func BuildBuiltinRules(cfg *RulesConfig) []AlertRule {
	if cfg == nil {
		cfg = &RulesConfig{}
	}
	afb := &adminFallbackBurstRule{
		threshold: DefaultAdminFallbackBurstThreshold,
		window:    DefaultAdminFallbackBurstWindow,
	}
	if cfg.AdminFallbackBurst != nil {
		if cfg.AdminFallbackBurst.Threshold > 0 {
			afb.threshold = cfg.AdminFallbackBurst.Threshold
		}
		if cfg.AdminFallbackBurst.WindowSeconds > 0 {
			afb.window = time.Duration(cfg.AdminFallbackBurst.WindowSeconds) * time.Second
		}
	}

	pl := &pauseLongRule{
		threshold: DefaultPauseLongThreshold,
		window:    DefaultPauseLongWindow,
	}
	if cfg.PauseLong != nil && cfg.PauseLong.ThresholdSeconds > 0 {
		pl.threshold = time.Duration(cfg.PauseLong.ThresholdSeconds) * time.Second
	}

	npi := &nonOrgProfileInstallRule{
		approved: map[string]struct{}{},
		fired:    map[string]struct{}{},
	}
	if cfg.NonOrgProfileInstall != nil {
		for _, u := range cfg.NonOrgProfileInstall.ApprovedURLs {
			if u != "" {
				npi.approved[u] = struct{}{}
			}
		}
	}

	uhr := &unusualHighRiskActionRule{
		subresources:      stringSet(DefaultK8sHighRiskSubresources),
		clusterMutations:  stringSet(DefaultK8sHighRiskClusterMutations),
	}
	if cfg.UnusualHighRiskAction != nil {
		if len(cfg.UnusualHighRiskAction.HighRiskSubresources) > 0 {
			uhr.subresources = stringSet(cfg.UnusualHighRiskAction.HighRiskSubresources)
		}
		if len(cfg.UnusualHighRiskAction.HighRiskClusterMutations) > 0 {
			uhr.clusterMutations = stringSet(cfg.UnusualHighRiskAction.HighRiskClusterMutations)
		}
	}

	return []AlertRule{afb, pl, npi, uhr}
}

// stringSet is a tiny helper to turn a slice into a lookup map for
// O(1) membership tests inside the hot-path Observe calls.
func stringSet(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if x != "" {
			out[x] = struct{}{}
		}
	}
	return out
}

// RuleEngine wraps an underlying Emitter (typically *Manager). Every
// event handed to Emit() is forwarded to the underlying emitter first
// + then observed by each registered rule; fired alerts are re-emitted
// through the underlying emitter so they land in the SAME JSONL log +
// HTTPS webhook as decision events.
//
// The engine is itself an Emitter so the proxy hot-path doesn't need
// to know whether alerts are enabled — wiring the engine in place of
// the bare Manager is the toggle.
//
// Concurrency: rules are evaluated under a single per-engine mutex
// so each rule's sliding-window state remains consistent under
// concurrent Emit() calls. The mutex is held briefly (no I/O); the
// downstream Emit() of an alert is OUTSIDE the lock to avoid
// re-entering rules while the lock is held (alert events skip rule
// evaluation anyway — see Emit()).
type RuleEngine struct {
	emitter     Emitter
	rules       []AlertRule
	mu          sync.Mutex
	firedCount  atomic.Int64
	lastPattern atomic.Value // string
	now         func() time.Time
}

// NewRuleEngine constructs an engine wrapping the given Emitter. A
// nil Emitter is rejected — the engine is only useful when alerts can
// reach the JSONL log + webhook.
func NewRuleEngine(emitter Emitter, rules []AlertRule) (*RuleEngine, error) {
	if emitter == nil {
		return nil, fmt.Errorf("audit: rule engine requires a non-nil Emitter")
	}
	eng := &RuleEngine{
		emitter: emitter,
		rules:   rules,
		now:     func() time.Time { return time.Now().UTC() },
	}
	eng.lastPattern.Store("")
	return eng, nil
}

// withClock is a test hook so race / sliding-window tests can advance
// time deterministically without sleeping the test.
func (e *RuleEngine) withClock(now func() time.Time) *RuleEngine {
	e.now = now
	return e
}

// Emit forwards ev to the underlying emitter + then runs every rule
// against the event under the engine mutex. Each fired alert is
// re-emitted through the underlying emitter (NOT back through the
// engine — alerts don't trigger rules) so it lands in the JSONL log
// + webhook alongside the decision that triggered it.
func (e *RuleEngine) Emit(ctx context.Context, ev Event) {
	if e == nil {
		return
	}
	// Alert events skip rule evaluation entirely — prevents recursion +
	// avoids feedback loops where a noisy alert triggers itself.
	if ev.EventType == EventTypeSecurityAlert {
		e.emitter.Emit(ctx, ev)
		return
	}
	// AUDIT_DROPPED markers are transport-layer signals, not real
	// decisions; skip rule evaluation but still forward them so the
	// downstream consumer sees the gap.
	if ev.EventType == EventTypeAuditDropped {
		e.emitter.Emit(ctx, ev)
		return
	}
	e.emitter.Emit(ctx, ev)
	now := e.now()
	e.mu.Lock()
	fires := make([]firedAlert, 0)
	for _, r := range e.rules {
		if alert, ok := r.Observe(ev, now); ok {
			fires = append(fires, firedAlert{rule: r, fire: alert})
		}
	}
	e.mu.Unlock()
	// Emit alerts outside the lock — the underlying Emitter does its
	// own bounded-queue handling + we don't want to block other rule
	// evaluations on a downstream consumer.
	for _, f := range fires {
		alertEv := buildAlertEvent(f.rule, f.fire, now)
		e.firedCount.Add(1)
		e.lastPattern.Store(f.rule.Name())
		e.emitter.Emit(ctx, alertEv)
	}
}

// firedAlert pairs a rule with its single Observe() return so the
// engine can build alert events after releasing the lock.
type firedAlert struct {
	rule AlertRule
	fire AlertFire
}

// Status snapshots the wrapped emitter's status + the engine's own
// alert counters. The MCP audit-export status tool surfaces this so
// operators can see "is the engine running, how many alerts have
// fired, what was the last pattern" in one shot.
func (e *RuleEngine) Status() Status {
	if e == nil {
		return Status{}
	}
	s := e.emitter.Status()
	s.AlertsEnabled = true
	s.AlertsFiredCount = e.firedCount.Load()
	if v, ok := e.lastPattern.Load().(string); ok {
		s.LastAlertPattern = v
	}
	return s
}

// RuleNames returns the registered rule names in stable order.
// Surfaced by MCP + banner output.
func (e *RuleEngine) RuleNames() []string {
	if e == nil {
		return nil
	}
	out := make([]string, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r.Name())
	}
	return out
}

// buildAlertEvent constructs the OCSF v1.1.0 class 6003 alert Event
// from a rule's per-fire metadata. Activity is "Other" (99); status
// is "Other" (99); the iam-jit-specific bits land under unmapped.iam_jit
// so a SIEM pivot on class_uid=6003 + activity_id=99 surfaces every
// alert across the Bounce suite.
//
// Per [[security-team-positioning-safety-not-surveillance]]: every
// string this function emits is NEUTRAL. A test scans the JSON output
// for forbidden words to enforce that.
func buildAlertEvent(r AlertRule, fire AlertFire, now time.Time) Event {
	ext := map[string]any{}
	for k, v := range fire.Ext {
		ext[k] = v
	}
	if _, ok := ext["pattern"]; !ok {
		ext["pattern"] = r.Name()
	}
	if _, ok := ext["window_seconds"]; !ok && fire.WindowSeconds > 0 {
		ext["window_seconds"] = fire.WindowSeconds
	}
	if _, ok := ext["matched_event_count"]; !ok && fire.MatchedEventCount > 0 {
		ext["matched_event_count"] = fire.MatchedEventCount
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
		Time:         now.UTC().UnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   ActivityOther,
		ActivityName: AlertActivityName,
		TypeUID:      ClassUID*100 + ActivityOther,
		TypeName:     typeNameForActivity(ActivityOther),
		SeverityID:   r.Severity(),
		Severity:     severityName(r.Severity()),
		StatusID:     StatusOther,
		Status:       "Other",
		StatusDetail: fire.Detail,
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType:         string(EventTypeSecurityAlert),
				Pattern:           r.Name(),
				WindowSeconds:     fire.WindowSeconds,
				MatchedEventCount: fire.MatchedEventCount,
				Suggestion:        fire.Suggestion,
				Ext:               ext,
			},
		},
		EventType: EventTypeSecurityAlert,
	}
}

// severityName maps the OCSF severity_id enum to its canonical name.
// Used to populate the alert Event's Severity string field.
func severityName(id int) string {
	switch id {
	case SeverityInformational:
		return "Informational"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------
// Built-in rule implementations.
// ---------------------------------------------------------------------

// adminFallbackBurstRule fires when more than threshold BYPASS
// verdicts (pause-active escape-hatch decisions) land inside window.
// Uses a sliding ring of timestamps; old entries fall off on each
// Observe so memory is bounded by threshold + a small overhead.
type adminFallbackBurstRule struct {
	threshold int
	window    time.Duration
	// times holds the timestamps of recent BYPASS events. The slice is
	// trimmed on every Observe to keep its size bounded by the
	// in-window event count (which itself is bounded by the rule's
	// firing threshold + a small overshoot before the engine emits the
	// alert).
	times []time.Time
}

func (r *adminFallbackBurstRule) Name() string        { return "admin_fallback_burst" }
func (r *adminFallbackBurstRule) Description() string { return "Multiple admin-fallback (pause-bypass) grants in a short window" }
func (r *adminFallbackBurstRule) Severity() int       { return SeverityMedium }

func (r *adminFallbackBurstRule) Observe(ev Event, now time.Time) (AlertFire, bool) {
	if !isAdminFallbackEvent(ev) {
		return AlertFire{}, false
	}
	cutoff := now.Add(-r.window)
	// Drop entries older than the window.
	keep := r.times[:0]
	for _, t := range r.times {
		if !t.Before(cutoff) {
			keep = append(keep, t)
		}
	}
	r.times = keep
	r.times = append(r.times, now)
	if len(r.times) <= r.threshold {
		return AlertFire{}, false
	}
	count := len(r.times)
	// Reset the buffer after firing so the same burst doesn't re-fire
	// on every subsequent event in the same window — operator sees one
	// alert per burst, not one per event-over-threshold.
	r.times = r.times[:0]
	return AlertFire{
		Detail: fmt.Sprintf(
			"Pattern admin_fallback_burst fired: %d admin-fallback grants in last %s",
			count, r.window),
		WindowSeconds:     int(r.window.Seconds()),
		MatchedEventCount: count,
		Suggestion:        SuggestionAdminFallbackBurst,
	}, true
}

// pauseLongRule fires when the observed span between the first +
// most-recent BYPASS event exceeds threshold. Approximates "the
// operator has been in a pause window for at least N minutes" using
// only the audit-event stream (no separate pause-event channel).
// Resets after each fire so a continuing pause re-fires once per
// threshold rather than continuously.
type pauseLongRule struct {
	threshold time.Duration
	window    time.Duration // upper bound on how far back to look — bounds memory under sustained traffic
	firstAt   time.Time
}

func (r *pauseLongRule) Name() string        { return "pause_long" }
func (r *pauseLongRule) Description() string { return "Pause / admin-fallback window has been active long enough to merit review" }
func (r *pauseLongRule) Severity() int       { return SeverityMedium }

func (r *pauseLongRule) Observe(ev Event, now time.Time) (AlertFire, bool) {
	if !isAdminFallbackEvent(ev) {
		// Non-admin-fallback events end any tracked pause window — the
		// operator is back to gated decisions.
		r.firstAt = time.Time{}
		return AlertFire{}, false
	}
	if r.firstAt.IsZero() {
		r.firstAt = now
		return AlertFire{}, false
	}
	span := now.Sub(r.firstAt)
	if span < r.threshold {
		return AlertFire{}, false
	}
	pauseSeconds := int(span.Seconds())
	// Reset so the next fire requires another full threshold of
	// continuous BYPASS events.
	r.firstAt = now
	return AlertFire{
		Detail: fmt.Sprintf(
			"Pattern pause_long fired: pause-bypass window observed for %s (threshold %s)",
			span.Round(time.Second), r.threshold),
		WindowSeconds:     int(r.threshold.Seconds()),
		MatchedEventCount: 1,
		Suggestion:        SuggestionPauseLong,
		Ext: map[string]any{
			"observed_pause_seconds": pauseSeconds,
		},
	}, true
}

// nonOrgProfileInstallRule fires once per (profile-name,
// profile-source) pair when the profile's source URL is non-empty
// AND NOT in the operator-curated allowlist. Deduped so a flood of
// decisions under a single non-org profile produces ONE alert, not
// one per decision.
type nonOrgProfileInstallRule struct {
	approved map[string]struct{}
	fired    map[string]struct{}
}

func (r *nonOrgProfileInstallRule) Name() string        { return "non_org_profile_install" }
func (r *nonOrgProfileInstallRule) Description() string { return "Profile installed from a source URL outside the org-approved allowlist" }
func (r *nonOrgProfileInstallRule) Severity() int       { return SeverityMedium }

func (r *nonOrgProfileInstallRule) Observe(ev Event, _ time.Time) (AlertFire, bool) {
	src := profileSource(ev)
	if src == "" || src == "local" {
		return AlertFire{}, false
	}
	if _, ok := r.approved[src]; ok {
		return AlertFire{}, false
	}
	name := ev.Unmapped.IAMJIT.Profile
	dedupeKey := name + "|" + src
	if _, ok := r.fired[dedupeKey]; ok {
		return AlertFire{}, false
	}
	r.fired[dedupeKey] = struct{}{}
	return AlertFire{
		Detail: fmt.Sprintf(
			"Pattern non_org_profile_install fired: profile %q installed from %s (not in approved-URL allowlist)",
			name, src),
		WindowSeconds:     0,
		MatchedEventCount: 1,
		Suggestion:        SuggestionNonOrgProfileInstall,
		Ext: map[string]any{
			"observed_profile_source": src,
			"observed_profile_name":   name,
		},
	}, true
}

// profileSource extracts the profile_source field from an event's
// ext map. Returns "" when missing / wrong-typed.
func profileSource(ev Event) string {
	if ev.Unmapped.IAMJIT.Ext == nil {
		return ""
	}
	v, ok := ev.Unmapped.IAMJIT.Ext["profile_source"]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// unusualHighRiskActionRule fires when a transparent-mode DENY
// (verdict=DENY + enforced=true) lands on a K8s high-risk verb:
// a subresource in HighRiskSubresources OR a DELETE / mutating verb
// on a cluster-scoped resource in HighRiskClusterMutations.
//
// Per [[scorer-is-ground-truth]] the rule trusts the scorer's DENY
// — it's surfacing the kind of decision a security-team reader most
// wants to know fired, not re-judging it.
type unusualHighRiskActionRule struct {
	subresources     map[string]struct{}
	clusterMutations map[string]struct{}
}

func (r *unusualHighRiskActionRule) Name() string        { return "unusual_high_risk_action" }
func (r *unusualHighRiskActionRule) Description() string { return "Transparent-mode DENY on a K8s high-risk verb (exec/escalate/bind/cluster-scoped mutation/etc.)" }
func (r *unusualHighRiskActionRule) Severity() int       { return SeverityHigh }

func (r *unusualHighRiskActionRule) Observe(ev Event, _ time.Time) (AlertFire, bool) {
	if !strings.EqualFold(ev.Unmapped.IAMJIT.Verdict, "DENY") {
		return AlertFire{}, false
	}
	if !ev.Unmapped.IAMJIT.Enforced {
		return AlertFire{}, false
	}
	if !strings.EqualFold(ev.Unmapped.IAMJIT.Mode, "transparent") {
		return AlertFire{}, false
	}
	sub := extStringFromEvent(ev, "k8s_subresource")
	verb := strings.ToLower(extStringFromEvent(ev, "k8s_verb"))
	resource := ""
	if len(ev.Resources) > 0 {
		// Resource type is "kubernetes <singular>"; the parser feeds
		// the plural form into the ext map under k8s_resource (not yet
		// present in the Event ext — use the resources[].uid which holds
		// the plural).
		resource = resourceFromUID(ev.Resources[0].UID)
	}

	if sub != "" {
		if _, ok := r.subresources[strings.ToLower(sub)]; ok {
			return fireUnusual(sub, verb, resource, "subresource"), true
		}
	}
	if _, ok := r.clusterMutations[strings.ToLower(resource)]; ok {
		// Mutating verbs on cluster-scoped sensitive resources.
		if isMutatingVerb(verb) {
			return fireUnusual(sub, verb, resource, "cluster_mutation"), true
		}
	}
	return AlertFire{}, false
}

// isMutatingVerb reports whether the K8s verb modifies state (the
// canonical RBAC mutating set used in built-in safe-default profiles).
func isMutatingVerb(verb string) bool {
	switch strings.ToLower(verb) {
	case "create", "update", "patch", "delete", "deletecollection":
		return true
	}
	return false
}

// resourceFromUID extracts the resource (plural) from an OCSF
// resources[].uid built by buildResources(). The shape is one of:
//
//	"namespaces/<ns>/<resource>/<name>"  namespaced + named
//	"namespaces/<ns>/<resource>"         namespaced collection
//	"<resource>/<name>"                  cluster-scoped + named
//	"<resource>"                         cluster-scoped collection
//
// We pull the resource by stripping the namespaces/<ns>/ prefix when
// present + then taking the first segment.
func resourceFromUID(uid string) string {
	rest := uid
	if strings.HasPrefix(rest, "namespaces/") {
		// Skip "namespaces/<ns>/".
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 3 {
			return ""
		}
		rest = parts[2]
	}
	if rest == "" {
		return ""
	}
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

// fireUnusual composes the AlertFire returned by the
// unusual_high_risk_action rule.
func fireUnusual(sub, verb, resource, kind string) AlertFire {
	target := verb
	if sub != "" {
		target = sub
	}
	if resource != "" {
		target = target + " on " + resource
	}
	return AlertFire{
		Detail: fmt.Sprintf(
			"Pattern unusual_high_risk_action fired: transparent-mode DENY observed for %s",
			target),
		WindowSeconds:     0,
		MatchedEventCount: 1,
		Suggestion:        SuggestionUnusualHighRiskAction,
		Ext: map[string]any{
			"observed_kind":        kind,
			"observed_subresource": sub,
			"observed_verb":        verb,
			"observed_resource":    resource,
		},
	}
}

// isAdminFallbackEvent reports whether the event represents a
// pause-bypass / admin-fallback grant (the operator-initiated escape
// hatch that demotes transparent-mode enforcement to cooperative for
// the pause window). The proxy sets DecisionInput.AdminFallback when
// the decision was made while a pause was active; that bit lands on
// unmapped.iam_jit.ext.admin_fallback. This helper is the single
// source of truth for the predicate so the admin_fallback_burst +
// pause_long rules stay aligned.
func isAdminFallbackEvent(ev Event) bool {
	if ev.Unmapped.IAMJIT.Ext == nil {
		return false
	}
	v, ok := ev.Unmapped.IAMJIT.Ext["admin_fallback"]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// extStringFromEvent reads a string field from the event's
// unmapped.iam_jit.ext map. Returns "" when missing / wrong-typed.
// Named distinctly from presets.go's extString (which navigates a
// generic map path) to avoid the file-level collision while keeping
// both call sites focused.
func extStringFromEvent(ev Event, key string) string {
	if ev.Unmapped.IAMJIT.Ext == nil {
		return ""
	}
	v, ok := ev.Unmapped.IAMJIT.Ext[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
