// Package recommender synthesizes draft rules from observed audit-
// log traffic.
//
// Cross-product parity with iam-jit-bouncer's Slice D recommender
// (see [[cross-product-agent-parity]]): an agent that learned
// `ibounce recommend` uses the same observation-then-synthesize
// shape on `kbounce rules recommend`.
//
// Algorithm (mirrors the Python side; K8s-flavored):
//
//  1. Filter to ALLOW decisions only (deny/prompt are NOT
//     endorsement; cross-product CRIT-28-01 invariant).
//  2. Skip task-scoped decisions by default (they're one-off
//     declared sessions; rolling them into permanent rules is
//     opt-in via include_task_scoped).
//  3. Group by (resource, verb).
//  4. For groups with support >= min_support:
//     - Detect a useful namespace longest-common-prefix glob.
//     - Detect a useful resource-name longest-common-prefix glob.
//     - Construct an ALLOW rule with the detected scopes.
//
// Per [[scorer-is-ground-truth]]: synthesis is deterministic.
// No LLM. Frequency + LCP detection. The agent always reviews +
// decides; nothing auto-applies unless --apply is passed.
//
// Per audit-cadence (b) in the parent commit body: when the
// operator passes --apply, the synthesizer dedupes against rules
// already present in the store. If a recommendation matches a
// rule pattern + scopes already in the table, it's skipped — so
// re-running recommend never resurrects a rule the operator
// previously removed (the absence of the rule in the table IS
// the operator's signal that they don't want it).
package recommender

import (
	"sort"
	"strings"
	"time"

	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// MinNamespaceSupportFraction is the minimum fraction of a group's
// observations that must share a namespace prefix before we infer
// a namespace scope. Below this, ship the rule with no namespace
// scope rather than narrow to a prefix that the majority of
// historical traffic wouldn't have matched (cross-product
// MED-28-01 invariant).
const MinNamespaceSupportFraction = 0.5

// MinResourceSupportFraction mirrors MinNamespaceSupportFraction
// for the resource-name LCP detection.
const MinResourceSupportFraction = 0.5

// MinSupportDefault is the default --min-support gate.
const MinSupportDefault = 3

// Recommendation is one synthesized draft rule + the WHY data the
// operator needs to review it. Per the Research Assistant pattern
// in the Python recommender: never just "here's a rule," always
// "here's the rule + the observation that justified it."
type Recommendation struct {
	// ProposedRule is the rule the operator would get from
	// `--apply` for this recommendation.
	ProposedRule rules.ProxyRule

	// SupportCount is the number of observed ALLOW decisions in the
	// window that match this (resource, verb) group.
	SupportCount int

	// HitRate is SupportCount divided by the total observed ALLOW
	// decisions in the window. Useful for prioritizing review.
	HitRate float64

	// NamespaceRationale explains the namespace scope (or absence).
	// Empty when no namespace data was observed.
	NamespaceRationale string

	// ResourceRationale explains the resource-name scope (or
	// absence). Empty when no name data was observed.
	ResourceRationale string

	// SkippedReason is non-empty when --apply would skip this
	// recommendation because the rule already exists in the store
	// (audit-cadence (b)). Recommendations are still returned so the
	// operator can see "yes, this is already covered" rather than
	// silently disappearing.
	SkippedReason string
}

// ToMap returns a JSON-friendly representation for CLI --json +
// MCP tool responses.
func (r Recommendation) ToMap() map[string]any {
	out := map[string]any{
		"proposed_rule": r.ProposedRule.ToMap(),
		"support_count": r.SupportCount,
		"hit_rate":      round4(r.HitRate),
	}
	if r.NamespaceRationale != "" {
		out["namespace_rationale"] = r.NamespaceRationale
	}
	if r.ResourceRationale != "" {
		out["resource_rationale"] = r.ResourceRationale
	}
	if r.SkippedReason != "" {
		out["skipped_reason"] = r.SkippedReason
	}
	return out
}

// WindowSummary is the leading paragraph data for a `recommend`
// output. Mirrors the Python summarize_window shape.
type WindowSummary struct {
	TotalCalls         int
	DistinctResources  int
	DistinctVerbs      int
	AllowCount         int
	DenyCount          int
	WindowStart        time.Time
	WindowEnd          time.Time
}

// ToMap returns a JSON-friendly representation.
func (w WindowSummary) ToMap() map[string]any {
	out := map[string]any{
		"total_calls":        w.TotalCalls,
		"distinct_resources": w.DistinctResources,
		"distinct_verbs":     w.DistinctVerbs,
		"allow_count":        w.AllowCount,
		"deny_count":         w.DenyCount,
	}
	if !w.WindowStart.IsZero() {
		out["window_start"] = w.WindowStart.UTC().Format(time.RFC3339)
	}
	if !w.WindowEnd.IsZero() {
		out["window_end"] = w.WindowEnd.UTC().Format(time.RFC3339)
	}
	return out
}

// SynthesizeOptions tunes one synthesis run.
type SynthesizeOptions struct {
	// MinSupport is the minimum decision count per (resource, verb)
	// group before we'll synthesize a rule. Defaults to MinSupportDefault.
	MinSupport int

	// IncludeTaskScoped, when true, also folds task-scoped
	// decisions into the recommendation set. Default false (task-
	// scoped decisions are one-off declared sessions).
	IncludeTaskScoped bool

	// ExistingRules are the rules currently in the store. Used to
	// mark recommendations as already-covered (audit-cadence (b))
	// so re-running recommend doesn't resurrect previously-removed
	// patterns or duplicate active ones. May be nil — recommendations
	// are returned without dedupe.
	ExistingRules []rules.ProxyRule
}

// Synthesize builds draft rules from the given decision rows. Pure
// function: no I/O. The caller (CLI or MCP tool) is responsible
// for fetching decisions + persisting the result.
//
// Returns recommendations sorted by support DESC then by pattern
// for stable output.
func Synthesize(decisions []store.DecisionRow, opts SynthesizeOptions) ([]Recommendation, WindowSummary) {
	summary := summarize(decisions)
	if opts.MinSupport <= 0 {
		opts.MinSupport = MinSupportDefault
	}

	// Group ALLOW decisions by (resource, verb).
	type groupKey struct {
		resource string
		verb     string
	}
	groups := map[groupKey][]store.DecisionRow{}
	totalAllow := 0
	for _, d := range decisions {
		if d.DecisionVerdict != "allow" {
			continue
		}
		if !opts.IncludeTaskScoped && d.TaskID != "" {
			continue
		}
		resource := strings.ToLower(strings.TrimSpace(d.ParsedResource))
		verb := strings.ToLower(strings.TrimSpace(d.ParsedVerb))
		if resource == "" || verb == "" {
			// Unparseable rows can't drive a rule pattern.
			continue
		}
		k := groupKey{resource: resource, verb: verb}
		groups[k] = append(groups[k], d)
		totalAllow++
	}

	recs := make([]Recommendation, 0, len(groups))
	for k, members := range groups {
		support := len(members)
		if support < opts.MinSupport {
			continue
		}
		nsScope, nsRationale := detectNamespacePrefix(members)
		nameScope, nameRationale := detectResourcePrefix(members)
		rule := rules.ProxyRule{
			Pattern:        k.resource + ":" + k.verb,
			Effect:         rules.EffectAllow,
			NamespaceScope: nsScope,
			ResourceScope:  nameScope,
			Note:           noteFromWindow(support, summary),
			Origin:         "recommendation",
		}
		rec := Recommendation{
			ProposedRule:       rule,
			SupportCount:       support,
			HitRate:            float64(support) / float64(maxInt(totalAllow, 1)),
			NamespaceRationale: nsRationale,
			ResourceRationale:  nameRationale,
		}
		if reason := dedupReason(rule, opts.ExistingRules); reason != "" {
			rec.SkippedReason = reason
		}
		recs = append(recs, rec)
	}

	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].SupportCount != recs[j].SupportCount {
			return recs[i].SupportCount > recs[j].SupportCount
		}
		return recs[i].ProposedRule.Pattern < recs[j].ProposedRule.Pattern
	})
	return recs, summary
}

// summarize is the WindowSummary builder. Operates on the raw
// decision list (pre-filter) so the summary reports the full
// observation window.
func summarize(decisions []store.DecisionRow) WindowSummary {
	if len(decisions) == 0 {
		return WindowSummary{}
	}
	out := WindowSummary{TotalCalls: len(decisions)}
	resources := map[string]struct{}{}
	verbs := map[string]struct{}{}
	for _, d := range decisions {
		if d.ParsedResource != "" {
			resources[strings.ToLower(d.ParsedResource)] = struct{}{}
		}
		if d.ParsedVerb != "" {
			verbs[strings.ToLower(d.ParsedVerb)] = struct{}{}
		}
		switch d.DecisionVerdict {
		case "allow":
			out.AllowCount++
		case "deny":
			out.DenyCount++
		}
		if !d.At.IsZero() {
			if out.WindowStart.IsZero() || d.At.Before(out.WindowStart) {
				out.WindowStart = d.At
			}
			if d.At.After(out.WindowEnd) {
				out.WindowEnd = d.At
			}
		}
	}
	out.DistinctResources = len(resources)
	out.DistinctVerbs = len(verbs)
	return out
}

// detectNamespacePrefix returns the namespace scope to use for a
// group + a rationale string. Returns ("", "...") when no useful
// prefix exists.
func detectNamespacePrefix(group []store.DecisionRow) (string, string) {
	observed := 0
	values := make([]string, 0, len(group))
	for _, d := range group {
		if d.ParsedNamespace != "" {
			values = append(values, d.ParsedNamespace)
			observed++
		}
	}
	support := len(group)
	if observed == 0 {
		// All cluster-scoped requests; no namespace to scope by.
		return "", ""
	}
	if float64(observed) < MinNamespaceSupportFraction*float64(support) {
		return "", "only " + intStr(observed) + " of " + intStr(support) +
			" calls had observable namespace; not narrowing by namespace"
	}
	if allEqual(values) {
		return values[0], values[0] + " (all " + intStr(observed) + " observed calls)"
	}
	prefix := longestCommonPrefix(values)
	if prefix == "" {
		return "", "observed namespaces share no common prefix; not narrowing"
	}
	glob := prefix + "*"
	return glob, intStr(observed) + " of " + intStr(support) +
		" calls share namespace prefix " + glob
}

// detectResourcePrefix mirrors detectNamespacePrefix for the
// resource-name (the named object the URL targeted, e.g. "my-pod").
func detectResourcePrefix(group []store.DecisionRow) (string, string) {
	observed := 0
	values := make([]string, 0, len(group))
	for _, d := range group {
		if d.ParsedName != "" {
			values = append(values, d.ParsedName)
			observed++
		}
	}
	support := len(group)
	if observed == 0 {
		// Collection-level operations don't target a named object;
		// no resource-name scope to derive.
		return "", ""
	}
	if float64(observed) < MinResourceSupportFraction*float64(support) {
		return "", "only " + intStr(observed) + " of " + intStr(support) +
			" calls had observable resource name; not narrowing by name"
	}
	if allEqual(values) {
		return values[0], values[0] + " (all " + intStr(observed) + " observed calls)"
	}
	prefix := longestCommonPrefix(values)
	if prefix == "" {
		return "", "observed names share no common prefix; not narrowing"
	}
	glob := prefix + "*"
	return glob, intStr(observed) + " of " + intStr(support) +
		" calls share resource-name prefix " + glob
}

// dedupReason returns the reason a recommendation would be skipped
// because an equivalent rule already exists in the store.
// audit-cadence (b): never resurrect a rule the operator deleted —
// re-running recommend keeps re-deriving the same rule, but if
// the operator removed it then re-running shouldn't auto-restore.
// We dedupe against the CURRENT rule set; an operator who removed
// a rule + immediately re-ran recommend has the option to opt back
// in by passing --apply-only with the specific pattern.
func dedupReason(candidate rules.ProxyRule, existing []rules.ProxyRule) string {
	for _, e := range existing {
		if e.Pattern == candidate.Pattern &&
			e.NamespaceScope == candidate.NamespaceScope &&
			e.ResourceScope == candidate.ResourceScope &&
			e.Effect == candidate.Effect {
			return "rule with this pattern + scopes already in store " +
				"(use `kbounce rules list` to see)"
		}
	}
	return ""
}

// FilterByWindow returns the subset of decisions within [since, until].
// Both bounds are inclusive; zero values mean "unbounded that side."
// Decisions with a zero At fall through (we can't compare them) — same
// fallback behavior as the Python recommender.
func FilterByWindow(decisions []store.DecisionRow, since, until time.Time) []store.DecisionRow {
	out := make([]store.DecisionRow, 0, len(decisions))
	for _, d := range decisions {
		if !since.IsZero() && !d.At.IsZero() && d.At.Before(since) {
			continue
		}
		if !until.IsZero() && !d.At.IsZero() && d.At.After(until) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// FilterByPatterns returns the subset of recommendations whose
// proposed rule's pattern is in the allow list. Used by --apply-only.
// Patterns matched exactly (no globbing) so the operator types the
// exact pattern they saw in `recommend`'s output.
func FilterByPatterns(recs []Recommendation, patterns []string) []Recommendation {
	if len(patterns) == 0 {
		return recs
	}
	want := map[string]struct{}{}
	for _, p := range patterns {
		want[strings.TrimSpace(p)] = struct{}{}
	}
	out := make([]Recommendation, 0, len(recs))
	for _, r := range recs {
		if _, ok := want[r.ProposedRule.Pattern]; ok {
			out = append(out, r)
		}
	}
	return out
}

// noteFromWindow renders the Note string stamped onto each
// recommended rule. Cross-product parity with the Python recommender
// (same "recommended from N observed calls" shape).
func noteFromWindow(support int, w WindowSummary) string {
	b := strings.Builder{}
	b.WriteString("recommended from ")
	b.WriteString(intStr(support))
	b.WriteString(" observed calls")
	if !w.WindowStart.IsZero() && !w.WindowEnd.IsZero() {
		b.WriteString(" in window ")
		b.WriteString(w.WindowStart.UTC().Format(time.RFC3339))
		b.WriteString(" → ")
		b.WriteString(w.WindowEnd.UTC().Format(time.RFC3339))
	}
	return b.String()
}

// longestCommonPrefix returns the longest prefix shared by every
// string in `xs`. Empty slice → empty string.
func longestCommonPrefix(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	prefix := xs[0]
	for _, s := range xs[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func allEqual(xs []string) bool {
	if len(xs) <= 1 {
		return true
	}
	first := xs[0]
	for _, s := range xs[1:] {
		if s != first {
			return false
		}
	}
	return true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func intStr(n int) string {
	// Tiny helper so the rationale strings don't carry strconv in
	// every call site.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	if neg {
		digits = append(digits, '-')
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

func round4(f float64) float64 {
	// Cheap 4-decimal rounding for JSON output.
	if f >= 0 {
		return float64(int(f*10000+0.5)) / 10000
	}
	return float64(int(f*10000-0.5)) / 10000
}
