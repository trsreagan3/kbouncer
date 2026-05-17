// Package rules implements kbouncer's deterministic rule engine.
//
// A ProxyRule is the K8s analog of the Python iam-jit-bouncer's
// ProxyRule. Pattern shape: `resource:verb_glob` (e.g. `pods:create`,
// `secrets:get`, `*:delete*`). Scoped fields layer on top:
//
//   - namespace_scope — AWS-IAM-style glob matched against ParsedRequest.Namespace
//   - resource_scope  — glob matched against ParsedRequest.Name
//   - verb_scope      — glob matched against ParsedRequest.Verb (usually
//     redundant with the verb_glob in the pattern but exists for backward
//     compat with rule rows seeded by other tooling)
//
// Evaluation order per the iam-jit-bouncer Python RuleSet semantics
// (mirror keeps cross-product audit-log review consistent):
//
//  1. Any matching DENY rule  -> Effect.Deny (explicit deny beats allow)
//  2. Else any matching ALLOW -> Effect.Allow
//  3. Else nil                 (caller falls through to its next layer)
//
// The rule shape is intentionally minimal per [[safety-mode-lean-permissive]].
// No annotations, no field selectors, no label matchers. Users who need
// that complexity can fall back to a K8s admission webhook. kbouncer is
// the "Little Snitch" gating layer, not a second AdmissionController.
//
// Per [[scorer-is-ground-truth]] precedent: rule matching is
// deterministic. No LLM in this path. Predictable behavior is the whole
// point of a gate.
package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// Effect is a rule's verdict when matched.
type Effect string

const (
	// EffectAllow allows the matched request through.
	EffectAllow Effect = "allow"
	// EffectDeny denies the matched request.
	EffectDeny Effect = "deny"
)

// IsValid returns true for the two canonical effect values.
func (e Effect) IsValid() bool {
	switch e {
	case EffectAllow, EffectDeny:
		return true
	}
	return false
}

// Origin labels how a rule entered the store. Stable enum so the
// audit-review UI can color-code "user-added" vs "task-derived" rows.
const (
	// OriginUser was added explicitly by an operator via `rules add`.
	OriginUser = "user"
	// OriginTask was synthesized from an active task scope (rules in
	// tasks live on the task row, NOT in the rules table; this label is
	// reserved for the in-memory rules a TaskScope builds).
	OriginTask = "task"
	// OriginLearn was auto-captured in learn mode (future).
	OriginLearn = "learn"
	// OriginDefault came from a built-in baseline.
	OriginDefault = "default"
)

// ProxyRule is one row in kbouncer's RuleSet.
type ProxyRule struct {
	// Pattern is `resource:verb_glob`. Required.
	//
	// Accepted shapes:
	//   resource:verb_glob   e.g. "pods:create", "secrets:get", "pods:*"
	//   *:verb_glob          e.g. "*:delete*" (cross-resource deny pattern,
	//                        essential for prod-deny-destructive presets)
	//   *                    bare wildcard = match any resource:any verb
	//                        (normalized to "*:*")
	//
	// verb_glob may include "*" and "?". resource may be either a bare
	// lowercased plural ("pods", "deployments", "configmaps") or "*".
	// Empty parts and whitespace are rejected.
	Pattern string

	// Effect is the verdict when this rule matches. Defaults to allow
	// when zero-valued, but New / parseRule force an explicit value.
	Effect Effect

	// NamespaceScope is an AWS-IAM-style glob matched against the parsed
	// namespace. Empty or "*" = match any namespace. For cluster-scoped
	// requests the parsed namespace is "" — a non-wildcard scope that
	// requires a namespace then fails to match (conservative; caller
	// falls through to its next layer).
	NamespaceScope string

	// ResourceScope is a glob matched against the parsed resource Name
	// (the named object the URL targets, e.g. "my-pod"). Empty or "*" =
	// match any name. For collection-level operations (list, create,
	// deletecollection) the parsed name is "" — same conservative
	// behavior as NamespaceScope.
	ResourceScope string

	// VerbScope is a glob matched against the parsed Verb. Usually
	// redundant with the verb portion of Pattern but exists for backward
	// compat with rule rows seeded by other tooling. Empty or "*" =
	// match any verb.
	VerbScope string

	// Note is an operator-readable description of why this rule exists.
	Note string

	// Origin labels how the rule entered the store. See Origin* consts.
	Origin string
}

// ID is the rule's row id in the rules table. Zero for in-memory rules
// (task-scope-derived, defaults, etc.).
type ID int64

// StoredRule pairs a ProxyRule with its database id. Returned by the
// store's ListRules so callers know which row to remove on `rules remove`.
type StoredRule struct {
	ID   ID
	Rule ProxyRule
}

// ToMap returns a JSON-friendly representation. Used by the CLI's
// --json output mode + audit-log detail payloads.
func (r ProxyRule) ToMap() map[string]any {
	return map[string]any{
		"pattern":         r.Pattern,
		"effect":          string(r.Effect),
		"namespace_scope": r.NamespaceScope,
		"resource_scope":  r.ResourceScope,
		"verb_scope":      r.VerbScope,
		"note":            r.Note,
		"origin":          r.Origin,
	}
}

// ParsedRequest is the minimal view of a kube-apiserver request the
// rule engine matches against. Kept local to this package so the
// engine can be unit-tested without dragging in the proxy / parser.
//
// Symmetric to profile.ParsedRequest; the proxy populates both from
// its parser.ParsedRequest. We keep the two distinct so the rule
// engine can grow K8s-specific fields (Group, Subresource) the
// profile evaluator doesn't need.
type ParsedRequest struct {
	// Verb is the K8s-canonical verb or the subresource name when the
	// URL targets a subresource (exec, log, ...). Matches the verb_glob
	// half of Pattern.
	Verb string

	// Resource is the plural lowercase resource (pods, deployments,
	// secrets, ...). Matches the resource half of Pattern.
	Resource string

	// Namespace is the namespace from the URL or "" for cluster-scoped.
	Namespace string

	// Name is the named object the URL targets, or "" for collection-
	// level operations.
	Name string

	// Group is the API group ("" for core). Not matched by the K-Slice 3
	// rule shape but carried for future expansion (CRD-aware rules).
	Group string

	// Subresource is the trailing path segment (exec, log, ...). Not
	// matched separately in K-Slice 3 — subresources flow through Verb
	// because the parser sets Verb=Subresource when present.
	Subresource string
}

// ErrInvalidPattern is returned by ParsePattern + RuleSet.Add for
// malformed patterns. Wrapping in an explicit error type lets the
// store reject bad rules at insert time (matches the Python
// InvalidRuleError pattern that closed WB23 MED-23-02).
type ErrInvalidPattern struct {
	Pattern string
	Reason  string
}

func (e *ErrInvalidPattern) Error() string {
	return fmt.Sprintf("kbouncer: invalid rule pattern %q: %s", e.Pattern, e.Reason)
}

// ParsePattern splits a `resource:verb_glob` pattern. Returns
// (resource, verb_glob, nil) or ("", "", *ErrInvalidPattern) on
// malformed input.
//
// Mirrors the Python parse_pattern semantics (with K8s resource taking
// the place of AWS service prefix).
func ParsePattern(pattern string) (string, string, error) {
	token := strings.TrimSpace(pattern)
	if token == "" {
		return "", "", &ErrInvalidPattern{Pattern: pattern, Reason: "pattern is empty"}
	}
	if strings.ContainsAny(token, " \t\n") {
		return "", "", &ErrInvalidPattern{Pattern: pattern, Reason: "pattern contains whitespace"}
	}
	// Bare "*" = any resource, any verb.
	if token == "*" {
		return "*", "*", nil
	}
	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return "", "", &ErrInvalidPattern{
			Pattern: pattern,
			Reason:  "must be 'resource:verb_glob' (e.g. 'pods:create', 'secrets:get', '*:delete*')",
		}
	}
	resource, verb := parts[0], parts[1]
	if resource == "" || verb == "" {
		return "", "", &ErrInvalidPattern{
			Pattern: pattern,
			Reason:  "resource and verb halves must both be non-empty",
		}
	}
	// Resource may be "*" (cross-resource patterns) or a bare plural.
	// Partial wildcards like "pod*" are rejected — K8s resource names
	// are flat strings, not globs, so a wildcard at the resource half
	// would imply matching semantics we don't have. Use "*" for the
	// wildcard or list explicit resources.
	if resource != "*" && strings.Contains(resource, "*") {
		return "", "", &ErrInvalidPattern{
			Pattern: pattern,
			Reason:  "resource half may be '*' or a bare plural; partial wildcards are rejected",
		}
	}
	return strings.ToLower(resource), verb, nil
}

// globToRegex translates an AWS-IAM-style glob (only `*` and `?` are
// meta) into a compiled regex. We do NOT use Go's path.Match because
// it admits `[abc]` character classes that AWS IAM-style globs don't
// support — a user writing a literal `[` in a pattern would get
// character-class semantics they didn't ask for. Same fix the Python
// side closed in WB23 LOW-23-02.
func globToRegex(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteString(`\z`)
	return regexp.Compile(b.String())
}

func globMatch(value, pattern string) bool {
	re, err := globToRegex(pattern)
	if err != nil {
		// Defensive: a malformed glob never matches. Caller has
	// already accepted the pattern at insert time so this is rare.
		return false
	}
	return re.MatchString(value)
}

// Matches returns true iff the rule matches the given parsed request.
// All comparisons are case-sensitive on the K8s-canonical form except
// resource (always lowercased — K8s resource plurals are lowercase by
// convention).
func (r ProxyRule) Matches(req *ParsedRequest) bool {
	if req == nil {
		return false
	}
	resource, verbGlob, err := ParsePattern(r.Pattern)
	if err != nil {
		// Malformed rule never matches; the store should reject these at
		// insert time but a hand-edited DB could still surface one.
		return false
	}
	if resource != "*" && resource != strings.ToLower(req.Resource) {
		return false
	}
	if !globMatch(req.Verb, verbGlob) {
		return false
	}
	if r.NamespaceScope != "" && r.NamespaceScope != "*" {
		if req.Namespace == "" {
			// Rule scopes by namespace but request is cluster-scoped —
			// be conservative: don't match. Caller falls through.
			return false
		}
		if !globMatch(req.Namespace, r.NamespaceScope) {
			return false
		}
	}
	if r.ResourceScope != "" && r.ResourceScope != "*" {
		if req.Name == "" {
			return false
		}
		if !globMatch(req.Name, r.ResourceScope) {
			return false
		}
	}
	if r.VerbScope != "" && r.VerbScope != "*" {
		if !globMatch(req.Verb, r.VerbScope) {
			return false
		}
	}
	return true
}

// RuleSet is an ordered collection of ProxyRules with deterministic
// evaluation. Safe for concurrent reads after construction; not safe
// for concurrent Add. The store owns the canonical RuleSet; callers
// snapshot via Store.LoadRuleSet().
type RuleSet struct {
	rules []ProxyRule
}

// NewRuleSet builds a RuleSet from the given rules. Order is preserved
// for first-match semantics.
func NewRuleSet(rs []ProxyRule) *RuleSet {
	return &RuleSet{rules: append([]ProxyRule(nil), rs...)}
}

// Rules returns a shallow copy of the underlying rule slice. Used by
// callers that need to introspect the set (CLI list, audit display).
func (rs *RuleSet) Rules() []ProxyRule {
	if rs == nil {
		return nil
	}
	out := make([]ProxyRule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// Len reports the number of rules in the set.
func (rs *RuleSet) Len() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}

// Add appends a rule. Returns an error if the pattern is malformed.
// Callers that want pre-validated rules can use the zero-error path by
// validating with ParsePattern first.
func (rs *RuleSet) Add(r ProxyRule) error {
	if _, _, err := ParsePattern(r.Pattern); err != nil {
		return err
	}
	if r.Effect != "" && !r.Effect.IsValid() {
		return fmt.Errorf("kbouncer: invalid rule effect %q (want allow or deny)", r.Effect)
	}
	rs.rules = append(rs.rules, r)
	return nil
}

// EvalResult is what Evaluate returns: the matched rule's effect plus
// the rule itself (so the caller can carry it into the audit log). Nil
// when no rule matched.
type EvalResult struct {
	Effect Effect
	Rule   ProxyRule
}

// Evaluate runs the rule set against the request and returns the
// effective verdict.
//
// Order (deny-beats-allow, first-match within each class):
//   1. Any matching DENY  -> EffectDeny + that rule
//   2. Any matching ALLOW -> EffectAllow + that rule
//   3. No match           -> nil (caller falls through)
//
// Pure: no I/O, no side effects.
func (rs *RuleSet) Evaluate(req *ParsedRequest) *EvalResult {
	if rs == nil || len(rs.rules) == 0 || req == nil {
		return nil
	}
	var matchedDeny *ProxyRule
	var matchedAllow *ProxyRule
	for i := range rs.rules {
		r := &rs.rules[i]
		if !r.Matches(req) {
			continue
		}
		if r.Effect == EffectDeny && matchedDeny == nil {
			matchedDeny = r
		} else if r.Effect == EffectAllow && matchedAllow == nil {
			matchedAllow = r
		}
	}
	if matchedDeny != nil {
		return &EvalResult{Effect: EffectDeny, Rule: *matchedDeny}
	}
	if matchedAllow != nil {
		return &EvalResult{Effect: EffectAllow, Rule: *matchedAllow}
	}
	return nil
}
