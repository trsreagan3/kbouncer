// Package dynamicdeny implements kbouncer's consumer side of the
// cross-product dynamic-deny rules surface (#324b).
//
// The full cross-product design lives in the iam-roles repo at
// `docs/DYNAMIC-DENY-RULES.md`; the on-disk YAML shape is described by
// `docs/schemas/dynamic-denies-v1.json`. This package implements:
//
//   - Loader: reads + validates `~/.iam-jit/dynamic-denies.yaml`
//     against the v1.0 schema shape, filters down to rules whose
//     `applied_to` includes `kbouncer` (the cross-product spec uses
//     the `kbouncer` token).
//   - Watcher: fsnotify-driven hot reload of the YAML file. On parse
//     error, retains the previous in-memory rule set (fail-CLOSED per
//     `[[ibounce-honest-positioning]]`) + emits an admin-action OCSF
//     event so the operator sees the failure without grepping.
//
// kbouncer's matcher works against parsed K8s requests (namespace +
// cluster + group/version/resource triple) rather than ARNs / hostnames
// / URLs. Pattern kinds the loader produces:
//
//   - `namespace:<glob>`  — matches `request.Namespace`
//   - `cluster:<glob>`    — matches the configured cluster identifier
//   - `<group>/<version>/<resource>` — matches the parsed K8s
//     group/version/resource triple. Use `core` for the core API
//     (e.g. `core/v1/secrets`); the parser emits an empty Group for
//     core API requests so the matcher normalizes `core` ⟷ "" on
//     compare.
//
// Filter precedence: a target string with no recognized shape is
// SILENTLY SKIPPED at load time (the cross-product resolver in #324e
// is responsible for routing ARN / URL / hostname targets to the right
// bouncer; kbouncer doesn't know how to act on those even if `applied_to`
// claims they apply to kbouncer).
package dynamicdeny

import (
	"strings"
	"time"
)

// PatternKind names the kind of K8s pattern a compiled rule matches
// against. Surfaces in the deny audit event's `ext.dynamic_deny_pattern_kind`
// field so an analyst can answer "did the namespace-scoped rule fire
// or the resource-triple rule?" without re-parsing the rule body.
type PatternKind string

const (
	// PatternKindNamespace matches against the parsed K8s namespace.
	// Globs supported (single leading `*.` only via the same grammar
	// as `*.example.com`); exact + simple prefix-glob (`prod-*`) are
	// the operator-friendly cases.
	PatternKindNamespace PatternKind = "namespace"
	// PatternKindCluster matches against the configured cluster
	// identifier (the kubeconfig cluster name kbouncer was launched
	// with; surfaces under proxy.Config.Cluster).
	PatternKindCluster PatternKind = "cluster"
	// PatternKindResource matches against the parsed K8s
	// group/version/resource triple. Lowercase + canonical core-API
	// alias is `core` (the parser emits an empty Group for the core
	// API; the matcher normalizes `core` ⟷ "" on compare).
	PatternKindResource PatternKind = "resource"
)

// Pattern is one compiled target — paired with its source rule id so
// the audit event can name the originating rule. A single dynamic-deny
// Rule can produce multiple Patterns (one per entry in the rule's
// Targets list); they share the same RuleID + Reason.
type Pattern struct {
	// Kind names the K8s pattern flavor.
	Kind PatternKind
	// Raw is the operator-written target string (preserved for the
	// audit `deny_reason` field so SIEM rules can pivot on the EXACT
	// string the operator deployed).
	Raw string
	// Body is the post-prefix body for namespace + cluster patterns
	// (`prod` from `namespace:prod`, `prod-east` from `cluster:prod-east`).
	// For resource patterns it's the canonical `group/version/resource`
	// triple (already lowercased + `core` alias resolved).
	Body string
	// Group / Version / Resource break the resource triple apart so
	// the matcher hot-path doesn't re-split on every request. Empty
	// for non-resource patterns.
	Group    string
	Version  string
	Resource string
	// IsGlob is true when the pattern body uses the single-leading-`*.`
	// glob shape (namespace + cluster patterns only). Resource patterns
	// do NOT support glob — the triple is exact-match.
	IsGlob bool
	// GlobSuffix is the post-`*.` body for IsGlob patterns. Empty for
	// exact patterns.
	GlobSuffix string
	// GlobPrefix is the pre-`*` body for trailing-star globs
	// (`prod-*`). Single-leading-`*.` and single-trailing-`*` are the
	// two operator-friendly shapes; both are useful for namespace
	// naming conventions.
	GlobPrefix string
	// IsPrefixGlob distinguishes `prod-*` (true) from `*.prod` (false).
	IsPrefixGlob bool
	// RuleID is the source rule's `dd_<ULID>` id. Surfaces in the audit
	// event's `ext.dynamic_deny_rule_id` field.
	RuleID string
	// Reason is the source rule's free-text reason. Surfaces in the
	// audit `deny_reason` field verbatim.
	Reason string
}

// Rule is one dynamic-deny rule, deserialized from the YAML file +
// filtered for kbouncer applicability. Mirrors the on-disk schema field
// names so a future yaml-round-trip writer can reuse this struct as-is.
type Rule struct {
	// ID is the rule's stable identifier (`dd_<ULID>`). Surfaces in the
	// audit `ext.dynamic_deny_rule_id` field when the rule fires.
	ID string `yaml:"id" json:"id"`
	// Targets are the operator-supplied target patterns. For kbouncer
	// these are namespace globs (`namespace:prod`, `namespace:prod-*`),
	// cluster patterns (`cluster:prod-east`), or K8s resource triples
	// (`apps/v1/deployments`, `core/v1/secrets`). Non-matching shapes
	// are silently skipped at compile time.
	Targets []string `yaml:"targets" json:"targets"`
	// Reason is the operator's free-text reason — surfaces in the deny
	// audit event verbatim so a downstream operator sees `why` without
	// context-switching.
	Reason string `yaml:"reason" json:"reason"`
	// Duration is the Go-style duration string (`30m`, `3h`, `7d`) or
	// the literal `permanent`. Anchors `ExpiresAt`.
	Duration string `yaml:"duration" json:"duration"`
	// AddedBy / AddedAt / ExpiresAt are audit-trail metadata. ExpiresAt
	// is nil for `duration: permanent`.
	AddedBy   string     `yaml:"added_by" json:"added_by"`
	AddedAt   time.Time  `yaml:"added_at" json:"added_at"`
	ExpiresAt *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
	// AppliedTo names which bouncer(s) this rule applies to. The loader
	// filters for entries containing `"kbouncer"` before returning.
	AppliedTo []string `yaml:"applied_to" json:"applied_to"`
	// AppliesToRecommender is consumed by the iam-jit recommender
	// (#324f); kbouncer ignores it but preserves the field so a
	// round-trip writer doesn't lose data.
	AppliesToRecommender bool `yaml:"applies_to_recommender" json:"applies_to_recommender"`
	// Source provenance — cli / mcp / org-distributed / imported.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
	// OrgDistributedURL is only present when Source == "org-distributed".
	OrgDistributedURL string `yaml:"org_distributed_url,omitempty" json:"org_distributed_url,omitempty"`
}

// File is the top-level on-disk YAML shape. Field names match the
// v1.0 schema byte-for-byte so a round-trip writer can emit the same
// file an operator hand-edits.
type File struct {
	SchemaVersion      string `yaml:"schema_version" json:"schema_version"`
	Product            string `yaml:"product,omitempty" json:"product,omitempty"`
	ExportedAt         string `yaml:"exported_at,omitempty" json:"exported_at,omitempty"`
	SourceHostnameHash string `yaml:"source_hostname_hash,omitempty" json:"source_hostname_hash,omitempty"`
	Denies             []Rule `yaml:"denies" json:"denies"`
}

// RuleSet is the in-memory snapshot the proxy consults. Holds the
// filtered + compiled patterns ready for hot-path Match calls.
type RuleSet struct {
	// Rules are the filtered + active rules (applied_to contains
	// "kbouncer" AND not expired at load time). Preserved alongside
	// the compiled Patterns so reload + /healthz can introspect them.
	Rules []Rule
	// Patterns are the compiled patterns across all active rules. Hot
	// path iterates this slice on every request.
	Patterns []Pattern
	// SourcePath is the path the rules were loaded from. Surfaces in
	// the startup banner + the /healthz response so an operator who
	// configured a non-default path sees it back.
	SourcePath string
	// LoadedAt is the wall-clock timestamp the snapshot was built.
	// Surfaces in /healthz so an operator can see "last successful
	// reload was N seconds ago."
	LoadedAt time.Time
}

// Empty returns an empty RuleSet — used by callers that need a
// non-nil placeholder before the first load.
func Empty() *RuleSet { return &RuleSet{} }

// MatchInput is the per-request data the matcher consumes. Caller
// populates from the proxy's parser.ParsedRequest + the kbouncer
// proxy.Config.Cluster field. Empty fields skip their respective
// pattern kinds (e.g. an empty Cluster never matches a cluster
// pattern; matches namespace + resource patterns normally).
type MatchInput struct {
	Namespace string
	Cluster   string
	Group     string // K8s API group, "" for core API
	Version   string
	Resource  string
}

// Match scans the compiled patterns + returns the first hit or nil.
// Hot-path; O(N) on the pattern count which is small (operator-set
// rules; we don't expect thousands at a time).
func (rs *RuleSet) Match(in MatchInput) *Pattern {
	if rs == nil || len(rs.Patterns) == 0 {
		return nil
	}
	for i := range rs.Patterns {
		p := &rs.Patterns[i]
		switch p.Kind {
		case PatternKindNamespace:
			if in.Namespace == "" {
				continue
			}
			if matchSimple(p, in.Namespace) {
				return p
			}
		case PatternKindCluster:
			if in.Cluster == "" {
				continue
			}
			if matchSimple(p, in.Cluster) {
				return p
			}
		case PatternKindResource:
			// Resource triple is exact-match — the parser emits a
			// canonical lowercase shape so a case-insensitive compare
			// is sufficient here. Normalize an empty Group to "core"
			// against the pattern body before comparing.
			reqGroup := strings.ToLower(in.Group)
			if reqGroup == "" {
				reqGroup = "core"
			}
			if reqGroup != p.Group {
				continue
			}
			if !strings.EqualFold(in.Version, p.Version) {
				continue
			}
			if !strings.EqualFold(in.Resource, p.Resource) {
				continue
			}
			return p
		}
	}
	return nil
}

// matchSimple applies the namespace + cluster glob grammar:
//   - exact match (case-insensitive)
//   - leading `*.<suffix>` matches `<x>.<suffix>` AND the bare `<suffix>`
//   - trailing `<prefix>-*` matches anything starting with `<prefix>-`
//     (the dash anchor is part of the pattern, not the matcher).
func matchSimple(p *Pattern, v string) bool {
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	switch {
	case p.IsGlob:
		// Leading `*.` glob.
		if lower == p.GlobSuffix {
			return true
		}
		return strings.HasSuffix(lower, "."+p.GlobSuffix)
	case p.IsPrefixGlob:
		// Trailing `*` glob — match any string starting with the
		// pre-`*` body.
		return strings.HasPrefix(lower, p.GlobPrefix)
	default:
		return lower == strings.ToLower(p.Body)
	}
}

// Globs returns a deduplicated list of every operator-written target
// across all active kbouncer-applicable rules. Useful for /healthz +
// the startup banner.
func (rs *RuleSet) Globs() []string {
	if rs == nil || len(rs.Rules) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		for _, t := range r.Targets {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}
