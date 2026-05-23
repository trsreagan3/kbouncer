// denies.go — read recent DENY decisions from the kbouncer SQLite
// store + synthesise the suggested_allow_command per row.
//
// #386 / §A25 Phase 2 (kbouncer). The MCP tool
// `kbounce_denies_recent` + the cross-product `iam-jit denies recent`
// fan-out both consume this surface.
//
// Per [[cross-product-agent-parity]] the row shape mirrors the
// Python ibounce DenyRow: when, agent_session_id, action, resource,
// deny_reason, deny_source, suggested_allow_command,
// rule_id_if_dynamic.

package profileallow

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/trsreagan3/kbouncer/internal/store"
)

// DenyRow is one row returned by RecentDenies. Mirrors the Python
// DenyRow dataclass in iam_jit.profile_allow.denies.
type DenyRow struct {
	When                  string `json:"when"`
	Bouncer               string `json:"bouncer"`
	AgentSessionID        string `json:"agent_session_id"`
	Action                string `json:"action"`
	Resource              string `json:"resource"`
	DenyReason            string `json:"deny_reason"`
	DenySource            string `json:"deny_source"`
	RuleIDIfDynamic       string `json:"rule_id_if_dynamic,omitempty"`
	SuggestedAllowCommand string `json:"suggested_allow_command"`
}

// Deny-source classification matches the Python denies module's
// values byte-for-byte so a cross-product report can group rows.
const (
	DenySourceStaticProfile          = "static_profile"
	DenySourceDynamicDeny            = "dynamic_deny"
	DenySourceSafeDefault            = "safe_default"
	DenySourceProfileOnlyAccountIDs  = "profile_only_account_ids"
	DenySourceProfileOnlyRegions     = "profile_only_regions"
	DenySourceProfileAllowBaseline   = "profile_allow_baseline"
	DenySourceTaskDeny               = "task_deny"
	DenySourceGlobalDeny             = "global_deny"
	DenySourceUnknown                = "unknown"
)

var dynamicRuleIDRe = regexp.MustCompile(`dd_[0-9A-HJKMNP-TV-Z]{26}`)

// ClassifyDenySource projects a deny_reason string into a
// (source, rule_id_or_empty) pair using the same heuristics as the
// Python denies module.
func ClassifyDenySource(reason string) (string, string) {
	if reason == "" {
		return DenySourceUnknown, ""
	}
	if m := dynamicRuleIDRe.FindString(reason); m != "" {
		return DenySourceDynamicDeny, m
	}
	r := strings.ToLower(reason)
	if strings.Contains(r, "dynamic deny") || strings.Contains(r, "dynamic-deny") {
		return DenySourceDynamicDeny, ""
	}
	if strings.Contains(r, "profile_only_account_ids") {
		return DenySourceProfileOnlyAccountIDs, ""
	}
	if strings.Contains(r, "profile_only_regions") {
		return DenySourceProfileOnlyRegions, ""
	}
	if strings.Contains(r, "'safe-default'") || strings.Contains(r, "safe-default") {
		return DenySourceSafeDefault, ""
	}
	if strings.Contains(r, "allow_baseline") {
		return DenySourceProfileAllowBaseline, ""
	}
	if strings.HasPrefix(r, "profile ") || strings.Contains(r, "profile '") {
		return DenySourceStaticProfile, ""
	}
	if strings.Contains(r, "task deny") || strings.Contains(r, "task-deny") {
		return DenySourceTaskDeny, ""
	}
	if strings.HasPrefix(r, "rule ") || strings.Contains(r, "global deny") {
		return DenySourceGlobalDeny, ""
	}
	return DenySourceUnknown, ""
}

// SynthSuggestedAllowCommand builds the one-line `kbounce profile
// allow ...` command an operator can copy-paste to unblock a future
// request matching the deny. Mirrors the Python denies module's
// shape; the verbatim bouncer name in the command is the
// per-product flip.
func SynthSuggestedAllowCommand(resource, action, denySource string) string {
	switch denySource {
	case DenySourceDynamicDeny:
		return "# this deny is from a dynamic-deny rule; lift via " +
			"`iam-jit deny remove <id>`"
	case DenySourceProfileOnlyAccountIDs, DenySourceProfileOnlyRegions:
		return "# this deny is from a profile account/region floor; edit " +
			"the profile's only_account_ids / only_regions field directly"
	}
	if resource == "" || resource == "*" || action == "" || !strings.Contains(action, ":") {
		return "# the deny lacks a specific resource/action; review the " +
			"profile manually before allowing"
	}
	return fmt.Sprintf("kbounce profile allow --target '%s' --action '%s' "+
		"--reason \"<why this is safe>\"", resource, action)
}

// RecentDeniesOptions tunes a single RecentDenies query.
type RecentDeniesOptions struct {
	// Store is the SQLite handle to read decisions from. Required.
	Store *store.Store

	// Since is the lower bound for the `at` column. Zero → no
	// lower bound (return up to Limit rows).
	Since time.Time

	// AgentSessionID, when non-empty, filters to one MCP session.
	AgentSessionID string

	// Limit caps the returned row count. 0 → 50.
	Limit int
}

// RecentDenies reads recent DENY decisions from the SQLite store
// and projects them into DenyRow values.
func RecentDenies(opts RecentDeniesOptions) ([]DenyRow, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("kbounce: RecentDenies: Store is required")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	// We use the existing RecentDecisions accessor + filter
	// in-memory. Going through a custom SELECT would couple this
	// package to the store schema; the in-memory filter is fine
	// at the limits we care about (< 1k rows).
	all, err := opts.Store.RecentDecisions(limit * 4)
	if err != nil {
		return nil, fmt.Errorf("kbounce: load recent decisions: %w", err)
	}
	out := make([]DenyRow, 0, limit)
	for _, d := range all {
		if !strings.EqualFold(d.DecisionVerdict, "DENY") {
			continue
		}
		if !opts.Since.IsZero() && d.At.Before(opts.Since) {
			continue
		}
		if opts.AgentSessionID != "" && d.AgentSessionID != opts.AgentSessionID {
			continue
		}
		action, resource := actionAndResource(d)
		source, ruleID := ClassifyDenySource(d.DecisionReason)
		out = append(out, DenyRow{
			When:                  d.At.UTC().Format("2006-01-02T15:04:05Z"),
			Bouncer:               "kbounce",
			AgentSessionID:        d.AgentSessionID,
			Action:                action,
			Resource:              resource,
			DenyReason:            d.DecisionReason,
			DenySource:            source,
			RuleIDIfDynamic:       ruleID,
			SuggestedAllowCommand: SynthSuggestedAllowCommand(resource, action, source),
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// actionAndResource builds the cross-product (action, resource)
// pair from a kbouncer DecisionRow.
//
//	action   = <group>/<resource>:<verb>  (with "core" alias for empty group)
//	resource = <namespace>/<name>          (with "*" for the cluster-scope case)
func actionAndResource(d store.DecisionRow) (string, string) {
	group := d.ParsedGroup
	if group == "" {
		group = "core"
	}
	res := d.ParsedResource
	if res == "" {
		res = "*"
	}
	action := fmt.Sprintf("%s/%s:%s", group, res, strings.ToLower(d.ParsedVerb))
	resource := d.ParsedNamespace + "/" + d.ParsedName
	if d.ParsedNamespace == "" && d.ParsedName == "" {
		resource = "*"
	}
	return action, resource
}
