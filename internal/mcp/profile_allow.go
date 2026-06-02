// profile_allow.go — MCP tool handlers for #386 / §A25 Phase 2.
//
// kbounce_profile_allow + kbounce_denies_recent. Mirrors the iam-jit
// Python bouncer_profile_allow + bouncer_denies_recent shapes per
// [[cross-product-agent-parity]].
//
// Agent-self-grant safety rail: the source is hard-coded to
// profileallow.SourceMCP so the operations-layer's pending-queue
// gate fires unless the operator opted in via
// IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT=1. The pending JSONL queue
// lives at ~/.iam-jit/bouncer/profile-allow-pending.jsonl —
// SHARED with the other bouncers so an operator-review surface
// (Phase 3) sees every bouncer's pending entries.

package mcp

import (
	"fmt"
	"time"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/profileallow"
)

// toolProfileAllow dispatches the kbounce_profile_allow MCP tool.
func (s *Server) toolProfileAllow(args map[string]any) (map[string]any, error) {
	target, _ := args["target"].(string)
	reason, _ := args["reason"].(string)
	duration, _ := args["duration"].(string)
	profileName, _ := args["profile"].(string)

	var actions []string
	switch a := args["action"].(type) {
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok {
				actions = append(actions, s)
			}
		}
	case []string:
		actions = a
	case string:
		actions = []string{a}
	}

	actor := s.cfg.Actor
	activeName := ""
	if s.cfg.ActiveProfile != nil {
		activeName = s.cfg.ActiveProfile.Name
	}

	res, err := profileallow.AddProfileAllowRule(profileallow.Options{
		Target:        target,
		Actions:       actions,
		Reason:        reason,
		Duration:      duration,
		ProfileName:   profileName,
		ActiveProfile: activeName,
		ProfilesPath:  s.cfg.ProfilesPath,
		Source:        profileallow.SourceMCP,
		Actor:         actor,
		AuditEmitter:  s.cfg.AuditEmitter,
	})
	if err != nil {
		// Surface structured errors (target_too_broad / bad_action /
		// org_distributed / ...) so the agent can adjust + retry.
		if perr, ok := err.(*profileallow.Error); ok {
			return map[string]any{
				"ok":      false,
				"error":   perr.Message,
				"code":    perr.Code,
				"details": perr.Details,
			}, nil
		}
		return nil, fmt.Errorf("kbounce_profile_allow: %w", err)
	}
	out := map[string]any{
		"ok":               true,
		"status":           res.Status,
		"profile_name":     res.ProfileName,
		"profile_path":     res.ProfilePath,
		"actions":          res.Actions,
		"target":           res.Target,
		"reason":           res.Reason,
		"duration":         res.Duration,
		"expires_at":       res.ExpiresAt,
		"actor":            res.Actor,
		"source":           res.Source,
		"rule_count_after": res.RuleCountAfter,
		// target_scope_advisory is true when --target does NOT name a
		// K8s namespace, so the evaluator will NOT scope the allow to it
		// (scoping then comes only from the action's resource half).
		// Lets the agent know the target is metadata-only — mirrors the
		// CLI's add-time warning. Honest per [[ibounce-honest-positioning]].
		"target_scope_advisory": !profile.TargetEnforcedAsNamespace(target),
	}
	if res.PendingEntry != nil {
		out["pending_entry"] = res.PendingEntry
	}
	return out, nil
}

// toolDeniesRecent dispatches the kbounce_denies_recent MCP tool.
func (s *Server) toolDeniesRecent(args map[string]any) (map[string]any, error) {
	if s.cfg.Store == nil {
		return map[string]any{
			"ok":    false,
			"error": "store_not_configured",
			"detail": "kbounce_denies_recent requires the MCP server to be " +
				"wired with the SQLite store; pass --db PATH to `kbounce mcp serve`",
		}, nil
	}
	sinceStr := "5m"
	if v, ok := args["since"].(string); ok && v != "" {
		sinceStr = v
	}
	agentSession := ""
	if v, ok := args["agent_session"].(string); ok {
		agentSession = v
	}
	limit := 50
	switch v := args["limit"].(type) {
	case float64:
		limit = int(v)
	case int:
		limit = v
	}
	lower, perr := parseMCPSince(sinceStr)
	if perr != nil {
		return map[string]any{
			"ok":    false,
			"error": "invalid_since",
			"detail": perr.Error(),
		}, nil
	}
	rows, err := profileallow.RecentDenies(profileallow.RecentDeniesOptions{
		Store:          s.cfg.Store,
		Since:          lower,
		AgentSessionID: agentSession,
		Limit:          limit,
	})
	if err != nil {
		return nil, err
	}
	// Marshal DenyRow slice into []map[string]any so the JSON
	// encoder downstream emits the canonical wire shape.
	outRows := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		outRows = append(outRows, map[string]any{
			"when":                    r.When,
			"bouncer":                 r.Bouncer,
			"agent_session_id":        r.AgentSessionID,
			"action":                  r.Action,
			"resource":                r.Resource,
			"deny_reason":             r.DenyReason,
			"deny_source":             r.DenySource,
			"rule_id_if_dynamic":      r.RuleIDIfDynamic,
			"suggested_allow_command": r.SuggestedAllowCommand,
		})
	}
	return map[string]any{
		"ok":      true,
		"bouncer": "kbounce",
		"rows":    outRows,
		"count":   len(outRows),
	}, nil
}

// parseMCPSince mirrors parseSinceFlag in the CLI package without
// importing it (avoid CLI-package cycle).
func parseMCPSince(spec string) (time.Time, error) {
	s := spec
	if s == "" {
		return time.Time{}, nil
	}
	if len(s) >= 10 && (s[4] == '-' || containsT(s)) {
		t, err := time.Parse(time.RFC3339, s)
		if err == nil {
			return t, nil
		}
		return time.Time{}, err
	}
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("--since %q: too short", spec)
	}
	unit := s[len(s)-1]
	qty := 0
	for i := 0; i < len(s)-1; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return time.Time{}, fmt.Errorf("--since %q: non-numeric quantity", spec)
		}
		qty = qty*10 + int(c-'0')
	}
	var d time.Duration
	switch unit {
	case 's':
		d = time.Duration(qty) * time.Second
	case 'm':
		d = time.Duration(qty) * time.Minute
	case 'h':
		d = time.Duration(qty) * time.Hour
	case 'd':
		d = time.Duration(qty) * 24 * time.Hour
	case 'w':
		d = time.Duration(qty) * 7 * 24 * time.Hour
	default:
		return time.Time{}, fmt.Errorf("--since %q: unknown unit %q", spec, string(unit))
	}
	return time.Now().UTC().Add(-d), nil
}

func containsT(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 'T' {
			return true
		}
	}
	return false
}
