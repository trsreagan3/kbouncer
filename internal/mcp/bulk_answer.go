// Bulk-answer MCP tools for the [[bulk-prompt-answer-ux]] memo.
//
// Two tools:
//
//   kbounce_prompts_bulk_pending  read-only burst introspection. Returns
//                                 the most-recent unresolved burst row
//                                 + the dedup'd (verb, resource) tuples
//                                 currently pending. Always available
//                                 (no token gate); enables an agent to
//                                 surface "you have 12 prompts pending
//                                 since 14:07" to the operator.
//
//   kbounce_prompts_bulk_answer   write-side bulk-answer. Applies the
//                                 chosen disposition + resolves the
//                                 burst. GATED behind an operator-set
//                                 token: per the memo's "Don't" list,
//                                 an adversarial agent calling this
//                                 unauthenticated could bulk-allow
//                                 itself, defeating the operator-in-
//                                 loop intent. Default: OFF (the tool
//                                 returns an error unless the operator
//                                 set --bulk-answer-mcp-token on
//                                 `kbounce mcp serve` AND the agent's
//                                 tool-call args include the matching
//                                 token value).
//
// The token is a per-deployment shared secret. The operator picks a
// strong value once + pastes it into the agent UI's "tools/auth
// arguments" surface (Claude Code's MCP server JSON, Cursor's tool
// config, etc.). Not an authentication system; just a gate that
// prevents an attacker who compromises only the agent context from
// triggering a bulk-allow.
//
// Per [[security-team-positioning-safety-not-surveillance]]: neutral
// tool-name + descriptions. No "you're being blocked" framing.

package mcp

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// BulkAnswerTokenArgKey is the JSON-RPC tools/call argument name the
// operator-set token MUST appear under. Documented in the
// kbounce_prompts_bulk_answer tool description so the agent UI knows
// what to plumb.
const BulkAnswerTokenArgKey = "operator_token"

// bulkAnswerRuleNote / bulkAnswerCreatedBy mirror the CLI constants of
// the same name. Duplicated (rather than imported from cli/) so the MCP
// package doesn't depend on internal/cli.
const (
	bulkAnswerRuleNote   = "bulk-answer auto-rule"
	bulkAnswerCreatedBy  = "bulk-answer-mcp"
)

// toolPromptsBulkPending implements kbounce_prompts_bulk_pending. Read-
// only burst introspection. No token gate.
//
// Surface (returned as the tool's structuredContent):
//
//	burst_id          int64    most-recent unresolved burst id, or 0
//	detected_at       string   ISO-8601 UTC timestamp
//	prompt_count      int      count the detector observed at trip time
//	window_seconds    int      sliding-window length
//	pending_now       int      count of CURRENTLY-pending prompts (may
//	                           differ from prompt_count if more came in)
//	shapes            []obj    {verb, resource, count} dedup'd
//	available_options []string {session, 3h, 10min, profile, none}
//	bulk_answer_enabled bool   whether the operator wired the token
//	                           (false = bulk_answer tool will refuse)
func (s *Server) toolPromptsBulkPending(_ map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	st := s.cfg.Store
	burst, err := st.LatestUnresolvedBurst()
	if err != nil {
		return nil, err
	}
	shapes, err := st.SnapshotPendingPromptShapes()
	if err != nil {
		return nil, err
	}
	pendingNow := 0
	for _, sh := range shapes {
		pendingNow += sh.Count
	}
	shapeRows := make([]map[string]any, 0, len(shapes))
	for _, sh := range shapes {
		shapeRows = append(shapeRows, map[string]any{
			"verb":     sh.Verb,
			"resource": sh.Resource,
			"count":    sh.Count,
		})
	}
	out := map[string]any{
		"shapes":           shapeRows,
		"pending_now":      pendingNow,
		"bulk_answer_enabled": s.cfg.BulkAnswerToken != "",
		"available_options": []string{
			store.BulkResolutionSession,
			store.BulkResolution3h,
			store.BulkResolution10min,
			store.BulkResolutionProfile,
			store.BulkResolutionNone,
		},
	}
	if burst == nil {
		out["burst_id"] = int64(0)
		out["note"] = "no unresolved burst; pending_now may still be > 0 if the operator answered prior bursts individually"
		return out, nil
	}
	out["burst_id"] = burst.ID
	out["detected_at"] = burst.DetectedAt
	out["prompt_count"] = burst.PromptCount
	out["window_seconds"] = burst.WindowSeconds
	return out, nil
}

// toolPromptsBulkAnswer implements kbounce_prompts_bulk_answer. Write-
// side; gated behind the operator-set token.
//
// Args:
//
//	decision        required: session | 3h | 10min | profile | none
//	profile         required when decision="profile"
//	operator_token  required when cfg.BulkAnswerToken non-empty; MUST
//	                match (constant-time compare)
//
// Per the memo's "Don't" list: this tool is OFF by default. The
// operator wires it on by passing --bulk-answer-mcp-token to
// `kbounce mcp serve` + pasting the same value into the agent UI's
// tools/auth arguments.
func (s *Server) toolPromptsBulkAnswer(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	// Token gate. Default OFF: no token configured → tool refuses
	// regardless of what the agent sends. Same shape the Python side
	// uses for analogous gated tools.
	if s.cfg.BulkAnswerToken == "" {
		return nil, errors.New(
			"kbounce_prompts_bulk_answer: disabled. Operator must start " +
				"`kbounce mcp serve` with --bulk-answer-mcp-token <secret> " +
				"+ the agent must send that secret in args.operator_token. " +
				"Per [[bulk-prompt-answer-ux]] memo: bulk-answer is operator-" +
				"in-loop by default.")
	}
	supplied := stringArg(args, BulkAnswerTokenArgKey, "")
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(s.cfg.BulkAnswerToken)) != 1 {
		return nil, errors.New(
			"kbounce_prompts_bulk_answer: operator_token missing or does not match. " +
				"The operator's --bulk-answer-mcp-token value is required.")
	}
	decision := stringArg(args, "decision", "")
	if !store.IsValidBulkResolution(decision) {
		return nil, fmt.Errorf(
			"decision must be one of: session, 3h, 10min, profile, none (got %q)",
			decision)
	}
	profName := stringArg(args, "profile", "")
	if decision == store.BulkResolutionProfile && profName == "" {
		return nil, errors.New(
			"kbounce_prompts_bulk_answer: decision=profile requires args.profile=NAME")
	}

	burst, err := s.cfg.Store.LatestUnresolvedBurst()
	if err != nil {
		return nil, err
	}
	if burst == nil {
		return nil, errors.New("kbounce_prompts_bulk_answer: no unresolved burst")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	summary, err := applyBulkAnswerMCP(s.cfg.Store, burst, decision, profName, s.cfg.ProfilesPath, s.cfg.Actor)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"burst_id":   burst.ID,
		"decision":   decision,
		"profile":    profName,
		"summary":    summary,
	}, nil
}

// applyBulkAnswerMCP mirrors cli.applyBulkAnswer. Duplicated (rather
// than imported) so the MCP package doesn't pull internal/cli. The two
// implementations are deliberately tested in parallel to keep them in
// sync.
func applyBulkAnswerMCP(
	st *store.Store,
	burst *store.BurstEvent,
	decision, profileName, profilesPath, actor string,
) (string, error) {
	now := time.Now().UTC()
	var ruleCount int
	switch decision {
	case store.BulkResolutionSession,
		store.BulkResolution3h,
		store.BulkResolution10min:
		ttl, err := bulkAnswerTTLMCP(decision)
		if err != nil {
			return "", err
		}
		shapes, err := st.SnapshotPendingPromptShapes()
		if err != nil {
			return "", err
		}
		expiry := now.Add(ttl)
		for _, sh := range shapes {
			pattern := fmt.Sprintf("%s:%s", strings.ToLower(sh.Resource), sh.Verb)
			r := rules.ProxyRule{
				Pattern: pattern,
				Effect:  rules.EffectAllow,
				Note: fmt.Sprintf("%s (burst #%d, %d prompts)",
					bulkAnswerRuleNote, burst.ID, sh.Count),
				Origin: rules.OriginUser,
			}
			if _, err := st.AddTimeBoundedRule(r, expiry, bulkAnswerCreatedBy); err != nil {
				return "", fmt.Errorf("install bulk-allow rule %q: %w", pattern, err)
			}
			ruleCount++
		}
	case store.BulkResolutionProfile:
		path := profilesPath
		if path == "" {
			dp, err := profile.DefaultProfilesPath()
			if err != nil {
				return "", fmt.Errorf("resolve profiles path: %w", err)
			}
			path = dp
		}
		profiles, err := profile.LoadProfiles(path)
		if err != nil {
			return "", fmt.Errorf("load profiles: %w", err)
		}
		if _, err := profiles.Active(profileName); err != nil {
			return "", fmt.Errorf("profile %q not found in %s", profileName, path)
		}
		if err := st.SetProfileReloadSignal(profileName, actor); err != nil {
			return "", err
		}
	case store.BulkResolutionNone:
		// Fall through to the bulk-answer + burst-resolve steps below.
	}
	answered, err := st.BulkAnswerPendingPrompts(decision, actor)
	if err != nil {
		return "", err
	}
	if _, err := st.ResolveBurstEvent(burst.ID, decision); err != nil {
		return "", err
	}
	switch decision {
	case store.BulkResolutionProfile:
		return fmt.Sprintf(
			"burst #%d resolved: profile-switch requested to %q; %d pending prompt(s) marked answered.",
			burst.ID, profileName, answered), nil
	case store.BulkResolutionNone:
		return fmt.Sprintf(
			"burst #%d resolved: no rule change; %d pending prompt(s) marked answered.",
			burst.ID, answered), nil
	default:
		return fmt.Sprintf(
			"burst #%d resolved: installed %d time-bounded ALLOW rule(s); %d pending prompt(s) marked answered.",
			burst.ID, ruleCount, answered), nil
	}
}

func bulkAnswerTTLMCP(decision string) (time.Duration, error) {
	switch decision {
	case store.BulkResolution10min:
		return 10 * time.Minute, nil
	case store.BulkResolution3h:
		return 3 * time.Hour, nil
	case store.BulkResolutionSession:
		return 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("bulkAnswerTTLMCP: %q has no TTL", decision)
}
