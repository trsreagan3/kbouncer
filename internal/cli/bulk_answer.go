// Prompts bulk-answer subcommand — the operator-facing surface for the
// [[bulk-prompt-answer-ux]] memo.
//
// When N prompts are enqueued within T seconds the proxy emits a
// BURST_DETECTED event the operator's next `kbouncer prompts
// bulk-answer` invocation surfaces. The operator picks ONE disposition:
//
//	--decision session  → install bulk-allow rules until proxy restart
//	                      (modeled as a 24h TTL; the proxy doesn't have
//	                      a true "agent session" concept, so we cap +
//	                      document explicitly per the memo's "Session
//	                      semantics" section)
//	--decision 3h       → 3-hour TTL on the resulting bulk-allow rules
//	--decision 10min    → 10-minute TTL on the resulting bulk-allow rules
//	--decision profile  → hot-swap kbounce's active profile to --profile
//	                      NAME (the running proxy picks it up via the
//	                      profile_reload_signal table; takes effect on
//	                      the next inbound request)
//	--decision none     → no rule change; mark pending prompts answered
//	                      with kind=bulk + target=none (the original
//	                      403s stand; the operator chose to leave them)
//
// Per [[safety-mode-lean-permissive]]: this is the safety valve that
// prevents the "block-happy = uninstalled" failure mode for the common
// case where the operator has the wrong profile active mid-session.
//
// Per [[security-team-positioning-safety-not-surveillance]]: neutral
// language — no "block" / "suspicious" / "violation" framing in the
// banner. The CLI just reports the count + offers the choices.
//
// Per [[creates-never-mutates]]: every disposition creates NEW state
// (rules or signal rows). It NEVER edits a pre-existing profile or
// rewrites an existing rule.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/proxy"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// bulkAnswerRuleNote is the note string set on every rule created via
// the bulk-answer flow. Stable so audit-review tooling + `kbounce rules
// list` can group bulk-answer rows visually.
const bulkAnswerRuleNote = "bulk-answer auto-rule"

// bulkAnswerCreatedBy is the actor stamped on rules.created_by when the
// bulk-answer flow installs a row. Distinct from the operator name
// recorded on the burst-event resolution so audit review can tell
// "WHO answered" (burst row) from "WHAT created this rule" (rule row).
const bulkAnswerCreatedBy = "bulk-answer"

// newPromptsBulkAnswerCmd implements `kbouncer prompts bulk-answer`.
// Wired into the existing newPromptsCmd group by the AddCommand call
// added in prompts.go below.
func newPromptsBulkAnswerCmd() *cobra.Command {
	var (
		decision     string
		profileName  string
		dbPath       string
		profilesPath string
	)
	cmd := &cobra.Command{
		Use:   "bulk-answer --decision KIND [--profile NAME]",
		Short: "Resolve a burst of pending DENY prompts with one disposition",
		Long: `Resolve a burst of pending DENY prompts with one disposition.

When the proxy is gating many calls in a short window (default: 5
prompts in 60 seconds) it emits a BURST_DETECTED event. This command
surfaces that burst + applies the chosen disposition across every
currently-pending prompt in one shot.

Dispositions:

  --decision session   Install bulk-allow rules covering the burst's
                       (verb, resource) tuples, expiring in 24h. The
                       proxy has no true 'agent session' concept; this
                       is documented as 'until restart or 24h, whichever
                       is first' per the bulk-prompt-answer-ux memo.
  --decision 3h        Same allow rules, 3-hour TTL.
  --decision 10min     Same allow rules, 10-minute TTL.
  --decision profile   Hot-swap the running proxy's active profile to
                       --profile NAME (the proxy's reload watcher picks
                       up the request within ~1s). Pending prompts are
                       marked answered with kind=bulk + target=profile.
                       Use this when the burst is caused by a too-narrow
                       profile being active (the common 'wrong profile'
                       failure mode).
  --decision none      No rule change; mark the pending prompts answered
                       with kind=bulk + target=none. The original 403
                       responses stand. Operator chose to leave them.

The bulk-allow rules are TIME-BOUNDED — they auto-expire at the chosen
TTL and stop matching new requests. Per [[creates-never-mutates]] the
rows stay in the rules table for audit review even after expiry; only
LoadRuleSet's wall-clock filter stops them from firing.

Refuses (non-zero exit) when no unresolved burst exists. To answer
prompts individually instead, use 'kbounce prompts answer'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !store.IsValidBulkResolution(decision) {
				return fmt.Errorf(
					"--decision must be one of: session, 3h, 10min, profile, none (got %q)",
					decision)
			}
			if decision == store.BulkResolutionProfile && profileName == "" {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"--decision profile requires --profile NAME")
				os.Exit(2)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			burst, err := st.LatestUnresolvedBurst()
			if err != nil {
				return err
			}
			if burst == nil {
				fmt.Fprintln(cmd.OutOrStdout(),
					"(no unresolved burst; nothing to bulk-answer)")
				os.Exit(1)
			}

			summary, err := applyBulkAnswer(st, burst, decision, profileName, profilesPath, currentActor())
			if err != nil {
				var sideErr *sideEffectError
				if errors.As(err, &sideErr) {
					fmt.Fprintln(cmd.ErrOrStderr(), sideErr.Message)
					os.Exit(sideErr.ExitCode)
				}
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), summary)
			return nil
		},
	}
	cmd.Flags().StringVar(&decision, "decision", "",
		"Required. session | 3h | 10min | profile | none. See `--help` for semantics.")
	_ = cmd.MarkFlagRequired("decision")
	cmd.Flags().StringVar(&profileName, "profile", "",
		"With --decision profile: name of the profile to hot-swap to.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml). "+
			"Used only with --decision profile to validate the name "+
			"before signaling the running proxy.")
	return cmd
}

// applyBulkAnswer is the shared core used by both the CLI command + the
// MCP tool. Returns a one-line human-readable summary on success.
//
// Steps (in order; intentionally NOT a transaction — SQLite serializes
// per-DB writes and the operations are independently reversible):
//
//  1. For session/3h/10min: snapshot the (verb, resource) tuples from
//     pending prompts + create one time-bounded ALLOW rule per tuple.
//  2. For profile: validate the requested profile name + write a
//     profile_reload_signal row. The running proxy picks it up + hot-
//     swaps; nothing happens here at the rule layer.
//  3. Mark all currently-pending prompts as answered with kind=bulk +
//     target=<decision>. Wakes any in-process sync waiters with an
//     allow/deny decision matching the chosen disposition.
//  4. Resolve the burst row + bookend the audit trail.
func applyBulkAnswer(
	st *store.Store,
	burst *store.BurstEvent,
	decision, profileName, profilesPath, actor string,
) (string, error) {
	now := timeNowUTC()
	var ruleCount int
	switch decision {
	case store.BulkResolutionSession,
		store.BulkResolution3h,
		store.BulkResolution10min:
		ttl, err := bulkAnswerTTL(decision)
		if err != nil {
			return "", err
		}
		shapes, err := st.SnapshotPendingPromptShapes()
		if err != nil {
			return "", err
		}
		expiry := now.Add(ttl)
		for _, sh := range shapes {
			// Pattern shape mirrors `kbounce rules add`: "resource:verb".
			// The (verb, resource) tuple captured by SnapshotPendingPrompt
			// Shapes is already filtered to non-empty pairs.
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
		// Validate the profile name BEFORE writing the signal so a
		// typo doesn't hand-off a bad name to the running proxy. Same
		// resolver the proxy uses.
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
			return "", &sideEffectError{
				Message:  fmt.Sprintf("profile %q not found in %s", profileName, path),
				ExitCode: 2,
			}
		}
		if err := st.SetProfileReloadSignal(profileName, actor); err != nil {
			return "", err
		}
	case store.BulkResolutionNone:
		// No rule change; flow to the bulk-answer + burst-resolve steps.
	default:
		return "", fmt.Errorf("unhandled decision %q", decision)
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
			"burst #%d resolved: profile-switch requested to %q; %d pending prompt(s) marked answered. The running proxy hot-swaps within ~1s.",
			burst.ID, profileName, answered), nil
	case store.BulkResolutionNone:
		return fmt.Sprintf(
			"burst #%d resolved: no rule change; %d pending prompt(s) marked answered (kind=bulk, target=none).",
			burst.ID, answered), nil
	default:
		return fmt.Sprintf(
			"burst #%d resolved: installed %d time-bounded ALLOW rule(s) (TTL %s); %d pending prompt(s) marked answered.",
			burst.ID, ruleCount, humanTTL(decision), answered), nil
	}
}

// bulkAnswerTTL maps a resolution kind to its rule TTL. "session" caps
// at 24h per the memo's "Session semantics" guidance (no true agent
// session concept; document explicitly).
func bulkAnswerTTL(decision string) (time.Duration, error) {
	switch decision {
	case store.BulkResolution10min:
		return 10 * time.Minute, nil
	case store.BulkResolution3h:
		return 3 * time.Hour, nil
	case store.BulkResolutionSession:
		return 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("bulkAnswerTTL: %q has no TTL", decision)
}

func humanTTL(decision string) string {
	switch decision {
	case store.BulkResolution10min:
		return "10m"
	case store.BulkResolution3h:
		return "3h"
	case store.BulkResolutionSession:
		return "24h (session)"
	}
	return decision
}

// timeNowUTC is a tiny indirection so tests can swap to a deterministic
// clock without monkey-patching time.Now. Kept package-private; tests
// in this package reach for the override variable directly.
var timeNowUTC = func() time.Time {
	return time.Now().UTC()
}

// ensureBulkAnswerImports keeps the import for proxy alive when bulk
// answer is referenced only by name elsewhere in the package. (Go's
// goimports prunes unreferenced imports otherwise.) The proxy package
// is the source of the burst-detector defaults the help text quotes
// indirectly via the memo wording.
var _ = proxy.BurstThresholdDefault
