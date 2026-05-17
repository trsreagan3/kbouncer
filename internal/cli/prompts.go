// Prompts subcommand group: view + answer DENY notifications the proxy
// queued.
//
// `kbouncer prompts` mirrors `iam-jit-bouncer prompts` (Python side,
// #5) so an operator who learned one product can use the other without
// re-reading the docs.
//
//	prompts list [--status STATUS] [--limit N]
//	prompts show ID
//	prompts answer ID --kind always
//	prompts answer ID --kind profile --target NAME
//	prompts answer ID --kind ignore
//
// When the proxy runs with `--prompt-on-deny`, every transparent-mode
// DENY writes a row here so the operator can later answer
// (always-allow / add-to-profile / ignore). The agent has already
// been denied by the time the prompt appears — answers take effect
// on the NEXT call of the same shape.
//
// v1.0 (now): async queue. v1.1 will add a synchronous prompt where
// the proxy briefly waits for an answer before returning.
//
// Side-effects per answer kind:
//
//	always  → rules table not in kbouncer yet (K-Slice 3); for now the
//	          answer is RECORDED with a clear warning that the rule will
//	          only fire once K-Slice 3's rule engine lands. Symmetric
//	          deferral to the Python prompts.answer --kind always path
//	          when the iam-jit-bouncer rules table is absent.
//	profile → append ProfileAllowRule to --target NAME (refuses if the
//	          profile's Source is non-local; org-distributed profiles
//	          are read-only at this CLI surface per [[enterprise-
//	          profile-distribution]])
//	ignore  → mark answered with no side effect
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// newPromptsCmd assembles the `prompts` group and its subcommands.
func newPromptsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prompts",
		Short: "View + answer DENY notifications the proxy queued",
		Long: `View + answer DENY notifications the proxy queued.

When the proxy runs with --prompt-on-deny, every transparent-mode
DENY also writes a row here so the operator can later answer
(always-allow / add-to-profile / ignore). The agent has already
been denied by the time the prompt appears — answers take effect
on the NEXT call of the same shape.`,
		Args: cobra.NoArgs,
	}
	// UAT-K2 BLOCKER-K2-02: reject unknown sub-subcommands.
	cmd.RunE = parentRequiresSubcommand("prompts", cmd)
	cmd.AddCommand(newPromptsListCmd())
	cmd.AddCommand(newPromptsShowCmd())
	cmd.AddCommand(newPromptsAnswerCmd())
	return cmd
}

func newPromptsListCmd() *cobra.Command {
	var (
		status string
		limit  int
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show prompts in the queue",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isValidPromptStatus(status) {
				return fmt.Errorf("--status must be one of: pending, answered, ignored (got %q)", status)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rows, err := st.ListPendingPrompts(status, limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "(no %s prompts)\n", status)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%5s  %-20s  %-10s  %s\n",
				"id", "at", "verb", "resource")
			fmt.Fprintln(cmd.OutOrStdout(), "----------------------------------------------------------------")
			for _, r := range rows {
				resource := r.Resource
				if r.Namespace != "" {
					resource = r.Namespace + "/" + resource
				}
				if r.Name != "" {
					resource = resource + "/" + r.Name
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%5d  %-20s  %-10s  %s\n",
					r.ID, r.CreatedAt, r.Verb, resource)
				fmt.Fprintf(cmd.OutOrStdout(), "        reason: %s\n", r.DenyReason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&status, "status", "pending",
		"Filter by status: pending | answered | ignored.")
	cmd.Flags().IntVar(&limit, "limit", 20, "Max rows to return.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newPromptsShowCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "show ID",
		Short: "Show one prompt with full detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parsePromptID(args[0])
			if err != nil {
				return err
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			row, err := st.GetPendingPrompt(id)
			if err != nil {
				return err
			}
			if row == nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "prompt #%d not found\n", id)
				os.Exit(1)
			}
			// JSON output mirrors the Python bouncer's `prompts show`
			// (json.dumps(row, indent=2)) so cross-product tooling
			// works against either binary.
			b, err := json.MarshalIndent(promptRowToMap(row), "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newPromptsAnswerCmd() *cobra.Command {
	var (
		kind         string
		target       string
		dbPath       string
		profilesPath string
	)
	cmd := &cobra.Command{
		Use:   "answer ID --kind KIND [--target NAME]",
		Short: "Answer a pending prompt + apply the side-effect",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parsePromptID(args[0])
			if err != nil {
				return err
			}
			if !isValidAnswerKind(kind) {
				return fmt.Errorf("--kind must be one of: always, profile, ignore (got %q)", kind)
			}
			if kind == store.PromptAnswerKindProfile && target == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "--kind profile requires --target NAME")
				os.Exit(2)
			}
			actor := currentActor()

			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			prompt, err := st.GetPendingPrompt(id)
			if err != nil {
				return err
			}
			if prompt == nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "prompt #%d not found\n", id)
				os.Exit(1)
			}
			if prompt.Status != store.PromptStatusPending {
				fmt.Fprintf(cmd.OutOrStdout(),
					"prompt #%d already %q; nothing to do\n", id, prompt.Status)
				return nil
			}

			// Apply side effect BEFORE marking the prompt answered. If
			// the mutation fails (e.g. profile is org-distributed and
			// read-only) we abort without losing the prompt.
			summary, err := applyPromptAnswer(prompt, kind, target, profilesPath)
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), err.Error())
				// Operator-visible side-effect failure (read-only
				// profile, etc.) exits 2 to match the Python bouncer's
				// behavior; internal failures still propagate.
				var sideErr *sideEffectError
				if errors.As(err, &sideErr) {
					os.Exit(sideErr.ExitCode)
				}
				return err
			}

			ok, err := st.AnswerPendingPrompt(id, kind, target, actor)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintf(cmd.OutOrStdout(),
					"prompt #%d: answer not recorded (race?)\n", id)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "prompt #%d answered: %s\n", id, summary)
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "",
		"always = record intent to allow this verb+resource globally "+
			"(rule engine lands in K-Slice 3; for now the answer is "+
			"recorded with a warning). profile = append a ProfileAllowRule "+
			"to --target (must be a local profile). ignore = mark answered "+
			"without side effect.")
	_ = cmd.MarkFlagRequired("kind")
	cmd.Flags().StringVar(&target, "target", "",
		"With --kind profile: the profile name to append to.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml). "+
			"Honors KBOUNCER_PROFILES_PATH env var if unset.")
	return cmd
}

// sideEffectError is returned by applyPromptAnswer for operator-fixable
// problems (e.g. profile is read-only). The cobra RunE captures it via
// errors.As and exits with sideErr.ExitCode so script wrappers can
// distinguish operator-fixable errors (2) from internal failures (1).
type sideEffectError struct {
	Message  string
	ExitCode int
}

func (e *sideEffectError) Error() string { return e.Message }

// applyPromptAnswer performs the side-effect for the given answer
// kind. Returns a one-line human summary on success, or an error.
// Symmetric to the Python iam_jit.bouncer_cli prompts_answer_cmd
// side-effect block.
func applyPromptAnswer(p *store.PromptRow, kind, target, profilesPath string) (string, error) {
	switch kind {
	case store.PromptAnswerKindIgnore:
		return "marked answered (no rule change)", nil
	case store.PromptAnswerKindAlways:
		// K-Slice 3 lands the rules table; until then we record the
		// answer + warn the user the rule won't take effect yet.
		// Symmetric deferral to the Python prompts answer --kind always
		// when its rules table is absent. Picking option (a) per the
		// task spec — a no-op-with-warning is cleaner than half-
		// landing a rules table that K-Slice 3 will replace.
		return "intent recorded (kbouncer rules engine lands in K-Slice 3; until then no rule was added — answering again after K-Slice 3 will install the rule)", nil
	case store.PromptAnswerKindProfile:
		return appendPromptToProfile(p, target, profilesPath)
	default:
		return "", fmt.Errorf("unknown answer kind %q", kind)
	}
}

// appendPromptToProfile finds the named local profile, appends a
// ProfileAllowRule derived from the prompt, and writes the profile
// back via UpsertProfile. Refuses if the profile is org-distributed
// (Source != local) so engineers can't bypass org guardrails via the
// prompt-answer flow.
func appendPromptToProfile(p *store.PromptRow, target, profilesPath string) (string, error) {
	path := profilesPath
	if path == "" {
		rp, err := profile.DefaultProfilesPath()
		if err != nil {
			return "", fmt.Errorf("resolve profiles path: %w", err)
		}
		path = rp
	}
	profiles, err := profile.LoadProfiles(path)
	if err != nil {
		return "", fmt.Errorf("load profiles: %w", err)
	}
	prof, ok := profiles.All[target]
	if !ok || prof == nil {
		return "", &sideEffectError{
			Message:  fmt.Sprintf("profile %q not found", target),
			ExitCode: 1,
		}
	}
	if !prof.IsLocalSource() {
		return "", &sideEffectError{
			Message: fmt.Sprintf(
				"profile %q is sourced from %q and is read-only; "+
					"pick a different local profile or fork the YAML",
				target, prof.Source),
			ExitCode: 2,
		}
	}
	// Build the new allow rule. The "pattern" string is opaque to
	// kbouncer K-Slice 7 (deny-only evaluator) and round-trips through
	// YAML — K-Slice 3's rule engine will consume it. Storing
	// "verb resource" (e.g. "get pods") matches the convention used in
	// install_test.go's AllowRules fixtures.
	pattern := p.Verb
	if p.Resource != "" {
		if pattern != "" {
			pattern += " " + p.Resource
		} else {
			pattern = p.Resource
		}
	}
	if pattern == "" {
		pattern = fmt.Sprintf("decision #%d", p.DecisionID)
	}
	newRule := profile.ProfileAllowRule{
		Pattern: pattern,
		Note:    fmt.Sprintf("answered prompt #%d", p.ID),
	}
	prof.AllowRules = append(prof.AllowRules, newRule)
	if err := profile.UpsertProfile(prof, path); err != nil {
		return "", fmt.Errorf("upsert profile %q: %w", target, err)
	}
	return fmt.Sprintf("appended allow_rule to profile %q", target), nil
}

// isValidPromptStatus returns true for the three canonical statuses
// recognized by store.ListPendingPrompts.
func isValidPromptStatus(s string) bool {
	switch s {
	case store.PromptStatusPending, store.PromptStatusAnswered, store.PromptStatusIgnored:
		return true
	}
	return false
}

// isValidAnswerKind returns true for the three canonical answer kinds
// recognized by store.AnswerPendingPrompt.
func isValidAnswerKind(s string) bool {
	switch s {
	case store.PromptAnswerKindAlways, store.PromptAnswerKindProfile, store.PromptAnswerKindIgnore:
		return true
	}
	return false
}

// parsePromptID converts a CLI positional argument to an int64 prompt
// id with a friendly error message on bad input.
func parsePromptID(raw string) (int64, error) {
	var id int64
	if _, err := fmt.Sscan(raw, &id); err != nil || id <= 0 {
		return 0, fmt.Errorf("prompt id %q: must be a positive integer", raw)
	}
	return id, nil
}

// promptRowToMap converts a PromptRow to a JSON-friendly map for
// `prompts show`. Empty strings stay as empty strings (NOT null) to
// match Python's behavior; callers that want NULL can filter.
func promptRowToMap(r *store.PromptRow) map[string]any {
	return map[string]any{
		"id":            r.ID,
		"created_at":    r.CreatedAt,
		"decision_id":   r.DecisionID,
		"verb":          r.Verb,
		"group":         r.Group,
		"version":       r.Version,
		"resource":      r.Resource,
		"namespace":     r.Namespace,
		"name":          r.Name,
		"deny_reason":   r.DenyReason,
		"status":        r.Status,
		"answer_kind":   r.AnswerKind,
		"answer_target": r.AnswerTarget,
		"answered_by":   r.AnsweredBy,
		"answered_at":   r.AnsweredAt,
	}
}
