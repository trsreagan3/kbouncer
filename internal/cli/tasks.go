// Tasks subcommand group: open / inspect / close per-task scopes.
//
// `kbouncer tasks` mirrors `iam-jit-bouncer tasks` (Python side) so an
// operator who learned one product can use the other without re-reading
// the docs. The shared mental model:
//
//	tasks start --description "..." [--allow CSV] [--deny CSV] [--ttl 30m] [--owner USER]
//	tasks active
//	tasks end [--reason "..."]
//	tasks review TASK_ID
//
// A task narrows the bouncer's behavior for its duration. The agent
// declares allow rules (what the task needs) + deny rules (what the
// task must not touch, e.g. prod). Global rules still apply on top —
// task-deny + global-deny both block; global-allow that wasn't declared
// in task-allow still goes through (so infrastructure calls keep
// working). See the proxy package's composition-order doc.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
	"github.com/trsreagan3/kbouncer/internal/tasks"
)

// newTasksCmd assembles the `tasks` group and its subcommands.
func newTasksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tasks",
		Short: "Open / inspect / close per-task scopes",
		Long: `Open / inspect / close per-task scopes.

A task narrows kbounce's behavior for its duration. Use this when an
agent (or you) is doing a discrete task that should be tightly scoped,
e.g. "investigate prod alert", "rotate staging cert". The agent declares
allow rules (what the task needs) + deny rules (what the task must not
touch); kbounce enforces the scope until the task ends or its TTL
expires.

Rule shorthand: 'pattern[@namespace_scope][#resource_scope]'.
Examples:
  pods:get,pods:list             — collection allow shorthand
  pods:*@prod-billing            — pods:* scoped to namespace prod-billing
  *:delete*                      — cross-resource delete deny`,
		Args: cobra.NoArgs,
	}
	// UAT-K2 BLOCKER-K2-02: reject unknown sub-subcommands.
	cmd.RunE = parentRequiresSubcommand("tasks", cmd)
	cmd.AddCommand(newTasksStartCmd())
	cmd.AddCommand(newTasksActiveCmd())
	cmd.AddCommand(newTasksEndCmd())
	cmd.AddCommand(newTasksReviewCmd())
	cmd.AddCommand(newTasksListCmd())
	return cmd
}

func newTasksStartCmd() *cobra.Command {
	var (
		description string
		allowCSV    string
		denyCSV     string
		ttl         string
		owner       string
		dbPath      string
	)
	cmd := &cobra.Command{
		Use:   "start --description \"...\" [--allow CSV] [--deny CSV] [--ttl 30m] [--owner USER]",
		Short: "Open a new task scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			durationMin, err := parseTTLMinutes(ttl)
			if err != nil {
				return err
			}
			// UAT-K2 HIGH-K2-01: use the strict shorthand parser so
			// malformed @ns=value scopes are surfaced as errors at
			// task-start time rather than silently producing a never-
			// matching rule.
			allowRules, err := tasks.ParseShorthandListStrict(allowCSV)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "rejected --allow: %v\n", err)
				os.Exit(2)
			}
			denyRules, err := tasks.ParseShorthandListStrict(denyCSV)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "rejected --deny: %v\n", err)
				os.Exit(2)
			}

			scope, err := tasks.BuildScope(
				description, allowRules, denyRules,
				durationMin, currentActor(), owner,
			)
			if err != nil {
				var ve *tasks.ValidationError
				if errors.As(err, &ve) {
					fmt.Fprintf(cmd.ErrOrStderr(), "rejected: %v\n", err)
					os.Exit(2)
				}
				return err
			}

			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			if err := st.AddTask(scope); err != nil {
				if errors.Is(err, store.ErrActiveTaskExists) {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"%v\nrun `kbouncer tasks active` to see the current task; "+
							"`kbouncer tasks end` to end it.\n", err)
					os.Exit(2)
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"started task %s (expires %s)\n", scope.TaskID, scope.ExpiresAt)
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "",
		"Human-readable task description (recorded in audit log). Required.")
	_ = cmd.MarkFlagRequired("description")
	cmd.Flags().StringVar(&allowCSV, "allow", "",
		"Comma-separated allow-rule shorthand list "+
			"(e.g. 'pods:get,pods:list@prod-billing').")
	cmd.Flags().StringVar(&denyCSV, "deny", "",
		"Comma-separated deny-rule shorthand list (e.g. '*:delete*').")
	cmd.Flags().StringVar(&ttl, "ttl", "30m",
		"Task TTL. Format '30m' / '2h' / '90s'. Max 24h.")
	cmd.Flags().StringVar(&owner, "owner", "",
		"Per-owner task slot (omit for the default-owner slot).")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newTasksActiveCmd() *cobra.Command {
	var (
		owner  string
		asJSON bool
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "active",
		Short: "Show the currently-active task (if any)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			active, err := st.GetActiveTask(owner)
			if err != nil {
				return err
			}
			if active == nil {
				if asJSON {
					fmt.Fprintln(cmd.OutOrStdout(), `{"active": null}`)
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "(no active task)")
				}
				return nil
			}
			if asJSON {
				b, err := json.MarshalIndent(active.ToMap(), "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "task_id:      %s\n", active.TaskID)
			fmt.Fprintf(w, "description:  %s\n", active.Description)
			fmt.Fprintf(w, "started_at:   %s\n", active.StartedAt)
			fmt.Fprintf(w, "expires_at:   %s\n", active.ExpiresAt)
			fmt.Fprintf(w, "started_by:   %s\n", active.StartedBy)
			if active.Owner != "" {
				fmt.Fprintf(w, "owner:        %s\n", active.Owner)
			}
			fmt.Fprintf(w, "allow rules:  %d\n", len(active.AllowRules))
			for _, r := range active.AllowRules {
				fmt.Fprintf(w, "  + %s%s\n", r.Pattern, formatRuleScope(r))
			}
			fmt.Fprintf(w, "deny rules:   %d\n", len(active.DenyRules))
			for _, r := range active.DenyRules {
				fmt.Fprintf(w, "  - %s%s\n", r.Pattern, formatRuleScope(r))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "",
		"Owner slot filter (omit for the default-owner slot).")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON instead of the human view.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newTasksEndCmd() *cobra.Command {
	var (
		owner  string
		reason string
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "end [--reason \"...\"]",
		Short: "End the currently-active task",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			active, err := st.GetActiveTask(owner)
			if err != nil {
				return err
			}
			if active == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "(no active task to end)")
				return nil
			}
			ok, err := st.EndTask(active.TaskID, currentActor(), reason, tasks.StatusCompleted)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"task %s could not be ended (already ended?)\n", active.TaskID)
				os.Exit(1)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ended task %s\n", active.TaskID)
			return nil
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "",
		"Owner slot filter (omit for the default-owner slot).")
	cmd.Flags().StringVar(&reason, "reason", "manually ended",
		"End reason recorded in audit log.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newTasksReviewCmd() *cobra.Command {
	var (
		asJSON bool
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "review TASK_ID",
		Short: "Post-task review: total decisions, allow/deny breakdown, denied calls",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			review, err := st.TaskReviewSummary(args[0])
			if err != nil {
				return err
			}
			if review == nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "no task with id %q\n", args[0])
				os.Exit(1)
			}
			if asJSON {
				m := map[string]any{
					"task_id":          review.TaskID,
					"description":      review.Description,
					"status":           review.Status,
					"started_at":       review.StartedAt,
					"expires_at":       review.ExpiresAt,
					"ended_at":         review.EndedAt,
					"end_reason":       review.EndReason,
					"owner":            review.Owner,
					"decision_count":   review.DecisionCount,
					"allow_count":      review.AllowCount,
					"deny_count":       review.DenyCount,
					"first_decision":   review.FirstDecisionAt,
					"last_decision":    review.LastDecisionAt,
					"denied_calls_n":   len(review.DeniedCalls),
				}
				b, err := json.MarshalIndent(m, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "task:        %s\n", review.TaskID)
			fmt.Fprintf(w, "description: %s\n", review.Description)
			fmt.Fprintf(w, "status:      %s\n", review.Status)
			if review.Owner != "" {
				fmt.Fprintf(w, "owner:       %s\n", review.Owner)
			}
			windowEnd := review.EndedAt
			if windowEnd == "" {
				windowEnd = review.ExpiresAt
			}
			fmt.Fprintf(w, "window:      %s -> %s\n", review.StartedAt, windowEnd)
			fmt.Fprintf(w, "decisions:   %d total (allow=%d deny=%d)\n",
				review.DecisionCount, review.AllowCount, review.DenyCount)
			if len(review.DeniedCalls) > 0 {
				fmt.Fprintf(w, "denied calls (%d):\n", len(review.DeniedCalls))
				for _, d := range review.DeniedCalls {
					name := d.Name
					if name == "" {
						name = "-"
					}
					fmt.Fprintf(w, "  %s  %s:%s  name=%s\n",
						d.At, d.Resource, d.Verb, name)
					fmt.Fprintf(w, "      -- %s\n", d.Reason)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON instead of the human view.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newTasksListCmd() *cobra.Command {
	var (
		statusFilter string
		limit        int
		asJSON       bool
		dbPath       string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List task scopes (newest first, with optional status filter)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rows, err := st.ListTasks(statusFilter, limit)
			if err != nil {
				return err
			}
			if asJSON {
				out := make([]map[string]any, 0, len(rows))
				for _, s := range rows {
					out = append(out, s.ToMap())
				}
				b, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no tasks)")
				return nil
			}
			for _, s := range rows {
				desc := s.Description
				if len(desc) > 60 {
					desc = desc[:57] + "..."
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"%s  %9s  started %s by %s  --  %s\n",
					s.TaskID, s.Status, s.StartedAt, s.StartedBy, desc)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&statusFilter, "status", "",
		"Filter by status: active | completed | expired | replaced.")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max rows to return.")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON instead of the human view.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func formatRuleScope(r rules.ProxyRule) string {
	bits := make([]string, 0, 2)
	if r.NamespaceScope != "" {
		bits = append(bits, "ns="+r.NamespaceScope)
	}
	if r.ResourceScope != "" {
		bits = append(bits, "name="+r.ResourceScope)
	}
	if len(bits) == 0 {
		return ""
	}
	return " [" + strings.Join(bits, ", ") + "]"
}

// parseTTLMinutes accepts the same suffix-based duration shape the
// pause CLI uses ("30m" / "2h" / "90s") and returns whole minutes for
// build_task_scope's duration field. Fractional minutes round UP so a
// '90s' TTL produces a 2-minute task (rather than 1) — the user asked
// for "at least 90 seconds" and the scope shouldn't surprise-expire.
//
// Returns an error for malformed input, durations <= 0, or > 24h
// (matches build_task_scope's MaxDurationMinutes).
func parseTTLMinutes(raw string) (int, error) {
	seconds, err := parseDuration(raw)
	if err != nil {
		return 0, err
	}
	if seconds < 60 {
		return 1, nil
	}
	mins := int(seconds / 60)
	if seconds%60 != 0 {
		mins++
	}
	if mins < tasks.MinDurationMinutes {
		return 0, fmt.Errorf("ttl %q: must be >= 1 minute", raw)
	}
	if mins > tasks.MaxDurationMinutes {
		return 0, fmt.Errorf("ttl %q: must be <= 24h", raw)
	}
	return mins, nil
}

