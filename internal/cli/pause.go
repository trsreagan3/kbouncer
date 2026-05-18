// Pause subcommand group: timed escape hatch for the proxy.
//
// `kbouncer pause` mirrors `iam-jit-bouncer pause` (Python side, #6a)
// so an operator who learned one product can use the other without
// re-reading the docs. The shared mental model:
//
//	pause start --for 30m --reason "..."   open a window
//	pause stop                             end early
//	pause status                           show active window if any
//	pause history --limit N                recent windows for audit review
//
// While a pause is active, the proxy demotes effective behavior from
// transparent to cooperative — the verdict text is preserved (audit
// reviewers still see what WOULD have been denied) but enforcement is
// suspended. Every call inside the window records pause_id linkage so
// reviewers can ask "what calls happened inside that window?" with a
// single SQL join. Auto-reverts at expiry; no daemon required (lazy
// GC in store.GetActivePause).
//
// Per [[safety-mode-lean-permissive]] in the product memory: the
// friendlier middle ground between "Ctrl-C the proxy" and
// "redo my rules". Audit-trail does the work; the bypass is
// acceptable precisely because every call during it is logged.
package cli

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// newPauseCmd assembles the `pause` group and its subcommands.
func newPauseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pause",
		Short: "Timed escape hatch — temporarily demote the proxy to advisory",
		Long: `Temporarily demote the proxy to advisory (cooperative) mode for a
window. The proxy keeps observing + logging every call (the decisions
audit row links to the pause id so reviewers can ask "what happened
inside that window?"), but DENY verdicts no longer return 403 to the
client. Auto-reverts at expiry; resume early with 'pause stop'.

Use this when you NEED to do something the rules don't permit and
editing rules would take longer than the work. The friendlier middle
ground between "Ctrl-C the proxy" and "redo my rules."`,
		Args: cobra.NoArgs,
	}
	// UAT-K2 BLOCKER-K2-02: reject unknown sub-subcommands.
	cmd.RunE = parentRequiresSubcommand("pause", cmd)
	cmd.AddCommand(newPauseStartCmd())
	cmd.AddCommand(newPauseStopCmd())
	cmd.AddCommand(newPauseStatusCmd())
	cmd.AddCommand(newPauseHistoryCmd())
	return cmd
}

func newPauseStartCmd() *cobra.Command {
	var (
		duration     string
		reason       string
		dbPath       string
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "start --for DURATION [--reason ...]",
		Short: "Open a new pause window",
		RunE: func(cmd *cobra.Command, args []string) error {
			seconds, err := parseDuration(duration)
			if err != nil {
				return err
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			actor := currentActor()
			pid, err := st.StartPause(seconds, reason, actor)
			if err != nil {
				// Exit code 2 mirrors the Python pause-refused path so
				// scripts wrapping both products can distinguish
				// operator-visible refusals (overlap / cap) from
				// internal store errors.
				fmt.Fprintf(cmd.ErrOrStderr(), "pause refused: %v\n", err)
				os.Exit(2)
			}
			active, err := st.GetActivePause()
			if err != nil {
				return err
			}
			if active == nil {
				return errors.New("pause window started but immediately not active (clock skew?)")
			}
			// Admin-action audit event per [[basic-app-hygiene-features]]
			// TIER 1 — distinct from the synthetic EventTypeAdminFallback
			// Grant the proxy emits when it observes the pause-open edge
			// (#270). The admin-action event is the "who opened the
			// window?" config-change row; the proxy synthetic is the
			// alert-rule input. Both ride the same audit-export channel.
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionPauseStart,
				Actor:      actor,
				EntityKind: "pause_window",
				EntityName: fmt.Sprintf("pause#%d", pid),
				Source:     audit.AdminActionSourceCLI,
				// Before: no pause active. After: window opened with the
				// requested duration + reason. Hashes give the
				// tamper-detection rule a stable witness of what
				// changed.
				Before: nil,
				After: map[string]any{
					"pause_id":         pid,
					"duration_seconds": seconds,
					"ends_at":          active.EndsAt,
					"reason":           reason,
				},
				ExtraExt: map[string]any{
					"pause_id":         pid,
					"duration_seconds": seconds,
				},
			})
			fmt.Fprintf(cmd.OutOrStdout(),
				"pause #%d active — proxy is COOPERATIVE for the next %s (ends at %s).\n",
				pid, duration, active.EndsAt)
			fmt.Fprintln(cmd.OutOrStdout(),
				"Every call during this window is still recorded in the "+
					"decisions audit log with pause_id linkage.")
			fmt.Fprintln(cmd.OutOrStdout(),
				"Run `kbouncer pause stop` to end early.")
			return nil
		},
	}
	cmd.Flags().StringVar(&duration, "for", "",
		"How long to pause. Format: '30m' / '2h' / '90s'. Max 24h "+
			"(longer windows are an 'I don't want the proxy' signal — "+
			"just stop the daemon instead).")
	_ = cmd.MarkFlagRequired("for")
	cmd.Flags().StringVar(&reason, "reason", "",
		"One-line reason recorded in the pause audit row + shown on "+
			"/healthz. e.g. 'incident response' / 'cluster migration'.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

func newPauseStopCmd() *cobra.Command {
	var (
		dbPath       string
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "End the currently-active pause (if any)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			actor := currentActor()
			pid, err := st.EndPause(actor)
			if err != nil {
				return err
			}
			if pid == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "no pause is currently active.")
				return nil
			}
			// Admin-action audit event — pairs with the synthetic
			// EventTypePauseEnd the proxy emits on the close-edge.
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionPauseStop,
				Actor:      actor,
				EntityKind: "pause_window",
				EntityName: fmt.Sprintf("pause#%d", *pid),
				Source:     audit.AdminActionSourceCLI,
				Before:     map[string]any{"pause_id": *pid, "active": true},
				After:      map[string]any{"pause_id": *pid, "active": false, "end_kind": "resumed_early"},
				ExtraExt: map[string]any{
					"pause_id": *pid,
					"end_kind": "resumed_early",
				},
			})
			fmt.Fprintf(cmd.OutOrStdout(), "pause #%d ended early.\n", *pid)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

func newPauseStatusCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the current pause window, if any",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			active, err := st.GetActivePause()
			if err != nil {
				return err
			}
			if active == nil {
				fmt.Fprintln(cmd.OutOrStdout(),
					"no pause active. Proxy enforces per configured mode.")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"pause #%d ACTIVE (started %s, ends %s, by %s)\n",
				active.ID, active.StartedAt, active.EndsAt, active.StartedBy)
			if active.Reason != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  reason: %s\n", active.Reason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newPauseHistoryCmd() *cobra.Command {
	var (
		limit  int
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show recent pause windows for audit review",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rows, err := st.ListRecentPauses(limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no pauses recorded)")
				return nil
			}
			for _, r := range rows {
				endKind := r.EndKind
				if endKind == "" {
					endKind = "(still active)"
				}
				ended := r.EndedAtActual
				if ended == "" {
					ended = "(open)"
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"#%d  started=%s  ends_at=%s  actual_end=%s  kind=%s  by=%s\n",
					r.ID, r.StartedAt, r.EndsAt, ended, endKind, r.StartedBy)
				if r.Reason != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "   reason: %s\n", r.Reason)
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "Max rows to return.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

// parseDuration parses a duration in the suffix-based shape operators
// actually type: "30s" / "30m" / "2h" / "90s". Rejects bare integers,
// garbage prefixes, non-positive values, and durations >
// store.MaxPauseDurationSeconds.
//
// Picks suffix-based parsing rather than time.ParseDuration because
// time.ParseDuration accepts forms like "30" (which would silently
// parse as 30ns) and "1d" (which it rejects but with a confusing
// error). Operators want simple s/m/h with friendly error messages.
//
// Returns int64 seconds for direct hand-off to store.StartPause.
func parseDuration(raw string) (int64, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return 0, fmt.Errorf("duration is required")
	}
	suffix := s[len(s)-1:]
	mult := map[string]int64{"s": 1, "m": 60, "h": 3600}
	m, ok := mult[suffix]
	if !ok {
		return 0, fmt.Errorf("duration %q: must end in s/m/h (e.g. 30m, 2h, 90s)", raw)
	}
	n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("duration %q: prefix must be an integer count", raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("duration %q: must be > 0", raw)
	}
	total := n * m
	if total > store.MaxPauseDurationSeconds {
		return 0, fmt.Errorf("duration %q: cannot exceed 24h", raw)
	}
	return total, nil
}

// currentActor returns the operator name recorded in audit rows. Best-
// effort: USER env var, then user.Current(), then "cli" as a last
// resort. Symmetric with the Python bouncer's _current_actor helper.
func currentActor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "cli"
}
