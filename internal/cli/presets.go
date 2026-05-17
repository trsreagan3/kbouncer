// `kbounce presets` — list / show / apply curated rule packs.
//
// Cross-product parity with iam-jit-bouncer's `presets` group (see
// [[cross-product-agent-parity]]): same subcommand shape, same JSON
// shape. Per [[safe-default-is-readonly-admin-minus]]: presets are
// SEPARATE from the safe-default profile — they're a starter rule
// mechanism the operator applies + customizes, not a hard floor.
//
//	presets list                 — names + 1-line descriptions
//	presets show NAME            — full preset content
//	presets apply NAME [--db P]  — append to the rules table
//
// audit-cadence summary (per [[audit-cadence-discipline]]):
//
//	(b) `presets apply` ADDS rules to the table — it does NOT
//	    overwrite. Operator who reapplies the same preset will see
//	    duplicate rules; the AddRule call logs them at origin=default
//	    so post-hoc review can spot the duplication. Refusing to add
//	    duplicates would surprise operators who genuinely want a
//	    second copy with different scopes.
//	(c) the MCP variant of apply (kbounce_apply_preset) requires
//	    the same store config as the CLI; an agent can READ presets
//	    via `presets list / show` but applying takes the same code
//	    path as the operator-CLI invocation.
package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/presets"
	"github.com/trsreagan3/kbouncer/internal/store"
)

func newPresetsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "presets",
		Short: "List, show, and apply curated rule packs",
		Long: `kbounce ships a small set of curated rule packs ("presets") so
operators (and agents) have starting points for common K8s shapes
instead of authoring from scratch.

Presets are SEPARATE from the safe-default profile:
  * safe-default     hard-floor deny layer that fires BEFORE the
                     global rules table; can't be overridden by a
                     task scope.
  * presets          starter rule sets applied to the global rules
                     table via ` + "`presets apply NAME`" + `; the operator
                     edits / removes them like any other rules.

They compose: profile denies still fire first.

  kbounce presets list
  kbounce presets show cluster-admin-minus-destructive
  kbounce presets apply eks-cluster-survey`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("presets", cmd)
	cmd.AddCommand(newPresetsListCmd())
	cmd.AddCommand(newPresetsShowCmd())
	cmd.AddCommand(newPresetsApplyCmd())
	return cmd
}

func newPresetsListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the built-in preset names + descriptions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, err := presets.List()
			if err != nil {
				return err
			}
			if asJSON {
				out := make([]map[string]any, 0, len(catalog))
				for _, p := range catalog {
					out = append(out, map[string]any{
						"name":        p.Name,
						"description": p.Description,
						"rule_count":  len(p.Rules),
					})
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "kbounce built-in presets:\n\n")
			for _, p := range catalog {
				fmt.Fprintf(w, "  %s\n", p.Name)
				if p.Description != "" {
					// Print only the first line of the description so the
					// list view stays scannable; `show` reveals the full
					// body.
					first := firstLine(p.Description)
					fmt.Fprintf(w, "      %s\n", first)
				}
				fmt.Fprintf(w, "      (%d rules)\n", len(p.Rules))
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Use `kbounce presets show NAME` for full detail.")
			fmt.Fprintln(w, "Use `kbounce presets apply NAME` to add the preset's rules to the global table.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON instead of the human table.")
	return cmd
}

func newPresetsShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show the full content of a preset (name, description, rules)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := presets.Get(args[0])
			if err != nil {
				return err
			}
			if asJSON {
				b, _ := json.MarshalIndent(p.ToMap(), "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "name:        %s\n", p.Name)
			if p.Description != "" {
				fmt.Fprintf(w, "description: %s\n", p.Description)
			}
			fmt.Fprintf(w, "rules:       %d\n", len(p.Rules))
			for _, r := range p.Rules {
				scope := ""
				if r.NamespaceScope != "" {
					scope += fmt.Sprintf(" ns=%s", r.NamespaceScope)
				}
				if r.ResourceScope != "" {
					scope += fmt.Sprintf(" name=%s", r.ResourceScope)
				}
				note := ""
				if r.Note != "" {
					note = "  # " + r.Note
				}
				fmt.Fprintf(w, "  %5s  %s%s%s\n", r.Effect, r.Pattern, scope, note)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON instead of the human table.")
	return cmd
}

func newPresetsApplyCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "apply NAME",
		Short: "Insert the named preset's rules into the global rules table",
		Long: `Insert the named preset's rules into the global rules table.

Adds — does NOT overwrite. Apply twice + you'll see duplicate rows
(audit-logged at origin=default each time). Remove specific rules
with ` + "`kbounce rules remove ID`" + ` if you want to undo.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := presets.Get(args[0])
			if err != nil {
				return err
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			applied := 0
			for _, r := range p.Rules {
				if _, err := st.AddRule(r); err != nil {
					return fmt.Errorf(
						"apply preset %q rule %q: %w (applied %d so far)",
						p.Name, r.Pattern, err, applied)
				}
				applied++
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"applied preset %q: %d rule(s) added.\n", p.Name, applied)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

// firstLine returns the first non-empty line of s, trimmed.
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
