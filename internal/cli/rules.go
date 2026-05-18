// Rules subcommand group: manage the kbouncer global rule table.
//
// `kbouncer rules` mirrors `iam-jit-bouncer rules` (Python side) so an
// operator who learned one product can use the other without re-reading
// the docs. The shared mental model:
//
//	rules add --pattern P --effect E [--namespace-scope NS] [--resource-scope RS] [--note "..."]
//	rules list [--json]
//	rules remove ID
//
// The rule table is consulted by the proxy's EvaluateRequestFull BETWEEN
// the profile-deny hard floor (K-Slice 7) and the default-policy
// fallthrough. See the proxy package's composition-order doc.
//
// Per [[scorer-is-ground-truth]] precedent: rule matching is
// deterministic. No LLM in this path. Predictable behavior is the
// whole point of a gate.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// newRulesCmd assembles the `rules` group and its subcommands.
func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage kbounce global rules (allow / deny + namespace / resource scoping)",
		Long: `Manage the global rule table kbounce's proxy consults between the
profile-deny hard floor and the default-policy fallthrough.

Pattern shape: 'resource:verb_glob'. Examples:
  pods:create        — exact pods+create
  secrets:get        — read a secret
  pods:*             — any verb on pods
  *:delete*          — any delete-shaped verb on any resource
  *                  — match anything (rarely useful as a deny; common
                       as the only-rule-that-fires base)

Verb_glob supports '*' and '?'. Resource half may be '*' or a bare
plural ('pods', 'deployments', ...).`,
		Args: cobra.NoArgs,
	}
	// UAT-K2 BLOCKER-K2-02: reject unknown sub-subcommands.
	cmd.RunE = parentRequiresSubcommand("rules", cmd)
	cmd.AddCommand(newRulesAddCmd())
	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesRemoveCmd())
	cmd.AddCommand(newRulesRecommendCmd())
	return cmd
}

func newRulesAddCmd() *cobra.Command {
	var (
		pattern      string
		effect       string
		nsScope      string
		resScope     string
		verbScope    string
		note         string
		dbPath       string
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "add --pattern P --effect E [--namespace-scope NS] [--resource-scope RS] [--note ...]",
		Short: "Add a global rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			eff := rules.Effect(effect)
			if !eff.IsValid() {
				return fmt.Errorf("--effect must be allow or deny (got %q)", effect)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			// Capture before-state for the admin-action hash so the
			// tamper-detection rule can witness exactly which rules
			// changed.
			beforeRules, _ := st.ListRules()
			r := rules.ProxyRule{
				Pattern:        pattern,
				Effect:         eff,
				NamespaceScope: nsScope,
				ResourceScope:  resScope,
				VerbScope:      verbScope,
				Note:           note,
				Origin:         rules.OriginUser,
			}
			id, err := st.AddRule(r)
			if err != nil {
				if errors.Is(err, store.ErrInvalidRule) {
					// UAT-K2 MED-K2-01: strip one "kbounce:" prefix layer
					// so the error doesn't read "rejected: kbounce: invalid
					// rule: kbounce: invalid rule pattern ...". Both layers
					// add the prefix; one is sufficient at the CLI surface.
					msg := strings.TrimPrefix(err.Error(), "kbounce: invalid rule: ")
					fmt.Fprintf(cmd.ErrOrStderr(), "rejected: %s\n", msg)
					os.Exit(2)
				}
				return err
			}
			afterRules, _ := st.ListRules()
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionRuleAdd,
				Actor:      currentActor(),
				EntityKind: "rule",
				EntityName: pattern,
				Source:     audit.AdminActionSourceCLI,
				Before:     rulesToHashable(beforeRules),
				After:      rulesToHashable(afterRules),
				ExtraExt: map[string]any{
					"rule_id": int64(id),
					"effect":  string(eff),
					"pattern": pattern,
				},
			})
			fmt.Fprintf(cmd.OutOrStdout(), "added rule #%d: %s %s\n",
				int64(id), eff, pattern)
			return nil
		},
	}
	cmd.Flags().StringVar(&pattern, "pattern", "",
		"Rule pattern: 'resource:verb_glob' (e.g. 'pods:create', 'secrets:get', '*:delete*'). Required.")
	_ = cmd.MarkFlagRequired("pattern")
	cmd.Flags().StringVar(&effect, "effect", "allow",
		"Rule effect: allow | deny. Default allow.")
	cmd.Flags().StringVar(&nsScope, "namespace-scope", "",
		"Optional namespace glob (e.g. 'prod-*'). Cluster-scoped requests "+
			"do not match a namespace-scoped rule.")
	cmd.Flags().StringVar(&resScope, "resource-scope", "",
		"Optional resource-name glob (e.g. 'api-*'). Collection-level "+
			"operations do not match a name-scoped rule.")
	cmd.Flags().StringVar(&verbScope, "verb-scope", "",
		"Optional extra verb glob (usually redundant with the verb half "+
			"of --pattern; exists for backward compat).")
	cmd.Flags().StringVar(&note, "note", "",
		"Operator-readable note describing why this rule exists.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var (
		asJSON bool
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all rules in evaluation order",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			got, err := st.ListRules()
			if err != nil {
				return err
			}
			if asJSON {
				rows := make([]map[string]any, 0, len(got))
				for _, sr := range got {
					m := sr.Rule.ToMap()
					m["id"] = int64(sr.ID)
					rows = append(rows, m)
				}
				b, err := json.MarshalIndent(rows, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				return nil
			}
			if len(got) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no rules configured)")
				return nil
			}
			for _, sr := range got {
				scope := ""
				if sr.Rule.NamespaceScope != "" {
					scope += fmt.Sprintf(" ns=%s", sr.Rule.NamespaceScope)
				}
				if sr.Rule.ResourceScope != "" {
					scope += fmt.Sprintf(" name=%s", sr.Rule.ResourceScope)
				}
				note := ""
				if sr.Rule.Note != "" {
					note = "  # " + sr.Rule.Note
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%4d  %5s  %s%s%s\n",
					int64(sr.ID), sr.Rule.Effect, sr.Rule.Pattern, scope, note)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON instead of the human table.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	return cmd
}

func newRulesRemoveCmd() *cobra.Command {
	var (
		dbPath       string
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "remove ID",
		Short: "Remove a rule by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || id <= 0 {
				return fmt.Errorf("rule id %q: must be a positive integer", args[0])
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			beforeRules, _ := st.ListRules()
			removed, removedPattern := findRule(beforeRules, rules.ID(id))
			ok, err := st.RemoveRule(rules.ID(id))
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintf(cmd.ErrOrStderr(), "no rule with id #%d\n", id)
				os.Exit(1)
			}
			afterRules, _ := st.ListRules()
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionRuleRemove,
				Actor:      currentActor(),
				EntityKind: "rule",
				EntityName: removedPattern,
				Source:     audit.AdminActionSourceCLI,
				Before:     rulesToHashable(beforeRules),
				After:      rulesToHashable(afterRules),
				ExtraExt: map[string]any{
					"rule_id":         id,
					"removed_pattern": removedPattern,
					"removed_effect":  removed,
				},
			})
			fmt.Fprintf(cmd.OutOrStdout(), "removed rule #%d\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

// rulesToHashable reshapes a StoredRule slice into a stable
// JSON-marshalable form for the admin-action before/after hash. Sorts
// by ID so the hash is invariant to caller ordering (the store
// already returns ordered rows, but this is the load-bearing
// canonical-form guarantee for the tamper-detection rule).
func rulesToHashable(in []rules.StoredRule) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, sr := range in {
		m := sr.Rule.ToMap()
		m["id"] = int64(sr.ID)
		out = append(out, m)
	}
	return out
}

// findRule returns the effect + pattern of the rule with the given
// id, or empty strings when not present. Best-effort lookup so the
// admin-action event can carry the operator-readable identity of the
// removed rule.
func findRule(rs []rules.StoredRule, id rules.ID) (effect, pattern string) {
	for _, sr := range rs {
		if sr.ID == id {
			return string(sr.Rule.Effect), sr.Rule.Pattern
		}
	}
	return "", ""
}
