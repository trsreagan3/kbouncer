// `kbounce rules recommend` — synthesize draft rules from observed
// audit-log traffic.
//
// Cross-product parity with iam-jit-bouncer's `recommend` subcommand
// (see [[cross-product-agent-parity]]): same flag shapes, same JSON
// output structure, same --save-as-profile auto-naming UX.
//
//	rules recommend [--since DURATION] [--until DURATION]
//	                [--min-support N] [--limit N]
//	                [--apply] [--apply-only CSV]
//	                [--include-task-scoped]
//	                [--save-as-profile [NAME]]
//	                [--profile-description "..."]
//	                [--db PATH] [--json]
//
// Per [[scorer-is-ground-truth]] + [[no-nl-synthesis]]: synthesis is
// deterministic. No LLM. The recommender groups observed traffic by
// (resource, verb), thresholds on support, applies longest-common-
// prefix detection for namespace + resource-name scopes, and emits
// draft ALLOW rules the operator can review.
//
// audit-cadence summary (per [[audit-cadence-discipline]]):
//
//	(a) the synthesizer dedupes against rules currently in the
//	    store so re-running `recommend` doesn't resurrect a rule
//	    the operator removed (kbounce has no rule_removed event
//	    table; absence-of-rule IS the operator's signal).
//	(b) `--save-as-profile` MERGES into an existing local profile
//	    rather than overwriting; collision-avoid via `-2`/`-3`
//	    suffix; refuses on org-sourced (non-local) profiles.
//	(c) auto-naming follows [[profile-auto-naming]]: TTY-detect →
//	    prompt with suggested default; non-TTY → auto-generate +
//	    print chosen name to stderr.
package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/recommender"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// newRulesRecommendCmd wires the `rules recommend` subcommand under
// the existing `rules` group. Exported via newRulesCmd's AddCommand
// in rules.go (added in the same commit).
func newRulesRecommendCmd() *cobra.Command {
	var (
		sinceFlag           string
		untilFlag           string
		minSupport          int
		limitFlag           int
		applyFlag           bool
		applyOnlyCSV        string
		includeTaskScoped   bool
		saveAsProfileFlag   string
		saveAsProfileSet    bool
		profileDescription  string
		dbPath              string
		profilesPath        string
		asJSON              bool
	)
	cmd := &cobra.Command{
		Use:   "recommend",
		Short: "Synthesize draft rules from observed audit-log traffic",
		Long: `Synthesize draft rules from observed audit-log traffic.

Observation algorithm (deterministic — no LLM):
  1. Filter to ALLOW decisions over the window.
  2. Group by (resource, verb).
  3. For groups with support >= --min-support, emit an ALLOW rule
     with namespace + resource-name scopes derived from longest-
     common-prefix when at least half the calls share a prefix.
  4. Sort by support DESC; print as a table or --json.

By default --recommend is READ-ONLY: it prints the recommendations
without persisting anything. Pass --apply to insert the rules into
the global rules table, or --save-as-profile [NAME] to write the
recommendations as a NEW local profile's allow_rules.

Auto-naming for --save-as-profile (cross-product parity per
[[profile-auto-naming]]):
  * NAME provided                 → use it (with collision-avoid).
  * NAME omitted + TTY            → prompt with a context-suggested
                                    default; Enter accepts.
  * NAME omitted + non-TTY        → auto-generate the default + print
                                    it to stderr.

Example:

  kbounce rules recommend --since 24h --min-support 5

  kbounce rules recommend --since 1h --apply

  kbounce rules recommend --since 24h --save-as-profile
  # ↑ prompts: 'name your profile [default: auto-2026-05-17-pods-readonly]:'

  kbounce rules recommend --since 24h --save-as-profile my-cluster-survey
`,
		Args: cobra.NoArgs,
		// Detect whether --save-as-profile was passed (even with the
		// empty value that means "auto-name me"). cobra doesn't surface
		// "flag set but value empty" vs "flag not set" without inspecting
		// the flag set; we use PreRun to capture the bit.
		PreRunE: func(cmd *cobra.Command, args []string) error {
			saveAsProfileSet = cmd.Flags().Changed("save-as-profile")
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			// Fetch a large slab of recent decisions; the recommender
			// filters by window in-memory. 5000 covers a typical day's
			// activity on a busy single-user laptop; bump if needed.
			decisions, err := st.RecentDecisions(1000)
			if err != nil {
				return fmt.Errorf("read decisions: %w", err)
			}

			since := parseRelativeOrAbsolute(sinceFlag)
			until := parseRelativeOrAbsolute(untilFlag)
			windowed := recommender.FilterByWindow(decisions, since, until)

			// audit-cadence (a): pass current rule set to the recommender
			// so dedupe can mark recommendations that are already covered.
			existing, err := st.ListRules()
			if err != nil {
				return fmt.Errorf("read existing rules: %w", err)
			}
			existingRules := make([]rules.ProxyRule, 0, len(existing))
			for _, sr := range existing {
				existingRules = append(existingRules, sr.Rule)
			}

			recs, summary := recommender.Synthesize(windowed, recommender.SynthesizeOptions{
				MinSupport:        minSupport,
				IncludeTaskScoped: includeTaskScoped,
				ExistingRules:     existingRules,
			})

			// --apply-only filters before applying; --limit caps the
			// display set. Apply happens AFTER filtering so the operator
			// sees the same list that gets persisted.
			if applyOnlyCSV != "" {
				recs = recommender.FilterByPatterns(recs, splitCSV(applyOnlyCSV))
			}
			if limitFlag > 0 && limitFlag < len(recs) {
				recs = recs[:limitFlag]
			}

			// JSON output happens FIRST so --json --apply still gets the
			// machine-readable view of what was applied.
			if asJSON {
				printRecommendationsJSON(cmd, summary, recs)
			} else {
				printRecommendationsHuman(cmd, summary, recs)
			}

			// Side-effect paths.
			if applyFlag {
				applied, err := applyRecommendations(st, recs)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "applied %d rule(s).\n", applied)
			}
			if saveAsProfileSet {
				name, err := saveRecommendationsAsProfile(
					cmd, recs, summary, saveAsProfileFlag,
					profileDescription, profilesPath)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"saved %d recommendation(s) as profile %q.\n",
					len(recs), name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sinceFlag, "since", "",
		"Window start. Relative (e.g. '1h', '24h', '7d') or absolute "+
			"ISO-8601 ('2026-05-17T00:00:00Z'). Default: whole log.")
	cmd.Flags().StringVar(&untilFlag, "until", "",
		"Window end. Same shapes as --since. Default: now.")
	cmd.Flags().IntVar(&minSupport, "min-support", recommender.MinSupportDefault,
		"Minimum number of observed calls per (resource, verb) group "+
			"before we'll emit a recommendation. Below this, sparse "+
			"traffic is skipped (the operator can add explicit rules "+
			"by hand).")
	cmd.Flags().IntVar(&limitFlag, "limit", 0,
		"Max recommendations to display (after support-sort). Zero = no limit.")
	cmd.Flags().BoolVar(&applyFlag, "apply", false,
		"Persist the recommended rules into the global rules table. "+
			"Audit-logged as origin=recommendation.")
	cmd.Flags().StringVar(&applyOnlyCSV, "apply-only", "",
		"Comma-separated list of patterns; only recommendations whose "+
			"pattern matches the CSV are applied/saved. Use to narrow a "+
			"batch.")
	cmd.Flags().BoolVar(&includeTaskScoped, "include-task-scoped", false,
		"Fold task-scoped decisions into the analysis. Off by default: "+
			"task-scoped decisions are one-off declared sessions and "+
			"shouldn't auto-promote to permanent rules.")
	cmd.Flags().StringVar(&saveAsProfileFlag, "save-as-profile", "",
		"Write the recommendations as a NEW local profile's allow_rules. "+
			"NAME is OPTIONAL per [[profile-auto-naming]]: if omitted and "+
			"stdout is a TTY, kbounce prompts with a suggested default; "+
			"if non-TTY, kbounce auto-generates the name + prints it to "+
			"stderr. Refuses if the target profile already exists as an "+
			"org-distributed (non-local) profile.")
	// Make the flag's NAME optional. cobra string flags accept an empty
	// value when --save-as-profile= is passed; we also want
	// `--save-as-profile` (no =) to work. We rely on Changed() in
	// PreRunE; the flag value defaults to "" which the auto-name logic
	// handles.
	cmd.Flags().Lookup("save-as-profile").NoOptDefVal = ""
	cmd.Flags().StringVar(&profileDescription, "profile-description", "",
		"Description string for the saved profile (only meaningful with "+
			"--save-as-profile). Defaults to a one-line auto-generated "+
			"description.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit JSON instead of the human table.")
	return cmd
}

// printRecommendationsHuman renders the table-form view.
func printRecommendationsHuman(cmd *cobra.Command, summary recommender.WindowSummary, recs []recommender.Recommendation) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "observation window: %d call(s); allow=%d deny=%d distinct_resources=%d distinct_verbs=%d\n",
		summary.TotalCalls, summary.AllowCount, summary.DenyCount,
		summary.DistinctResources, summary.DistinctVerbs)
	if !summary.WindowStart.IsZero() {
		fmt.Fprintf(w, "window: %s → %s\n",
			summary.WindowStart.UTC().Format(time.RFC3339),
			summary.WindowEnd.UTC().Format(time.RFC3339))
	}
	if len(recs) == 0 {
		fmt.Fprintln(w, "(no recommendations met the support threshold)")
		return
	}
	fmt.Fprintf(w, "%-4s  %-30s  %-8s  %s\n", "SUP", "PATTERN", "EFFECT", "SCOPES / NOTES")
	for _, r := range recs {
		scope := ""
		if r.ProposedRule.NamespaceScope != "" {
			scope += fmt.Sprintf(" ns=%s", r.ProposedRule.NamespaceScope)
		}
		if r.ProposedRule.ResourceScope != "" {
			scope += fmt.Sprintf(" name=%s", r.ProposedRule.ResourceScope)
		}
		marker := ""
		if r.SkippedReason != "" {
			marker = "  [SKIPPED: " + r.SkippedReason + "]"
		}
		fmt.Fprintf(w, "%-4d  %-30s  %-8s %s%s\n",
			r.SupportCount, r.ProposedRule.Pattern, r.ProposedRule.Effect, scope, marker)
		if r.NamespaceRationale != "" {
			fmt.Fprintf(w, "        ↳ ns: %s\n", r.NamespaceRationale)
		}
		if r.ResourceRationale != "" {
			fmt.Fprintf(w, "        ↳ name: %s\n", r.ResourceRationale)
		}
	}
}

func printRecommendationsJSON(cmd *cobra.Command, summary recommender.WindowSummary, recs []recommender.Recommendation) {
	out := map[string]any{
		"summary":         summary.ToMap(),
		"recommendations": toMapList(recs),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Fprintln(cmd.OutOrStdout(), string(b))
}

func toMapList(recs []recommender.Recommendation) []map[string]any {
	out := make([]map[string]any, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.ToMap())
	}
	return out
}

// applyRecommendations inserts the non-skipped recommendations into
// the rules table. Returns the count inserted. Errors halt the
// inserts so a partial-apply doesn't leave the operator with an
// inconsistent state.
func applyRecommendations(st *store.Store, recs []recommender.Recommendation) (int, error) {
	applied := 0
	for _, r := range recs {
		if r.SkippedReason != "" {
			continue
		}
		if _, err := st.AddRule(r.ProposedRule); err != nil {
			return applied, fmt.Errorf(
				"apply rule %q: %w (applied %d so far)",
				r.ProposedRule.Pattern, err, applied)
		}
		applied++
	}
	return applied, nil
}

// saveRecommendationsAsProfile resolves the NAME (auto-generate /
// TTY-prompt as appropriate), refuses on org-sourced existing
// profiles, merges into the existing profile's allow_rules when
// the operator targeted an existing local profile (dedupe on
// pattern+scopes), and writes via UpsertProfile.
//
// Returns the chosen name so the caller can echo it.
func saveRecommendationsAsProfile(
	cmd *cobra.Command,
	recs []recommender.Recommendation,
	summary recommender.WindowSummary,
	nameArg string,
	description string,
	profilesPath string,
) (string, error) {
	path := profilesPath
	if path == "" {
		rp, err := profile.DefaultProfilesPath()
		if err != nil {
			return "", err
		}
		path = rp
	}

	// Load existing profiles for collision-avoid + merge semantics.
	profiles, err := profile.LoadProfiles(path)
	if err != nil {
		return "", fmt.Errorf("load profiles: %w", err)
	}
	taken := map[string]bool{}
	for n := range profiles.All {
		taken[n] = true
	}

	suggested := SuggestProfileName(recs, summary)
	chosen, err := ResolveProfileName(cmd.OutOrStdout(), cmd.ErrOrStderr(),
		os.Stdin, nameArg, suggested, taken, IsTerminal)
	if err != nil {
		return "", err
	}

	desc := description
	if desc == "" {
		desc = fmt.Sprintf(
			"auto-generated from `kbounce rules recommend` "+
				"(%d recommendation(s) from %d observed call(s)).",
			len(recs), summary.AllowCount)
	}

	// Build the profile we'll write.
	newAllow := make([]profile.ProfileAllowRule, 0, len(recs))
	for _, r := range recs {
		if r.SkippedReason != "" {
			continue
		}
		// audit-cadence (b): merge if there's an existing LOCAL profile
		// of the same name; refuse if existing is org-sourced. We did
		// the org-sourced refusal check via UpsertProfile's read-only
		// gate; the merge happens here.
		newAllow = append(newAllow, profile.ProfileAllowRule{
			Pattern: r.ProposedRule.Pattern,
			Note:    r.ProposedRule.Note,
		})
	}

	target := &profile.Profile{
		Name:        chosen,
		Description: desc,
	}
	if prior, ok := profiles.All[chosen]; ok && prior != nil {
		if !prior.IsLocalSource() {
			return "", fmt.Errorf(
				"profile %q is sourced from %q and is read-only; "+
					"pick a different name", chosen, prior.Source)
		}
		// Merge: keep prior fields, append new allow_rules deduped.
		target = prior
		target.Name = chosen
		newAllow = mergeAllowRules(target.AllowRules, newAllow)
	}
	target.AllowRules = newAllow

	if err := profile.UpsertProfile(target, path); err != nil {
		return "", fmt.Errorf("upsert profile %q: %w", chosen, err)
	}
	return chosen, nil
}

// mergeAllowRules appends `incoming` rules onto `prior`, dedupe on
// the (pattern, arn_scope, region_scope) tuple — the same fields
// the YAML round-trips. Keeps prior order + appends new entries at
// the end so an operator scanning the YAML sees what got added in
// this run at the bottom.
func mergeAllowRules(prior []profile.ProfileAllowRule, incoming []profile.ProfileAllowRule) []profile.ProfileAllowRule {
	seen := map[string]bool{}
	key := func(r profile.ProfileAllowRule) string {
		return r.Pattern + "|" + r.ArnScope + "|" + r.RegionScope
	}
	for _, r := range prior {
		seen[key(r)] = true
	}
	out := make([]profile.ProfileAllowRule, 0, len(prior)+len(incoming))
	out = append(out, prior...)
	for _, r := range incoming {
		if seen[key(r)] {
			continue
		}
		seen[key(r)] = true
		out = append(out, r)
	}
	return out
}

// SuggestProfileName builds the auto-generated default profile name
// per the [[profile-auto-naming]] convention:
//
//	auto-{YYYY-MM-DD}-{top-1-2-resources}-readonly
//
// Constraints: lowercase alphanumeric + hyphen, ASCII-safe, ≤63 chars
// (K8s label limit). Exported so the MCP tool can call it directly.
func SuggestProfileName(recs []recommender.Recommendation, summary recommender.WindowSummary) string {
	date := time.Now().UTC().Format("2006-01-02")
	if !summary.WindowEnd.IsZero() {
		date = summary.WindowEnd.UTC().Format("2006-01-02")
	}
	// Pick top 1-2 resources by recommendation count, sorted by
	// support DESC then name for determinism.
	type rc struct {
		name  string
		count int
	}
	counts := map[string]int{}
	for _, r := range recs {
		parts := strings.SplitN(r.ProposedRule.Pattern, ":", 2)
		if len(parts) > 0 && parts[0] != "" && parts[0] != "*" {
			counts[parts[0]] += r.SupportCount
		}
	}
	ranked := make([]rc, 0, len(counts))
	for n, c := range counts {
		ranked = append(ranked, rc{name: n, count: c})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].count != ranked[j].count {
			return ranked[i].count > ranked[j].count
		}
		return ranked[i].name < ranked[j].name
	})
	tops := []string{}
	for i := 0; i < 2 && i < len(ranked); i++ {
		tops = append(tops, sanitizeForName(ranked[i].name))
	}
	resourcePart := strings.Join(tops, "-")
	if resourcePart == "" {
		resourcePart = "mixed"
	}
	name := fmt.Sprintf("auto-%s-%s-readonly", date, resourcePart)
	return clampLabel(name)
}

// sanitizeForName strips characters outside the K8s-name-ish charset.
// Keeps lowercase letters + digits; everything else becomes a hyphen.
func sanitizeForName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	b := strings.Builder{}
	for _, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	out = strings.Trim(out, "-")
	if out == "" {
		out = "mixed"
	}
	return out
}

// clampLabel ensures the resulting profile name is ≤63 chars (the
// K8s label cap, used as a safe upper bound across surfaces).
func clampLabel(s string) string {
	if len(s) <= 63 {
		return s
	}
	return strings.TrimRight(s[:63], "-")
}

// ResolveProfileName resolves the chosen profile name per
// [[profile-auto-naming]]:
//
//   - nameArg non-empty → use it
//   - nameArg empty + TTY → prompt with `suggested` as the default
//   - nameArg empty + non-TTY → use `suggested` + print to stderr
//
// `taken` is the set of profile names that already exist; the
// returned name has been collision-avoided via `-2`/`-3` suffix.
//
// `isTTY` is injected so tests can simulate both branches without
// hitting real stdin/term state.
func ResolveProfileName(
	out, errW interface{ Write([]byte) (int, error) },
	stdin *os.File,
	nameArg, suggested string,
	taken map[string]bool,
	isTTY func() bool,
) (string, error) {
	chosen := nameArg
	if chosen == "" {
		if isTTY() {
			// Interactive prompt.
			fmt.Fprintf(out, "name your profile [default: %s]: ", suggested)
			reader := bufio.NewReader(stdin)
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				chosen = suggested
			} else {
				chosen = line
			}
		} else {
			chosen = suggested
			fmt.Fprintf(errW, "kbounce: using auto-generated profile name: %s\n", chosen)
		}
	}
	chosen = AvoidNameCollision(chosen, taken)
	if chosen == "" {
		return "", errors.New("kbounce: empty profile name after collision-avoid")
	}
	return chosen, nil
}

// AvoidNameCollision suffixes `name` with `-2`, `-3`, ... until it's
// not in `taken`. Returns `name` unchanged if it wasn't taken.
// Exported so the MCP tool surface can call it directly.
func AvoidNameCollision(name string, taken map[string]bool) string {
	if !taken[name] {
		return name
	}
	for i := 2; i < 1000; i++ {
		candidate := fmt.Sprintf("%s-%d", name, i)
		if !taken[candidate] {
			return candidate
		}
	}
	// Pathological — return a timestamp suffix as last resort.
	return fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
}

// IsTerminal returns true when stdout is a TTY. Wrapped in a function
// rather than called directly so tests can stub the value.
var IsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// parseRelativeOrAbsolute accepts a relative duration ("1h", "24h",
// "7d", "30m") or an ISO-8601 absolute timestamp. Empty string →
// zero time (no bound).
func parseRelativeOrAbsolute(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	// Try absolute first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	// Try relative duration. Support 'd' shorthand for days (Go's
	// time.ParseDuration doesn't natively).
	if strings.HasSuffix(s, "d") {
		num := strings.TrimSuffix(s, "d")
		if d, err := time.ParseDuration(num + "h"); err == nil {
			return time.Now().UTC().Add(-d * 24)
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().UTC().Add(-d)
	}
	return time.Time{}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
