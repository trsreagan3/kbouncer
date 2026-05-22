// `kbounce audit tail` — local-operator audit UX.
//
// Per [[cross-product-agent-parity]] this file is the kbounce sibling
// of ibounce + dbounce's same-named subcommand. Shape:
//
//	kbounce audit tail [--limit N] [--follow]
//	                   [--filter EXPR ...]
//	                   [--summary]
//	                   [--export {jsonl,csv,ocsf-bundle} --out PATH
//	                    [--csv-columns col1,col2,...]]
//	                   [--db PATH]
//
// The default (no flags beyond --limit) prints the existing 5-column
// table — backwards-compatible with the pre-#268 surface.
//
// FILTER MODEL
//
//   - Each row is wrapped as an audit.Event via FromDecision so the
//     filter language operates against the OCSF wire shape every
//     SIEM-side query also uses (one mental model, not two).
//   - Three operators: `=` (string equality), `~` (regex), `>=` /
//     `<=` (numeric). Repeatable; AND-combined.
//   - Supported fields match the cross-product spec + add kbounce-
//     native `resource.namespace` (the K8s namespace) for kbounce.
//
// AGENT-FIELD COVERAGE
//
// Per #289 (closes the kbounce-agent-identity-sqlite-gap) the
// decisions table persists the agent name + per-MCP-session id
// alongside every row. `audit tail` reads those columns and surfaces
// them under unmapped.iam_jit.agent so --filter on
// unmapped.iam_jit.agent.name / agent.session_id works against
// SQLite-sourced events exactly the same way it does against the
// JSONL log. Pre-#289 rows have NULL columns and fall through to the
// default {name:"unknown", detected_from:"unknown"} block —
// accurate, since we never had the identity to record for those
// rows.
//
// SECURITY-RELEVANT INVARIANTS
//
//   - PII fields (actor.user.name, actor.user.uid, RawUserAgent,
//     process_exe, parent_exe) are OUT of the default CSV column set.
//     Opt-in via --csv-columns to surface them. Per
//     [[security-team-positioning-safety-not-surveillance]] the local
//     stream stays full-fidelity; the export defaults are conservative.
//   - --follow + --summary are mutually exclusive — summary is a
//     terminal aggregation, follow is an open-ended stream.
//   - All export formats round-trip without re-querying the proxy; the
//     command is read-only against the SQLite store (no network calls,
//     no mutation) per [[creates-never-mutates]] +
//     [[self-host-zero-billing-dependency]].
package cli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// followPollInterval is the SQLite poll cadence in --follow mode. 500ms
// matches the cross-product spec; lower would burn CPU on an idle proxy,
// higher would feel laggy to an operator watching a live stream.
const followPollInterval = 500 * time.Millisecond

// followBatch is the chunk size pulled from SQLite per poll tick. The
// store caps at 1000; 200 is large enough to absorb a small burst
// without falling behind while keeping per-tick work bounded.
const followBatch = 200

// defaultCSVColumns is the conservative default column set for
// `--export csv`. Excludes PII / sensitive fields (actor.user.name,
// actor.user.uid, agent.process_exe, agent.parent_exe,
// agent.user_agent_raw). Operators who need those surfaced opt in via
// --csv-columns.
var defaultCSVColumns = []string{
	"timestamp",
	"severity",
	"event_type",
	"actor",
	"operation",
	"verdict",
	"agent.name",
	"agent.session_id",
}

// supportedFilterFields documents the cross-product field vocabulary
// the --filter expressions key off. Kept in one place so a typo in a
// filter expression surfaces "field not supported (try one of: ...)"
// rather than silently matching nothing.
var supportedFilterFields = []string{
	"severity_id",
	"activity_id",
	"status_id",
	"actor.user.name",
	"api.operation",
	"unmapped.iam_jit.agent.name",
	"unmapped.iam_jit.agent.session_id",
	"unmapped.iam_jit.event_type",
	// kbounce-native extension fields per cross-product spec
	// ("If kbounce has unique fields (e.g., k8s `resource.namespace`),
	// support filtering on them + document as kbounce-specific.").
	"resource.namespace",
	"resource.name",
	"resource.type",
	"unmapped.iam_jit.verdict",
	"unmapped.iam_jit.mode",
	"unmapped.iam_jit.profile",
	"unmapped.iam_jit.enforced",
}

// newAuditTailCmd implements `kbounce audit tail` with the full flag
// set documented in the file-doc above.
func newAuditTailCmd() *cobra.Command {
	var (
		limit       int
		dbPath      string
		follow      bool
		filterExprs []string
		summary     bool
		exportFmt   string
		outPath     string
		csvCols     string
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show recent decisions; optionally follow, filter, summarize, or export",
		Long: `Show the most recent decisions from the kbounce audit DB,
newest first by default. Operator-facing surface:

  --limit N            cap row count (1-1000, default 50)
  --follow             tail the audit DB live (Ctrl-C to exit)
  --filter EXPR        OCSF-field predicate (repeatable, AND-combined)
                       forms: field=value | field~regex
                              field>=N | field<=N
  --summary            print group counts instead of rows
  --export FORMAT      jsonl | csv | ocsf-bundle (requires --out)
  --out PATH           output file for --export
  --csv-columns LIST   comma-separated column list for --export csv

See docs/QUERYING-AUDIT-LOGS.md for the filter-field catalog +
worked examples.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > 1000 {
				return fmt.Errorf("--limit must be in 1-1000 (got %d)", limit)
			}
			if follow && summary {
				return errors.New(
					"--follow and --summary are mutually exclusive " +
						"(summary is a terminal aggregation; follow is open-ended)")
			}
			if exportFmt != "" && outPath == "" {
				return errors.New("--export requires --out PATH")
			}
			if outPath != "" && exportFmt == "" {
				return errors.New("--out requires --export FORMAT")
			}
			if exportFmt != "" && follow {
				return errors.New("--export and --follow are mutually exclusive")
			}
			if csvCols != "" && exportFmt != "csv" {
				return errors.New("--csv-columns only applies to --export csv")
			}

			filters, err := parseFilterExprs(filterExprs)
			if err != nil {
				return err
			}

			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			switch {
			case summary:
				return runAuditTailSummary(cmd.OutOrStdout(), st, limit, filters)
			case exportFmt != "":
				cols := defaultCSVColumns
				if csvCols != "" {
					cols = parseCSVColumns(csvCols)
				}
				return runAuditTailExport(
					cmd.OutOrStdout(), cmd.ErrOrStderr(),
					st, limit, filters, exportFmt, outPath, cols)
			case follow:
				return runAuditTailFollow(cmd.Context(), cmd.OutOrStdout(),
					st, limit, filters)
			default:
				return runAuditTailRows(cmd.OutOrStdout(), st, limit, filters)
			}
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50,
		"Max rows to return / consider (1-1000). Default 50.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	cmd.Flags().BoolVar(&follow, "follow", false,
		"Tail the audit DB live; new decisions print as they land. "+
			"Polls every 500ms. Exit with Ctrl-C / SIGINT.")
	cmd.Flags().StringSliceVar(&filterExprs, "filter", nil,
		"OCSF-field filter expression (repeatable; AND-combined). "+
			"Forms: field=value, field~regex, field>=N, field<=N. "+
			"See docs/QUERYING-AUDIT-LOGS.md for the supported-field "+
			"catalog.")
	cmd.Flags().BoolVar(&summary, "summary", false,
		"Print group counts (by event_type, severity, actor, operation) "+
			"instead of rows. Mutually exclusive with --follow.")
	cmd.Flags().StringVar(&exportFmt, "export", "",
		"Export FORMAT for downstream tools. One of: jsonl, csv, "+
			"ocsf-bundle. Requires --out PATH.")
	cmd.Flags().StringVar(&outPath, "out", "",
		"Output file path for --export. Truncated on each invocation.")
	cmd.Flags().StringVar(&csvCols, "csv-columns", "",
		"Comma-separated column list for --export csv. Default omits "+
			"PII (actor.user.name, agent.process_exe, ...). Opt in by "+
			"naming the column explicitly.")
	return cmd
}

// runAuditTailRows is the legacy non-follow / non-summary / non-export
// path — the existing table view, plus optional --filter pre-pass.
func runAuditTailRows(w io.Writer, st *store.Store, limit int, filters []rowFilter) error {
	rows, err := st.RecentDecisions(limit)
	if err != nil {
		return err
	}
	rows = applyFiltersToRows(rows, filters)
	if len(rows) == 0 {
		if len(filters) > 0 {
			fmt.Fprintln(w, "(no decisions match the given filters)")
		} else {
			fmt.Fprintln(w, "(no decisions recorded yet)")
		}
		return nil
	}
	writeTableHeader(w)
	for _, r := range rows {
		writeTableRow(w, r)
	}
	return nil
}

// runAuditTailSummary prints group-by counts for the most recent
// `limit` rows, after applying filters. Four groupings per the cross-
// product spec.
func runAuditTailSummary(w io.Writer, st *store.Store, limit int, filters []rowFilter) error {
	rows, err := st.RecentDecisions(limit)
	if err != nil {
		return err
	}
	rows = applyFiltersToRows(rows, filters)
	byEventType := map[string]int{}
	bySeverity := map[string]int{}
	byActor := map[string]int{}
	byOperation := map[string]int{}
	for _, r := range rows {
		ev := decisionRowToEvent(r)
		byEventType[orUnknown(string(ev.EventType))]++
		bySeverity[orUnknown(ev.Severity)]++
		byActor[orUnknown(actorLabel(ev))]++
		byOperation[orUnknown(ev.API.Operation)]++
	}
	fmt.Fprintf(w, "audit-tail summary (%d row(s) considered)\n", len(rows))
	writeSummarySection(w, "BY EVENT_TYPE", byEventType)
	writeSummarySection(w, "BY SEVERITY", bySeverity)
	writeSummarySection(w, "BY ACTOR", byActor)
	writeSummarySection(w, "BY API.OPERATION", byOperation)
	return nil
}

// runAuditTailExport writes the filtered row set to outPath in the
// requested format.
func runAuditTailExport(_ io.Writer, stderr io.Writer, st *store.Store,
	limit int, filters []rowFilter, format, outPath string, csvCols []string) error {
	rows, err := st.RecentDecisions(limit)
	if err != nil {
		return err
	}
	rows = applyFiltersToRows(rows, filters)

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open --out %s: %w", outPath, err)
	}
	defer f.Close()

	switch format {
	case "jsonl":
		enc := json.NewEncoder(f)
		for _, r := range rows {
			ev := decisionRowToEvent(r)
			if err := enc.Encode(ev); err != nil {
				return fmt.Errorf("encode jsonl: %w", err)
			}
		}
	case "csv":
		if err := writeCSVExport(f, rows, csvCols); err != nil {
			return err
		}
	case "ocsf-bundle":
		if err := writeOCSFBundle(f, rows); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown --export format %q (want: jsonl|csv|ocsf-bundle)", format)
	}

	fmt.Fprintf(stderr, "wrote %d row(s) to %s (format=%s)\n",
		len(rows), outPath, format)
	return nil
}

// runAuditTailFollow polls the SQLite DB every followPollInterval and
// prints new rows as they land. Exits cleanly on SIGINT / context
// cancellation.
//
// The "newness" cursor is the row timestamp + parsed verb/path tuple
// — DecisionRow doesn't expose the SQLite rowid, so we de-dup against
// the last-seen "fingerprint" set. False-dupes can't happen across
// distinct rows because RecordDecision always stamps a unique
// At timestamp via time.Now() (microsecond resolution on macOS/Linux),
// and the proxy serializes decision writes through one Store.
func runAuditTailFollow(ctx context.Context, w io.Writer, st *store.Store,
	limit int, filters []rowFilter) error {
	sigCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Print one-time banner so the operator knows we are live.
	fmt.Fprintln(w, "(following kbounce audit DB; Ctrl-C to exit)")

	// Initial fill: emit the last `limit` rows so the operator has
	// context, then watch for new arrivals.
	initial, err := st.RecentDecisions(limit)
	if err != nil {
		return err
	}
	initial = applyFiltersToRows(initial, filters)
	if len(initial) > 0 {
		writeTableHeader(w)
		// RecentDecisions returns newest-first; reverse so the live
		// stream reads top-to-bottom in chronological order — easier
		// to scan than a reversed scroll.
		for i := len(initial) - 1; i >= 0; i-- {
			writeTableRow(w, initial[i])
		}
	} else {
		writeTableHeader(w)
	}
	// Anchor cursor to the most-recent row's timestamp. Rows whose
	// At > cursor are emitted on subsequent polls.
	var cursor time.Time
	if len(initial) > 0 {
		cursor = initial[0].At
	}
	// Track fingerprints we've already emitted in the current second
	// to dedupe when several rows share the same wall-clock second.
	seen := map[string]struct{}{}
	for _, r := range initial {
		seen[rowFingerprint(r)] = struct{}{}
	}

	ticker := time.NewTicker(followPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-sigCtx.Done():
			fmt.Fprintln(w, "(follow stopped)")
			return nil
		case <-ticker.C:
			next, err := st.RecentDecisions(followBatch)
			if err != nil {
				return err
			}
			// Walk oldest-first so we print in chronological order.
			fresh := make([]store.DecisionRow, 0, len(next))
			for i := len(next) - 1; i >= 0; i-- {
				r := next[i]
				if !r.At.After(cursor) && r.At != cursor {
					continue
				}
				fp := rowFingerprint(r)
				if _, dup := seen[fp]; dup {
					continue
				}
				fresh = append(fresh, r)
			}
			fresh = applyFiltersToRows(fresh, filters)
			for _, r := range fresh {
				writeTableRow(w, r)
				seen[rowFingerprint(r)] = struct{}{}
				if r.At.After(cursor) {
					cursor = r.At
				}
			}
			// Cap the seen set so a long-running follow doesn't grow
			// unbounded. Trim entries older than 60s — RecordDecision
			// can't reorder more than the poll interval, so 60s is a
			// generous safety margin.
			if len(seen) > 4096 {
				seen = map[string]struct{}{}
				// Re-seed with the most recent fingerprints so the
				// next tick doesn't re-emit them.
				for _, r := range next {
					seen[rowFingerprint(r)] = struct{}{}
				}
			}
		}
	}
}

// rowFingerprint is the dedupe key used by --follow. Composed of the
// timestamp + method + path + verdict — three independent rows can
// share a timestamp under load, but the rest of the tuple distinguishes
// them. Not cryptographic; collision risk is rapidly-discovered
// missed-events at worst, not a correctness defect.
func rowFingerprint(r store.DecisionRow) string {
	return r.At.UTC().Format(time.RFC3339Nano) + "|" +
		r.Method + "|" + r.Path + "|" + r.DecisionVerdict + "|" +
		r.DecisionReason
}

// decisionRowToEvent wraps a SQLite DecisionRow as an OCSF Event using
// the same FromDecision builder the audit-export pipeline uses. This
// is the bridge that lets --filter / --summary / --export operate
// against the same wire shape downstream SIEMs see.
//
// Agent fields are read from the persisted decisions.agent_name +
// decisions.agent_session_id columns (#289 closes the kbounce-agent-
// identity-sqlite-gap). DetectedFrom is reconstructed best-effort:
// a populated session id implies the MCP-clientinfo source (only the
// MCP handshake binds a session id); a populated name without a
// session id implies the user-agent source. Empty AgentName falls
// through to the FromDecision default {name:"unknown",
// detected_from:"unknown"} block — accurate for pre-#289 rows.
func decisionRowToEvent(r store.DecisionRow) audit.Event {
	in := audit.DecisionInput{
		At:                r.At,
		Mode:              r.ModeAtDecision,
		Profile:           r.ProfileName,
		Verdict:           r.DecisionVerdict,
		Reason:            r.DecisionReason,
		DecisionSource:    r.DecisionSource,
		Enforced:          r.Enforced,
		Method:            r.Method,
		Path:              r.Path,
		ParsedVerb:        r.ParsedVerb,
		ParsedGroup:       r.ParsedGroup,
		ParsedVersion:     r.ParsedVersion,
		ParsedResource:    r.ParsedResource,
		ParsedNamespace:   r.ParsedNamespace,
		ParsedName:        r.ParsedName,
		ParsedSubresource: r.ParsedSubresource,
		IsWatch:           r.IsWatch,
		IsDryRun:          r.IsDryRun,
		StreamKind:        r.StreamKind,
		TaskID:            r.TaskID,
		Agent:             agentInfoFromRow(r),
	}
	return audit.FromDecision(in)
}

// agentInfoFromRow rebuilds the audit.AgentInfo from the columns
// persisted by #289 + #320. Shared by every SQLite read path (audit
// tail, investigate, /audit/events, web UI) so the agent block
// surfaces identically across surfaces. The PrincipalName field on
// DecisionInput is the K8s-subject path — distinct from the agent
// (which is the calling client identity); we populate both via the
// Actor block downstream when name is non-empty.
//
// #320 / §A18: reads `detected_from` from the persisted column
// instead of heuristically inferring it. Pre-#320 rows surface
// `DetectionSourceUnknown` via the schema-level DEFAULT — historical
// events stay accurate (we don't synthesize a detection source we
// didn't actually observe).
func agentInfoFromRow(r store.DecisionRow) audit.AgentInfo {
	if r.AgentName == "" && r.AgentSessionID == "" &&
		(r.DetectedFrom == "" || r.DetectedFrom == audit.DetectionSourceUnknown) {
		return audit.AgentInfo{}
	}
	info := audit.AgentInfo{
		Name:      r.AgentName,
		SessionID: r.AgentSessionID,
	}
	if r.DetectedFrom != "" {
		info.DetectedFrom = r.DetectedFrom
	} else {
		info.DetectedFrom = audit.DetectionSourceUnknown
	}
	return info
}

// --------------------------------------------------------------------
// Filter parsing + evaluation.
// --------------------------------------------------------------------

// rowFilter is the parsed form of one --filter expression. The
// matcher closure is bound at parse time so the eval loop is a flat
// function-call per (row, filter).
type rowFilter struct {
	raw     string
	matcher func(audit.Event) bool
}

// parseFilterExprs walks the --filter slice, validating + compiling
// each expression. Returns a typed-error message naming the bad
// expression + listing the supported fields so the operator can
// self-correct without `--help` scrolling.
func parseFilterExprs(exprs []string) ([]rowFilter, error) {
	out := make([]rowFilter, 0, len(exprs))
	for _, raw := range exprs {
		f, err := parseFilterExpr(raw)
		if err != nil {
			return nil, fmt.Errorf("--filter %q: %w (supported fields: %s)",
				raw, err, strings.Join(supportedFilterFields, ", "))
		}
		out = append(out, f)
	}
	return out, nil
}

// parseFilterExpr parses one expression. Order matters: `>=` and `<=`
// must be tested before `=` so a numeric expression doesn't trip the
// equality branch and pin field="9>=foo".
func parseFilterExpr(raw string) (rowFilter, error) {
	if strings.Contains(raw, ">=") {
		field, rhs, ok := splitOnce(raw, ">=")
		if !ok || field == "" || rhs == "" {
			return rowFilter{}, errors.New("bad >= expression")
		}
		if !isSupportedField(field) {
			return rowFilter{}, fmt.Errorf("field %q not supported", field)
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(rhs), 64)
		if err != nil {
			return rowFilter{}, fmt.Errorf("RHS of >= not numeric: %v", err)
		}
		return rowFilter{raw: raw, matcher: func(ev audit.Event) bool {
			fv, ok := numericFieldValue(ev, field)
			return ok && fv >= n
		}}, nil
	}
	if strings.Contains(raw, "<=") {
		field, rhs, ok := splitOnce(raw, "<=")
		if !ok || field == "" || rhs == "" {
			return rowFilter{}, errors.New("bad <= expression")
		}
		if !isSupportedField(field) {
			return rowFilter{}, fmt.Errorf("field %q not supported", field)
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(rhs), 64)
		if err != nil {
			return rowFilter{}, fmt.Errorf("RHS of <= not numeric: %v", err)
		}
		return rowFilter{raw: raw, matcher: func(ev audit.Event) bool {
			fv, ok := numericFieldValue(ev, field)
			return ok && fv <= n
		}}, nil
	}
	if strings.Contains(raw, "~") {
		field, rhs, ok := splitOnce(raw, "~")
		if !ok || field == "" || rhs == "" {
			return rowFilter{}, errors.New("bad ~ expression")
		}
		if !isSupportedField(field) {
			return rowFilter{}, fmt.Errorf("field %q not supported", field)
		}
		re, err := regexp.Compile(rhs)
		if err != nil {
			return rowFilter{}, fmt.Errorf("bad regex: %v", err)
		}
		return rowFilter{raw: raw, matcher: func(ev audit.Event) bool {
			return re.MatchString(stringFieldValue(ev, field))
		}}, nil
	}
	if strings.Contains(raw, "=") {
		field, rhs, ok := splitOnce(raw, "=")
		if !ok || field == "" {
			return rowFilter{}, errors.New("bad = expression")
		}
		if !isSupportedField(field) {
			return rowFilter{}, fmt.Errorf("field %q not supported", field)
		}
		want := rhs
		return rowFilter{raw: raw, matcher: func(ev audit.Event) bool {
			return stringFieldValue(ev, field) == want
		}}, nil
	}
	return rowFilter{}, errors.New(
		"no operator found (expected one of =, ~, >=, <=)")
}

// splitOnce splits s on the FIRST occurrence of sep. Returns
// (left, right, true) on success; ("", "", false) when sep not found.
// Used for filter parsing so a regex containing "=" doesn't get
// torn in half.
func splitOnce(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

// isSupportedField checks the cross-product field catalog. Membership
// test is cheap (O(N) over a ~15-entry slice) and avoids the
// `init()`-time map cost most callers won't trigger.
func isSupportedField(field string) bool {
	for _, f := range supportedFilterFields {
		if f == field {
			return true
		}
	}
	return false
}

// stringFieldValue projects an OCSF Event down to one named field as
// a string. Returns "" for fields the event doesn't carry — equality
// against "" then matches the absence-of-value case (intentional;
// matches `jq -r '.field // ""'` semantics).
func stringFieldValue(ev audit.Event, field string) string {
	switch field {
	case "severity_id":
		return strconv.Itoa(ev.SeverityID)
	case "activity_id":
		return strconv.Itoa(ev.ActivityID)
	case "status_id":
		return strconv.Itoa(ev.StatusID)
	case "actor.user.name":
		if ev.Actor != nil && ev.Actor.User != nil {
			return ev.Actor.User.Name
		}
		return ""
	case "api.operation":
		return ev.API.Operation
	case "unmapped.iam_jit.agent.name":
		if ev.Unmapped.IAMJIT.Agent != nil {
			return ev.Unmapped.IAMJIT.Agent.Name
		}
		return ""
	case "unmapped.iam_jit.agent.session_id":
		if ev.Unmapped.IAMJIT.Agent != nil {
			return ev.Unmapped.IAMJIT.Agent.SessionID
		}
		return ""
	case "unmapped.iam_jit.event_type":
		return ev.Unmapped.IAMJIT.EventType
	case "unmapped.iam_jit.verdict":
		return ev.Unmapped.IAMJIT.Verdict
	case "unmapped.iam_jit.mode":
		return ev.Unmapped.IAMJIT.Mode
	case "unmapped.iam_jit.profile":
		return ev.Unmapped.IAMJIT.Profile
	case "unmapped.iam_jit.enforced":
		if ev.Unmapped.IAMJIT.Enforced {
			return "true"
		}
		return "false"
	case "resource.namespace":
		// kbounce-native: pull from the first resource's UID parts (or
		// from the ext.namespace field which mirrors the parsed value).
		if v, ok := ev.Unmapped.IAMJIT.Ext["namespace"].(string); ok {
			return v
		}
		return ""
	case "resource.name":
		if len(ev.Resources) > 0 {
			return ev.Resources[0].Name
		}
		return ""
	case "resource.type":
		if len(ev.Resources) > 0 {
			return ev.Resources[0].Type
		}
		return ""
	}
	return ""
}

// numericFieldValue is the float64 view used by `>=` / `<=`. Only the
// id-shaped fields are numeric in OCSF; everything else returns
// (0, false) so a numeric filter on a string field cleanly misses
// instead of silently matching 0.
func numericFieldValue(ev audit.Event, field string) (float64, bool) {
	switch field {
	case "severity_id":
		return float64(ev.SeverityID), true
	case "activity_id":
		return float64(ev.ActivityID), true
	case "status_id":
		return float64(ev.StatusID), true
	}
	return 0, false
}

// applyFiltersToRows filters a slice of DecisionRows through the
// parsed filter set. Returns the slice unchanged when filters is empty
// (no allocation; the common path is cheap).
func applyFiltersToRows(rows []store.DecisionRow, filters []rowFilter) []store.DecisionRow {
	if len(filters) == 0 {
		return rows
	}
	out := make([]store.DecisionRow, 0, len(rows))
	for _, r := range rows {
		ev := decisionRowToEvent(r)
		match := true
		for _, f := range filters {
			if !f.matcher(ev) {
				match = false
				break
			}
		}
		if match {
			out = append(out, r)
		}
	}
	return out
}

// --------------------------------------------------------------------
// Output helpers (table view + summary + CSV + OCSF bundle).
// --------------------------------------------------------------------

func writeTableHeader(w io.Writer) {
	fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-9s  %s\n",
		"AT (UTC)", "MODE", "VERDICT", "SOURCE", "REQUEST")
}

func writeTableRow(w io.Writer, r store.DecisionRow) {
	at := r.At.UTC().Format("2006-01-02 15:04:05")
	src := r.DecisionSource
	if src == "" {
		src = "-"
	}
	req := r.Method + " " + r.Path
	if len(req) > 60 {
		req = req[:57] + "..."
	}
	fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-9s  %s\n",
		at, r.ModeAtDecision, r.DecisionVerdict, src, req)
	if r.DecisionReason != "" {
		reason := r.DecisionReason
		if len(reason) > 80 {
			reason = reason[:77] + "..."
		}
		fmt.Fprintf(w, "%48s  %s\n", "↳", reason)
	}
}

func writeSummarySection(w io.Writer, title string, counts map[string]int) {
	fmt.Fprintf(w, "\n%s\n", title)
	if len(counts) == 0 {
		fmt.Fprintln(w, "  (no rows)")
		return
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	// Sort by count desc, then key asc for stable ordering on ties.
	sort.SliceStable(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		fmt.Fprintf(w, "  %6d  %s\n", counts[k], k)
	}
}

func actorLabel(ev audit.Event) string {
	if ev.Actor != nil && ev.Actor.User != nil && ev.Actor.User.Name != "" {
		return ev.Actor.User.Name
	}
	if ev.Actor != nil && ev.Actor.Session != nil && ev.Actor.Session.UID != "" {
		return "session:" + ev.Actor.Session.UID
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// parseCSVColumns splits a comma-separated --csv-columns value and
// trims whitespace per entry. Empty entries are dropped so trailing
// commas are forgiven.
func parseCSVColumns(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// writeCSVExport renders rows as CSV with the supplied column list.
// Per the file-doc, the DEFAULT column list excludes PII; an operator
// who explicitly names a PII column gets it.
func writeCSVExport(w io.Writer, rows []store.DecisionRow, cols []string) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write(cols); err != nil {
		return fmt.Errorf("csv header: %w", err)
	}
	for _, r := range rows {
		ev := decisionRowToEvent(r)
		rec := make([]string, len(cols))
		for i, c := range cols {
			rec[i] = csvColumnValue(ev, c)
		}
		if err := cw.Write(rec); err != nil {
			return fmt.Errorf("csv row: %w", err)
		}
	}
	if err := cw.Error(); err != nil {
		return fmt.Errorf("csv flush: %w", err)
	}
	return nil
}

// csvColumnValue projects an OCSF Event into a CSV cell. Supports both
// the friendly aliases (`timestamp`, `severity`, `actor`, `verdict`)
// and the raw OCSF dotted-path names accepted by --filter, so an
// operator can compose with a single mental model.
func csvColumnValue(ev audit.Event, col string) string {
	switch col {
	case "timestamp":
		return time.UnixMilli(ev.Time).UTC().Format(time.RFC3339)
	case "severity":
		return ev.Severity
	case "event_type":
		if ev.Unmapped.IAMJIT.EventType != "" {
			return ev.Unmapped.IAMJIT.EventType
		}
		return string(ev.EventType)
	case "actor":
		return actorLabel(ev)
	case "operation":
		return ev.API.Operation
	case "verdict":
		return ev.Unmapped.IAMJIT.Verdict
	case "agent.name":
		if ev.Unmapped.IAMJIT.Agent != nil {
			return ev.Unmapped.IAMJIT.Agent.Name
		}
		return ""
	case "agent.session_id":
		if ev.Unmapped.IAMJIT.Agent != nil {
			return ev.Unmapped.IAMJIT.Agent.SessionID
		}
		return ""
	}
	// Fall through to the filter-field projection so an explicit
	// --csv-columns can request any OCSF field the filter layer
	// already exposes.
	return stringFieldValue(ev, col)
}

// OCSFBundle is the wrapper an SIEM batch-import endpoint accepts:
// one Detection Finding (OCSF class 2004) carrying a payload[] of
// API Activity events. Lets a security team upload a forensic snapshot
// of recent decisions in one shot rather than streaming one-by-one.
//
// The Detection Finding shape follows OCSF 1.1.0 — required fields:
// metadata, time, class_uid (2004), category_uid (2),
// activity_id (1=Create), severity_id, status_id, finding_info.
type OCSFBundle struct {
	Metadata     audit.OCSFMetadata `json:"metadata"`
	Time         int64              `json:"time"`
	ClassUID     int                `json:"class_uid"`
	ClassName    string             `json:"class_name"`
	CategoryUID  int                `json:"category_uid"`
	CategoryName string             `json:"category_name"`
	ActivityID   int                `json:"activity_id"`
	ActivityName string             `json:"activity_name"`
	TypeUID      int                `json:"type_uid"`
	TypeName     string             `json:"type_name"`
	SeverityID   int                `json:"severity_id"`
	Severity     string             `json:"severity"`
	StatusID     int                `json:"status_id"`
	Status       string             `json:"status"`
	FindingInfo  OCSFFindingInfo    `json:"finding_info"`
	Events       []audit.Event      `json:"events"`
}

// OCSFFindingInfo is the Detection Finding's finding_info object.
type OCSFFindingInfo struct {
	UID         string `json:"uid"`
	Title       string `json:"title"`
	Desc        string `json:"desc"`
	CreatedTime int64  `json:"created_time"`
}

// writeOCSFBundle emits a single OCSF Detection Finding wrapping the
// filtered event set. The bundle satisfies the OCSF 1.1.0 class 2004
// required-field set so a SIEM that ingests Detection Findings (most
// SIEMs do; AWS Security Lake, Splunk, Sentinel) accepts the document
// without product-specific mapping.
func writeOCSFBundle(w io.Writer, rows []store.DecisionRow) error {
	events := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		events = append(events, decisionRowToEvent(r))
	}
	now := time.Now().UTC()
	bundle := OCSFBundle{
		Metadata: audit.OCSFMetadata{
			Version: audit.OCSFSchemaVersion,
			Product: audit.OCSFProduct{
				Name:       audit.ProductName,
				VendorName: audit.VendorName,
				Version:    version,
			},
		},
		Time:         now.UnixMilli(),
		ClassUID:     2004,
		ClassName:    "Detection Finding",
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: "Create",
		TypeUID:      2004*100 + 1,
		TypeName:     "Detection Finding: Create",
		SeverityID:   audit.SeverityInformational,
		Severity:     "Informational",
		StatusID:     audit.StatusOther,
		Status:       "Other",
		FindingInfo: OCSFFindingInfo{
			UID:   fmt.Sprintf("kbounce-audit-tail-%d", now.UnixNano()),
			Title: "kbounce audit-tail export",
			Desc: fmt.Sprintf(
				"Operator-initiated batch export of %d kbounce audit-log row(s) via `kbounce audit tail --export ocsf-bundle`.",
				len(events)),
			CreatedTime: now.UnixMilli(),
		},
		Events: events,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		return fmt.Errorf("encode ocsf-bundle: %w", err)
	}
	return nil
}
