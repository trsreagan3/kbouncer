// CLI coverage for the enhanced `kbounce audit tail` surface (#268):
// --follow, --filter, --summary, --export {jsonl,csv,ocsf-bundle}.
//
// Each test seeds a fresh SQLite store with a known set of
// DecisionRows, then invokes the cobra command end-to-end via
// runCLI / runCLIRaw — same pattern the rest of the cli package uses.
// Test guidelines:
//   - No network calls (the command is read-only against a local DB).
//   - --follow tests cancel via context to stop the SIGINT loop
//     deterministically; no signal sending.
//   - JSON / CSV / OCSF-bundle outputs round-trip through their
//     respective decoders so format drift surfaces immediately.
package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

// seedDecisions opens a fresh store at dbPath and records the given
// rows in order. Returns the open store so the test can poke at it
// directly when needed (e.g. to record more rows mid-test for the
// --follow case).
func seedDecisions(t *testing.T, dbPath string, rows []store.DecisionRow) *store.Store {
	t.Helper()
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	for _, r := range rows {
		_, err := st.RecordDecision(r)
		require.NoError(t, err)
	}
	return st
}

// fixtureDecisions returns a small, diverse set of decisions covering
// the main filter axes: verdict, mode, verb, namespace, decision
// source. Time-spaced by 1ms so the --follow cursor distinguishes them
// cleanly.
func fixtureDecisions(base time.Time) []store.DecisionRow {
	return []store.DecisionRow{
		{
			At:              base.Add(1 * time.Millisecond),
			Method:          "GET",
			Path:            "/api/v1/namespaces/prod/pods",
			ParsedVerb:      "list",
			ParsedResource:  "pods",
			ParsedNamespace: "prod",
			DecisionVerdict: "allow",
			ModeAtDecision:  "transparent",
			Enforced:        true,
			DecisionSource:  "profile",
			ProfileName:     "safe-default",
		},
		{
			At:              base.Add(2 * time.Millisecond),
			Method:          "DELETE",
			Path:            "/api/v1/namespaces/prod/pods/db-0",
			ParsedVerb:      "delete",
			ParsedResource:  "pods",
			ParsedNamespace: "prod",
			ParsedName:      "db-0",
			DecisionVerdict: "deny",
			DecisionReason:  "matched deny rule",
			ModeAtDecision:  "transparent",
			Enforced:        true,
			DecisionSource:  "profile",
			ProfileName:     "safe-default",
		},
		{
			At:              base.Add(3 * time.Millisecond),
			Method:          "POST",
			Path:            "/api/v1/namespaces/dev/secrets",
			ParsedVerb:      "create",
			ParsedResource:  "secrets",
			ParsedNamespace: "dev",
			DecisionVerdict: "deny",
			DecisionReason:  "advisory: secret writes flagged",
			ModeAtDecision:  "cooperative",
			Enforced:        false,
			DecisionSource:  "global",
		},
	}
}

func TestAuditTail_DefaultTableRendersAllRows(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	out, _, err := runCLI(t, db, "audit", "tail", "--limit", "10")
	require.NoError(t, err)
	assert.Contains(t, out, "AT (UTC)")
	assert.Contains(t, out, "/api/v1/namespaces/prod/pods")
	assert.Contains(t, out, "/api/v1/namespaces/dev/secrets")
}

func TestAuditTail_EmptyDBPrintsFriendlyMessage(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st, err := store.Open(db)
	require.NoError(t, err)
	st.Close()

	out, _, err := runCLI(t, db, "audit", "tail")
	require.NoError(t, err)
	assert.Contains(t, out, "(no decisions recorded yet)")
}

func TestAuditTail_LimitRangeValidation(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")

	_, _, err := runCLI(t, db, "audit", "tail", "--limit", "0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be in 1-1000")

	_, _, err = runCLI(t, db, "audit", "tail", "--limit", "5000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be in 1-1000")
}

// --------------------------------------------------------------------
// Filter coverage.
// --------------------------------------------------------------------

func TestAuditTail_FilterEqualityNarrowsRows(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	out, _, err := runCLI(t, db, "audit", "tail",
		"--filter", "api.operation=delete")
	require.NoError(t, err)
	assert.Contains(t, out, "db-0")
	assert.NotContains(t, out, "/api/v1/namespaces/dev/secrets")
	assert.NotContains(t, out, "/api/v1/namespaces/prod/pods\n",
		"list pods (no name) row must be filtered out")
}

func TestAuditTail_FilterRegexMatches(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	out, _, err := runCLI(t, db, "audit", "tail",
		"--filter", "api.operation~^(create|delete)$")
	require.NoError(t, err)
	assert.Contains(t, out, "/api/v1/namespaces/prod/pods/db-0")
	assert.Contains(t, out, "/api/v1/namespaces/dev/secrets")
	// list-pods row should NOT match the regex.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "/api/v1/namespaces/prod/pods ") {
			t.Fatalf("list-pods row leaked through regex filter: %q", line)
		}
	}
}

func TestAuditTail_FilterNumericGTEAndLTE(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	// All fixture rows are Informational (severity_id=1). >= 1 matches
	// all; >= 2 matches none.
	out, _, err := runCLI(t, db, "audit", "tail", "--filter", "severity_id>=1")
	require.NoError(t, err)
	assert.Contains(t, out, "/api/v1/namespaces/prod/pods")

	out, _, err = runCLI(t, db, "audit", "tail", "--filter", "severity_id>=2")
	require.NoError(t, err)
	assert.Contains(t, out, "(no decisions match the given filters)")

	// activity_id<=2 (Read=2, Create=1) matches list-pods + create-
	// secrets but NOT delete (4). Confirms the numeric operator does
	// arithmetic (not string compare) — the failing case otherwise
	// would be "4" < "2" being true under string compare.
	out, _, err = runCLI(t, db, "audit", "tail", "--filter", "activity_id<=2")
	require.NoError(t, err)
	assert.Contains(t, out, "/api/v1/namespaces/prod/pods")
	assert.Contains(t, out, "/api/v1/namespaces/dev/secrets")
	assert.NotContains(t, out, "/db-0",
		"delete row (activity_id=4) must be filtered out")
}

func TestAuditTail_FilterNestedPathResolves(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	// resource.namespace is a nested-path field per the kbounce-
	// specific extension to the cross-product filter catalog.
	out, _, err := runCLI(t, db, "audit", "tail",
		"--filter", "resource.namespace=dev")
	require.NoError(t, err)
	assert.Contains(t, out, "/api/v1/namespaces/dev/secrets")
	assert.NotContains(t, out, "/api/v1/namespaces/prod/pods")
}

func TestAuditTail_FilterANDComposes(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	// AND: cooperative mode AND DENY verdict — matches the dev-secrets
	// row only.
	out, _, err := runCLI(t, db, "audit", "tail",
		"--filter", "unmapped.iam_jit.mode=cooperative",
		"--filter", "unmapped.iam_jit.verdict=DENY")
	require.NoError(t, err)
	assert.Contains(t, out, "/api/v1/namespaces/dev/secrets")
	assert.NotContains(t, out, "/api/v1/namespaces/prod/pods")
}

func TestAuditTail_FilterUnknownFieldErrors(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runCLI(t, db, "audit", "tail",
		"--filter", "no.such.field=foo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
	assert.Contains(t, err.Error(), "severity_id",
		"the error must list the supported-field catalog")
}

// --------------------------------------------------------------------
// Summary coverage.
// --------------------------------------------------------------------

func TestAuditTail_SummaryCountsByGrouping(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	out, _, err := runCLI(t, db, "audit", "tail", "--summary")
	require.NoError(t, err)
	assert.Contains(t, out, "summary (3 row(s) considered)")
	// Two of three rows have api.operation in {delete, create}; one
	// has list. The grouping must be visible.
	assert.Contains(t, out, "BY API.OPERATION")
	assert.Contains(t, out, "delete")
	assert.Contains(t, out, "create")
	assert.Contains(t, out, "list")
	assert.Contains(t, out, "BY SEVERITY")
	assert.Contains(t, out, "Informational")
}

func TestAuditTail_SummaryEmptyDBProducesZeroCounts(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st, err := store.Open(db)
	require.NoError(t, err)
	st.Close()

	out, _, err := runCLI(t, db, "audit", "tail", "--summary")
	require.NoError(t, err)
	assert.Contains(t, out, "summary (0 row(s) considered)")
	assert.Contains(t, out, "(no rows)")
}

func TestAuditTail_FollowAndSummaryConflictErrors(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")

	_, _, err := runCLI(t, db, "audit", "tail", "--follow", "--summary")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// --------------------------------------------------------------------
// Export coverage.
// --------------------------------------------------------------------

func TestAuditTail_ExportRequiresOut(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")

	_, _, err := runCLI(t, db, "audit", "tail", "--export", "jsonl")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --out")

	_, _, err = runCLI(t, db, "audit", "tail",
		"--out", filepath.Join(dir, "x"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --export")
}

func TestAuditTail_ExportJSONLRoundTrips(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	out := filepath.Join(dir, "events.jsonl")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runCLI(t, db, "audit", "tail",
		"--export", "jsonl", "--out", out)
	require.NoError(t, err)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	require.Len(t, lines, 3, "one OCSF event per decision row")
	for _, line := range lines {
		var ev map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &ev),
			"each line must be standalone JSON (jq-compatible)")
		assert.Equal(t, "API Activity", ev["class_name"])
		md, _ := ev["metadata"].(map[string]any)
		require.NotNil(t, md)
		prod, _ := md["product"].(map[string]any)
		require.NotNil(t, prod)
		assert.Equal(t, "kbounce", prod["name"])
	}
}

func TestAuditTail_ExportCSVParsesAndDefaultsExcludePII(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	out := filepath.Join(dir, "events.csv")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runCLI(t, db, "audit", "tail",
		"--export", "csv", "--out", out)
	require.NoError(t, err)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	rdr := csv.NewReader(bytes.NewReader(raw))
	records, err := rdr.ReadAll()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 2, "header + at least one row")

	header := records[0]
	wantDefault := []string{"timestamp", "severity", "event_type", "actor",
		"operation", "verdict", "agent.name", "agent.session_id"}
	assert.Equal(t, wantDefault, header)

	// Per the file-doc: default CSV MUST NOT carry the raw user agent
	// or other PII columns. Spot-check that the names are absent.
	for _, col := range header {
		assert.NotContains(t, col, "process_exe",
			"process tree fields must not appear in the default CSV")
		assert.NotContains(t, col, "user_agent_raw",
			"raw user agent must not appear in the default CSV")
	}
}

func TestAuditTail_ExportCSVCustomColumnsOptIn(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	out := filepath.Join(dir, "events.csv")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runCLI(t, db, "audit", "tail",
		"--export", "csv", "--out", out,
		"--csv-columns", "timestamp,actor,actor.user.name,operation,verdict")
	require.NoError(t, err)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	rdr := csv.NewReader(bytes.NewReader(raw))
	records, err := rdr.ReadAll()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 2)

	header := records[0]
	assert.Equal(t,
		[]string{"timestamp", "actor", "actor.user.name", "operation", "verdict"},
		header)
}

func TestAuditTail_CSVColumnsOnlyWithCSV(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")

	_, _, err := runCLI(t, db, "audit", "tail",
		"--export", "jsonl", "--out", filepath.Join(dir, "x"),
		"--csv-columns", "timestamp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--csv-columns only applies to --export csv")
}

func TestAuditTail_ExportOCSFBundleValidates(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	out := filepath.Join(dir, "bundle.json")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runCLI(t, db, "audit", "tail",
		"--export", "ocsf-bundle", "--out", out)
	require.NoError(t, err)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var bundle map[string]any
	require.NoError(t, json.Unmarshal(raw, &bundle))
	// Detection Finding required-field set per OCSF 1.1.0 class 2004.
	assert.EqualValues(t, 2004, bundle["class_uid"])
	assert.Equal(t, "Detection Finding", bundle["class_name"])
	assert.EqualValues(t, 2, bundle["category_uid"])
	assert.EqualValues(t, 1, bundle["activity_id"])
	assert.NotNil(t, bundle["finding_info"])
	finding, _ := bundle["finding_info"].(map[string]any)
	require.NotNil(t, finding)
	assert.NotEmpty(t, finding["uid"])
	assert.NotEmpty(t, finding["title"])

	events, _ := bundle["events"].([]any)
	require.Len(t, events, 3, "bundle must wrap all 3 decision rows")
	first, _ := events[0].(map[string]any)
	require.NotNil(t, first)
	assert.Equal(t, "API Activity", first["class_name"])
}

func TestAuditTail_FilterPlusExportComposes(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	out := filepath.Join(dir, "filtered.jsonl")
	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runCLI(t, db, "audit", "tail",
		"--filter", "api.operation=delete",
		"--export", "jsonl", "--out", out)
	require.NoError(t, err)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	require.Len(t, lines, 1, "filter must apply before export")
	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &ev))
	assert.Equal(t, "delete", ev["api"].(map[string]any)["operation"])
}

// --------------------------------------------------------------------
// Follow coverage.
// --------------------------------------------------------------------

// safeBuffer wraps bytes.Buffer with a mutex so the test goroutine
// reading String() races cleanly against the follow goroutine writing
// table rows. bytes.Buffer is not safe for concurrent access; this
// keeps -race quiet without adding production surface.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestAuditTail_FollowPrintsNewRowsAndExits drives --follow against a
// store that grows mid-run, then cancels via context (the parent of
// signal.NotifyContext) to exit cleanly. Catches the regression where
// the poll loop misses a row that lands between the initial fill and
// the first ticker tick.
func TestAuditTail_FollowPrintsNewRowsAndExits(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	base := time.Now().UTC()
	// Seed one row so the initial-fill code path runs.
	st := seedDecisions(t, db, fixtureDecisions(base)[:1])

	st2, err := store.Open(db)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	buf := &safeBuffer{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := runAuditTailFollow(ctx, buf, st2, 50, nil)
		assert.NoError(t, err)
	}()

	// Give the goroutine a tick to do the initial fill.
	time.Sleep(50 * time.Millisecond)
	// Append a new decision; the next ticker tick (~500ms) should
	// observe + print it.
	_, err = st.RecordDecision(store.DecisionRow{
		At:              base.Add(2 * time.Second),
		Method:          "POST",
		Path:            "/api/v1/namespaces/qa/pods/inserted-during-follow",
		ParsedVerb:      "create",
		ParsedResource:  "pods",
		ParsedNamespace: "qa",
		DecisionVerdict: "allow",
		ModeAtDecision:  "transparent",
		Enforced:        true,
	})
	require.NoError(t, err)

	// Wait long enough for at least one tick of the 500ms poller plus
	// some slack on a loaded CI machine.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "inserted-during-follow") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	st.Close()
	st2.Close()

	out := buf.String()
	assert.Contains(t, out, "(following kbounce audit DB",
		"banner must announce live-mode to the operator")
	assert.Contains(t, out, "inserted-during-follow",
		"row written mid-follow must surface in the output")
	assert.Contains(t, out, "(follow stopped)",
		"cancel path must print the close-out marker")
}

// TestAuditTail_FollowExitsOnCancel covers the happy-path shutdown
// even when no new rows arrive — the loop must respond to context
// cancellation, not block forever waiting for traffic.
func TestAuditTail_FollowExitsOnCancel(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()

	ctx, cancel := context.WithCancel(context.Background())
	buf := &safeBuffer{}
	done := make(chan struct{})
	go func() {
		_ = runAuditTailFollow(ctx, buf, st, 50, nil)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("follow loop did not exit within 2s of cancel")
	}
}

// --------------------------------------------------------------------
// Internal helpers.
// --------------------------------------------------------------------

func TestAuditTail_StringFieldValueProjections(t *testing.T) {
	row := fixtureDecisions(time.Now().UTC())[1] // the DELETE row
	ev := decisionRowToEvent(row)

	cases := []struct {
		field string
		want  string
	}{
		{"api.operation", "delete"},
		{"unmapped.iam_jit.verdict", "DENY"},
		{"unmapped.iam_jit.mode", "transparent"},
		{"unmapped.iam_jit.profile", "safe-default"},
		{"unmapped.iam_jit.enforced", "true"},
		{"resource.namespace", "prod"},
		{"resource.name", "prod/db-0"},
		{"unmapped.iam_jit.agent.name", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			assert.Equal(t, c.want, stringFieldValue(ev, c.field))
		})
	}
}

func TestAuditTail_ParseFilterExprUnknownOperatorErrors(t *testing.T) {
	_, err := parseFilterExpr("api.operation")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no operator found")
}

// Compile-time guard: TestMain-like check that the cross-product
// supported-field catalog never regresses below the spec's minimum
// set. Catches the case where someone removes a field without
// auditing whether ibounce / dbounce still ship it.
func TestAuditTail_CrossProductFieldSet(t *testing.T) {
	required := []string{
		"severity_id", "activity_id", "status_id",
		"actor.user.name", "api.operation",
		"unmapped.iam_jit.agent.name",
		"unmapped.iam_jit.agent.session_id",
		"unmapped.iam_jit.event_type",
	}
	have := map[string]bool{}
	for _, f := range supportedFilterFields {
		have[f] = true
	}
	for _, f := range required {
		assert.True(t, have[f], "cross-product field %q must remain supported", f)
	}
}

// Sanity: a single timing-jitter-prone test (rather than scattered
// time.Sleep usage) that confirms followPollInterval matches the
// cross-product spec.
func TestAuditTail_FollowPollIntervalMatchesSpec(t *testing.T) {
	assert.Equal(t, 500*time.Millisecond, followPollInterval,
		"per [[cross-product-agent-parity]] every Bounce ships --follow at 500ms")
}

// noopFmtUsage avoids the unused fmt import if the future test set
// removes the last `fmt.` reference. Kept to make import maintenance
// predictable for the parallel ibounce / dbounce sibling work.
var _ = fmt.Sprint
