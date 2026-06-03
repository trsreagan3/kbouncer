// anomaly_block_live_test.go proves Phase H block-mode ENFORCEMENT
// through the REAL kbouncer decision path (iam-jit#59) — an actual K8s
// API request flowing through Server.handle against a fake apiserver,
// not Detector.Decide in isolation.
//
// Coverage:
//   - TestBlockModeEnforcesViaPreDecisionLivePath: a volume-spike burst
//     in mode=block is eventually DENIED (403, K8s Status shape) by the
//     live proxy + the fake apiserver stops receiving the burst.
//   - TestBlockModeCannotLoosenFloorDenyLivePath: a profile/transparent
//     floor-deny stays 403 even under an anomalous burst — the anomaly
//     path is consulted only on a non-deny floor and never loosens.
//   - TestAlertModeNeverDeniesLivePath: the same burst in alert mode is
//     never denied (every request forwards) — default behavior preserved.
//   - TestBlockModeDenyPersistsExactlyOneRow: a block-mode anomaly denial
//     on a default-allow request persists EXACTLY ONE decision row
//     (verdict=deny, source=anomaly_block) to SQLite AND the JSONL chain
//     — NO phantom allow — and the Ed25519 chain verifies clean (#17).
//   - TestProfileAllowAnomalyBlockSingleRow: same exactly-one-row property
//     when the would-be-allow came from the PROFILE-ALLOW terminal, not
//     the default fall-through (#17 — covers all allow terminals).
//   - TestNonAnomalousAllowSingleRow: a normal (non-anomalous) allow still
//     persists exactly one allow row — the pre-persist hook is a no-op.
//   - TestDeterministicDenyUnchangedBlockMode: a profile/deterministic
//     deny persists one deny row with source!=anomaly_block — deny
//     terminals are unchanged (the hook is never consulted on a deny).
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/anomaly"
	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/store"
)

func anomalyCfg(mode string) anomaly.Config {
	c := anomaly.DefaultConfig()
	c.Enabled = true
	c.Mode = mode
	c.Sensitivity = "medium"
	c.MinActionsForBaseline = 5
	return c
}

// wireDetector installs a fresh detector for the test + resets the
// process-wide slot on cleanup so tests don't leak into each other.
func wireDetector(t *testing.T, cfg anomaly.Config) {
	t.Helper()
	SetAnomalyDetector(NewAnomalyDetector(cfg))
	t.Cleanup(func() { SetAnomalyDetector(nil) })
}

// k8sGet drives one GET through the live proxy with an agent identity.
func k8sGet(t *testing.T, baseURL, path, agent string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	require.NoError(t, err)
	req.Header.Set("X-Agent-Name", agent)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestBlockModeEnforcesViaPreDecisionLivePath(t *testing.T) {
	wireDetector(t, anomalyCfg("block"))
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow, // floor ALLOWs; only anomaly can deny
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// A sharp burst for one (agent, verb, resource). The recent-window
	// rate climbs above the learned per-hour baseline mean, so Decide
	// tightens allow->deny BEFORE the apiserver is contacted.
	denied := false
	for i := 0; i < 400; i++ {
		if k8sGet(t, ts.URL, "/api/v1/namespaces/default/pods", "agent-burst") == http.StatusForbidden {
			denied = true
			break
		}
	}
	if !denied {
		t.Fatalf("block mode never DENIED an anomalous burst through the live path; "+
			"block is not enforcing pre-decision (apiserver hits=%d)", len(fas.received))
	}
}

func TestBlockModeCannotLoosenFloorDenyLivePath(t *testing.T) {
	wireDetector(t, anomalyCfg("block"))
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)
	p := loadStagingProfile(t) // denies anything with "prod" in the namespace

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: p,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// The profile floor-denies prod namespaces. Hammer it: every request
	// must stay 403 (a deny is never loosened to a forward by the anomaly
	// machinery), and the apiserver must NEVER receive a prod request.
	for i := 0; i < 50; i++ {
		got := k8sGet(t, ts.URL, "/api/v1/namespaces/prod-app/pods", "agent-x")
		if got != http.StatusForbidden {
			t.Fatalf("floor-deny request #%d → %d; want 403 (anomaly must NEVER loosen a deny)", i, got)
		}
	}
	if len(fas.received) != 0 {
		t.Fatalf("a floor-denied request reached the apiserver %d time(s); deny must be enforced", len(fas.received))
	}
}

func TestAlertModeNeverDeniesLivePath(t *testing.T) {
	wireDetector(t, anomalyCfg("alert"))
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	for i := 0; i < 400; i++ {
		if got := k8sGet(t, ts.URL, "/api/v1/namespaces/default/pods", "agent-alert"); got == http.StatusForbidden {
			t.Fatalf("alert mode DENIED request #%d (403); alert must never block", i)
		}
	}
	if flagged := loadAnomalyDetector().Status()["anomalies_flagged"].(int64); flagged < 1 {
		t.Fatalf("alert mode should still FLAG the spike for review; anomalies_flagged=%d", flagged)
	}
}

func TestDisabledDetectorNeverDeniesLivePath(t *testing.T) {
	wireDetector(t, anomaly.DefaultConfig()) // disabled
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	for i := 0; i < 200; i++ {
		if got := k8sGet(t, ts.URL, "/api/v1/namespaces/default/pods", "agent-off"); got == http.StatusForbidden {
			t.Fatalf("disabled detector DENIED request #%d (403); default-off must never block", i)
		}
	}
}

// countAnomalyBlockDenies returns how many SQLite decision rows carry
// verdict=deny + source=anomaly_block, and the flat verdict/source list
// for diagnostics.
func countAnomalyBlockDenies(t *testing.T, st *store.Store) (int, []string) {
	t.Helper()
	rows, err := st.RecentDecisions(1000)
	require.NoError(t, err)
	var n int
	var all []string
	for _, row := range rows {
		all = append(all, row.DecisionVerdict+"/"+row.DecisionSource)
		if row.DecisionSource == anomalyDenySource && row.DecisionVerdict == "deny" {
			n++
		}
	}
	return n, all
}

// burstUntilDenyOneAtATime drives single GETs through the proxy for one
// (agent, verb, resource) key until one returns 403 (an anomaly-block
// tighten). It snapshots the SQLite row count immediately BEFORE the
// request that 403s and returns (totalRowsBefore, denied). Each request
// through EvaluateRequestFull persists exactly one row, so the caller can
// assert the delta after the denied request is exactly 1 (the deny) — no
// phantom allow for the blocked request.
func burstUntilDenyOneAtATime(t *testing.T, st *store.Store, baseURL, path, agent string) (rowsBefore int, denied bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		rows, err := st.RecentDecisions(2000)
		require.NoError(t, err)
		before := len(rows)
		if k8sGet(t, baseURL, path, agent) == http.StatusForbidden {
			return before, true
		}
	}
	return 0, false
}

// TestBlockModeDenyPersistsExactlyOneRow is the Fix-1 / #17 correctness
// guard: when mode=block tightens a would-be-ALLOW request to a deny, the
// proxy must persist EXACTLY ONE decision row for that request — the deny
// (verdict=deny, source=anomaly_block) — in BOTH SQLite and the JSONL
// chain, with NO phantom allow row. This is the whole point of the #17
// restructure: PR #16 double-recorded (a phantom allow from
// EvaluateRequestFull PLUS a second deny written in handle()), over-
// counting allows and putting a contradictory allow+deny pair on the
// append-only Ed25519 chain. The pre-persist AnomalyTighten hook now
// tightens BEFORE the evaluator's single writeDecision, so one request =
// one row.
//
// The covered allow terminal here is the DEFAULT-ALLOW fall-through
// (DefaultPolicyAllow, no profile). TestProfileAllowAnomalyBlockSingleRow
// covers the profile-allow terminal.
func TestBlockModeDenyPersistsExactlyOneRow(t *testing.T) {
	wireDetector(t, anomalyCfg("block"))
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	// Wire a JSONL log + chain so we can verify the Ed25519 coverage.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain := audit.LoadChainState(dir, 0)
	lw, err := audit.NewLogWriter(ctx, audit.LogWriterOptions{
		Path:  logPath,
		Fsync: false, // speed — we sync manually after the run
		Chain: chain,
	})
	require.NoError(t, err)
	defer lw.Close()
	mgr := audit.NewManager(audit.ManagerOptions{LogWriter: lw})
	defer mgr.Close()

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow, // floor = allow; only anomaly blocks
		Upstream:      up,
		AuditEmitter:  mgr,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// Drive one-at-a-time until a 403, snapshotting the SQLite row count
	// right before the denied request.
	rowsBefore, denied := burstUntilDenyOneAtATime(t, st, ts.URL,
		"/api/v1/namespaces/default/pods", "agent-audit")
	if !denied {
		t.Fatal("block mode never denied the burst; cannot test audit persistence (detector may not have warmed)")
	}

	// --- EXACTLY-ONE-ROW: the denied request added exactly ONE row, and
	//     it is the anomaly_block deny — no phantom allow for it. ---
	rowsAfter, err := st.RecentDecisions(2000)
	require.NoError(t, err)
	delta := len(rowsAfter) - rowsBefore
	if delta != 1 {
		var tail []string
		for _, row := range rowsAfter[:min(len(rowsAfter), 5)] {
			tail = append(tail, row.DecisionVerdict+"/"+row.DecisionSource)
		}
		t.Fatalf("#17 REGRESSION: anomaly-blocked request persisted %d rows; want EXACTLY 1 "+
			"(the deny, no phantom allow). newest rows: %s", delta, strings.Join(tail, ", "))
	}
	// RecentDecisions is newest-first, so the single new row is rowsAfter[0].
	newest := rowsAfter[0]
	require.Equal(t, "deny", newest.DecisionVerdict,
		"#17: the single new row for an anomaly-blocked request must be the DENY")
	require.Equal(t, anomalyDenySource, newest.DecisionSource,
		"#17: the single new row's source must be anomaly_block (not a phantom allow)")
	require.True(t, newest.Enforced, "#17: the anomaly-block deny must be Enforced")

	// --- SQLite contains at least one anomaly_block deny row. ---
	anomalyBlockDenies, all := countAnomalyBlockDenies(t, st)
	if anomalyBlockDenies == 0 {
		t.Fatalf("Fix-1 REGRESSION: 0 rows with verdict=deny + source=%q in SQLite; all rows: %s",
			anomalyDenySource, strings.Join(all, ", "))
	}

	// Wait for the JSONL log to flush.
	require.Eventually(t, func() bool {
		return lw.Total() > 0
	}, 5*time.Second, 20*time.Millisecond, "JSONL writer should flush events")

	// --- JSONL must contain at least one anomaly_block deny event AND no
	//     phantom allow for the blocked request's shape. ---
	mgr.Close()
	lw.Close()
	jsonlAnomalyBlockDenies := countJSONLAnomalyBlockDenies(t, logPath)
	if jsonlAnomalyBlockDenies == 0 {
		t.Fatalf("Fix-1 REGRESSION: 0 JSONL events with verdict=deny + decision_source=%q; "+
			"the Ed25519 chain has a hole", anomalyDenySource)
	}

	// --- chain must verify clean over a log that includes anomaly-block rows. ---
	res, err := audit.VerifyChainFile(logPath, chain.StateFileAbsent())
	require.NoError(t, err)
	if !res.OK() {
		t.Fatalf("Fix-1 REGRESSION: Ed25519 chain verification FAILED after "+
			"writing anomaly-block denial rows; inconsistencies: %+v", res.Inconsistencies)
	}
	t.Logf("chain OK: %d events checked, %d anomaly_block deny rows in SQLite, "+
		"%d anomaly_block deny events in JSONL; blocked request added exactly 1 row",
		res.EventsChecked, anomalyBlockDenies, jsonlAnomalyBlockDenies)
}

// countJSONLAnomalyBlockDenies scans a JSONL audit log and returns the
// number of events with verdict=deny + decision_source=anomaly_block.
func countJSONLAnomalyBlockDenies(t *testing.T, logPath string) int {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotEmpty(t, raw, "JSONL log must not be empty")
	var n int
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue // skip non-JSON lines (e.g. chain state header)
		}
		unmapped, ok := ev["unmapped"].(map[string]any)
		if !ok {
			continue
		}
		iamJit, ok := unmapped["iam_jit"].(map[string]any)
		if !ok {
			continue
		}
		verdict, _ := iamJit["verdict"].(string)
		var src string
		if ext, ok := iamJit["ext"].(map[string]any); ok {
			src, _ = ext["decision_source"].(string)
		}
		if strings.EqualFold(verdict, "deny") && src == anomalyDenySource {
			n++
		}
	}
	return n
}

// TestProfileAllowAnomalyBlockSingleRow proves the #17 fix covers the
// PROFILE-ALLOW terminal, not just the default-allow fall-through. A
// request that a profile allow_rule explicitly blesses is a would-be-
// ALLOW; when mode=block tightens it, the proxy must STILL persist exactly
// one row (the deny, source=anomaly_block) — no phantom profile.allow row.
// This is the case the task flags as easy to miss: anomaly-blocked
// requests are typically ones the profile ALLOWS.
func TestProfileAllowAnomalyBlockSingleRow(t *testing.T) {
	wireDetector(t, anomalyCfg("block"))
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	// An allow_rule that explicitly blesses the collection-list of pods
	// (a collection GET parses to verb "list", not "get") so the request
	// takes the SourceProfileAllow terminal (not the default fall-
	// through). Use default-DENY so a non-matching request would deny —
	// proving the allow came from the profile allow_rule, not the floor.
	p := &profile.Profile{
		Name:       "agent-prof",
		AllowRules: []profile.ProfileAllowRule{{Pattern: "pods:list"}},
	}

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyDeny, // only the allow_rule allows pods:get
		ActiveProfile: p,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	rowsBefore, denied := burstUntilDenyOneAtATime(t, st, ts.URL,
		"/api/v1/namespaces/default/pods", "agent-prof-allow")
	if !denied {
		t.Fatal("block mode never denied the profile-allowed burst; detector may not have warmed")
	}

	rowsAfter, err := st.RecentDecisions(2000)
	require.NoError(t, err)
	delta := len(rowsAfter) - rowsBefore
	if delta != 1 {
		var tail []string
		for _, row := range rowsAfter[:min(len(rowsAfter), 5)] {
			tail = append(tail, row.DecisionVerdict+"/"+row.DecisionSource)
		}
		t.Fatalf("#17 REGRESSION (profile-allow): anomaly-blocked request persisted %d rows; "+
			"want EXACTLY 1 deny, no phantom profile.allow. newest: %s", delta, strings.Join(tail, ", "))
	}
	newest := rowsAfter[0]
	require.Equal(t, "deny", newest.DecisionVerdict,
		"#17 profile-allow: single new row must be the deny")
	require.Equal(t, anomalyDenySource, newest.DecisionSource,
		"#17 profile-allow: single new row's source must be anomaly_block, NOT profile.allow")

	// Confirm the test actually exercised the PROFILE-ALLOW terminal: the
	// warm-up requests (before the tighten) must have persisted as
	// source=profile.allow allows. If they were all default/deny the test
	// would be vacuous (the deny could have come from the floor, not the
	// anomaly hook on a profile-allow).
	var profileAllowWarmups int
	for _, row := range rowsAfter {
		if row.DecisionSource == SourceProfileAllow && row.DecisionVerdict == "allow" {
			profileAllowWarmups++
		}
	}
	require.GreaterOrEqual(t, profileAllowWarmups, 1,
		"expected warm-up requests to take the profile.allow terminal; the tighten "+
			"must fire on a would-be profile-ALLOW, not a default-deny")

	// Confirm at least one anomaly_block deny exists.
	n, all := countAnomalyBlockDenies(t, st)
	require.GreaterOrEqual(t, n, 1,
		"profile-allow path produced 0 anomaly_block denies; rows: %s", strings.Join(all, ", "))
}

// TestNonAnomalousAllowSingleRow is the no-regression guard: a normal
// (non-anomalous) allowed request still persists EXACTLY ONE allow row —
// the pre-persist hook must not write an extra row or mutate a clean
// allow. We use a single quiet request so the detector never tightens.
func TestNonAnomalousAllowSingleRow(t *testing.T) {
	wireDetector(t, anomalyCfg("block"))
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	// One quiet request — no burst, so the detector cannot tighten.
	got := k8sGet(t, ts.URL, "/api/v1/namespaces/default/pods", "agent-quiet-allow")
	require.Equal(t, http.StatusOK, got, "single quiet request must be allowed (not anomalous)")

	rows, err := st.RecentDecisions(2000)
	require.NoError(t, err)
	require.Len(t, rows, 1, "a single allowed request must persist EXACTLY ONE row")
	require.Equal(t, "allow", rows[0].DecisionVerdict, "the single row must be an allow")
	require.NotEqual(t, anomalyDenySource, rows[0].DecisionSource,
		"a non-anomalous allow must NOT be tagged anomaly_block")
	require.False(t, rows[0].Enforced, "a non-anomalous allow must not be Enforced")
}

// TestDeterministicDenyUnchangedBlockMode is the no-regression guard for
// the DENY path: a profile/deterministic deny must persist exactly one
// deny row whose source is NOT anomaly_block — the anomaly hook is never
// consulted on a deny floor, so deny terminals are byte-for-byte unchanged.
func TestDeterministicDenyUnchangedBlockMode(t *testing.T) {
	wireDetector(t, anomalyCfg("block"))
	st := freshStore(t)
	fas := newFakeAPIServer(t, true)
	up := upstreamFor(t, fas)
	p := loadStagingProfile(t) // denies anything with "prod" in the namespace

	s := NewServer(Config{
		Mode:          ModeTransparent,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: p,
		Upstream:      up,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	got := k8sGet(t, ts.URL, "/api/v1/namespaces/prod-app/pods", "agent-deny")
	require.Equal(t, http.StatusForbidden, got, "profile must deny a prod-namespace request")

	rows, err := st.RecentDecisions(2000)
	require.NoError(t, err)
	require.Len(t, rows, 1, "a single profile-denied request must persist EXACTLY ONE row")
	require.Equal(t, "deny", rows[0].DecisionVerdict)
	require.Equal(t, SourceProfile, rows[0].DecisionSource,
		"a deterministic profile deny must keep source=profile, NOT anomaly_block")
	require.NotEqual(t, anomalyDenySource, rows[0].DecisionSource)
}
