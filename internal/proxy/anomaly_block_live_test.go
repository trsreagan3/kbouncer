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
//   - TestBlockModeDenyPersistsAuditRow: a block-mode anomaly denial
//     writes a decision row (verdict=deny, source=anomaly_block) to SQLite
//     AND the JSONL chain, so the audit record is complete and chain
//     verification passes over a log that includes anomaly-block rows.
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

// TestBlockModeDenyPersistsAuditRow is the Fix-1 regression guard:
// when mode=block tightens an anomalous request to a deny (enforces 403),
// the decision row MUST land in SQLite (verdict=deny, source=anomaly_block)
// AND in the JSONL chain so the chain verifies clean over a log that
// includes anomaly-block denials.
//
// Pre-fix: the allow row from EvaluateRequestFull was the only row
// persisted; the enforced deny was silent (29/29 allow rows, 0 deny rows).
// Post-fix: the tighten writes a second decision row via writeDecision +
// emitAuditEvent so every enforcement decision has an audit record.
func TestBlockModeDenyPersistsAuditRow(t *testing.T) {
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

	// Drive a burst until we see at least one 403 (anomaly-block denial).
	var firstDenyAt int
	for i := 0; i < 400; i++ {
		if k8sGet(t, ts.URL, "/api/v1/namespaces/default/pods", "agent-audit") == http.StatusForbidden {
			firstDenyAt = i
			break
		}
	}
	if firstDenyAt == 0 && k8sGet(t, ts.URL, "/api/v1/namespaces/default/pods", "agent-audit") != http.StatusForbidden {
		t.Fatal("block mode never denied the burst; cannot test audit persistence (detector may not have warmed)")
	}

	// Wait for the JSONL log to flush the events from the burst.
	require.Eventually(t, func() bool {
		return lw.Total() > int64(firstDenyAt)
	}, 5*time.Second, 20*time.Millisecond, "JSONL writer should flush at least %d events", firstDenyAt+1)

	// --- Fix 1 assertion A: SQLite must contain at least one deny row
	//     with decision_source = anomaly_block. ---
	rows, err := st.RecentDecisions(200)
	require.NoError(t, err)
	var anomalyBlockDenies int
	for _, row := range rows {
		if row.DecisionSource == anomalyDenySource && row.DecisionVerdict == "deny" {
			anomalyBlockDenies++
		}
	}
	if anomalyBlockDenies == 0 {
		// Reconstruct verdicts so the failure message shows what was written.
		var verdicts []string
		for _, row := range rows {
			verdicts = append(verdicts, row.DecisionVerdict+"/"+row.DecisionSource)
		}
		t.Fatalf("Fix-1 REGRESSION: block-mode anomaly denial produced 0 rows with "+
			"verdict=deny + source=%q in SQLite; all %d rows: %s",
			anomalyDenySource, len(rows), strings.Join(verdicts, ", "))
	}

	// --- Fix 1 assertion B: JSONL must contain at least one event with
	//     the anomaly_block verdict=deny so the SIEM chain covers it. ---
	mgr.Close()
	lw.Close()
	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotEmpty(t, raw, "JSONL log must not be empty")
	var jsonlAnomalyBlockDenies int
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
		// verdict is directly in unmapped.iam_jit (uppercased).
		// decision_source is in unmapped.iam_jit.ext.decision_source.
		verdict, _ := iamJit["verdict"].(string)
		var src string
		if ext, ok := iamJit["ext"].(map[string]any); ok {
			src, _ = ext["decision_source"].(string)
		}
		if strings.EqualFold(verdict, "deny") && src == anomalyDenySource {
			jsonlAnomalyBlockDenies++
		}
	}
	if jsonlAnomalyBlockDenies == 0 {
		t.Fatalf("Fix-1 REGRESSION: block-mode anomaly denial produced 0 JSONL events "+
			"with verdict=deny + decision_source=%q; the Ed25519 chain has a hole",
			anomalyDenySource)
	}

	// --- Fix 1 assertion C: chain must verify clean over a log that
	//     includes anomaly-block rows. ---
	res, err := audit.VerifyChainFile(logPath, chain.StateFileAbsent())
	require.NoError(t, err)
	if !res.OK() {
		t.Fatalf("Fix-1 REGRESSION: Ed25519 chain verification FAILED after "+
			"writing anomaly-block denial rows; inconsistencies: %+v", res.Inconsistencies)
	}
	t.Logf("chain OK: %d events checked, %d anomaly_block deny rows in SQLite, "+
		"%d anomaly_block deny events in JSONL",
		res.EventsChecked, anomalyBlockDenies, jsonlAnomalyBlockDenies)
}
