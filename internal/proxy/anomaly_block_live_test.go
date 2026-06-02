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
package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/anomaly"
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
