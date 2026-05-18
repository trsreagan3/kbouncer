// Proxy-integration tests for pause-aware enforcement (#6a).
//
// Critical safety properties exercised here:
//
//   - test_pause_demotes_transparent_to_cooperative — when a pause is
//     active, the decision verdict text is preserved (audit reviewers
//     still see what WOULD have been denied) but the observation's mode
//     is demoted so the forwarding layer doesn't 403 the client.
//
//   - test_no_pause_preserves_transparent_mode — regression guard:
//     without a pause, transparent mode stays transparent. Otherwise
//     the pause check would silently disable enforcement for everyone.
//
//   - test_pause_does_not_change_cooperative_mode — cooperative is
//     already advisory; a pause is a no-op for enforcement behavior.
//     The audit row still records pause_id so reviewers can see the
//     window, but mode_at_decision shouldn't change.
//
//   - test_expired_pause_no_longer_demotes_mode — after expiry, the
//     next EvaluateRequest hits the lazy-GC path and clears the pause.
//     Subsequent calls enforce normally.
//
//   - test_healthz_surfaces_active_pause — /healthz JSON includes an
//     active pause window so monitors can flag windows left open by
//     mistake (e.g. ops paused at 5pm and went home).
package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/parser"
)

func TestPause_DemotesTransparentToCooperative(t *testing.T) {
	st := freshStore(t)
	pid, err := st.StartPause(600, "test", "me")
	require.NoError(t, err)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyDeny, nil, "", EvalOptions{})

	// Verdict text is preserved (audit captures what WOULD have been denied)
	assert.Equal(t, VerdictDeny, obs.DecisionVerdict)
	// Mode in observation is demoted so the forwarding layer stays open
	assert.Equal(t, string(ModeCooperative), obs.ModeAtDecision)
	assert.False(t, obs.Enforced, "pause must clear Enforced so the proxy doesn't 403 the client")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].PauseID, "decision row must record pause_id linkage")
	assert.Equal(t, pid, *rows[0].PauseID)
}

func TestPause_NoPausePreservesTransparentMode(t *testing.T) {
	// Regression guard: without a pause, transparent enforcement is
	// NOT silently disabled.
	st := freshStore(t)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyDeny, nil, "", EvalOptions{})

	assert.Equal(t, string(ModeTransparent), obs.ModeAtDecision)
	assert.True(t, obs.Enforced, "no pause → transparent + deny stays enforced")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].PauseID, "no pause active → decision row pause_id must be NULL")
}

func TestPause_DoesNotChangeCooperativeMode(t *testing.T) {
	// Cooperative is already advisory; a pause is a no-op for
	// enforcement behavior. mode_at_decision stays cooperative.
	st := freshStore(t)
	_, err := st.StartPause(600, "", "me")
	require.NoError(t, err)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequestFull(req, st, ModeCooperative, DefaultPolicyDeny, nil, "", EvalOptions{})

	assert.Equal(t, string(ModeCooperative), obs.ModeAtDecision)
}

func TestPause_ExpiredNoLongerDemotesMode(t *testing.T) {
	// After expiry, the next EvaluateRequest hits the lazy-GC path
	// and clears the pause. Subsequent calls enforce normally.
	st := freshStore(t)
	_, err := st.StartPause(1, "", "me")
	require.NoError(t, err)

	time.Sleep(1100 * time.Millisecond)

	req := parser.MustParseTestURL(http.MethodGet, "/api/v1/namespaces/default/pods/p")
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyDeny, nil, "", EvalOptions{})

	assert.Equal(t, string(ModeTransparent), obs.ModeAtDecision,
		"expired pause must not demote — enforcement returns once the window passes")
}

func TestHealthz_SurfacesActivePause(t *testing.T) {
	st := freshStore(t)
	pid, err := st.StartPause(600, "incident response", "me")
	require.NoError(t, err)

	srv := NewServer(Config{}, st)
	// Bind to an ephemeral port via httptest so we don't collide with
	// a real kbouncer running on 8766 during developer test runs.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.ServeListener(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	resp, err := http.Get("http://" + l.Addr().String() + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))

	pause, ok := payload["pause"].(map[string]any)
	require.True(t, ok, "/healthz must include a non-nil pause object when one is active; got %v", payload["pause"])
	assert.Equal(t, float64(pid), pause["id"])
	assert.Equal(t, "incident response", pause["reason"])
	assert.NotEmpty(t, pause["started_at"])
	assert.NotEmpty(t, pause["ends_at"])
}

func TestHealthz_NoPauseLeavesFieldNil(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{}, st)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.healthz(rr, req)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &payload))
	assert.Nil(t, payload["pause"], "no pause active → pause field is null")
}

// TestHealthz_AuditUnhealthyReturns503 confirms the heartbeat-gap
// fallback wired via AuditHealthCheck flips /healthz to 503 per
// [[prompt-injection-disable-bouncer-threat]] +
// [[audit-export-failure-visibility]]. The audit-export channel
// itself may be the failure source, so the /healthz HTTP status code
// is one of two independent fallback surfaces (stderr is the other)
// an operator can monitor with shell-grade tooling.
func TestHealthz_AuditUnhealthyReturns503(t *testing.T) {
	st := freshStore(t)
	cfg := Config{
		AuditHealthCheck: func() bool { return false },
	}
	srv := NewServer(cfg, st)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.healthz(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code,
		"unhealthy audit export must flip /healthz to 503")
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &payload))
	assert.Equal(t, "degraded", payload["status"])
	assert.Equal(t, false, payload["audit_export_healthy"])
}

// TestHealthz_AuditHealthyReturns200 confirms the normal-state path
// is unaffected when the audit-export watchdog reports healthy.
func TestHealthz_AuditHealthyReturns200(t *testing.T) {
	st := freshStore(t)
	cfg := Config{
		AuditHealthCheck: func() bool { return true },
	}
	srv := NewServer(cfg, st)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.healthz(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &payload))
	assert.Equal(t, true, payload["audit_export_healthy"])
}
