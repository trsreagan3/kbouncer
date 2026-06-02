package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/profile"
)

// healthz_parity_544_test.go — #544 / MRR-5 M2 + M3 cross-bouncer
// parity tests for the kbouncer /healthz endpoint. Asserts the wire-
// shape OBSERVABLE through the HTTP probe (never inspects internal
// struct fields) so the field set stays aligned with ibounce's
// /healthz per [[cross-product-agent-parity]].
//
// The 6-test corpus mirrors the same shape filed against gbounce +
// dbounce; the cross-bouncer composite monitor in MRR-5 §2 relies on
// the key set being identical across all four bouncers.

// nopParityEmitter satisfies audit.Emitter with no behavior — used to
// flip the AuditEmitter-configured branch on for chain_initialized.
type nopParityEmitter struct {
	mu sync.Mutex
}

func (e *nopParityEmitter) Emit(_ context.Context, _ audit.Event) {}
func (e *nopParityEmitter) Status() audit.Status                  { return audit.Status{} }

// startHealthzTestServer is a small wrapper that builds a Server with
// the given Config + optional AuditEmitter, spins up an httptest
// server against the mux, and returns the probe URL. The signature is
// minimal because the parity tests only need to GET /healthz.
func startHealthzTestServer(t *testing.T, withEmitter bool) string {
	t.Helper()
	st := freshStore(t)
	cfg := Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
	}
	if withEmitter {
		cfg.AuditEmitter = &nopParityEmitter{}
	}
	s := NewServer(cfg, st)
	ts := httptest.NewServer(s.http.Handler)
	t.Cleanup(ts.Close)
	return ts.URL + "/healthz"
}

// fetchHealthzBody is the shared GET + JSON-decode + 200-check helper.
func fetchHealthzBody(t *testing.T, healthURL string) map[string]any {
	t.Helper()
	resp, err := http.Get(healthURL)
	require.NoError(t, err, "GET %s", healthURL)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 from /healthz")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))
	return payload
}

// TestHealthz_HasChainInitialized — #544 — bare /healthz must include
// the chain_initialized key per [[cross-product-agent-parity]]. The
// absence of the key would break any composite monitor that asserts a
// uniform key set across all four bouncers.
func TestHealthz_HasChainInitialized(t *testing.T) {
	healthURL := startHealthzTestServer(t, false)
	body := fetchHealthzBody(t, healthURL)
	_, ok := body["chain_initialized"]
	assert.True(t, ok, "/healthz missing chain_initialized field: %#v", body)
}

// TestHealthz_ChainInitializedTrueWhenConfigured — #544 — when the
// audit emitter is wired (AuditEmitter != nil), chain_initialized
// must be true. Verifies the field tracks the underlying emitter
// state rather than being hard-coded.
func TestHealthz_ChainInitializedTrueWhenConfigured(t *testing.T) {
	healthURL := startHealthzTestServer(t, true)
	body := fetchHealthzBody(t, healthURL)
	got, ok := body["chain_initialized"].(bool)
	require.True(t, ok, "chain_initialized not a bool: %#v (type %T)",
		body["chain_initialized"], body["chain_initialized"])
	assert.True(t, got,
		"chain_initialized = false; want true when AuditEmitter is configured")
}

// TestHealthz_ChainInitializedFalseWhenNoChain — #544 — when no audit
// emitter is wired (AuditEmitter == nil), chain_initialized must be
// false. Closes the cold-start gap noted in MRR-5-MONITORING-RUNBOOK
// §6 M2: a non-configured audit chain MUST surface immediately on
// /healthz, not on the first decision attempt.
func TestHealthz_ChainInitializedFalseWhenNoChain(t *testing.T) {
	healthURL := startHealthzTestServer(t, false)
	body := fetchHealthzBody(t, healthURL)
	got, ok := body["chain_initialized"].(bool)
	require.True(t, ok, "chain_initialized not a bool: %#v (type %T)",
		body["chain_initialized"], body["chain_initialized"])
	assert.False(t, got,
		"chain_initialized = true; want false when AuditEmitter is nil")
}

// TestHealthz_HasProfileAllowCounts — MED finding — kbouncer's main
// /healthz must surface a profile allow-rule count + a lifetime
// total-allows counter for parity with gbounce's
// mitm_allow_rules_count + total_mitm_allows. allow_rules_in_active_profile
// must equal len(active profile's AllowRules); total_profile_allows must
// be present (and a number) on the bare probe.
func TestHealthz_HasProfileAllowCounts(t *testing.T) {
	st := freshStore(t)
	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)
	s.SetActiveProfile(&profile.Profile{
		Name: "scoped",
		AllowRules: []profile.ProfileAllowRule{
			{Pattern: "configmaps:get", ArnScope: "namespaces/default"},
			{Pattern: "pods:list"},
		},
	})
	ts := httptest.NewServer(s.http.Handler)
	t.Cleanup(ts.Close)
	body := fetchHealthzBody(t, ts.URL+"/healthz")

	cnt, ok := body["allow_rules_in_active_profile"].(float64)
	require.True(t, ok, "allow_rules_in_active_profile missing/not numeric: %#v", body["allow_rules_in_active_profile"])
	assert.Equal(t, float64(2), cnt,
		"allow_rules_in_active_profile should equal the active profile's allow-rule count")

	_, ok = body["total_profile_allows"].(float64)
	assert.True(t, ok, "/healthz missing total_profile_allows counter: %#v", body["total_profile_allows"])
}

// TestHealthz_HasLlmBudget — #544 — /healthz must include the
// llm_budget key per [[cross-product-agent-parity]]. Symmetric to
// TestHealthz_HasChainInitialized.
func TestHealthz_HasLlmBudget(t *testing.T) {
	healthURL := startHealthzTestServer(t, false)
	body := fetchHealthzBody(t, healthURL)
	_, ok := body["llm_budget"]
	assert.True(t, ok, "/healthz missing llm_budget field: %#v", body)
}

// TestHealthz_LlmBudgetEnabledFalse — #544 — Go bouncers don't run
// LLM per [[bouncer-zero-llm-when-agent-in-loop]] so the llm_budget
// block must report enabled=false unconditionally. This is honest per
// [[ibounce-honest-positioning]] (not a stub) — if kbouncer ever adds
// LLM features, this test should fail loudly so the parity shape gets
// re-evaluated against ibounce's full disabled→enabled shape.
func TestHealthz_LlmBudgetEnabledFalse(t *testing.T) {
	healthURL := startHealthzTestServer(t, false)
	body := fetchHealthzBody(t, healthURL)
	llmBudget, ok := body["llm_budget"].(map[string]any)
	require.True(t, ok, "llm_budget not an object: %#v (type %T)",
		body["llm_budget"], body["llm_budget"])
	enabled, ok := llmBudget["enabled"].(bool)
	require.True(t, ok, "llm_budget.enabled not a bool: %#v (type %T)",
		llmBudget["enabled"], llmBudget["enabled"])
	assert.False(t, enabled,
		"llm_budget.enabled = true; kbouncer doesn't run LLM per [[bouncer-zero-llm-when-agent-in-loop]]")
}

// TestHealthz_LlmBudgetShapeMatchesIbounceWhenDisabled — #544 — when
// the side-LLM is OFF, ibounce reports exactly `{"enabled": false}`
// (single key, no other fields). Go bouncers' disabled-shape MUST
// match byte-for-byte so a cross-bouncer SRE monitor that parses
// llm_budget.enabled doesn't trip on unexpected extra fields. Per
// MRR-5 §2 the composite monitor reads this block uniformly.
func TestHealthz_LlmBudgetShapeMatchesIbounceWhenDisabled(t *testing.T) {
	healthURL := startHealthzTestServer(t, false)
	body := fetchHealthzBody(t, healthURL)
	llmBudget, ok := body["llm_budget"].(map[string]any)
	require.True(t, ok, "llm_budget not an object: %#v", body["llm_budget"])
	assert.Len(t, llmBudget, 1,
		"llm_budget has %d keys; want exactly 1 (enabled) to match ibounce's disabled-shape: %#v",
		len(llmBudget), llmBudget)
	_, ok = llmBudget["enabled"]
	assert.True(t, ok, "llm_budget missing required 'enabled' key: %#v", llmBudget)
}
