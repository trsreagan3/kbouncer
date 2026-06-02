// anomaly_wire_test.go covers the kbouncer-specific Phase H wiring
// (#718 ADOPT-4): env config, K8s signal extraction, the
// observe-and-alert tap, and the /healthz + query status surface.
package proxy

import (
	"testing"

	"github.com/trsreagan3/kbouncer/internal/anomaly"
)

func TestAnomalyConfigFromEnvDisabledByDefault(t *testing.T) {
	t.Setenv("IAM_JIT_ANOMALY_DETECTION", "")
	c, err := AnomalyConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Enabled {
		t.Fatalf("anomaly detection must be DISABLED by default")
	}
}

func TestAnomalyConfigFromEnvEnable(t *testing.T) {
	t.Setenv("IAM_JIT_ANOMALY_DETECTION", "1")
	t.Setenv("IAM_JIT_ANOMALY_MODE", "block")
	t.Setenv("IAM_JIT_ANOMALY_SENSITIVITY", "high")
	t.Setenv("IAM_JIT_ANOMALY_MIN_ACTIONS", "7")
	c, err := AnomalyConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Enabled || c.Mode != "block" || c.Sensitivity != "high" || c.MinActionsForBaseline != 7 {
		t.Fatalf("env not honored: %+v", c)
	}
}

func TestK8sAnomalySignals(t *testing.T) {
	action, res := k8sAnomalySignals("delete", "production", "pods", "DELETE")
	if action != "delete" {
		t.Fatalf("expected verb action, got %q", action)
	}
	if res != "production/pods" {
		t.Fatalf("expected namespaced resource, got %q", res)
	}
	// Cluster-scoped (no namespace) + missing verb falls back to method.
	action, res = k8sAnomalySignals("", "", "clusterroles", "GET")
	if action != "GET" || res != "clusterroles" {
		t.Fatalf("cluster-scoped fallback wrong: %q / %q", action, res)
	}
}

func TestAnomalyHealthzUnwired(t *testing.T) {
	SetAnomalyDetector(nil)
	h := anomalyHealthz()
	if h["enabled"].(bool) != false {
		t.Fatalf("unwired detector must report enabled:false")
	}
}

// TestObserveAnomalyAlertsNotBlocks asserts the tap surfaces a neutral
// event after a baseline-then-deviation sequence but never changes the
// request decision in the default alert mode.
func TestObserveAnomalyEmitsAfterBaseline(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	d := NewAnomalyDetector(cfg)
	SetAnomalyDetector(d)
	t.Cleanup(func() { SetAnomalyDetector(nil) })

	// Establish a baseline of normal traffic via the tap.
	for i := 0; i < 40; i++ {
		observeAnomaly("get", "default/pods", "agent-k", "ALLOW")
	}
	before := d.Status()["alerts_emitted"].(int64)
	// A run with a sharp volume spike should flag — drive through the
	// detector directly with the spike signal (the tap always passes
	// the single-event sentinels, so we exercise the scoring path here).
	out := d.Run(anomaly.RunInput{
		Action:              "get",
		AgentIdentity:       "agent-k",
		Resource:            "default/pods",
		ObservedHour:        -1,
		ObservedActionCount: 100000,
		FloorDecision:       "allow",
		RecordObservation:   true,
	})
	if out.Decision != "allow" {
		t.Fatalf("alert mode must not block; got %q", out.Decision)
	}
	after := d.Status()["alerts_emitted"].(int64)
	if after <= before {
		t.Fatalf("expected an alert to be emitted on the spike (before=%d after=%d)", before, after)
	}
	h := anomalyHealthz()
	if h["enabled"].(bool) != true {
		t.Fatalf("healthz should report enabled detector")
	}
}
