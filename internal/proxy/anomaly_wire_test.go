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

// TestObserveAnomalyEmitsThroughWire is the GENUINE wire test (#718
// finding LOW): it drives a volume-spike burst entirely THROUGH
// observeAnomaly (never d.Run directly) and asserts a neutral event is
// emitted. This FAILS against the old sentinel wire (ObservedHour=-1,
// ObservedActionCount=-1 meant no deviation dimension ever contributed,
// so behavioral detection was dead) and PASSES once observeAnomaly
// feeds the real hour-of-day + recent-window rate.
func TestObserveAnomalyEmitsThroughWire(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	d := NewAnomalyDetector(cfg)
	SetAnomalyDetector(d)
	t.Cleanup(func() { SetAnomalyDetector(nil) })

	// A sharp burst for one (agent, verb, namespace/resource): the
	// recent-window rate climbs far above the learned per-hour baseline
	// mean, so the action_frequency dimension trips — all THROUGH
	// observeAnomaly.
	for i := 0; i < 200; i++ {
		observeAnomaly("get", "default/pods", "agent-k", "ALLOW")
	}
	if got := d.Status()["alerts_emitted"].(int64); got < 1 {
		t.Fatalf("expected the wire to flag the volume spike (alerts_emitted=%d); "+
			"behavioral detection is dead if this is 0", got)
	}
	if scored := d.Status()["events_scored"].(int64); scored < 1 {
		t.Fatalf("expected the wire to score events through observeAnomaly; got %d", scored)
	}
	h := anomalyHealthz()
	if h["enabled"].(bool) != true {
		t.Fatalf("healthz should report enabled detector")
	}
	if h["recent_count"].(int) < 1 {
		t.Fatalf("expected recent ring to hold the emitted event")
	}
}

// TestDecideAnomalyTightenPanicDegradesToFloor verifies the defensive
// recover in decideAnomalyTighten: a panicking emitter in the core Decide
// path must not crash the hot path and must degrade to the FLOOR decision
// (allow stays allow, i.e. returns false/"not tightened").
//
// Mechanism: install a block-mode detector with a panicking emitter, then
// trigger the cold-start adversarial backstop via verb "delete" + resource
// "production/pods". Decide flags it as anomalous, calls the emitter
// (panic), and the defer/recover catches it — returning false (floor=allow).
func TestDecideAnomalyTightenPanicDegradesToFloor(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "block"
	cfg.MinActionsForBaseline = 50 // force cold-start so backstop can fire
	panicEmitter := func(_ map[string]any) {
		panic("simulated scorer panic for recover test")
	}
	anomaly.SetProduct("kbounce")
	d := anomaly.NewDetector(cfg, panicEmitter, false)
	SetAnomalyDetector(d)
	t.Cleanup(func() { SetAnomalyDetector(nil) })

	// "deletecluster" is in the adversarial backstop catalog; verb="delete"
	// + resource with namespace exercises the backstop on cold-start.
	got := decideAnomalyTighten("deletecluster", "production", "pods", "DELETE", "agent-test")
	if got {
		t.Fatalf("decideAnomalyTighten must return false (floor=allow) on a scorer panic, got true")
	}
}

// TestObserveAnomalyNormalTrafficQuietThroughWire asserts the wire does
// NOT cry wolf: a handful of calls below the baseline floor stay normal.
func TestObserveAnomalyNormalTrafficQuietThroughWire(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	d := NewAnomalyDetector(cfg)
	SetAnomalyDetector(d)
	t.Cleanup(func() { SetAnomalyDetector(nil) })

	for i := 0; i < 3; i++ {
		observeAnomaly("get", "default/pods", "agent-quiet", "ALLOW")
	}
	if got := d.Status()["alerts_emitted"].(int64); got != 0 {
		t.Fatalf("steady low-rate traffic must not be flagged; alerts_emitted=%d", got)
	}
}
