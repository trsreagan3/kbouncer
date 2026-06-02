// anomaly_wire.go is the THIN, protocol-specific glue between
// kbouncer's K8s-proxy decision path and the byte-identical
// internal/anomaly core (#718 ADOPT-4 / Phase H).
//
// Per [[config-export-wire-divergence]] the cross-repo core (config /
// baseline / detector / hook) is identical across gbounce / kbouncer /
// dbounce; ONLY this file (signal extraction + audit-emitter
// adaptation + healthz surface) differs per product. For kbouncer the
// protocol signals are:
//
//   - action        = the K8s verb (get / list / create / delete /
//                     exec / ...) — falls back to the HTTP method.
//   - resource      = "<namespace>/<resource>" (or the resource alone
//                     for cluster-scoped) — canonicalised by the core
//                     into a privacy-safe k8s:<env> bucket.
//   - agentIdentity = the resolved agent name (or "anonymous").
//
// DEFAULT = ALERT, NOT BLOCK per [[safety-mode-lean-permissive]].
//
// The detector is held in a package-level slot because the single
// emit call site (emitAuditEvent) is a package function, not a Server
// method. SetAnomalyDetector is called once at startup.
package proxy

import (
	"os"
	"strconv"
	"sync/atomic"

	"github.com/trsreagan3/kbouncer/internal/anomaly"
)

// anomalyDetector is the process-wide Phase H detector. nil disables
// the channel. Set once at startup via SetAnomalyDetector.
var anomalyDetector atomic.Value // *anomaly.Detector

// anomalyRecentMu-guarded ring of recent neutral anomaly events for
// the /healthz + query surface.
var (
	anomalyRecent   []map[string]any
	anomalyRecentMu = make(chan struct{}, 1) // 1-slot mutex
)

const anomalyRecentCap = 50

// SetAnomalyDetector installs the Phase H behavioral-deviation
// detector. nil disables the channel. The CLI calls this at startup
// when anomaly_detection is enabled.
func SetAnomalyDetector(d *anomaly.Detector) {
	if d == nil {
		anomalyDetector.Store((*anomaly.Detector)(nil))
		return
	}
	anomalyDetector.Store(d)
}

func loadAnomalyDetector() *anomaly.Detector {
	v := anomalyDetector.Load()
	if v == nil {
		return nil
	}
	d, _ := v.(*anomaly.Detector)
	return d
}

// observeAnomaly observes one decision into the behavioral baseline +
// scores it. Fail-soft + no-op when the detector is unwired/disabled.
func observeAnomaly(action, resource, agentIdentity, floorVerdict string) {
	d := loadAnomalyDetector()
	if d == nil || !d.Enabled() {
		return
	}
	floor := "allow"
	if floorVerdict == "DENY" || floorVerdict == "deny" {
		floor = "deny"
	}
	d.Run(anomaly.RunInput{
		Action:              action,
		AgentIdentity:       agentIdentity,
		Resource:            resource,
		ObservedHour:        -1,
		ObservedActionCount: -1,
		FloorDecision:       floor,
		RecordObservation:   true,
	})
}

// NewAnomalyDetector constructs a Detector wired to surface neutral
// OCSF anomaly events into the in-memory recent ring (which /healthz
// + the query surface expose). Returns a disabled no-op detector when
// cfg.Enabled is false.
func NewAnomalyDetector(cfg anomaly.Config) *anomaly.Detector {
	anomaly.SetProduct("kbounce")
	if !cfg.Enabled {
		return anomaly.NewDetector(cfg, nil, false)
	}
	return anomaly.NewDetector(cfg, anomalyEventSink, false)
}

// anomalyEventSink lands an emitted neutral OCSF anomaly event into the
// bounded recent ring.
func anomalyEventSink(event map[string]any) {
	anomalyRecentMu <- struct{}{}
	anomalyRecent = append(anomalyRecent, event)
	if len(anomalyRecent) > anomalyRecentCap {
		anomalyRecent = anomalyRecent[len(anomalyRecent)-anomalyRecentCap:]
	}
	<-anomalyRecentMu
}

// anomalyHealthz returns the /healthz + query-surface block. Always
// returns a map (enabled:false when unwired) so the composite monitor
// key set stays stable per [[cross-product-agent-parity]].
func anomalyHealthz() map[string]any {
	d := loadAnomalyDetector()
	if d == nil {
		return map[string]any{"enabled": false}
	}
	st := d.Status()
	anomalyRecentMu <- struct{}{}
	st["recent_count"] = len(anomalyRecent)
	<-anomalyRecentMu
	return st
}

// AnomalyConfigFromEnv builds the Phase H detector config from
// environment variables (frictionless opt-in per
// [[lightweight-frictionless-principle]]). Same env names across the
// suite per [[cross-product-agent-parity]]:
//
//	IAM_JIT_ANOMALY_DETECTION    = "1" / "true" to enable (default off)
//	IAM_JIT_ANOMALY_MODE         = "alert" (default) | "block"
//	IAM_JIT_ANOMALY_SENSITIVITY  = "low" | "medium" (default) | "high"
//	IAM_JIT_ANOMALY_MIN_ACTIONS  = integer baseline floor (default 50)
func AnomalyConfigFromEnv() (anomaly.Config, error) {
	enable := os.Getenv("IAM_JIT_ANOMALY_DETECTION")
	if enable != "1" && enable != "true" && enable != "TRUE" {
		return anomaly.DefaultConfig(), nil
	}
	block := map[string]any{"enabled": true}
	if v := os.Getenv("IAM_JIT_ANOMALY_MODE"); v != "" {
		block["mode"] = v
	}
	if v := os.Getenv("IAM_JIT_ANOMALY_SENSITIVITY"); v != "" {
		block["sensitivity"] = v
	}
	if v := os.Getenv("IAM_JIT_ANOMALY_MIN_ACTIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			block["min_actions_for_baseline"] = n
		}
	}
	return anomaly.LoadConfig(block)
}

// k8sAnomalySignals extracts (action, resource) for the anomaly core
// from the parsed K8s request. action prefers the verb; resource is
// "<namespace>/<resource>" or the bare resource for cluster scope.
func k8sAnomalySignals(verb, namespace, resource, method string) (string, string) {
	action := verb
	if action == "" {
		action = method
	}
	res := resource
	if namespace != "" && resource != "" {
		res = namespace + "/" + resource
	}
	return action, res
}
