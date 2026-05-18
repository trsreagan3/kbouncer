package audit

import (
	"context"
	"errors"
	"sync/atomic"
)

// Emitter is the interface the proxy hot-path uses to publish a
// decision event. Decoupled from Manager so tests + alternative
// future transports can plug in without touching the proxy code.
//
// Implementations MUST be non-blocking — the proxy decision path
// runs on a request goroutine, and a slow Emit would directly
// translate to extra request latency for kubectl / agent clients.
type Emitter interface {
	Emit(ctx context.Context, ev Event)
	// Status snapshots the emitter's runtime counters for the MCP
	// audit-export status tool + /healthz. Read-only.
	Status() Status
}

// Status is the runtime counter snapshot surfaced via MCP +
// /healthz. All fields are atomic-loaded reads of cumulative
// counters — no derived state, no expensive aggregations.
type Status struct {
	LogConfigured     bool   `json:"log_configured"`
	LogPath           string `json:"log_path,omitempty"`
	LogTotal          int64  `json:"log_total"`
	LogDropped        int64  `json:"log_dropped"`
	LogLastError      string `json:"log_last_error,omitempty"`
	WebhookConfigured bool   `json:"webhook_configured"`
	WebhookMaskedURL  string `json:"webhook_url,omitempty"`
	WebhookTotal      int64  `json:"webhook_total"`
	WebhookDropped    int64  `json:"webhook_dropped"`
	WebhookInFlight   int64  `json:"webhook_in_flight"`
	WebhookLastError  string `json:"webhook_last_error,omitempty"`
	TotalEvents       int64  `json:"total_events"`

	// Slice 2 alert-rule engine state. AlertsEnabled is true when a
	// RuleEngine is wrapping this status's source emitter (the
	// non-engine *Manager always reports false). AlertsFiredCount is
	// the cumulative number of alert events the engine has emitted;
	// LastAlertPattern is the name of the most-recently-fired rule
	// (empty until any rule fires).
	AlertsEnabled    bool   `json:"alerts_enabled"`
	AlertsFiredCount int64  `json:"alerts_fired_count"`
	LastAlertPattern string `json:"last_alert_pattern,omitempty"`

	// Heartbeat watchdog state (per [[prompt-injection-disable-bouncer
	// -threat]] + [[audit-export-failure-visibility]]). HeartbeatEnabled
	// reports whether a Heartbeater is wired with a non-zero interval
	// (operator passed --heartbeat-interval). HeartbeatIntervalSeconds
	// is the configured cadence; HeartbeatTotalEmitted is the
	// cumulative number of heartbeat events emitted (lets the SIEM
	// confirm the channel is alive end-to-end);
	// HeartbeatLastEmitUnixMilli is the wall-clock of the most-recent
	// emit (zero before the first tick); HeartbeatHealthy reports the
	// local watchdog's current state (mirrors what /healthz returns).
	HeartbeatEnabled           bool  `json:"heartbeat_enabled"`
	HeartbeatIntervalSeconds   int   `json:"heartbeat_interval_seconds,omitempty"`
	HeartbeatTotalEmitted      int64 `json:"heartbeat_total_emitted,omitempty"`
	HeartbeatLastEmitUnixMilli int64 `json:"heartbeat_last_emit_unix_milli,omitempty"`
	HeartbeatHealthy           bool  `json:"heartbeat_healthy"`
}

// Manager fans events out to the JSONL log writer + the HTTPS
// webhook pusher (each optional; either or both may be nil).
//
// Per the security-team-audit-export spec, both channels are
// independent: a webhook outage doesn't stop the log file from
// catching up via shipper, and a disk-full audit log doesn't stop
// the webhook from continuing to deliver. The Manager doesn't try
// to maintain ordering between the two channels — each consumer
// uses the monotonic DecisionID for ordering.
type Manager struct {
	log     *LogWriter
	webhook *WebhookPusher
	total   atomic.Int64
	// heartbeater is the optional liveness Heartbeater bound via
	// BindHeartbeater so Manager.Status() surfaces the watchdog
	// fields when the rule engine isn't wrapping this Manager. When
	// the engine IS wrapping, RuleEngine.Status() reads its own
	// e.heartbeater (set via RuleEngine.BindHeartbeater) so both
	// wiring shapes report the same snapshot.
	heartbeater *Heartbeater
}

// ManagerOptions configures a Manager. Pass a nil LogWriter or
// nil WebhookPusher to disable that channel.
type ManagerOptions struct {
	LogWriter     *LogWriter
	WebhookPusher *WebhookPusher
}

// NewManager constructs a Manager with the given (possibly nil)
// channels. A Manager with both channels nil is a no-op — Emit
// still increments the total counter so the MCP status tool can
// confirm the proxy was actually called.
func NewManager(opts ManagerOptions) *Manager {
	return &Manager{
		log:     opts.LogWriter,
		webhook: opts.WebhookPusher,
	}
}

// Emit fans the event out to both channels. Both writes are non-
// blocking — a full queue on either side drops the event for that
// channel + increments the channel-local dropped counter; the
// other channel is unaffected.
func (m *Manager) Emit(ctx context.Context, ev Event) {
	if m == nil {
		return
	}
	m.total.Add(1)
	if m.log != nil {
		_ = m.log.Write(ctx, ev)
	}
	if m.webhook != nil {
		_ = m.webhook.Push(ctx, ev)
	}
}

// Status snapshots the runtime counters.
func (m *Manager) Status() Status {
	s := Status{HeartbeatHealthy: true}
	if m == nil {
		return s
	}
	s.TotalEvents = m.total.Load()
	if m.log != nil {
		s.LogConfigured = true
		s.LogPath = m.log.Path()
		s.LogTotal = m.log.Total()
		s.LogDropped = m.log.Dropped()
		s.LogLastError = m.log.LastError()
	}
	if m.webhook != nil {
		s.WebhookConfigured = true
		s.WebhookMaskedURL = m.webhook.MaskedURL()
		s.WebhookTotal = m.webhook.Total()
		s.WebhookDropped = m.webhook.Dropped()
		s.WebhookInFlight = m.webhook.InFlight()
		s.WebhookLastError = m.webhook.LastError()
	}
	if m.heartbeater != nil && m.heartbeater.interval > 0 {
		s.HeartbeatEnabled = true
		s.HeartbeatIntervalSeconds = int(m.heartbeater.interval.Seconds())
		s.HeartbeatTotalEmitted = m.heartbeater.Seq()
		if last := m.heartbeater.LastEmit(); !last.IsZero() {
			s.HeartbeatLastEmitUnixMilli = last.UnixMilli()
		}
		s.HeartbeatHealthy = m.heartbeater.Healthy()
	}
	return s
}

// BindHeartbeater wires the given Heartbeater into the Manager so
// Status() surfaces the watchdog fields. Symmetric with
// RuleEngine.BindHeartbeater — when the operator hasn't enabled the
// rule engine, the bare Manager still reports heartbeat state for
// the MCP audit-export status tool.
func (m *Manager) BindHeartbeater(hb *Heartbeater) {
	if m == nil || hb == nil {
		return
	}
	m.heartbeater = hb
}

// Close stops both worker goroutines. Idempotent.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	if m.log != nil {
		m.log.Close()
	}
	if m.webhook != nil {
		m.webhook.Close()
	}
}

// ErrLicenseRequired is the error the CLI returns when an operator
// passes the webhook flags without an Enterprise license.
//
// kbounce does not yet have license-file plumbing (the Ed25519
// signature scheme + verifier is tracked in #235). Until that
// lands, the webhook flags are a placeholder: the CLI rejects them
// with this error directing the operator to the issue rather than
// silently constructing a webhook + bypassing the license check.
//
// When #235 lands, the CLI swaps this for the real license-file
// check; the audit package itself doesn't need to change.
var ErrLicenseRequired = errors.New(
	"audit webhook requires Enterprise license (placeholder — " +
		"license-file plumbing not yet implemented for kbounce; see #235)")
