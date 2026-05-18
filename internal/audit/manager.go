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
	s := Status{}
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
	return s
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
