// Package audit implements kbounce's audit-export transport layer:
// the JSONL log writer + the HTTPS webhook pusher that consume
// decision events emitted from the proxy hot-path.
//
// Shape: every decision in the proxy is funneled through
// FromDecision (the canonical event builder) into the Emitter
// interface, which the audit Manager implements. The Manager fans
// the event out to a JSONL LogWriter + an HTTPS WebhookPusher (each
// optional; an operator picks one or both).
//
// Schema is shared verbatim across the Bounce suite (ibounce,
// kbounce, dbounce) so a security team's downstream pipeline can
// ingest all three without product-specific glue. See the shared
// audit-export spec memo for the field list + tier gating.
//
// Critical invariants enforced here:
//
//   - Webhook token NEVER appears in startup banner, /healthz,
//     audit log file, retry error messages, or any other
//     serialization path. Masked everywhere except the actual
//     outgoing Authorization header. Tests assert this by scanning
//     all captured output for the token.
//
//   - Webhook push is ASYNC + BOUNDED + NEVER blocks the proxy
//     hot-path. Worker goroutine drains a 1000-deep channel;
//     overflow → drop + emit a synthetic AUDIT_DROPPED event so
//     reviewers see the gap rather than getting silently dropped
//     events.
//
//   - SSRF gate mirrors the dbounce MED-D8-06 pattern: net.LookupHost
//     against RFC1918 / loopback / link-local / .internal / .local
//     denylist. Opt-out via --allow-internal-webhook for legitimate
//     intranet collectors.
//
//   - Webhook is an Enterprise-tier feature gated by license-file
//     plumbing per [[security-team-audit-export]]. kbounce lacks
//     license-file plumbing as of #235; the CLI rejects the webhook
//     flags with a placeholder error until that lands.
package audit

import (
	"time"
)

// SchemaVersion is the version string emitted in every event. Bump
// when the schema changes in a way downstream consumers must adapt
// to. Independent of kbounce's binary version — the audit-export
// pipeline is its own compatibility surface.
const SchemaVersion = "1.0.0"

// ProductName identifies kbounce in shared multi-product audit
// streams. Matches the spec memo's product enum.
const ProductName = "kbounce"

// EventType names the kind of event being emitted. DECISION rows
// carry proxy decisions; AUDIT_DROPPED rows are synthetic markers
// the webhook pusher emits when its bounded queue overflows so
// reviewers see the gap rather than getting silently-dropped
// events. SECURITY_ALERT is reserved for Slice 2 (the rule engine).
type EventType string

const (
	// EventTypeDecision is the per-decision event emitted from the
	// proxy hot-path. Carries the full decision shape.
	EventTypeDecision EventType = "DECISION"

	// EventTypeAuditDropped is a synthetic marker the webhook pusher
	// emits when its bounded queue overflows. The Count field names
	// how many events were dropped before this marker fired.
	EventTypeAuditDropped EventType = "AUDIT_DROPPED"
)

// Event is the JSON-serialized shape emitted to both the JSONL log
// file and the HTTPS webhook. Field names match the shared cross-
// product schema in the [[security-team-audit-export]] memo — DO
// NOT rename without coordinating ibounce + dbounce parallel
// implementations.
//
// Optional / product-specific fields land under Ext as a JSON
// object so we can extend without renaming top-level keys (which
// would break downstream consumers).
type Event struct {
	Timestamp  string         `json:"ts"`
	Product    string         `json:"product"`
	Version    string         `json:"version"`
	EventType  EventType      `json:"event_type"`
	DecisionID int64          `json:"decision_id,omitempty"`
	Mode       string         `json:"mode,omitempty"`
	Profile    string         `json:"profile,omitempty"`
	Verdict    string         `json:"verdict,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Principal  string         `json:"principal,omitempty"`
	Action     string         `json:"action,omitempty"`
	Resource   string         `json:"resource,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	Enforced   bool           `json:"enforced,omitempty"`
	Host       string         `json:"host,omitempty"`
	Upstream   string         `json:"upstream,omitempty"`

	// Count is set on AUDIT_DROPPED markers to name the number of
	// dropped events the marker represents. Zero on normal decision
	// events (omitted via omitempty).
	Count int64 `json:"count,omitempty"`

	// Ext carries product-specific extension fields. For kbounce
	// this includes the parsed K8s verb / resource / namespace
	// breakdown + the stream-kind tag so downstream tooling can
	// filter to "show me only exec sessions" without re-parsing
	// the action string.
	Ext map[string]any `json:"ext,omitempty"`
}

// DecisionInput is the minimal struct the proxy passes to
// FromDecision — keeps the audit package free of proxy-package
// dependencies (no import cycles) while still capturing every
// field the shared schema requires.
//
// All fields are optional; missing-field defaults are sensible for
// observation-only test runs that don't go through the full proxy.
type DecisionInput struct {
	At                time.Time
	DecisionID        int64
	Mode              string
	Profile           string
	Verdict           string
	Reason            string
	DecisionSource    string
	Enforced          bool
	Host              string
	Upstream          string
	Method            string
	Path              string
	ParsedVerb        string
	ParsedGroup       string
	ParsedVersion     string
	ParsedResource    string
	ParsedNamespace   string
	ParsedName        string
	ParsedSubresource string
	IsWatch           bool
	IsDryRun          bool
	StreamKind        string
	TaskID            string
}

// FromDecision builds a canonical Event from a DecisionInput. The
// single source of truth for the audit-export schema — both the
// JSONL log writer and the HTTPS webhook pusher call this so the
// two channels emit byte-identical event bodies for the same
// decision (modulo the wrapping HTTP envelope on the webhook).
//
// Schema decisions:
//
//   - action = "METHOD path" (e.g. "GET /api/v1/pods") — mirrors
//     what an operator sees in `kbounce audit tail`; downstream
//     consumers join on this when correlating with kubectl logs.
//   - resource = the parsed K8s resource (e.g. "pods/my-pod" or
//     "namespaces/default/pods") rather than the raw path; raw
//     path is already in action.
//   - principal = "" for kbounce by default (Slice 1 doesn't yet
//     expose the inbound bearer-token subject; that's a separate
//     ask the security-team-audit-export memo lists for Slice 2).
//     The field stays in the schema so ibounce + dbounce populate
//     it identically.
//   - ext.k8s_verb / ext.namespace / ext.task_id surface kbounce-
//     specific detail without renaming top-level schema fields.
func FromDecision(in DecisionInput) Event {
	ts := in.At
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	action := in.Method
	if in.Path != "" {
		if action == "" {
			action = in.Path
		} else {
			action = in.Method + " " + in.Path
		}
	}
	resource := ""
	if in.ParsedResource != "" {
		resource = in.ParsedResource
		if in.ParsedName != "" {
			resource = resource + "/" + in.ParsedName
		}
		if in.ParsedNamespace != "" {
			resource = in.ParsedNamespace + "/" + resource
		}
	}

	ext := map[string]any{}
	if in.ParsedVerb != "" {
		ext["k8s_verb"] = in.ParsedVerb
	}
	if in.ParsedGroup != "" {
		ext["k8s_group"] = in.ParsedGroup
	}
	if in.ParsedVersion != "" {
		ext["k8s_version"] = in.ParsedVersion
	}
	if in.ParsedNamespace != "" {
		ext["namespace"] = in.ParsedNamespace
	}
	if in.ParsedSubresource != "" {
		ext["subresource"] = in.ParsedSubresource
	}
	if in.IsWatch {
		ext["is_watch"] = true
	}
	if in.IsDryRun {
		ext["is_dry_run"] = true
	}
	if in.StreamKind != "" {
		ext["stream_kind"] = in.StreamKind
	}
	if in.TaskID != "" {
		ext["task_id"] = in.TaskID
	}
	if in.DecisionSource != "" {
		ext["decision_source"] = in.DecisionSource
	}
	if len(ext) == 0 {
		ext = nil
	}

	return Event{
		Timestamp:  ts.UTC().Format(time.RFC3339Nano),
		Product:    ProductName,
		Version:    SchemaVersion,
		EventType:  EventTypeDecision,
		DecisionID: in.DecisionID,
		Mode:       in.Mode,
		Profile:    in.Profile,
		Verdict:    in.Verdict,
		Reason:     in.Reason,
		Action:     action,
		Resource:   resource,
		Enforced:   in.Enforced,
		Host:       in.Host,
		Upstream:   in.Upstream,
		Ext:        ext,
	}
}

// NewDroppedMarker builds an AUDIT_DROPPED synthetic event the
// webhook pusher emits when its bounded queue overflows. count
// names the number of events dropped before this marker fired.
func NewDroppedMarker(count int64) Event {
	return Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Product:   ProductName,
		Version:   SchemaVersion,
		EventType: EventTypeAuditDropped,
		Count:     count,
		Reason: "webhook queue overflow; downstream consumer should " +
			"investigate (proxy held + dropped the events to keep " +
			"the hot-path non-blocking)",
	}
}
