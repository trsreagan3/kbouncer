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
// Wire schema: OCSF v1.1.0 class 6003 (API Activity). Every event
// emitted by every product in the Bounce suite (ibounce / kbounce /
// dbounce) conforms to the same OCSF base shape so a customer's
// SIEM ingest (AWS Security Lake, Splunk, Cloudflare, IBM, ...)
// auto-categorizes the events without product-specific glue. See the
// [[ocsf-audit-schema]] memo for the per-product activity_id
// mappings + the unmapped.iam_jit extension catalog.
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
	"fmt"
	"strconv"
	"strings"
	"time"
)

// OCSFSchemaVersion is the OCSF schema version every event declares.
// Pinned to 1.1.0 per the [[ocsf-audit-schema]] decision (2026-05-18).
// Bumping requires a coordinated change across all 3 Bounce products
// + a schema-validation test refresh.
const OCSFSchemaVersion = "1.1.0"

// ProductName identifies kbounce in shared multi-product audit
// streams. Matches the OCSF metadata.product.name enum (and the
// older spec memo's product field).
const ProductName = "kbounce"

// VendorName is the OCSF metadata.product.vendor_name field. Same
// across the Bounce suite so a SIEM pivot on vendor groups our
// events.
const VendorName = "iam-jit"

// buildVersion is the kbounce binary's build version. Stamped at
// build time via the cli package's -ldflags variable; the audit
// package reads it via SetBuildVersion at startup so the import
// graph stays acyclic (cli imports audit, never the reverse).
//
// Unset → "dev" (matches cli.version's default).
var buildVersion = "dev"

// SetBuildVersion is called from cli.Main at startup to thread the
// linker-stamped binary version into the OCSF metadata.product.version
// field. Idempotent + safe to call before/after a NewManager.
func SetBuildVersion(v string) {
	if v == "" {
		return
	}
	buildVersion = v
}

// EventType names the kind of event being emitted. DECISION rows
// carry proxy decisions; AUDIT_DROPPED rows are synthetic markers
// the webhook pusher emits when its bounded queue overflows so
// reviewers see the gap rather than getting silently-dropped
// events. SECURITY_ALERT is reserved for Slice 2 (the rule engine).
//
// Retained from the legacy schema for backward-compat in callers
// that switch on EventType internally; the OCSF wire-shape does not
// surface this enum directly (use activity_id / activity_name).
type EventType string

const (
	// EventTypeDecision is the per-decision event emitted from the
	// proxy hot-path. Carries the full OCSF API Activity shape.
	EventTypeDecision EventType = "DECISION"

	// EventTypeAuditDropped is a synthetic marker the webhook pusher
	// emits when its bounded queue overflows. Surfaces as OCSF
	// activity_id=99 with unmapped.iam_jit.event_type=AUDIT_DROPPED.
	EventTypeAuditDropped EventType = "AUDIT_DROPPED"

	// EventTypeSecurityAlert is the synthetic marker the Slice 2 rule
	// engine emits when a sliding-window pattern fires. Surfaces as
	// OCSF activity_id=99 / activity_name="anomaly_detected" with
	// unmapped.iam_jit.event_type=ANOMALY_DETECTED. Per
	// [[security-team-positioning-safety-not-surveillance]] the wire
	// shape uses NEUTRAL language — "anomaly_detected" rather than
	// "violation" / "infraction" / "unauthorized" — so a security-team
	// reader sees an observation, not an accusation.
	EventTypeSecurityAlert EventType = "ANOMALY_DETECTED"

	// EventTypeSessionEnded is the synthetic marker emitted when an MCP
	// agent session closes (Feature 2 of [[agent-identity-in-audit]]).
	// Surfaces as OCSF activity_id=99 / activity_name="session_ended"
	// with unmapped.iam_jit.event_type=SESSION_ENDED + the bound
	// session's agent block. Lets analysts close their "all events
	// from session X" queries with both bookends.
	EventTypeSessionEnded EventType = "SESSION_ENDED"

	// EventTypeHeartbeat is the synthetic liveness marker emitted at a
	// fixed cadence by the Heartbeater goroutine when
	// --heartbeat-interval is non-zero. Surfaces as OCSF
	// activity_id=99 / activity_name="heartbeat" with
	// unmapped.iam_jit.event_type=HEARTBEAT.
	//
	// Per [[prompt-injection-disable-bouncer-threat]] +
	// [[audit-export-failure-visibility]]: heartbeats give downstream
	// SIEMs a positive liveness signal so an attacker who silenced the
	// audit-export channel (kill -9, disabled flag, broken webhook)
	// fails OPEN to a noisy "heartbeat_gap" alert on the SIEM side
	// rather than silently disappearing from the operator's view.
	//
	// Cross-product invariant per [[cross-product-agent-parity]]:
	// ibounce / kbounce / dbounce emit the SAME shape (different
	// product names in metadata.product) so a single SIEM dashboard
	// rule catches gaps across the suite.
	EventTypeHeartbeat EventType = "HEARTBEAT"

	// EventTypeAdminFallbackGrant is the synthetic marker emitted ONCE
	// when an operator opens a pause window — the explicit "the escape
	// hatch was opened" bookend. The per-decision DECISION events emitted
	// while the window is active still carry ext.admin_fallback=true
	// (the Slice 2 admin_fallback_burst rule counts those); this synthetic
	// event gives a SIEM a single high-signal row pinned to the window's
	// open edge so an analyst can answer "when did the pause start, who
	// opened it, why?" without scanning the per-decision stream. Surfaces
	// as OCSF activity_id=99 / activity_name="admin_fallback_grant" with
	// unmapped.iam_jit.event_type=ADMIN_FALLBACK_GRANT.
	//
	// Per [[security-team-audit-export]] + [[safety-mode-lean-permissive]]:
	// the audit trail does the work; the synthetic open-edge event is the
	// load-bearing piece that lets a SIEM rule fire INSTANTLY on pause-
	// open rather than after the per-decision burst threshold trips. Also
	// carries ext.admin_fallback=true so the existing admin_fallback_burst
	// rule observes it as its FIRST in-window event without the rule code
	// needing a synthetic-event-aware branch.
	EventTypeAdminFallbackGrant EventType = "ADMIN_FALLBACK_GRANT"

	// EventTypePauseEnd is the synthetic marker emitted ONCE when a
	// pause window closes — the explicit "the escape hatch was closed"
	// bookend that pairs with EventTypeAdminFallbackGrant. Carries
	// ext.pause_end_kind = "resumed_early" | "expired" so a SIEM rule
	// can distinguish operator-initiated closure from auto-revert.
	// Surfaces as OCSF activity_id=99 / activity_name="pause_end" with
	// unmapped.iam_jit.event_type=PAUSE_END.
	//
	// Per [[security-team-audit-export]]: paired bookends let a SIEM
	// computation "duration = pause_end.time - admin_fallback_grant.time
	// where pause_id matches" run as a single join across two events
	// rather than scanning the per-decision stream for first/last bypass
	// timestamps. Closes the window for the pause_long rule's analyst
	// pivot.
	EventTypePauseEnd EventType = "PAUSE_END"

	// EventTypeProfileInstall is the synthetic marker emitted ONCE per
	// successful `kbounce profile install --from URL` invocation. Carries
	// the source URL, computed sha256, and the names of the installed
	// profiles under unmapped.iam_jit.ext so the Slice 2
	// non_org_profile_install rule fires AT INSTALL TIME (rather than
	// only when the first decision under the installed profile lands).
	// Surfaces as OCSF activity_id=99 / activity_name="profile_install"
	// with unmapped.iam_jit.event_type=PROFILE_INSTALL.
	//
	// Per [[security-team-audit-export]]: install-time alerting is the
	// difference between catching a rogue URL within seconds of the
	// command running vs catching it only after the first proxied call
	// (which may be hours later for a profile installed during off-hours
	// onboarding). The synthetic event also populates the same Profile +
	// profile_source ext fields the decision-event path uses so the
	// existing non_org_profile_install rule predicate fires without
	// branch-on-event-type logic.
	EventTypeProfileInstall EventType = "PROFILE_INSTALL"
)

// OCSF activity_id enum (class 6003 / API Activity).
const (
	ActivityUnknown = 0
	ActivityCreate  = 1
	ActivityRead    = 2
	ActivityUpdate  = 3
	ActivityDelete  = 4
	ActivityOther   = 99
)

// OCSF status_id enum.
const (
	StatusUnknown = 0
	StatusSuccess = 1
	StatusFailure = 2
	StatusOther   = 99
)

// OCSF severity_id enum (only the values kbounce actually emits).
const (
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
)

// OCSF class / category constants for API Activity events.
const (
	ClassUID    = 6003
	ClassName   = "API Activity"
	CategoryUID = 6
	CategoryName = "Application Activity"
)

// OCSFProduct is the metadata.product object. Constant for kbounce
// except for the version field which the binary stamps at build time.
type OCSFProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

// OCSFMetadata is the metadata top-level object every OCSF event
// carries.
type OCSFMetadata struct {
	Version string      `json:"version"`
	Product OCSFProduct `json:"product"`
}

// OCSFUser is the user sub-object of OCSFActor.
type OCSFUser struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// OCSFSession is the session sub-object of OCSFActor.
type OCSFSession struct {
	UID string `json:"uid,omitempty"`
}

// OCSFActor is the actor (who initiated the API call) object.
type OCSFActor struct {
	User    *OCSFUser    `json:"user,omitempty"`
	Session *OCSFSession `json:"session,omitempty"`
}

// OCSFAPIService is the api.service sub-object.
type OCSFAPIService struct {
	Name string `json:"name,omitempty"`
}

// OCSFAPIRequest is the api.request sub-object.
type OCSFAPIRequest struct {
	UID string `json:"uid,omitempty"`
}

// OCSFAPI is the api object — operation, service, request.
type OCSFAPI struct {
	Operation string         `json:"operation,omitempty"`
	Service   OCSFAPIService `json:"service"`
	Request   OCSFAPIRequest `json:"request"`
}

// OCSFResource is one entry in the resources[] array.
type OCSFResource struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
}

// OCSFEndpoint is the src_endpoint / dst_endpoint object.
type OCSFEndpoint struct {
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// OCSFUnmapped is the unmapped top-level object — OCSF's
// vendor-extension hook. iam-jit-specific fields land under
// `unmapped.iam_jit`.
type OCSFUnmapped struct {
	IAMJIT IAMJITExt `json:"iam_jit"`
}

// OCSFAgent is the iam-jit-native agent-identity block under
// unmapped.iam_jit.agent (per [[agent-identity-in-audit]]). All
// fields except Name + DetectedFrom are optional; the wire shape
// guarantees Name (defaults to "unknown") + DetectedFrom (defaults
// to "unknown") are always present so an analyst can filter on
// "show me events where the agent block fell back to unknown" as a
// first-class signal.
//
// Cross-product invariant: ibounce / kbounce / dbounce all populate
// the same struct shape (different products may detect different
// agents, but the SIEM-side query is identical).
//
// Process-tree fields (ProcessExe / ParentExe) are SENSITIVE per
// [[security-team-positioning-safety-not-surveillance]] — stripped
// from the HTTPS webhook body by default (operator opts in). The
// local JSONL log + SQLite still carry them so the operator owns
// the full trail on their own machine.
type OCSFAgent struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	DetectedFrom string `json:"detected_from"`
	ProcessExe   string `json:"process_exe,omitempty"`
	ParentExe    string `json:"parent_exe,omitempty"`
	RawUserAgent string `json:"user_agent_raw,omitempty"`
}

// IAMJITExt is the iam-jit vendor extension under unmapped.iam_jit.
// Common fields (mode/profile/verdict/decision_id/enforced) match
// across the Bounce suite; product-specific fields live under Ext.
//
// For AUDIT_DROPPED events, EventType+DroppedCount+QueueSize are
// populated and decision-shape fields are omitted.
type IAMJITExt struct {
	Mode         string         `json:"mode,omitempty"`
	Profile      string         `json:"profile,omitempty"`
	Verdict      string         `json:"verdict,omitempty"`
	DecisionID   int64          `json:"decision_id,omitempty"`
	Enforced     bool           `json:"enforced,omitempty"`
	Ext          map[string]any `json:"ext,omitempty"`
	EventType    string         `json:"event_type,omitempty"`
	DroppedCount int64          `json:"dropped_count,omitempty"`
	QueueSize    int64          `json:"queue_size,omitempty"`

	// Slice 2 alert-rule fields (set on EventTypeSecurityAlert events;
	// omitted otherwise). Pattern names the rule that fired;
	// WindowSeconds + MatchedEventCount give the analyst the window
	// the rule evaluated over and how many decisions matched; Suggestion
	// is a NEUTRAL-language operator hint (e.g. "consider distributing
	// a profile with broader scope") — never accusatory.
	Pattern           string `json:"pattern,omitempty"`
	WindowSeconds     int    `json:"window_seconds,omitempty"`
	MatchedEventCount int    `json:"matched_event_count,omitempty"`
	Suggestion        string `json:"suggestion,omitempty"`

	// Agent is the iam-jit-native agent-identity block populated per
	// [[agent-identity-in-audit]]. Always non-nil for events emitted
	// by FromDecision (defaults to {name:"unknown", detected_from:
	// "unknown"} when no detection source fired) so a SIEM query on
	// unmapped.iam_jit.agent.name = "unknown" surfaces the unattributed
	// traffic as a first-class signal. Synthetic events (AUDIT_DROPPED,
	// security alerts) leave it nil — those aren't bound to any agent.
	Agent *OCSFAgent `json:"agent,omitempty"`

	// Heartbeat fields (populated on EventTypeHeartbeat events; omitted
	// otherwise). HeartbeatSeq is the monotonically-increasing tick id
	// (1-based) so a SIEM-side `heartbeat_gap` rule can detect missing
	// sequence numbers without timestamp arithmetic. HeartbeatInterval
	// Seconds is the configured cadence in seconds — lets the SIEM
	// rule auto-scale its tolerance window to whatever the operator
	// picked. HeartbeatGapMissed is set on `heartbeat_gap` alert events
	// to report how many ticks were missed before the gap was observed.
	HeartbeatSeq             int64 `json:"heartbeat_seq,omitempty"`
	HeartbeatIntervalSeconds int   `json:"heartbeat_interval_seconds,omitempty"`
	HeartbeatGapMissed       int   `json:"heartbeat_gap_missed,omitempty"`
}

// Event is the OCSF v1.1.0 class 6003 (API Activity) wire shape.
// Every field name + nested object matches the OCSF spec verbatim —
// downstream SIEMs (AWS Security Lake, Splunk, ...) ingest this
// directly without product-specific mapping.
//
// DecisionID is retained as a non-serialized field for internal log
// + webhook lookups (the canonical OCSF home for it is
// unmapped.iam_jit.decision_id + api.request.uid). EventType is
// retained for callers that switch on the kind of event without
// re-parsing OCSF activity_id.
type Event struct {
	Metadata     OCSFMetadata   `json:"metadata"`
	Time         int64          `json:"time"`
	ClassUID     int            `json:"class_uid"`
	ClassName    string         `json:"class_name"`
	CategoryUID  int            `json:"category_uid"`
	CategoryName string         `json:"category_name"`
	ActivityID   int            `json:"activity_id"`
	ActivityName string         `json:"activity_name"`
	TypeUID      int            `json:"type_uid"`
	TypeName     string         `json:"type_name"`
	SeverityID   int            `json:"severity_id"`
	Severity     string         `json:"severity"`
	StatusID     int            `json:"status_id"`
	Status       string         `json:"status"`
	StatusDetail string         `json:"status_detail,omitempty"`
	Actor        *OCSFActor     `json:"actor,omitempty"`
	API          OCSFAPI        `json:"api"`
	Resources    []OCSFResource `json:"resources"`
	SrcEndpoint  *OCSFEndpoint  `json:"src_endpoint,omitempty"`
	DstEndpoint  *OCSFEndpoint  `json:"dst_endpoint,omitempty"`
	Unmapped     OCSFUnmapped   `json:"unmapped"`

	// DecisionID is the SQLite decision-row id for this event. Used
	// internally by log.go + webhook.go for error-message correlation;
	// not serialized into the wire shape (the OCSF home is
	// unmapped.iam_jit.decision_id + api.request.uid). The "-" json
	// tag enforces that.
	DecisionID int64 `json:"-"`

	// EventType retains the legacy decision/dropped marker enum for
	// internal callers; not serialized (OCSF surfaces this via
	// activity_id + unmapped.iam_jit.event_type).
	EventType EventType `json:"-"`
}

// DecisionInput is the minimal struct the proxy passes to
// FromDecision — keeps the audit package free of proxy-package
// dependencies (no import cycles) while still capturing every
// field the OCSF wire-shape requires.
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
	// PrincipalName / PrincipalUID are best-effort fills for OCSF
	// actor.user. Slice 1 doesn't yet extract the inbound bearer-token
	// subject — these stay "" and the actor.user object is omitted.
	// Slice 2 (per the security-team-audit-export memo) wires SPIFFE /
	// JWT subject extraction.
	PrincipalName string
	PrincipalUID  string

	// ProfileSource records the provenance URL of the active profile
	// (empty / "local" when user-edited; an https URL when installed
	// via `kbounce profile install --from URL`). Threaded through so
	// the Slice 2 rule engine's non_org_profile_install rule can flag
	// decision events backed by a profile NOT in the org-approved
	// allowlist. Mirrors the profile.Profile.Source field 1:1.
	ProfileSource string

	// AdminFallback marks the decision as an operator-initiated
	// admin-fallback / pause-bypass — the proxy was running with a
	// pause window active, so transparent-mode enforcement was demoted
	// to cooperative. Used by the Slice 2 admin_fallback_burst +
	// pause_long rules to surface bursts of pause-bypass grants
	// without conflating them with vanilla cooperative-mode traffic.
	// The corresponding pause_id lives on the SQLite decisions row
	// (single source of truth); this is the in-event signal so the
	// rule engine can stay decoupled from store reads.
	AdminFallback bool

	// Agent carries the per-call agent-identity record per
	// [[agent-identity-in-audit]]. Populated by the proxy hot-path
	// from the inbound User-Agent + (when available) the registered
	// MCP session via audit.Registry. Empty AgentInfo → FromDecision
	// emits the default {name:"unknown", detected_from:"unknown"}
	// block so the wire shape always carries a queryable agent
	// object.
	Agent AgentInfo
}

// FromDecision builds an OCSF class 6003 (API Activity) Event from a
// DecisionInput. Single source of truth for the audit-export wire
// shape — both the JSONL log writer and the HTTPS webhook pusher
// call this so the two channels emit byte-identical event bodies for
// the same decision.
//
// Mappings (per [[ocsf-audit-schema]] memo):
//
//   - activity_id: K8s verb → Create / Read / Update / Delete / Other
//   - status_id: ALLOW → Success; DENY (enforced) → Failure;
//     DENY (advisory, cooperative) → Success with status_detail
//     recording the advisory deny reason
//   - severity_id: always Informational (Slice 1); higher severities
//     reserved for Slice 2's rule engine
//   - api.operation: K8s verb (e.g. "get", "list", "delete")
//   - api.service.name: "kubernetes"
//   - api.request.uid: decision_id stringified
//   - resources: one entry derived from the parsed K8s resource
//     (namespace + resource + name); empty array when no resource
//     can be derived (e.g. /api root)
//   - src_endpoint: the kbounce proxy bind (Host)
//   - dst_endpoint: the upstream kube-apiserver (Upstream)
//   - unmapped.iam_jit: kbounce-specific fields (mode/profile/verdict/
//     decision_id/enforced + ext for K8s verb / subresource / group /
//     version + decision_source + stream_kind / task_id when present)
func FromDecision(in DecisionInput) Event {
	ts := in.At
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	activityID := k8sVerbToActivityID(in.ParsedVerb)
	activityName := buildActivityName(in.ParsedVerb, in.ParsedResource)

	statusID, status, statusDetail := mapVerdictToStatus(in.Verdict, in.Enforced, in.Reason)

	api := OCSFAPI{
		Operation: in.ParsedVerb,
		Service:   OCSFAPIService{Name: "kubernetes"},
		Request:   OCSFAPIRequest{UID: strconv.FormatInt(in.DecisionID, 10)},
	}

	resources := buildResources(in)

	srcEndpoint := parseEndpoint(in.Host)
	dstEndpoint := parseEndpoint(in.Upstream)

	ext := buildExt(in)

	// #320 / §A18: when validation rejected an inbound X-Agent-*
	// header at request-time, splice the structured breadcrumb
	// onto the OCSF Ext map so it lands at
	// `unmapped.iam_jit.ext.agent_header_rejection`. NEVER includes
	// the raw value — only field + bounded enum reason + length.
	// Per [[cross-product-agent-parity]] the shape is identical to
	// ibounce + dbounce + gbounce.
	if in.Agent.HeaderRejection != nil {
		if ext == nil {
			ext = map[string]any{}
		}
		ext["agent_header_rejection"] = in.Agent.HeaderRejection
	}

	actor := buildActor(in)

	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         ts.UTC().UnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   activityID,
		ActivityName: activityName,
		TypeUID:      ClassUID*100 + activityID,
		TypeName:     typeNameForActivity(activityID),
		SeverityID:   SeverityInformational,
		Severity:     "Informational",
		StatusID:     statusID,
		Status:       status,
		StatusDetail: statusDetail,
		Actor:        actor,
		API:          api,
		Resources:    resources,
		SrcEndpoint:  srcEndpoint,
		DstEndpoint:  dstEndpoint,
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				Mode:       in.Mode,
				Profile:    in.Profile,
				Verdict:    strings.ToUpper(in.Verdict),
				DecisionID: in.DecisionID,
				Enforced:   in.Enforced,
				Ext:        ext,
				Agent:      in.Agent.ToOCSFAgent(),
			},
		},
		DecisionID: in.DecisionID,
		EventType:  EventTypeDecision,
	}
}

// nowUnixMilli returns time.Now().UTC().UnixMilli(). Centralized so
// the synthetic event builders (NewDroppedMarker, NewSessionEndedEvent)
// share one clock source — tests can override behavior at the call
// site by passing a fixed time through DecisionInput.At instead.
func nowUnixMilli() int64 {
	return time.Now().UTC().UnixMilli()
}

// RedactForWebhook returns a defensive copy of ev with SENSITIVE
// agent-identity fields stripped per
// [[security-team-positioning-safety-not-surveillance]]: process_exe
// + parent_exe reveal the operator's local tooling, so the HTTPS
// webhook body MUST NOT carry them unless the operator opted in.
//
// The local JSONL log + SQLite still carry the unredacted event —
// the operator owns those, the redaction only applies to the
// outbound-to-third-party transport.
//
// includeProcessTree=true is the operator opt-in (set via the CLI
// flag --audit-webhook-include-process-tree); false (the default)
// strips the sensitive fields.
//
// Cheap copy — the only mutation is replacing the Agent pointer.
func (ev Event) RedactForWebhook(includeProcessTree bool) Event {
	if includeProcessTree {
		return ev
	}
	if ev.Unmapped.IAMJIT.Agent == nil {
		return ev
	}
	a := *ev.Unmapped.IAMJIT.Agent
	a.ProcessExe = ""
	a.ParentExe = ""
	ev.Unmapped.IAMJIT.Agent = &a
	return ev
}

// NewDroppedMarker builds an OCSF-shaped synthetic event the webhook
// pusher emits when its bounded queue overflows. Surfaces as
// activity_id=99 (Other) with severity_id=3 (Medium) + status_id=99
// (Other) per the [[ocsf-audit-schema]] memo — the marker is neither
// success nor failure of an API call, just a transport-layer signal
// that events were dropped before reaching the consumer.
func NewDroppedMarker(count int64) Event {
	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         time.Now().UTC().UnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   ActivityOther,
		ActivityName: "audit_dropped",
		TypeUID:      ClassUID*100 + ActivityOther,
		TypeName:     typeNameForActivity(ActivityOther),
		SeverityID:   SeverityMedium,
		Severity:     "Medium",
		StatusID:     StatusOther,
		Status:       "Other",
		StatusDetail: "audit-export webhook dropped " + strconv.FormatInt(count, 10) +
			" events due to backpressure; downstream consumer should investigate " +
			"(proxy held + dropped the events to keep the hot-path non-blocking)",
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType:    string(EventTypeAuditDropped),
				DroppedCount: count,
			},
		},
		EventType: EventTypeAuditDropped,
	}
}

// NewHeartbeatEvent builds an OCSF-shaped synthetic heartbeat event
// the Heartbeater goroutine emits at a fixed cadence (one per
// --heartbeat-interval tick). Surfaces as activity_id=99 (Other) /
// activity_name="heartbeat" with severity_id=1 (Informational) +
// status_id=1 (Success) — a heartbeat is a positive liveness signal,
// not an anomaly, so the wire shape carries the lowest severity to
// keep alert-fatigue noise off the SIEM.
//
// Per [[prompt-injection-disable-bouncer-threat]]: the heartbeat is
// the CANARY that lets a downstream SIEM detect "the bouncer went
// quiet" — without it, an attacker that silences the audit-export
// channel disappears silently. A `heartbeat_gap` SIEM rule (mirrored
// on the local rule-engine side as heartbeatGapRule) flags missing
// ticks loudly.
func NewHeartbeatEvent(seq int64, intervalSeconds int) Event {
	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         nowUnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   ActivityOther,
		ActivityName: "heartbeat",
		TypeUID:      ClassUID*100 + ActivityOther,
		TypeName:     typeNameForActivity(ActivityOther),
		SeverityID:   SeverityInformational,
		Severity:     "Informational",
		StatusID:     StatusSuccess,
		Status:       "Success",
		StatusDetail: "audit-export heartbeat (positive liveness signal)",
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType:                string(EventTypeHeartbeat),
				HeartbeatSeq:             seq,
				HeartbeatIntervalSeconds: intervalSeconds,
			},
		},
		EventType: EventTypeHeartbeat,
	}
}

// MakeAdminFallbackGrantEvent builds the synthetic OCSF Event a proxy
// emits ONCE when an operator opens a pause window (the "escape hatch
// was opened" bookend). pauseID is the SQLite pause_events row id;
// reason + startedBy are free-form audit context the operator passed
// to `kbouncer pause start --reason ... --by ...`; endsAtUnixMilli is
// the wall-clock at which the pause window will auto-revert (the
// proxy may emit EventTypePauseEnd earlier if `pause stop` runs first).
//
// Carries ext.admin_fallback=true so the Slice 2 admin_fallback_burst
// + pause_long rules observe it as a first-class fallback event without
// the rule predicates needing a synthetic-event-aware branch (their
// isAdminFallbackEvent check is the single source of truth). Per
// [[security-team-positioning-safety-not-surveillance]] the status
// detail is NEUTRAL — names the action, never frames the operator.
func MakeAdminFallbackGrantEvent(pauseID int64, reason, startedBy string, endsAtUnixMilli int64) Event {
	ext := map[string]any{
		"admin_fallback":  true,
		"pause_id":        pauseID,
		"pause_started_by": startedBy,
		"pause_reason":    reason,
	}
	if endsAtUnixMilli > 0 {
		ext["pause_ends_at_unix_milli"] = endsAtUnixMilli
	}
	var actor *OCSFActor
	if startedBy != "" {
		actor = &OCSFActor{User: &OCSFUser{Name: startedBy}}
	}
	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         nowUnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   ActivityOther,
		ActivityName: "admin_fallback_grant",
		TypeUID:      ClassUID*100 + ActivityOther,
		TypeName:     typeNameForActivity(ActivityOther),
		SeverityID:   SeverityInformational,
		Severity:     "Informational",
		StatusID:     StatusSuccess,
		Status:       "Success",
		StatusDetail: fmt.Sprintf(
			"pause window opened (pause_id=%d) — proxy is COOPERATIVE until pause closes",
			pauseID),
		Actor: actor,
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypeAdminFallbackGrant),
				Ext:       ext,
			},
		},
		EventType: EventTypeAdminFallbackGrant,
	}
}

// MakePauseEndEvent builds the synthetic OCSF Event a proxy emits
// ONCE when a pause window closes — paired bookend to
// MakeAdminFallbackGrantEvent. endKind is the pause_events.end_kind
// column: "resumed_early" (operator ran `kbounce pause stop`) or
// "expired" (auto-revert at ends_at). endedBy is the actor associated
// with the closure when known (the CLI sets it on resumed_early;
// expired closures carry "auto").
//
// Per [[security-team-audit-export]]: the bookend lets a SIEM compute
// pause-window duration with a single join (pause_end.time minus
// admin_fallback_grant.time keyed on pause_id) rather than scanning
// the per-decision stream for first/last bypass timestamps.
func MakePauseEndEvent(pauseID int64, endKind, endedBy string) Event {
	ext := map[string]any{
		"pause_id":       pauseID,
		"pause_end_kind": endKind,
	}
	if endedBy != "" {
		ext["pause_ended_by"] = endedBy
	}
	var actor *OCSFActor
	if endedBy != "" {
		actor = &OCSFActor{User: &OCSFUser{Name: endedBy}}
	}
	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         nowUnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   ActivityOther,
		ActivityName: "pause_end",
		TypeUID:      ClassUID*100 + ActivityOther,
		TypeName:     typeNameForActivity(ActivityOther),
		SeverityID:   SeverityInformational,
		Severity:     "Informational",
		StatusID:     StatusSuccess,
		Status:       "Success",
		StatusDetail: fmt.Sprintf(
			"pause window closed (pause_id=%d, end_kind=%s)", pauseID, endKind),
		Actor: actor,
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypePauseEnd),
				Ext:       ext,
			},
		},
		EventType: EventTypePauseEnd,
	}
}

// MakeProfileInstallEvent builds the synthetic OCSF Event the
// profile-install path emits ONCE after a successful
// `kbounce profile install --from URL`. profileNames is the alphabetic-
// ordered list of profile names the install bundle contained; source is
// the fetch URL (forced onto every profile's Source field by the
// installer); sha256 is the hex digest of the fetched bytes; verified
// reports whether the operator passed --sha256 and the digest matched.
//
// Populates IAMJITExt.Profile (the first installed profile name; for
// single-profile bundles this is THE name) and ext.profile_source (the
// fetch URL) so the Slice 2 non_org_profile_install rule's existing
// predicate (profileSource() + ev.Unmapped.IAMJIT.Profile) fires at
// install-time without needing a synthetic-event branch. Multi-profile
// bundles emit ONE event whose ext.installed_profiles array carries the
// full list — the rule fires once per (firstName, source) pair, the
// analyst pivots into the array for the rest.
func MakeProfileInstallEvent(profileNames []string, source, sha256 string, verified bool) Event {
	first := ""
	if len(profileNames) > 0 {
		first = profileNames[0]
	}
	ext := map[string]any{
		"profile_source":      source,
		"installed_profiles":  profileNames,
		"installed_count":     len(profileNames),
		"installed_sha256":    sha256,
		"installed_sha256_verified": verified,
	}
	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         nowUnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   ActivityOther,
		ActivityName: "profile_install",
		TypeUID:      ClassUID*100 + ActivityOther,
		TypeName:     typeNameForActivity(ActivityOther),
		SeverityID:   SeverityInformational,
		Severity:     "Informational",
		StatusID:     StatusSuccess,
		Status:       "Success",
		StatusDetail: fmt.Sprintf(
			"installed %d profile(s) from %s", len(profileNames), source),
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypeProfileInstall),
				Profile:   first,
				Ext:       ext,
			},
		},
		EventType: EventTypeProfileInstall,
	}
}

// k8sVerbToActivityID maps a K8s verb (or subresource verb) to the
// OCSF activity_id enum per the [[ocsf-audit-schema]] memo. The
// canonical K8s verb list is the one Kubernetes RBAC uses; this is
// the SAME table the rule engine + parser already consult, kept
// here as the single ground-truth mapping for export shape.
//
// Per [[scorer-is-ground-truth]]: this is a flat lookup, not an LLM
// or scorer-derived classification. Verbs not in the table fall
// through to Other (99) — better to be honest about uncategorized
// verbs than to guess wrong.
func k8sVerbToActivityID(verb string) int {
	switch strings.ToLower(verb) {
	case "get", "list", "watch":
		return ActivityRead
	case "create":
		return ActivityCreate
	case "update", "patch":
		return ActivityUpdate
	case "delete", "deletecollection":
		return ActivityDelete
	case "exec", "portforward", "proxy", "bind", "escalate", "impersonate",
		"attach", "log", "logs":
		// Subresource-as-verb shape (per parser.ParsedRequest.Verb
		// docstring: subresources are first-class verbs). These don't
		// map cleanly to CRUD so OCSF "Other" is correct.
		return ActivityOther
	case "":
		return ActivityUnknown
	default:
		return ActivityOther
	}
}

// buildActivityName returns "<verb>_<resource-singular>" when both
// pieces are present — gives downstream tooling a stable
// human-readable label without re-parsing the API. Examples:
// "list_pods", "create_deployment", "delete_secret". Falls back to
// the bare verb when no resource was parsed (e.g. /healthz hits).
func buildActivityName(verb, resource string) string {
	v := strings.ToLower(verb)
	r := strings.ToLower(resource)
	if v == "" && r == "" {
		return "unknown"
	}
	if v == "" {
		return r
	}
	if r == "" {
		return v
	}
	return v + "_" + r
}

// typeNameForActivity returns the OCSF type_name string for the given
// activity_id. Tracks the OCSF spec's type_name enum verbatim.
func typeNameForActivity(activityID int) string {
	switch activityID {
	case ActivityCreate:
		return "API Activity: Create"
	case ActivityRead:
		return "API Activity: Read"
	case ActivityUpdate:
		return "API Activity: Update"
	case ActivityDelete:
		return "API Activity: Delete"
	case ActivityOther:
		return "API Activity: Other"
	default:
		return "API Activity: Unknown"
	}
}

// mapVerdictToStatus translates the bouncer's native verdict +
// enforced flag into OCSF status_id / status / status_detail per the
// [[ocsf-audit-schema]] memo. Cooperative-mode DENYs are advisory
// (the upstream call succeeded; the bouncer flagged it), so they map
// to Success with the deny reason in status_detail; transparent-mode
// DENYs return Failure since the upstream call did NOT happen.
//
// Per [[ibounce-honest-positioning]]: don't claim a deny "succeeded"
// when it didn't. The bouncer's native verdict + enforced flag stay
// in unmapped.iam_jit so downstream tools that want bouncer-native
// semantics keep them.
func mapVerdictToStatus(verdict string, enforced bool, reason string) (int, string, string) {
	v := strings.ToLower(verdict)
	switch v {
	case "allow":
		return StatusSuccess, "Success", reason
	case "deny":
		if enforced {
			return StatusFailure, "Failure", reason
		}
		// Cooperative-mode advisory deny: upstream call SUCCEEDED;
		// bouncer flagged it. Honest mapping per the memo.
		return StatusSuccess, "Success", "advisory deny (cooperative mode): " + reason
	case "bypass":
		return StatusSuccess, "Success", "pause-bypass: " + reason
	case "":
		return StatusUnknown, "Unknown", reason
	default:
		return StatusUnknown, "Unknown", reason
	}
}

// buildResources derives the OCSF resources[] entry from a parsed
// K8s request. Returns an empty slice (not nil) when no resource was
// parsed — OCSF requires the field to be present as an array.
//
// The resource shape mirrors the [[ocsf-audit-schema]] memo's
// k8s example:
//
//	name: "production/web-pod-123"  (namespace/name) or "web-pod-123"
//	      (cluster-scoped) or "pods" (collection-level)
//	uid:  "namespaces/production/pods/web-pod-123" (the canonical
//	      K8s self-link shape; "/pods/web-pod-123" for cluster-scope;
//	      "/pods" for collections)
//	type: "kubernetes pod" — singularize the resource for readability
func buildResources(in DecisionInput) []OCSFResource {
	if in.ParsedResource == "" {
		return []OCSFResource{}
	}
	r := in.ParsedResource
	name := r
	if in.ParsedName != "" {
		if in.ParsedNamespace != "" {
			name = in.ParsedNamespace + "/" + in.ParsedName
		} else {
			name = in.ParsedName
		}
	} else if in.ParsedNamespace != "" {
		name = in.ParsedNamespace + "/" + r
	}

	uidParts := []string{}
	if in.ParsedNamespace != "" {
		uidParts = append(uidParts, "namespaces", in.ParsedNamespace)
	}
	uidParts = append(uidParts, r)
	if in.ParsedName != "" {
		uidParts = append(uidParts, in.ParsedName)
	}
	uid := strings.Join(uidParts, "/")

	return []OCSFResource{{
		Name: name,
		UID:  uid,
		Type: "kubernetes " + singularize(r),
	}}
}

// singularize drops a trailing "s" / "es" / "ies" suffix to give a
// readable singular resource type for OCSF resources[].type. Tiny,
// best-effort — K8s plurals are mostly regular ("pods" → "pod",
// "services" → "service"). Irregulars (e.g. "endpoints") stay as-is.
func singularize(plural string) string {
	switch {
	case strings.HasSuffix(plural, "ies") && len(plural) > 3:
		return plural[:len(plural)-3] + "y"
	case strings.HasSuffix(plural, "ses") && len(plural) > 3:
		return plural[:len(plural)-2]
	case strings.HasSuffix(plural, "s") && !strings.HasSuffix(plural, "ss") &&
		len(plural) > 1 && plural != "endpoints":
		return plural[:len(plural)-1]
	default:
		return plural
	}
}

// parseEndpoint splits "host:port" into an OCSFEndpoint. Returns nil
// when the input is empty so the omitempty json tag drops it.
// Hostname-only inputs (no port) populate only Hostname.
func parseEndpoint(hostPort string) *OCSFEndpoint {
	if hostPort == "" {
		return nil
	}
	host := hostPort
	port := 0
	if idx := strings.LastIndex(hostPort, ":"); idx > 0 {
		host = hostPort[:idx]
		if p, err := strconv.Atoi(hostPort[idx+1:]); err == nil {
			port = p
		} else {
			host = hostPort
		}
	}
	ep := &OCSFEndpoint{Hostname: host, Port: port}
	// If host parses as a literal IP, surface it as IP instead of
	// hostname for SIEMs that bucket by ip vs hostname.
	if looksLikeIP(host) {
		ep.IP = host
		ep.Hostname = ""
	}
	return ep
}

// looksLikeIP is a cheap IPv4-shape check (dotted-quad of digits).
// Good enough for the src/dst_endpoint split — full RFC parsing isn't
// worth the dependency surface, and downstream SIEMs re-validate.
func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// buildExt assembles the unmapped.iam_jit.ext object for a decision
// event. Returns nil (omitempty) when no extension fields apply.
//
// Per the [[ocsf-audit-schema]] memo's kbounce ext catalog:
//
//	k8s_verb         the K8s verb (also in api.operation; kept here
//	                 for cross-product join with non-K8s OCSF events
//	                 that don't have a K8s notion of verb)
//	k8s_subresource  the trailing subresource (exec/log/status/...)
//	k8s_api_group    the API group ("apps", "rbac.authorization.k8s.io")
//	k8s_api_version  the API version ("v1", "v1beta1")
//
// kbounce-only fields preserved for compat with the legacy schema
// that downstream tooling may already key off:
//
//	namespace        the K8s namespace
//	is_watch         true on streaming watches
//	is_dry_run       true on dryRun=All requests
//	stream_kind      "watch" / "spdy" / ""
//	task_id          the active per-task scope id
//	decision_source  "profile" / "task" / "global" / "default" / ...
func buildExt(in DecisionInput) map[string]any {
	ext := map[string]any{}
	if in.ParsedVerb != "" {
		ext["k8s_verb"] = in.ParsedVerb
	}
	if in.ParsedSubresource != "" {
		ext["k8s_subresource"] = in.ParsedSubresource
	}
	if in.ParsedGroup != "" {
		ext["k8s_api_group"] = in.ParsedGroup
	}
	if in.ParsedVersion != "" {
		ext["k8s_api_version"] = in.ParsedVersion
	}
	if in.ParsedNamespace != "" {
		ext["namespace"] = in.ParsedNamespace
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
	if in.ProfileSource != "" {
		ext["profile_source"] = in.ProfileSource
	}
	if in.AdminFallback {
		ext["admin_fallback"] = true
	}
	if len(ext) == 0 {
		return nil
	}
	return ext
}

// buildActor returns the OCSF actor object — populated from the K8s
// principal when extracted, otherwise from the agent identity (per
// [[agent-identity-in-audit]]: the fingerprinted CALLING client is
// the actor when no bearer-token subject is available), otherwise
// from the task scope id (the closest proxy-level analog to a
// session), otherwise nil so the omitempty json tag drops the field
// entirely.
//
// Cross-product spec ([[cross-product-agent-parity]]):
//
//	event.Actor.User.Name = agent_name when PrincipalName is empty
//	  → an analyst grepping actor.user.name = "claude-code" against
//	    a SIEM corpus gets every call the agent made regardless of
//	    whether kbounce had K8s-subject extraction.
//	event.Unmapped.iam_jit.agent.{name,session_id} always populated
//	  → the same identity surfaces under the iam-jit-native block
//	    too (cross-product invariant).
//
// Slice 1 does not yet extract the inbound bearer-token subject;
// PrincipalName/PrincipalUID stay "" and actor.user falls back to
// agent_name when that's known. Slice 2 wires SPIFFE / JWT subject
// extraction per [[security-team-audit-export]]; when a real
// principal is present it takes precedence.
func buildActor(in DecisionInput) *OCSFActor {
	actor := &OCSFActor{}
	any := false
	switch {
	case in.PrincipalName != "" || in.PrincipalUID != "":
		actor.User = &OCSFUser{Name: in.PrincipalName, UID: in.PrincipalUID}
		any = true
	case in.Agent.Name != "" && in.Agent.Name != AgentNameUnknown:
		actor.User = &OCSFUser{Name: in.Agent.Name}
		any = true
	}
	if in.TaskID != "" {
		actor.Session = &OCSFSession{UID: in.TaskID}
		any = true
	}
	if !any {
		return nil
	}
	return actor
}
