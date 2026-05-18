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
			},
		},
		DecisionID: in.DecisionID,
		EventType:  EventTypeDecision,
	}
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
	if len(ext) == 0 {
		return nil
	}
	return ext
}

// buildActor returns the OCSF actor object — populated from the K8s
// principal when extracted, otherwise from the task scope id (the
// closest proxy-level analog to a session), otherwise nil so the
// omitempty json tag drops the field entirely.
//
// Slice 1 does not yet extract the inbound bearer-token subject;
// PrincipalName/PrincipalUID stay "" and actor.user is omitted.
// Slice 2 wires SPIFFE / JWT subject extraction per
// [[security-team-audit-export]].
func buildActor(in DecisionInput) *OCSFActor {
	actor := &OCSFActor{}
	any := false
	if in.PrincipalName != "" || in.PrincipalUID != "" {
		actor.User = &OCSFUser{Name: in.PrincipalName, UID: in.PrincipalUID}
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
