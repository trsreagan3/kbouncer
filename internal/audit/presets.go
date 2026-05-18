package audit

// Webhook presets: per-vendor adapters that transform an OCSF event
// (or batch of events) into the wire shape a SIEM expects. The
// canonical OCSF event written to the JSONL log file by
// log.go is UNCHANGED — presets only affect the webhook body +
// headers at send-time.
//
// Per [[audit-webhook-presets]] (2026-05-18): pure data
// transformation, no I/O, no SDK dependencies, no per-vendor token
// pre-validation. The adapter returns (url, headers, body); the
// existing WebhookPusher does the SSRF gate / retry / token-masking
// / queue-overflow handling regardless of which preset built the
// request.
//
// Cross-product parity per [[cross-product-agent-parity]]: same
// preset names ("generic", "datadog", "splunk-hec", "sentinel") +
// same overlay semantics as ibounce + dbounce. A SIEM consuming
// events from all three Bounce products gets identical vendor-native
// shapes — pivot by metadata.product.name to distinguish.
//
// Security Lake adapter is a separate slice (#258 — S3 + parquet,
// different transport).
//
// Per [[security-team-positioning-safety-not-surveillance]]: overlay
// language stays neutral — no "violation" / "unauthorized" framing
// on top of the OCSF event the scorer already produced. Per
// [[scorer-is-ground-truth]]: the adapter never re-evaluates
// severity / status / verdict; it copies the OCSF values into
// vendor-native slots only.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Preset names the wire shape the webhook pusher emits. Generic =
// backward-compat (Bearer + JSON array) per the Slice 1 shipped
// behavior; the named presets layer vendor-native fields + auth
// headers on top of the canonical OCSF event.
type Preset string

const (
	// PresetGeneric is the default; preserves the Slice 1 wire shape
	// byte-for-byte (Authorization: Bearer + Content-Type: application/json
	// + JSON-array body). New consumers + existing collectors both work
	// against this preset.
	PresetGeneric Preset = "generic"

	// PresetDatadog targets Datadog Logs HTTP intake. DD-API-KEY header
	// + per-event overlay (ddsource / service / ddtags / status / host /
	// message). The full OCSF event remains queryable as nested fields.
	PresetDatadog Preset = "datadog"

	// PresetSplunkHEC targets Splunk HTTP Event Collector. "Authorization:
	// Splunk <token>" header + NDJSON body where each line wraps the OCSF
	// event under the HEC "event" field with sourcetype / source / host /
	// time set from OCSF metadata.
	PresetSplunkHEC Preset = "splunk-hec"

	// PresetSentinel targets Microsoft Sentinel via the Log Analytics
	// Data Collector API. HMAC-SHA256-signed SharedKey Authorization
	// header derived from the workspace shared key + the body bytes +
	// the x-ms-date header. Log-Type chooses the custom-log table name.
	PresetSentinel Preset = "sentinel"
)

// AllPresets is the canonical list of supported preset names. Used
// by CLI flag validation + by docs / banner output to enumerate the
// available adapters.
func AllPresets() []Preset {
	return []Preset{PresetGeneric, PresetDatadog, PresetSplunkHEC, PresetSentinel}
}

// PresetDescriptor is the cross-product descriptor shape returned
// by both the CLI (`kbounce audit-webhook presets list --json`) and
// the MCP tool (`list_audit_webhook_presets`). Field set matches
// the ibounce `audit_webhook_preset_descriptors` helper byte-for-byte
// so an agent calling the matching tool on either bouncer sees
// identical JSON. Per [[cross-product-agent-parity]].
type PresetDescriptor struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	AuthHeader    string   `json:"auth_header"`
	BodyShape     string   `json:"body_shape"`
	RequiredFlags []string `json:"required_flags"`
	OptionalFlags []string `json:"optional_flags"`
}

// PresetDescriptors returns the static, in-binary descriptor list
// for every audit-webhook preset kbounce speaks.
//
// Exposed in the audit package (not in cli/) so both the CLI surface
// and the MCP tool can import it without creating a circular
// dependency (cli imports mcp; mcp must not import cli; both can
// import audit).
//
// Per [[scorer-is-ground-truth]] + [[don't-tailor-to-lighthouse]]:
// hand-maintained here. A test asserts every name returned by
// AllPresets() shows up in this list (preventing silent drift).
func PresetDescriptors() []PresetDescriptor {
	return []PresetDescriptor{
		{
			Name: "generic",
			Description: "Default. Bearer token in Authorization + JSON " +
				"body. Byte-identical to the pre-#257 wire shape; existing " +
				"webhook consumers + custom ingest scripts keep working " +
				"without code changes.",
			AuthHeader: "Authorization: Bearer <token>",
			BodyShape:  "JSON array of OCSF v1.1.0 class 6003 events",
			RequiredFlags: []string{
				"--audit-webhook-url",
				"--audit-webhook-token",
			},
			OptionalFlags: []string{
				"--audit-webhook-batch-size",
			},
		},
		{
			Name: "datadog",
			Description: "Datadog Logs HTTP intake. OCSF event overlaid " +
				"with DD-native fields (ddsource, service, ddtags, status, " +
				"message); the OCSF payload remains queryable as nested " +
				"fields. Vendor-reserved field collisions (status, host) " +
				"preserve the OCSF original under ocsf.<name>.",
			AuthHeader: "DD-API-KEY: <api_key>",
			BodyShape: "JSON array of OCSF events, each overlaid with " +
				"Datadog-native overlay fields",
			RequiredFlags: []string{
				"--audit-webhook-url",
				"--audit-webhook-token",
			},
			OptionalFlags: []string{
				"--audit-webhook-tags",
			},
		},
		{
			Name: "splunk-hec",
			Description: "Splunk HTTP Event Collector. NDJSON body where " +
				"each line wraps the OCSF event under HEC's `event` " +
				"envelope; sourcetype + source + host + time are set from " +
				"OCSF metadata.",
			AuthHeader: "Authorization: Splunk <hec_token>",
			BodyShape: "NDJSON; each line is one HEC envelope wrapping " +
				"one OCSF event",
			RequiredFlags: []string{
				"--audit-webhook-url",
				"--audit-webhook-token",
			},
			OptionalFlags: []string{},
		},
		{
			Name: "sentinel",
			Description: "Microsoft Sentinel / Log Analytics Workspace " +
				"via the Data Collector API. HMAC-SHA256-signed SharedKey " +
				"auth computed over the canonical (method, content-length, " +
				"content-type, x-ms-date, resource) string keyed by the " +
				"base64-decoded workspace shared key. The token value MUST " +
				"be the base64-encoded shared key.",
			AuthHeader: "Authorization: SharedKey <workspace-id>:<HMAC-SHA256>",
			BodyShape:  "JSON array of OCSF events",
			RequiredFlags: []string{
				"--audit-webhook-url",
				"--audit-webhook-token",
			},
			OptionalFlags: []string{
				"--audit-webhook-sentinel-table",
			},
		},
	}
}

// ParsePreset validates a CLI-supplied preset name. Returns the
// canonical Preset value or an error listing the supported names.
// Empty string normalizes to PresetGeneric so omitting the flag
// preserves the Slice 1 default.
func ParsePreset(s string) (Preset, error) {
	if s == "" {
		return PresetGeneric, nil
	}
	for _, p := range AllPresets() {
		if string(p) == s {
			return p, nil
		}
	}
	names := make([]string, 0, len(AllPresets()))
	for _, p := range AllPresets() {
		names = append(names, string(p))
	}
	return "", fmt.Errorf(
		"audit: unknown --audit-webhook-preset %q (supported: %s)",
		s, strings.Join(names, ", "))
}

// PresetConfig carries the per-deployment fields adapters need
// beyond the OCSF event itself. URL + Token come from the operator's
// CLI flags; Tags is a comma-separated free-form string appended to
// Datadog's ddtags (and stored in the audit log for completeness on
// other presets); SentinelTable names the Log Analytics custom-log
// table; Product identifies which Bounce product is emitting (always
// ProductName here, threaded in for symmetry with ibounce / dbounce).
type PresetConfig struct {
	URL           string
	Token         string
	Tags          string
	SentinelTable string
	Product       string
	// Now is an injectable clock for HMAC-signed presets so tests can
	// pin x-ms-date + signature against a known time. nil → time.Now.
	Now func() time.Time
}

// SentinelDefaultTable is the Log Analytics custom-log table name
// when the operator doesn't override via --audit-webhook-sentinel-table.
// Matches the ibounce + dbounce default for cross-product parity.
const SentinelDefaultTable = "IamJitBouncer"

// BuildRequest returns the (url, headers, body) tuple the webhook
// pusher should send for the chosen preset + event batch. Pure
// transformation; no I/O, no logging, no scoring.
//
// The generic preset marshals the typed Events directly so the wire
// shape is byte-identical to the Slice 1 pre-presets behavior (the
// Event struct's tagged field order is preserved). Vendor presets
// convert to map[string]any via EventsToMaps so adapters can layer
// vendor-overlay fields without re-defining every OCSF struct.
func BuildRequest(p Preset, cfg PresetConfig, events []Event) (
	targetURL string, headers map[string]string, body []byte, err error,
) {
	switch p {
	case "", PresetGeneric:
		return buildGeneric(cfg, events)
	case PresetDatadog, PresetSplunkHEC, PresetSentinel:
		maps, err := EventsToMaps(events)
		if err != nil {
			return "", nil, nil, err
		}
		switch p {
		case PresetDatadog:
			return buildDatadog(cfg, maps)
		case PresetSplunkHEC:
			return buildSplunkHEC(cfg, maps)
		case PresetSentinel:
			return buildSentinel(cfg, maps)
		}
		// Unreachable — outer switch case-guarded.
		return "", nil, nil, fmt.Errorf("audit: unhandled preset %q", p)
	default:
		return "", nil, nil, fmt.Errorf("audit: unknown preset %q", p)
	}
}

// EventsToMaps converts a slice of typed OCSF Events to a slice of
// generic maps so adapter code can layer vendor-specific overlay
// fields without re-defining every OCSF field. Round-trips through
// JSON which preserves the exact wire shape the JSONL log emits.
func EventsToMaps(events []Event) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			return nil, fmt.Errorf("marshal event id=%d: %w", ev.DecisionID, err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("unmarshal event id=%d: %w", ev.DecisionID, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// buildGeneric preserves the Slice 1 wire shape exactly: a JSON
// array of OCSF events with Bearer auth + application/json content
// type. Marshals the typed Event values directly so the field order
// matches the Event struct's json tag declarations (the Slice 1
// pre-presets behavior). Existing collectors configured before the
// preset flag landed MUST keep working without re-configuration.
func buildGeneric(cfg PresetConfig, events []Event) (string, map[string]string, []byte, error) {
	body, err := json.Marshal(events)
	if err != nil {
		return "", nil, nil, fmt.Errorf("generic preset: marshal: %w", err)
	}
	h := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + cfg.Token,
	}
	return cfg.URL, h, body, nil
}

// buildDatadog overlays Datadog-native fields onto each OCSF event
// and posts them as a JSON array with DD-API-KEY auth. The OCSF
// schema stays intact under the overlay so a downstream tool reading
// from DD's pipeline can find every original OCSF field; the overlay
// just gives DD's auto-categorization + dashboarding free.
//
// Per [[audit-webhook-presets]] field-overlap policy: when DD
// reserves a field name (status, host) that OCSF also defines, the
// vendor-derived value wins for DD's auto-categorization and the
// OCSF original is preserved under ocsf.<name>.
func buildDatadog(cfg PresetConfig, events []map[string]any) (string, map[string]string, []byte, error) {
	overlay := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		o := overlayCopy(ev)
		// ddsource is the SIEM-recognized integration name; "iam-jit"
		// groups all three Bounce products under one DD source filter.
		o["ddsource"] = "iam-jit"
		// service distinguishes the product within ddsource:iam-jit.
		o["service"] = productName(ev, cfg.Product)
		// ddtags get the static product tag + the bouncer-name tag,
		// plus any operator-supplied tags appended (free-form).
		o["ddtags"] = buildDDTags(productName(ev, cfg.Product), cfg.Tags)
		// host = the proxy's bind endpoint when known. Falls through
		// to absent so DD assigns its own source-IP host.
		if host := endpointHost(ev, "src_endpoint"); host != "" {
			// Preserve any pre-existing OCSF "host" semantics under
			// ocsf.host (OCSF doesn't define a top-level host, but
			// guard anyway for forward-compat with future schema bumps).
			if existing, ok := o["host"]; ok {
				stashOCSF(o, "host", existing)
			}
			o["host"] = host
		}
		// status (DD-reserved) derived from OCSF status_id. Preserve
		// the OCSF status string under ocsf.status so both are queryable.
		if existing, ok := o["status"]; ok {
			stashOCSF(o, "status", existing)
		}
		o["status"] = ddStatusFromOCSF(ev)
		// message: human-readable summary line for DD's search bar.
		o["message"] = buildMessage(ev)
		overlay = append(overlay, o)
	}
	body, err := json.Marshal(overlay)
	if err != nil {
		return "", nil, nil, fmt.Errorf("datadog preset: marshal: %w", err)
	}
	h := map[string]string{
		"Content-Type": "application/json",
		"DD-API-KEY":   cfg.Token,
	}
	return cfg.URL, h, body, nil
}

// buildSplunkHEC wraps each OCSF event in the HEC envelope and
// joins with newlines (NDJSON, per HEC's preferred ingest shape).
// sourcetype + source give Splunk's auto-categorization a stable
// label per Bounce product.
func buildSplunkHEC(cfg PresetConfig, events []map[string]any) (string, map[string]string, []byte, error) {
	var sb strings.Builder
	for i, ev := range events {
		envelope := map[string]any{
			"event":      ev,
			"sourcetype": "iam_jit:bouncer:" + productName(ev, cfg.Product),
			"source":     "iam-jit",
		}
		if host := endpointHost(ev, "src_endpoint"); host != "" {
			envelope["host"] = host
		}
		if t, ok := ocsfTimeUnixSeconds(ev); ok {
			envelope["time"] = t
		}
		b, err := json.Marshal(envelope)
		if err != nil {
			return "", nil, nil, fmt.Errorf("splunk-hec preset: marshal: %w", err)
		}
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.Write(b)
	}
	h := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Splunk " + cfg.Token,
	}
	return cfg.URL, h, []byte(sb.String()), nil
}

// buildSentinel signs the request per Microsoft's Log Analytics Data
// Collector API spec: HMAC-SHA256 over the canonical string
//
//	METHOD\n<content-length>\napplication/json\nx-ms-date:<date>\n/api/logs
//
// keyed by the base64-decoded workspace shared key. Signature is
// base64-encoded and prefixed with "SharedKey <workspace-id>:".
//
// The workspace ID is extracted from the URL host (the canonical
// Log Analytics ingest URL is
// https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=...).
func buildSentinel(cfg PresetConfig, events []map[string]any) (string, map[string]string, []byte, error) {
	body, err := json.Marshal(events)
	if err != nil {
		return "", nil, nil, fmt.Errorf("sentinel preset: marshal: %w", err)
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	date := now().UTC().Format(http.TimeFormat) // RFC1123 GMT
	workspaceID, err := sentinelWorkspaceIDFromURL(cfg.URL)
	if err != nil {
		return "", nil, nil, err
	}
	sharedKey, err := base64.StdEncoding.DecodeString(cfg.Token)
	if err != nil {
		return "", nil, nil, fmt.Errorf(
			"sentinel preset: --audit-webhook-token must be the base64 workspace shared key: %w", err)
	}
	stringToSign := fmt.Sprintf(
		"POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs",
		len(body), date)
	mac := hmac.New(sha256.New, sharedKey)
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	table := cfg.SentinelTable
	if table == "" {
		table = SentinelDefaultTable
	}
	h := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "SharedKey " + workspaceID + ":" + sig,
		"Log-Type":      table,
		"x-ms-date":     date,
	}
	return cfg.URL, h, body, nil
}

// sentinelWorkspaceIDFromURL extracts the workspace ID from the
// Sentinel ingest URL host. The canonical shape is
// "<workspace-id>.ods.opinsights.azure.com"; the workspace ID is the
// first dot-separated segment of the host.
func sentinelWorkspaceIDFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("sentinel preset: parse URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("sentinel preset: URL has no host")
	}
	idx := strings.Index(host, ".")
	if idx <= 0 {
		return "", fmt.Errorf(
			"sentinel preset: URL host %q must be of the form "+
				"<workspace-id>.ods.opinsights.azure.com", host)
	}
	return host[:idx], nil
}

// overlayCopy returns a shallow copy of ev so the adapter can layer
// fields without mutating the caller's map (which the JSONL log
// writer also holds a reference to via the EventsToMaps round-trip).
func overlayCopy(ev map[string]any) map[string]any {
	out := make(map[string]any, len(ev)+6)
	for k, v := range ev {
		out[k] = v
	}
	return out
}

// stashOCSF preserves an OCSF-original value under the "ocsf.<name>"
// shadow key when a vendor reserved a field name we need to overwrite.
// Per [[audit-webhook-presets]] field-overlap policy.
func stashOCSF(o map[string]any, name string, val any) {
	shadow, _ := o["ocsf"].(map[string]any)
	if shadow == nil {
		shadow = map[string]any{}
	}
	shadow[name] = val
	o["ocsf"] = shadow
}

// buildDDTags assembles the comma-separated ddtags string. Always
// includes product:iam-jit + bouncer:<product>; operator-supplied
// tags from --audit-webhook-tags are appended verbatim (no parsing).
func buildDDTags(product, operatorTags string) string {
	base := "product:iam-jit,bouncer:" + product
	if operatorTags != "" {
		base += "," + operatorTags
	}
	return base
}

// ddStatusFromOCSF maps the OCSF status_id enum to DD's status
// keyword set. Per [[audit-webhook-presets]]: 1→info, 2→error, 99→notice.
// Unknown / unset falls through to "info" rather than empty so DD's
// per-status filter still groups the event.
func ddStatusFromOCSF(ev map[string]any) string {
	v, ok := ev["status_id"]
	if !ok {
		return "info"
	}
	id, ok := toInt(v)
	if !ok {
		return "info"
	}
	switch id {
	case StatusSuccess:
		return "info"
	case StatusFailure:
		return "error"
	case StatusOther:
		return "notice"
	default:
		return "info"
	}
}

// buildMessage assembles the human-readable summary line DD uses as
// the searchable text. Per [[security-team-positioning-safety-not-
// surveillance]]: neutral phrasing, no "violation" / "unauthorized";
// just the verdict + the operation + the resource name + the mode.
//
// Example: "DENY delete pods/prod/db-0 (transparent, enforced)".
func buildMessage(ev map[string]any) string {
	verdict := extString(ev, "unmapped", "iam_jit", "verdict")
	if verdict == "" {
		verdict = strings.ToUpper(extString(ev, "status"))
	}
	op := extString(ev, "api", "operation")
	if op == "" {
		op = extString(ev, "activity_name")
	}
	resName := firstResourceName(ev)
	mode := extString(ev, "unmapped", "iam_jit", "mode")
	enforced := extBool(ev, "unmapped", "iam_jit", "enforced")
	parts := []string{}
	if verdict != "" {
		parts = append(parts, verdict)
	}
	if op != "" {
		parts = append(parts, op)
	}
	if resName != "" {
		parts = append(parts, resName)
	}
	msg := strings.Join(parts, " ")
	if mode != "" || enforced {
		extra := []string{}
		if mode != "" {
			extra = append(extra, mode)
		}
		if enforced {
			extra = append(extra, "enforced")
		}
		msg = strings.TrimSpace(msg + " (" + strings.Join(extra, ", ") + ")")
	}
	if msg == "" {
		// Fallback so DD always has a searchable line even on
		// shape-degraded events.
		msg = "audit event"
	}
	return msg
}

// firstResourceName returns the .name of the first resources[] entry,
// or "" when the array is empty (e.g. /healthz hits with no parsed
// K8s resource).
func firstResourceName(ev map[string]any) string {
	rs, ok := ev["resources"].([]any)
	if !ok || len(rs) == 0 {
		return ""
	}
	r, ok := rs[0].(map[string]any)
	if !ok {
		return ""
	}
	if n, ok := r["name"].(string); ok {
		return n
	}
	return ""
}

// endpointHost returns the hostname (or IP fallback) of the OCSF
// src_endpoint or dst_endpoint sub-object. Returns "" when the
// endpoint isn't present or has neither field set.
func endpointHost(ev map[string]any, key string) string {
	ep, ok := ev[key].(map[string]any)
	if !ok {
		return ""
	}
	if h, ok := ep["hostname"].(string); ok && h != "" {
		return h
	}
	if ip, ok := ep["ip"].(string); ok && ip != "" {
		return ip
	}
	return ""
}

// ocsfTimeUnixSeconds reads OCSF "time" (unix milliseconds) and
// returns it converted to unix seconds for HEC's "time" field. HEC
// accepts either int or float; we use int seconds for compactness.
// Returns ok=false when the field is missing or unparseable so the
// envelope omits "time" and HEC stamps on ingest.
func ocsfTimeUnixSeconds(ev map[string]any) (int64, bool) {
	v, ok := ev["time"]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n) / 1000, true
	case int64:
		return n / 1000, true
	case int:
		return int64(n) / 1000, true
	case string:
		// JSON unmarshal won't produce string for a numeric field but
		// guard for forward-compat with hand-built maps.
		i, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			return 0, false
		}
		return i / 1000, true
	default:
		return 0, false
	}
}

// productName returns the OCSF metadata.product.name when present
// (always set by the FromDecision builder); falls back to the
// PresetConfig.Product value (or "kbounce" if both are empty) so the
// adapter always emits a non-empty service / sourcetype tag.
func productName(ev map[string]any, fallback string) string {
	if md, ok := ev["metadata"].(map[string]any); ok {
		if prod, ok := md["product"].(map[string]any); ok {
			if name, ok := prod["name"].(string); ok && name != "" {
				return name
			}
		}
	}
	if fallback != "" {
		return fallback
	}
	return ProductName
}

// extString navigates a nested map[string]any path and returns the
// string at the leaf, or "" when any step is missing / wrong-typed.
func extString(m map[string]any, path ...string) string {
	cur := any(m)
	for i, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		v, ok := mm[p]
		if !ok {
			return ""
		}
		if i == len(path)-1 {
			s, _ := v.(string)
			return s
		}
		cur = v
	}
	return ""
}

// extBool navigates a nested map[string]any path and returns the bool
// at the leaf, or false when missing / wrong-typed.
func extBool(m map[string]any, path ...string) bool {
	cur := any(m)
	for i, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		v, ok := mm[p]
		if !ok {
			return false
		}
		if i == len(path)-1 {
			b, _ := v.(bool)
			return b
		}
		cur = v
	}
	return false
}

// toInt coerces a JSON-unmarshaled numeric value (float64, int, int64)
// to int. Returns ok=false on type mismatch so callers can default.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	default:
		return 0, false
	}
}
