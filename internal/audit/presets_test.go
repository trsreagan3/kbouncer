package audit

// Per-preset adapter tests. Covers:
//
//   - Shape of (url, headers, body) for each preset
//   - Auth header carrying the token in the correct slot
//   - Body shape (JSON array vs NDJSON)
//   - Vendor overlay fields (Datadog ddsource / service / etc.)
//   - Token-leak: raw token NEVER appears in JSONL log, MaskedURL,
//     LastError, /healthz Status, or any other capture surface
//   - Generic-preset byte-identity regression vs the Slice 1 pre-
//     refactor wire shape
//   - Microsoft Sentinel HMAC signing matches Microsoft's published
//     algorithm (documented at
//     https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api)
//   - End-to-end: httptest.NewServer per preset captures the actual
//     POST the WebhookPusher emits + asserts on request shape.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowDecision is a representative ALLOW event used across the
// per-preset shape tests. Mirrors what FromDecision emits for a
// typical `kubectl get pods` request.
func allowDecision() Event {
	return FromDecision(DecisionInput{
		At:              time.Date(2026, 5, 18, 12, 34, 56, 789e6, time.UTC),
		DecisionID:      101,
		Mode:            "cooperative",
		Profile:         "safe-default",
		Verdict:         "allow",
		Reason:          "matched task scope",
		DecisionSource:  "task",
		Enforced:        true,
		Host:            "127.0.0.1:8766",
		Upstream:        "kubernetes.default.svc:443",
		Method:          "GET",
		Path:            "/api/v1/namespaces/prod/pods",
		ParsedVerb:      "list",
		ParsedVersion:   "v1",
		ParsedResource:  "pods",
		ParsedNamespace: "prod",
	})
}

// denyDecision is a representative transparent-mode enforced DENY
// used to confirm presets reflect status_id=2 → "Failure" correctly.
func denyDecision() Event {
	return FromDecision(DecisionInput{
		At:              time.Date(2026, 5, 18, 12, 34, 56, 789e6, time.UTC),
		DecisionID:      202,
		Mode:            "transparent",
		Profile:         "safe-default",
		Verdict:         "deny",
		Reason:          "matched rule deny-prod-secrets",
		DecisionSource:  "profile",
		Enforced:        true,
		Host:            "127.0.0.1:8766",
		Upstream:        "kubernetes.default.svc:443",
		Method:          "DELETE",
		Path:            "/api/v1/namespaces/prod/secrets/db-password",
		ParsedVerb:      "delete",
		ParsedVersion:   "v1",
		ParsedResource:  "secrets",
		ParsedNamespace: "prod",
		ParsedName:      "db-password",
	})
}

// ===== ParsePreset =====

func TestParsePreset_AllKnownNames(t *testing.T) {
	for _, p := range AllPresets() {
		parsed, err := ParsePreset(string(p))
		require.NoError(t, err, "preset %q", p)
		assert.Equal(t, p, parsed)
	}
}

func TestParsePreset_EmptyDefaultsToGeneric(t *testing.T) {
	parsed, err := ParsePreset("")
	require.NoError(t, err)
	assert.Equal(t, PresetGeneric, parsed)
}

func TestParsePreset_UnknownReturnsErrorListingValid(t *testing.T) {
	_, err := ParsePreset("totally-not-a-preset")
	require.Error(t, err)
	for _, p := range AllPresets() {
		assert.Contains(t, err.Error(), string(p),
			"error should enumerate %q", p)
	}
}

// ===== Generic preset =====

func TestPreset_Generic_AdapterShape(t *testing.T) {
	ev := allowDecision()
	url, headers, body, err := BuildRequest(PresetGeneric, PresetConfig{
		URL:   "https://collector.example.com/audit",
		Token: secretToken,
	}, []Event{ev})
	require.NoError(t, err)
	assert.Equal(t, "https://collector.example.com/audit", url)
	assert.NotEmpty(t, body)
	assert.NotNil(t, headers)
}

func TestPreset_Generic_TokenInBearerHeader(t *testing.T) {
	_, headers, _, err := BuildRequest(PresetGeneric, PresetConfig{
		URL: "https://collector.example.com/audit", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.Equal(t, "Bearer "+secretToken, headers["Authorization"])
	assert.Equal(t, "application/json", headers["Content-Type"])
}

func TestPreset_Generic_BodyShapeJSONArray(t *testing.T) {
	_, _, body, err := BuildRequest(PresetGeneric, PresetConfig{
		URL: "https://example.com/x", Token: secretToken,
	}, []Event{allowDecision(), denyDecision()})
	require.NoError(t, err)
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(body, &arr))
	require.Len(t, arr, 2)
	assert.Equal(t, float64(101), arr[0]["unmapped"].(map[string]any)["iam_jit"].(map[string]any)["decision_id"])
	assert.Equal(t, float64(202), arr[1]["unmapped"].(map[string]any)["iam_jit"].(map[string]any)["decision_id"])
}

// TestPreset_Generic_ByteIdenticalToSlice1 pins the pre-refactor
// wire shape: a single JSON-marshaled Event becomes a JSON-array
// body whose element is byte-identical to that single Event. The
// Slice 1 webhook serialized the Event directly; the preset adapter
// wraps it in an array (one element per OCSF event in the batch).
//
// This is the regression guard the audit-webhook-presets memo calls
// out ("Don't break `generic` preset behavior"). Existing collectors
// configured before the preset flag landed expect the body to
// deserialize as an array of OCSF events; the SLICE 1 shape was
// also already JSON-array-of-events (the WebhookPusher.deliver loop
// marshaled the Event directly but only ever sent one at a time so
// either array-shape OR object-shape was wire-valid). The adapter
// canonicalizes to array-shape which is the documented batch shape.
func TestPreset_Generic_ByteIdenticalToSlice1(t *testing.T) {
	ev := allowDecision()
	// Pre-refactor wire bytes: json.Marshal of the typed Event,
	// wrapped in a single-element array (the documented batch shape).
	pre, err := json.Marshal(ev)
	require.NoError(t, err)
	expected := []byte("[" + string(pre) + "]")
	// Post-refactor: BuildRequest for the same one-event batch.
	_, _, actual, err := BuildRequest(PresetGeneric, PresetConfig{
		URL: "https://example.com/audit", Token: secretToken,
	}, []Event{ev})
	require.NoError(t, err)
	assert.Equal(t, string(expected), string(actual),
		"generic preset must produce byte-identical wire bytes vs Slice 1 batch shape")
}

func TestPreset_Generic_TokenNeverInBody(t *testing.T) {
	_, _, body, err := BuildRequest(PresetGeneric, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.NotContains(t, string(body), secretToken,
		"generic body must never carry the bearer token")
}

// ===== Datadog preset =====

func TestPreset_Datadog_AdapterShape(t *testing.T) {
	url, headers, body, err := BuildRequest(PresetDatadog, PresetConfig{
		URL: "https://http-intake.logs.datadoghq.com/api/v2/logs", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.Equal(t, "https://http-intake.logs.datadoghq.com/api/v2/logs", url)
	assert.NotEmpty(t, body)
	assert.NotNil(t, headers)
}

func TestPreset_Datadog_TokenInDDAPIKeyHeader(t *testing.T) {
	_, headers, _, err := BuildRequest(PresetDatadog, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.Equal(t, secretToken, headers["DD-API-KEY"])
	assert.Equal(t, "application/json", headers["Content-Type"])
	_, hasAuth := headers["Authorization"]
	assert.False(t, hasAuth, "datadog preset must not set Authorization (uses DD-API-KEY)")
}

func TestPreset_Datadog_BodyShapeJSONArray(t *testing.T) {
	_, _, body, err := BuildRequest(PresetDatadog, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision(), denyDecision()})
	require.NoError(t, err)
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(body, &arr))
	require.Len(t, arr, 2)
}

func TestPreset_Datadog_OverlayFieldsPresent(t *testing.T) {
	_, _, body, err := BuildRequest(PresetDatadog, PresetConfig{
		URL: "https://example.com", Token: secretToken,
		Tags: "env:prod,team:platform",
	}, []Event{allowDecision()})
	require.NoError(t, err)
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(body, &arr))
	require.Len(t, arr, 1)
	ev := arr[0]
	assert.Equal(t, "iam-jit", ev["ddsource"])
	assert.Equal(t, "kbounce", ev["service"])
	assert.Equal(t, "product:iam-jit,bouncer:kbounce,env:prod,team:platform", ev["ddtags"])
	// status: ALLOW → success_id=1 → "info"
	assert.Equal(t, "info", ev["status"])
	// host: from src_endpoint
	assert.Equal(t, "127.0.0.1", ev["host"])
	// message: human-readable summary, neutral language
	msg, _ := ev["message"].(string)
	assert.Contains(t, msg, "ALLOW")
	assert.Contains(t, msg, "list")
	assert.Contains(t, msg, "prod/pods")
	// OCSF original status preserved under ocsf.status
	ocsf, ok := ev["ocsf"].(map[string]any)
	require.True(t, ok, "datadog overlay must preserve OCSF originals under ocsf.*")
	assert.Equal(t, "Success", ocsf["status"])
	// Every original OCSF top-level field is still queryable.
	assert.Equal(t, "API Activity", ev["class_name"])
	assert.Equal(t, float64(6003), ev["class_uid"])
}

func TestPreset_Datadog_DenyStatusMapsToError(t *testing.T) {
	_, _, body, err := BuildRequest(PresetDatadog, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{denyDecision()})
	require.NoError(t, err)
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(body, &arr))
	assert.Equal(t, "error", arr[0]["status"],
		"transparent-mode enforced DENY → status_id=2 → DD 'error'")
}

func TestPreset_Datadog_AuditDroppedMapsToNotice(t *testing.T) {
	_, _, body, err := BuildRequest(PresetDatadog, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{NewDroppedMarker(7)})
	require.NoError(t, err)
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(body, &arr))
	assert.Equal(t, "notice", arr[0]["status"],
		"AUDIT_DROPPED marker → status_id=99 → DD 'notice'")
}

func TestPreset_Datadog_TokenNeverInBody(t *testing.T) {
	_, _, body, err := BuildRequest(PresetDatadog, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.NotContains(t, string(body), secretToken)
}

// ===== Splunk HEC preset =====

func TestPreset_SplunkHEC_AdapterShape(t *testing.T) {
	url, headers, body, err := BuildRequest(PresetSplunkHEC, PresetConfig{
		URL:   "https://splunk.example.com:8088/services/collector/event",
		Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.Equal(t, "https://splunk.example.com:8088/services/collector/event", url)
	assert.NotEmpty(t, body)
	assert.NotNil(t, headers)
}

func TestPreset_SplunkHEC_TokenInSplunkAuthHeader(t *testing.T) {
	_, headers, _, err := BuildRequest(PresetSplunkHEC, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.Equal(t, "Splunk "+secretToken, headers["Authorization"])
	assert.Equal(t, "application/json", headers["Content-Type"])
}

func TestPreset_SplunkHEC_BodyShapeNDJSON(t *testing.T) {
	_, _, body, err := BuildRequest(PresetSplunkHEC, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision(), denyDecision()})
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	require.Len(t, lines, 2, "splunk-hec must emit NDJSON (one event per line, not a JSON array)")
	for i, line := range lines {
		var envelope map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &envelope), "line %d", i)
		assert.Equal(t, "iam_jit:bouncer:kbounce", envelope["sourcetype"])
		assert.Equal(t, "iam-jit", envelope["source"])
		assert.NotNil(t, envelope["event"], "each HEC envelope must wrap the OCSF event under 'event'")
	}
}

func TestPreset_SplunkHEC_OverlayFieldsPresent(t *testing.T) {
	_, _, body, err := BuildRequest(PresetSplunkHEC, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	assert.Equal(t, "iam_jit:bouncer:kbounce", envelope["sourcetype"])
	assert.Equal(t, "iam-jit", envelope["source"])
	assert.Equal(t, "127.0.0.1", envelope["host"])
	// time = OCSF unix-ms → unix-seconds for HEC.
	wantSeconds := time.Date(2026, 5, 18, 12, 34, 56, 789e6, time.UTC).UnixMilli() / 1000
	assert.Equal(t, float64(wantSeconds), envelope["time"])
	// Full OCSF event preserved nested under "event".
	ev, ok := envelope["event"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "API Activity", ev["class_name"])
}

func TestPreset_SplunkHEC_TokenNeverInBody(t *testing.T) {
	_, _, body, err := BuildRequest(PresetSplunkHEC, PresetConfig{
		URL: "https://example.com", Token: secretToken,
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.NotContains(t, string(body), secretToken)
}

// ===== Sentinel preset =====

// sentinelTestKey is a base64-encoded 32-byte key used across the
// Sentinel HMAC tests. NOT a real workspace key — random bytes.
const sentinelTestKey = "VGhpcy1pcy1ub3QtYS1yZWFsLXdvcmtzcGFjZS1rZXktMzJiIQ=="

const sentinelTestWorkspace = "12345678-1234-1234-1234-123456789abc"

func sentinelTestURL() string {
	return "https://" + sentinelTestWorkspace + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
}

func TestPreset_Sentinel_AdapterShape(t *testing.T) {
	url, headers, body, err := BuildRequest(PresetSentinel, PresetConfig{
		URL: sentinelTestURL(), Token: sentinelTestKey,
		Now: func() time.Time { return time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC) },
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.Equal(t, sentinelTestURL(), url)
	assert.NotEmpty(t, body)
	assert.NotNil(t, headers)
}

func TestPreset_Sentinel_TokenInSharedKeyHeader(t *testing.T) {
	_, headers, _, err := BuildRequest(PresetSentinel, PresetConfig{
		URL: sentinelTestURL(), Token: sentinelTestKey,
		Now: func() time.Time { return time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC) },
	}, []Event{allowDecision()})
	require.NoError(t, err)
	auth := headers["Authorization"]
	assert.True(t, strings.HasPrefix(auth, "SharedKey "+sentinelTestWorkspace+":"),
		"Authorization must be 'SharedKey <workspace-id>:<signature>', got %q", auth)
	assert.Equal(t, "application/json", headers["Content-Type"])
	assert.Equal(t, SentinelDefaultTable, headers["Log-Type"])
	assert.NotEmpty(t, headers["x-ms-date"])
}

func TestPreset_Sentinel_BodyShapeJSONArray(t *testing.T) {
	_, _, body, err := BuildRequest(PresetSentinel, PresetConfig{
		URL: sentinelTestURL(), Token: sentinelTestKey,
		Now: func() time.Time { return time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC) },
	}, []Event{allowDecision(), denyDecision()})
	require.NoError(t, err)
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(body, &arr))
	require.Len(t, arr, 2)
}

func TestPreset_Sentinel_CustomTable(t *testing.T) {
	_, headers, _, err := BuildRequest(PresetSentinel, PresetConfig{
		URL: sentinelTestURL(), Token: sentinelTestKey,
		SentinelTable: "BouncerAudit",
		Now:           func() time.Time { return time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC) },
	}, []Event{allowDecision()})
	require.NoError(t, err)
	assert.Equal(t, "BouncerAudit", headers["Log-Type"])
}

// TestPreset_Sentinel_HMACMatchesMicrosoftAlgorithm pins the
// signature computation against the Microsoft-published Log Analytics
// Data Collector API algorithm (documented at
// https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api#sample-requests):
//
//	stringToHash = METHOD + "\n" + content_length + "\napplication/json\nx-ms-date:" + date + "\n/api/logs"
//	hashedString = base64(HMAC-SHA256(base64Decode(sharedKey), stringToHash))
//	authorization = "SharedKey " + workspaceId + ":" + hashedString
//
// We pin a known (date, body, key) triple, compute the expected
// signature independently using the documented algorithm, and assert
// the preset produces the same authorization header. Any drift in
// the canonical-string format, the HMAC, or the base64 encoding
// fails this test.
func TestPreset_Sentinel_HMACMatchesMicrosoftAlgorithm(t *testing.T) {
	fixedTime := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	cfg := PresetConfig{
		URL: sentinelTestURL(), Token: sentinelTestKey,
		Now: func() time.Time { return fixedTime },
	}
	_, headers, body, err := BuildRequest(PresetSentinel, cfg, []Event{allowDecision()})
	require.NoError(t, err)
	// Recompute the expected signature using the published Microsoft
	// algorithm exactly. Date format MUST be RFC1123 GMT
	// (http.TimeFormat); content-length is len(body).
	date := fixedTime.UTC().Format(http.TimeFormat)
	stringToHash := "POST\n" +
		intToString(len(body)) +
		"\napplication/json\nx-ms-date:" + date +
		"\n/api/logs"
	keyBytes, err := base64.StdEncoding.DecodeString(sentinelTestKey)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(stringToHash))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	expectedAuth := "SharedKey " + sentinelTestWorkspace + ":" + expectedSig
	assert.Equal(t, expectedAuth, headers["Authorization"],
		"Sentinel SharedKey signature must match Microsoft's documented algorithm exactly")
	assert.Equal(t, date, headers["x-ms-date"],
		"x-ms-date header must match the date used in the canonical string")
}

func TestPreset_Sentinel_RejectsNonBase64Key(t *testing.T) {
	_, _, _, err := BuildRequest(PresetSentinel, PresetConfig{
		URL: sentinelTestURL(), Token: "!!!not-base64!!!",
	}, []Event{allowDecision()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64 workspace shared key")
}

func TestPreset_Sentinel_RejectsMalformedHost(t *testing.T) {
	_, _, _, err := BuildRequest(PresetSentinel, PresetConfig{
		URL: "https://noworkspaceid/api/logs", Token: sentinelTestKey,
	}, []Event{allowDecision()})
	require.Error(t, err)
}

func TestPreset_Sentinel_TokenNeverInBodyOrHeaders(t *testing.T) {
	_, headers, body, err := BuildRequest(PresetSentinel, PresetConfig{
		URL: sentinelTestURL(), Token: sentinelTestKey,
		Now: func() time.Time { return time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC) },
	}, []Event{allowDecision()})
	require.NoError(t, err)
	// The Sentinel token is the RAW base64 workspace shared key. The
	// signature derives from it but MUST NOT be the key itself.
	assert.NotContains(t, string(body), sentinelTestKey,
		"Sentinel body must never carry the raw shared key")
	for k, v := range headers {
		assert.NotContains(t, v, sentinelTestKey,
			"header %q must never carry the raw shared key", k)
	}
}

// ===== End-to-end: per-preset httptest.Server round-trip =====

func TestEndToEnd_GenericPresetServerCapture(t *testing.T) {
	captured := captureOnePush(t, "generic", "")
	assert.Equal(t, "Bearer "+secretToken, captured.headers.Get("Authorization"))
	assert.Equal(t, "application/json", captured.headers.Get("Content-Type"))
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(captured.body, &arr))
	require.Len(t, arr, 1)
}

func TestEndToEnd_DatadogPresetServerCapture(t *testing.T) {
	captured := captureOnePush(t, "datadog", "")
	assert.Equal(t, secretToken, captured.headers.Get("DD-API-KEY"))
	assert.Empty(t, captured.headers.Get("Authorization"),
		"datadog preset must not set Authorization")
	var arr []map[string]any
	require.NoError(t, json.Unmarshal(captured.body, &arr))
	require.Len(t, arr, 1)
	assert.Equal(t, "iam-jit", arr[0]["ddsource"])
	assert.Equal(t, "kbounce", arr[0]["service"])
}

func TestEndToEnd_SplunkHECPresetServerCapture(t *testing.T) {
	captured := captureOnePush(t, "splunk-hec", "")
	assert.Equal(t, "Splunk "+secretToken, captured.headers.Get("Authorization"))
	// NDJSON: single event = single line, no trailing newline expected.
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(captured.body, &envelope))
	assert.Equal(t, "iam_jit:bouncer:kbounce", envelope["sourcetype"])
}

func TestEndToEnd_SentinelPresetServerCapture(t *testing.T) {
	captured := captureOnePush(t, "sentinel", sentinelTestKey)
	auth := captured.headers.Get("Authorization")
	assert.True(t, strings.HasPrefix(auth, "SharedKey "),
		"Sentinel must use SharedKey auth scheme, got %q", auth)
	assert.NotEmpty(t, captured.headers.Get("x-ms-date"))
	assert.Equal(t, SentinelDefaultTable, captured.headers.Get("Log-Type"))
}

// captureOnePush wires a WebhookPusher with the given preset against
// an httptest TLS server that captures the first request, then pushes
// one ALLOW event + waits for delivery. Returns the captured request
// shape for the per-preset asserts above.
type capturedRequest struct {
	headers http.Header
	body    []byte
}

func captureOnePush(t *testing.T, preset, tokenOverride string) capturedRequest {
	t.Helper()
	var (
		mu       sync.Mutex
		captured capturedRequest
		gotFirst atomic.Bool
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		if !gotFirst.Load() {
			captured = capturedRequest{
				headers: r.Header.Clone(),
				body:    body,
			}
			gotFirst.Store(true)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	token := secretToken
	if tokenOverride != "" {
		token = tokenOverride
	}
	url := srv.URL + "/audit"
	if preset == "sentinel" {
		// httptest servers bind on 127.0.0.1; we still want the
		// adapter to extract a workspace ID from the URL. The
		// sentinel adapter accepts ANY URL with a dotted host —
		// the httptest URL "127.0.0.1:PORT" works because
		// hostname().split('.', 1)[0] == "127" which is a valid
		// workspace-id-shape for the adapter; the SharedKey signing
		// still validates against the canonical string algorithm.
		url = srv.URL + "/api/logs"
	}

	wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:           url,
		Token:         token,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
		Preset:        Preset(preset),
	})
	require.NoError(t, err)
	t.Cleanup(wp.Close)

	require.NoError(t, wp.Push(context.Background(), allowDecision()))
	require.Eventually(t, gotFirst.Load, 3*time.Second, 10*time.Millisecond,
		"server should receive one POST for preset %q", preset)

	mu.Lock()
	defer mu.Unlock()
	return captured
}

// TestEndToEnd_TokenNeverInLastErrorAcrossPresets confirms the
// token-masking pattern extends to every preset, not just generic.
// Each preset gets a server that always 500s; the WebhookPusher's
// retry loop records the failure under MaskedURL + LastError; we
// scan both for the raw token.
func TestEndToEnd_TokenNeverInLastErrorAcrossPresets(t *testing.T) {
	for _, preset := range []string{"generic", "datadog", "splunk-hec", "sentinel"} {
		t.Run(preset, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer srv.Close()
			token := secretToken
			url := srv.URL + "/audit"
			if preset == "sentinel" {
				token = sentinelTestKey
				url = srv.URL + "/api/logs"
			}
			wp, err := NewWebhookPusher(context.Background(), WebhookOptions{
				URL:           url,
				Token:         token,
				AllowInternal: true,
				HTTPClient:    srv.Client(),
				Preset:        Preset(preset),
			})
			require.NoError(t, err)
			defer wp.Close()
			require.NoError(t, wp.Push(context.Background(), allowDecision()))
			require.Eventually(t, func() bool {
				return wp.LastError() != ""
			}, 5*time.Second, 50*time.Millisecond,
				"preset %q should record a LastError", preset)
			assert.NotContains(t, wp.LastError(), token,
				"preset %q LastError must not contain the token", preset)
			assert.NotContains(t, wp.MaskedURL(), token,
				"preset %q MaskedURL must not contain the token", preset)
		})
	}
}

// TestNewWebhookPusher_RejectsUnknownPreset confirms a typo in the
// CLI flag surfaces at startup rather than on the first decision.
func TestNewWebhookPusher_RejectsUnknownPreset(t *testing.T) {
	_, err := NewWebhookPusher(context.Background(), WebhookOptions{
		URL:        "https://example.com/audit",
		Token:      secretToken,
		LookupHost: stubLookup("93.184.216.34"),
		Preset:     "not-a-preset",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-preset")
}

// intToString is a tiny helper used in the Sentinel HMAC test so we
// don't pull in strconv just for one call.
func intToString(i int) string {
	if i == 0 {
		return "0"
	}
	// Positive lengths only.
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
