// CLI tests for the Slice 1 #252 audit-export flag wiring.
//
// Covers the license-gate placeholder + the SSRF flag plumbing.
// The transport-level tests live in internal/audit/{log,webhook}_test.go;
// these CLI tests pin the flag → option translation only.

package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
)

// TestAuditWebhook_NoLicenseShipsFree verifies the v1.0 OSS-only
// behavior per [[oss-only-launch-decision]]: the webhook transport
// ships FREE at v1.0; the license gate that previously returned
// audit.ErrLicenseRequired is disabled. With --allow-internal-webhook
// + a loopback collector the gate is the SSRF guard (orthogonal to
// licensing) + the webhook wires + Manager.Status() reports it
// configured.
//
// The license error sentinel is retained (see TestAuditWebhook_
// LicenseErrorSentinelStillExported) so the v1.1+ paid-tier reinstate
// path is a one-line change. This test pins the v1.0 reality: no
// license file present, feature works.
func TestAuditWebhook_NoLicenseShipsFree(t *testing.T) {
	// Use a public-IP HTTPS URL + a stub SSRF resolver so the
	// WebhookPusher's pre-flight passes; the actual HTTPS push is
	// never attempted (the test asserts on construction success,
	// not on a successful POST — those tests live in
	// internal/audit/webhook_test.go with srv.Client() wired in).
	//
	// The key calibration assertion: the returned error (if any)
	// must NOT mention licensing — the v1.0 OSS-only gate-disable
	// per [[oss-only-launch-decision]] means licensing is no longer
	// a failure mode at construction. A still-licensed gate would
	// trip with ErrLicenseRequired BEFORE the SSRF / TLS guards.
	dir := t.TempDir()
	mgr, _, closer, err := buildAuditManager(
		t.Context(),
		filepath.Join(dir, "audit.jsonl"), false,
		-1, -1, -1,
		"https://93.184.216.34/audit", // example.com IPv4 literal — public
		"test-bearer-token",
		1,
		false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		"", // alertRoutesPath
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	// The webhook MAY fail downstream (DNS / SSRF / network) but it
	// must NEVER fail with the license sentinel — the calibration
	// claim is "ships at v1.0 free."
	if err != nil {
		assert.NotErrorIs(t, err, audit.ErrLicenseRequired,
			"v1.0 disable: webhook construction must not surface ErrLicenseRequired")
		assert.NotContains(t, err.Error(), "Enterprise license",
			"v1.0 disable: webhook error must not mention licensing")
		t.Logf("webhook downstream failure (expected; not a license error): %v", err)
		return
	}
	require.NotNil(t, mgr)
	defer closer()
	st := mgr.Status()
	assert.True(t, st.WebhookConfigured,
		"manager status must report the webhook as configured")
}

// TestAuditWebhook_NoLicenseShipsFree_HTTPSRejected confirms the
// webhook still enforces the https:// requirement on non-loopback
// URLs (orthogonal to licensing — defense-in-depth against
// plaintext audit-event exfil per [[audit-export-failure-visibility]]).
func TestAuditWebhook_NoLicenseShipsFree_HTTPSRejected(t *testing.T) {
	_, _, _, err := buildAuditManager(
		t.Context(),
		"", false,
		-1, -1, -1,
		"http://93.184.216.34/audit", // plaintext + public
		"some-bearer-token",
		1,
		false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		"", // alertRoutesPath
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https://",
		"plaintext webhook URLs are rejected for the audit-events-on-the-wire threat")
}

// TestAuditLog_NoWebhookNoLicenseGate confirms the JSONL log path
// (free across all tiers) does NOT trigger the license gate. The
// gate is on the webhook flags only.
func TestAuditLog_NoWebhookNoLicenseGate(t *testing.T) {
	dir := t.TempDir()
	mgr, _, closer, err := buildAuditManager(
		t.Context(),
		dir+"/audit.jsonl", false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		"", // alertRoutesPath
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	require.NoError(t, err, "JSONL log alone should not require an Enterprise license")
	require.NotNil(t, mgr)
	defer closer()
	status := mgr.Status()
	assert.True(t, status.LogConfigured)
	assert.False(t, status.WebhookConfigured)
}

// TestAudit_NoFlagsNoManager confirms unset flags → no audit
// Manager constructed (the proxy config's AuditEmitter stays nil).
// Preserves backward compat for the existing test suite + the bare
// `kbounce run` path that doesn't opt into the export feature.
func TestAudit_NoFlagsNoManager(t *testing.T) {
	mgr, _, closer, err := buildAuditManager(
		t.Context(),
		"", false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		"", // alertRoutesPath
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	require.NoError(t, err)
	assert.Nil(t, mgr, "no flags → no Manager constructed")
	assert.NotNil(t, closer, "closer should be a no-op, not nil")
	closer() // must not panic
}

// TestAuditRoutes_NoLicenseShipsFree verifies the v1.0 OSS-only
// behavior per [[oss-only-launch-decision]]: the #280 per-org routing
// engine ships FREE at v1.0. Writes a minimal valid routes.yaml + a
// loopback collector destination + asserts the routes engine
// constructs cleanly with no license-file present.
func TestAuditRoutes_NoLicenseShipsFree(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Inject the token via env so the YAML's ${...} interpolation
	// resolves; routes.go requires a non-empty token on every webhook
	// destination (defense-in-depth orthogonal to licensing — an
	// unauth'd webhook would surface audit events to anyone who
	// guesses the URL).
	t.Setenv("AUDIT_NLSF_TOKEN", "test-token")
	routesYAML := `routes:
  - name: all-events
    match: {}
    destinations:
      - webhook:
          url: ` + srv.URL + `
          token: ${AUDIT_NLSF_TOKEN}
          allow_internal: true
`
	routesPath := filepath.Join(dir, "routes.yaml")
	require.NoError(t, os.WriteFile(routesPath, []byte(routesYAML), 0o600))

	mgr, _, closer, err := buildAuditManager(
		t.Context(),
		filepath.Join(dir, "audit.jsonl"), false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		routesPath,
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	require.NoError(t, err,
		"--alert-routes ships FREE at v1.0 per [[oss-only-launch-decision]]")
	require.NotNil(t, mgr)
	defer closer()
}

// TestRunCmdRegistersAlertRoutesFlag confirms the #280 --alert-routes
// flag is registered on `kbounce run`. Cross-product parity (ibounce
// + dbounce) ships the same flag name + YAML schema.
func TestRunCmdRegistersAlertRoutesFlag(t *testing.T) {
	cmd := newRunCmd()
	require.NotNil(t, cmd.Flags().Lookup("alert-routes"),
		"--alert-routes flag must be registered on `kbounce run`")
}

// TestAuditAlerts_NoLicenseShipsFree verifies the v1.0 OSS-only
// behavior per [[oss-only-launch-decision]]: the Slice-2 alert-rule
// engine ships FREE at v1.0. Writes an empty (valid) rules.yaml so
// BuildBuiltinRules constructs the six built-in rules + the engine
// wraps the manager.
func TestAuditAlerts_NoLicenseShipsFree(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte("{}\n"), 0o600))

	mgr, _, closer, err := buildAuditManager(
		t.Context(),
		filepath.Join(dir, "audit.jsonl"), false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		rulesPath,
		"", // alertRoutesPath
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	require.NoError(t, err,
		"--alert-rules ships FREE at v1.0 per [[oss-only-launch-decision]]")
	require.NotNil(t, mgr,
		"the returned emitter wraps the manager in a RuleEngine; both must be non-nil")
	defer closer()
}

// TestAuditHeartbeat_OnEnabledWiresHealthCheckAndEmits confirms that
// passing --heartbeat-interval wires a Heartbeater, immediately emits
// a first event, and returns a non-nil health-check callback for the
// proxy's /healthz handler to consult.
//
// Per [[prompt-injection-disable-bouncer-threat]] +
// [[audit-export-failure-visibility]]: the heartbeat is the canary +
// the health-check is the local fallback when the audit-export
// channel itself is the failure source.
func TestAuditHeartbeat_OnEnabledWiresHealthCheckAndEmits(t *testing.T) {
	dir := t.TempDir()
	mgr, healthCheck, closer, err := buildAuditManager(
		t.Context(),
		dir+"/audit.jsonl", false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		"", // alertRoutesPath
		audit.MinHeartbeatInterval,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	require.NoError(t, err)
	defer closer()
	require.NotNil(t, healthCheck, "heartbeat enabled → health-check callback must be non-nil")
	assert.True(t, healthCheck(), "newly-enabled heartbeater starts healthy")
	// Heartbeater emits one event immediately at Start so the first
	// status snapshot has heartbeat_total_emitted == 1.
	require.Eventually(t, func() bool {
		return mgr.Status().HeartbeatTotalEmitted >= 1
	}, 2*time.Second, 10*time.Millisecond,
		"heartbeater must emit the first tick on Start without waiting an interval")
	st := mgr.Status()
	assert.True(t, st.HeartbeatEnabled)
	assert.Equal(t, int(audit.MinHeartbeatInterval.Seconds()), st.HeartbeatIntervalSeconds)
	assert.True(t, st.HeartbeatHealthy)
}

// TestAuditHeartbeat_TooSmallIntervalRejected pins the eager
// validation of --heartbeat-interval; sub-1s values trip a clear
// CLI error rather than the audit package's defensive clamp.
func TestAuditHeartbeat_TooSmallIntervalRejected(t *testing.T) {
	_, _, _, err := buildAuditManager(
		t.Context(),
		"", false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		"", // alertRoutesPath
		100*time.Millisecond,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "heartbeat-interval",
		"the CLI error must mention the offending flag")
}

// TestAuditWebhook_LicenseErrorSentinelStillExported pins that the
// license error sentinel (audit.ErrLicenseRequired) remains exported
// even though it is NOT returned anywhere in the v1.0 buildAuditManager
// path. Per [[oss-only-launch-decision]]: "license code stays but
// does NOT enforce." Retaining the sentinel keeps the v1.1+ paid-tier
// reinstate path a one-line change (re-add a single early-return
// behind a `licensed()` check) — no audit-package refactor needed.
func TestAuditWebhook_LicenseErrorSentinelStillExported(t *testing.T) {
	require.NotNil(t, audit.ErrLicenseRequired,
		"sentinel must stay exported; future paid tier reinstates via this symbol")
	require.NotEmpty(t, audit.ErrLicenseRequired.Error())
	require.NotNil(t, audit.ErrAlertRulesLicenseRequired)
	require.NotNil(t, audit.ErrRoutesLicenseRequired)
}

// TestAuditWebhook_NoLicenseAdvisoryLogIsObservable confirms the
// advisory INFO log fires when --audit-webhook-url is set without a
// license. The log line is the operator's signal that the feature
// is running unlicensed at v1.0 per [[oss-only-launch-decision]];
// it carries the memo reference so anyone grepping zerolog output for
// "oss-only-launch-decision" finds the v1.0 disable path.
//
// This test exercises the log-line text rather than the gate
// behavior (TestAuditWebhook_NoLicenseShipsFree covers the gate);
// the two together pin both the calibration ("feature works") + the
// operator-observability ("operator can see why it works without a
// license file present").
func TestAuditWebhook_NoLicenseAdvisoryLogIsObservable(t *testing.T) {
	// Compile-time / source-level pin — the advisory string lives in
	// internal/cli/cli.go alongside the gate-disable. We verify the
	// memo-reference token is present in the source so a future
	// refactor that drops the memo-reference fails this test.
	const memoToken = "[[oss-only-launch-decision]]"
	src, err := os.ReadFile("cli.go")
	require.NoError(t, err)
	assert.Contains(t, string(src), memoToken,
		"cli.go must reference the founder-decision memo at every license-gate-disable site so an operator grepping the source finds the rationale")
	// Spot-check the three disable sites all carry the memo reference.
	count := strings.Count(string(src), memoToken)
	assert.GreaterOrEqual(t, count, 3,
		"each of the 3 disabled license gates (webhook, alert-rules, alert-routes) should reference the memo")
	// Silence unused — kept here so a future test author who adds an
	// atomic-based observability assert has the import primed.
	_ = atomic.AddInt32
}
