// CLI tests for the Slice 1 #252 audit-export flag wiring.
//
// Covers the license-gate placeholder + the SSRF flag plumbing.
// The transport-level tests live in internal/audit/{log,webhook}_test.go;
// these CLI tests pin the flag → option translation only.

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
)

// TestAuditWebhook_LicensePlaceholderRejects pins the Enterprise
// license gate per [[security-team-audit-export]]. kbounce does not
// yet have license-file plumbing (#235); until that lands the
// webhook flags MUST be rejected with a clear placeholder error
// rather than silently constructing a webhook + bypassing the
// license check.
func TestAuditWebhook_LicensePlaceholderRejects(t *testing.T) {
	_, _, _, err := buildAuditManager(
		t.Context(),
		"", false,
		-1, -1, -1,
		"https://collector.example.com/audit",
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
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrLicenseRequired,
		"webhook flags must return ErrLicenseRequired until license-file plumbing lands")
	assert.Contains(t, err.Error(), "#235",
		"error message should direct the operator to the tracking issue")
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
	)
	require.NoError(t, err)
	assert.Nil(t, mgr, "no flags → no Manager constructed")
	assert.NotNil(t, closer, "closer should be a no-op, not nil")
	closer() // must not panic
}

// TestAuditRoutes_LicensePlaceholderRejects pins the #280 Enterprise
// license gate for the per-org routing engine. Same placeholder shape
// as the webhook + alert-rules gates; all three wait on #235.
func TestAuditRoutes_LicensePlaceholderRejects(t *testing.T) {
	dir := t.TempDir()
	_, _, _, err := buildAuditManager(
		t.Context(),
		"", false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		"",
		dir+"/routes.yaml",
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrRoutesLicenseRequired,
		"--alert-routes must return ErrRoutesLicenseRequired until license-file plumbing lands")
	assert.Contains(t, err.Error(), "#235",
		"error message should direct the operator to the tracking issue")
}

// TestRunCmdRegistersAlertRoutesFlag confirms the #280 --alert-routes
// flag is registered on `kbounce run`. Cross-product parity (ibounce
// + dbounce) ships the same flag name + YAML schema.
func TestRunCmdRegistersAlertRoutesFlag(t *testing.T) {
	cmd := newRunCmd()
	require.NotNil(t, cmd.Flags().Lookup("alert-routes"),
		"--alert-routes flag must be registered on `kbounce run`")
}

// TestAuditAlerts_LicensePlaceholderRejects pins the Slice 2 Enterprise
// license gate for the alert-rule engine. Same placeholder shape as
// TestAuditWebhook_LicensePlaceholderRejects; both wait on #235.
func TestAuditAlerts_LicensePlaceholderRejects(t *testing.T) {
	dir := t.TempDir()
	_, _, _, err := buildAuditManager(
		t.Context(),
		"", false,
		-1, -1, -1,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
		dir+"/rules.yaml",
		"", // alertRoutesPath
		0,
		"",
		"", "", "", 0,
		"", "", "", "", "", 0, 0, "",
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrAlertRulesLicenseRequired,
		"--alert-rules must return ErrAlertRulesLicenseRequired until license-file plumbing lands")
	assert.Contains(t, err.Error(), "#235",
		"error message should direct the operator to the tracking issue")
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
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "heartbeat-interval",
		"the CLI error must mention the offending flag")
}

// TestAuditWebhook_LicenseErrorMessageSurface pins the error
// message text so an operator reading it gets actionable next
// steps (the issue # to follow, the placeholder caveat).
func TestAuditWebhook_LicenseErrorMessageSurface(t *testing.T) {
	require.NotEmpty(t, audit.ErrLicenseRequired.Error())
	msg := audit.ErrLicenseRequired.Error()
	assert.True(t, strings.Contains(msg, "Enterprise"))
	assert.True(t, strings.Contains(msg, "license"))
	assert.True(t, strings.Contains(msg, "#235"))
}
