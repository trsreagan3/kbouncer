// CLI tests for the Slice 1 #252 audit-export flag wiring.
//
// Covers the license-gate placeholder + the SSRF flag plumbing.
// The transport-level tests live in internal/audit/{log,webhook}_test.go;
// these CLI tests pin the flag → option translation only.

package cli

import (
	"strings"
	"testing"

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
	_, _, err := buildAuditManager(
		t.Context(),
		"", false,
		"https://collector.example.com/audit",
		"some-bearer-token",
		1,
		false,
		"generic", "", audit.SentinelDefaultTable,
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
	mgr, closer, err := buildAuditManager(
		t.Context(),
		dir+"/audit.jsonl", false,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
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
	mgr, closer, err := buildAuditManager(
		t.Context(),
		"", false,
		"", "", 1, false,
		"generic", "", audit.SentinelDefaultTable,
	)
	require.NoError(t, err)
	assert.Nil(t, mgr, "no flags → no Manager constructed")
	assert.NotNil(t, closer, "closer should be a no-op, not nil")
	closer() // must not panic
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
