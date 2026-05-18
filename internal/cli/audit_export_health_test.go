// Tests for `kbounce audit-export health` per [[audit-export-failure-
// visibility]]. Exit-code shape: 0 healthy / 1 degraded / 2 transport
// or parse error.

package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditExportHealth_HealthyReturnsZero confirms a /healthz reply
// with audit_export_healthy=true exits the subcommand cleanly.
func TestAuditExportHealth_HealthyReturnsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","audit_export_healthy":true}`))
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := runAuditExportHealth(context.Background(), srv.URL+"/healthz", false,
		&stdout, &stderr)
	assert.NoError(t, err, "healthy /healthz must exit 0")
	assert.Contains(t, stdout.String(), "OK")
	assert.Empty(t, stderr.String())
}

// TestAuditExportHealth_DegradedReturnsExit1 confirms /healthz
// reporting audit_export_healthy=false yields exit-1 with the
// degradation reason on stderr.
func TestAuditExportHealth_DegradedReturnsExit1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"degraded","audit_export_healthy":false,` +
			`"audit_export_degraded_reason":"log consecutive_failures=99 (threshold=3)"}`))
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := runAuditExportHealth(context.Background(), srv.URL+"/healthz", false,
		&stdout, &stderr)
	require.Error(t, err)
	aehe, ok := err.(*auditExportHealthError)
	require.True(t, ok, "degraded path must return *auditExportHealthError")
	assert.Equal(t, 1, aehe.ExitCode(),
		"degraded must exit 1 (transport error is 2; healthy is 0)")
	assert.Contains(t, stderr.String(), "DEGRADED")
	assert.Contains(t, stderr.String(), "log consecutive_failures=99")
}

// TestAuditExportHealth_TransportErrorReturnsExit2 confirms a
// connection failure exits 2 (distinct from the degraded path).
func TestAuditExportHealth_TransportErrorReturnsExit2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Use a deliberately-unbound port. The OS will refuse the connect.
	err := runAuditExportHealth(context.Background(),
		"http://127.0.0.1:1/healthz", false,
		&stdout, &stderr)
	require.Error(t, err)
	aehe, ok := err.(*auditExportHealthError)
	require.True(t, ok, "transport error must return *auditExportHealthError")
	assert.Equal(t, 2, aehe.ExitCode(),
		"transport error must exit 2 (distinct from healthy/0 + degraded/1)")
	assert.Contains(t, stderr.String(), "could not reach")
	assert.Contains(t, stderr.String(), "is kbounce running?")
}

// TestAuditExportHealth_BadJSONExitsTwo confirms a parse failure on
// /healthz body lands in the transport-error bucket (exit 2) rather
// than silently passing.
func TestAuditExportHealth_BadJSONExitsTwo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not-json-at-all`))
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := runAuditExportHealth(context.Background(), srv.URL+"/healthz", false,
		&stdout, &stderr)
	require.Error(t, err)
	aehe, ok := err.(*auditExportHealthError)
	require.True(t, ok)
	assert.Equal(t, 2, aehe.ExitCode())
	assert.Contains(t, stderr.String(), "parse /healthz JSON")
}

// TestAuditExportHealth_MissingReasonStillExits1 confirms a degraded
// /healthz reply WITHOUT a populated audit_export_degraded_reason
// still exits 1 (with a placeholder reason) rather than swallowing
// the degraded signal because the reason field was empty.
func TestAuditExportHealth_MissingReasonStillExits1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"degraded","audit_export_healthy":false}`))
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := runAuditExportHealth(context.Background(), srv.URL+"/healthz", false,
		&stdout, &stderr)
	require.Error(t, err)
	aehe, ok := err.(*auditExportHealthError)
	require.True(t, ok)
	assert.Equal(t, 1, aehe.ExitCode())
	assert.True(t,
		strings.Contains(stderr.String(), "DEGRADED") &&
			strings.Contains(stderr.String(), "no reason surfaced"),
		"missing reason field should still surface a placeholder + exit 1")
}

// TestAuditExportHealth_503WithoutAuditFieldStillExits1 confirms an
// older proxy that returns 503 without the new audit_export_healthy
// field still exits 1 — HTTP status takes precedence so legacy
// /healthz shapes are handled gracefully.
func TestAuditExportHealth_503WithoutAuditFieldStillExits1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"degraded"}`))
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := runAuditExportHealth(context.Background(), srv.URL+"/healthz", false,
		&stdout, &stderr)
	require.Error(t, err)
	aehe, ok := err.(*auditExportHealthError)
	require.True(t, ok)
	assert.Equal(t, 1, aehe.ExitCode(),
		"503 status code should always be treated as degraded regardless of body shape")
}
