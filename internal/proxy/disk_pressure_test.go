// disk_pressure_test.go — proxy-layer integration tests for the
// #461 / §A63c disk-pressure circuit breaker.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/kbouncer/internal/audit"
)

// TestHealthzIncludesAuditLogBlock asserts /healthz emits the
// audit_log block when DiskPressure is wired.
func TestHealthzIncludesAuditLogBlock(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// Drive a tick at 20% used so we have observation data.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatForProxy(20.0), time.Now())
	srv := NewServer(Config{DiskPressure: st}.Normalize(), freshStore(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Code = %d; want 200", rec.Code)
	}
	body := rec.Body.Bytes()
	for _, want := range []string{
		`"audit_log"`,
		`"disk_pressure_mode":"pause-requests"`,
		`"refuse_requests":false`,
		`"current_archive_count":`,
		`"current_archive_size_bytes":`,
		`"warn_pct":`,
		`"crit_pct":`,
		`"emergency_pct":`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("/healthz body missing %s\nbody=%s", want, body)
		}
	}
}

// TestHealthz503AtCriticalInPauseMode asserts the response flips to
// 503 when refuse_requests is true (98.5% crosses default crit=98%).
func TestHealthz503AtCriticalInPauseMode(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatForProxy(98.5), time.Now())
	srv := NewServer(Config{DiskPressure: st}.Normalize(), freshStore(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Code = %d; want 503", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"refuse_requests":true`) {
		t.Errorf("/healthz body missing refuse_requests=true: %s", body)
	}
	if !strings.Contains(body, `"status":"critical"`) {
		t.Errorf("/healthz body missing status=critical: %s", body)
	}
}

// TestHandle_DiskPressurePauseReturns503WithStructuredDeny asserts the
// request hot path refuses with 503 + the #459 structured-deny body
// shape when in pause-requests at critical.
func TestHandle_DiskPressurePauseReturns503WithStructuredDeny(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// 98.5% crosses the crit threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatForProxy(98.5), time.Now())
	srv := NewServer(Config{DiskPressure: st}.Normalize(), freshStore(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/namespaces/default/pods", nil)
	srv.handle(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Code = %d; want 503", rec.Code)
	}
	if got := rec.Header().Get("x-kbouncer-refusal"); got != "disk-pressure-pause" {
		t.Fatalf("x-kbouncer-refusal = %q; want disk-pressure-pause", got)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v\nraw=%s", err, rec.Body.String())
	}
	// #459 structured-deny shape merged into the body.
	if got := body["caught_by_bouncer"]; got != "kbouncer" {
		t.Fatalf("caught_by_bouncer = %v; want kbouncer", got)
	}
	if _, ok := body["recommended_action"]; !ok {
		t.Fatal("body missing recommended_action key")
	}
	if _, ok := body["structured_deny_schema_version"]; !ok {
		t.Fatal("body missing structured_deny_schema_version key")
	}
	// Disk-pressure metadata is attached so an operator-side diag tool
	// can grep the same body for the disk-state context.
	if _, ok := body["disk_pressure"]; !ok {
		t.Fatal("body missing disk_pressure block")
	}
	if got := body["reason"]; got != "ServiceUnavailable" {
		t.Fatalf("reason = %v; want ServiceUnavailable", got)
	}
	// Message LEADS with operator-friendly framing per
	// [[ambient-value-prop-and-friction-framing]] — no "ERROR" /
	// "BLOCKED" prefix.
	msg, _ := body["message"].(string)
	if !strings.Contains(msg, "bouncer paused") {
		t.Fatalf("message = %q; want 'bouncer paused' framing", msg)
	}
	if !strings.Contains(msg, "rotate-aggressively") {
		t.Fatalf("message = %q; want 'rotate-aggressively' configuration hint", msg)
	}
}

// TestHandle_DiskPressureRotateAggressivelyPasses asserts non-pause
// modes don't short-circuit the request hot path.
func TestHandle_DiskPressureRotateAggressivelyPasses(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModeRotateAggressively, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStatForProxy(96.0), time.Now())
	srv := NewServer(Config{DiskPressure: st}.Normalize(), freshStore(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/namespaces/default/pods", nil)
	srv.handle(rec, req)
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatal("rotate-aggressively must NOT 503 on disk pressure")
	}
	// We won't assert the inner observation shape — just that we did
	// not get the disk-pressure refusal.
	if got := rec.Header().Get("x-kbouncer-refusal"); got == "disk-pressure-pause" {
		t.Fatal("rotate-aggressively must NOT set disk-pressure-pause refusal header")
	}
}

// fakeDiskStatForProxy is a local helper that re-exports the audit
// package's GetDiskStatus-shaped test seam without exposing it as a
// public symbol on the audit package surface.
func fakeDiskStatForProxy(usedPct float64) func(path string, warnPct, critPct int) (audit.DiskStatus, error) {
	return func(path string, warnPct, critPct int) (audit.DiskStatus, error) {
		return audit.ClassifyDiskStatusForTest(usedPct, warnPct, critPct, path), nil
	}
}
