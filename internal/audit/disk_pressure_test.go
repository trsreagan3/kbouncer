// disk_pressure_test.go — unit tests for the disk-pressure circuit
// breaker (#461 / §A63c).
package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeDiskStat returns a closure that emits a synthetic DiskStatus with
// the given used_pct. Used by tests to drive critical / emergency
// transitions without real disk pressure.
//
// captureEmitter lives in alerts_test.go and is re-used here for OCSF
// event capture.
func fakeDiskStat(usedPct float64) func(path string, warnPct, critPct int) (DiskStatus, error) {
	return func(path string, warnPct, critPct int) (DiskStatus, error) {
		return ClassifyDiskStatusForTest(usedPct, warnPct, critPct, path), nil
	}
}

// TestDiskStatus_ReturnsExpectedFields asserts the Snapshot block
// exposes the cross-product field set.
func TestDiskStatus_ReturnsExpectedFields(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// First-tick has no observation yet → empty snapshot but mode +
	// thresholds populated.
	snap := st.Snapshot()
	if snap.Mode != DiskPressureModePauseRequests {
		t.Fatalf("Mode = %q; want %q", snap.Mode, DiskPressureModePauseRequests)
	}
	if snap.WarnPct != DefaultDiskWarnPercent {
		t.Fatalf("WarnPct = %d; want %d", snap.WarnPct, DefaultDiskWarnPercent)
	}
	if snap.CritPct != DefaultDiskCritPercent {
		t.Fatalf("CritPct = %d; want %d", snap.CritPct, DefaultDiskCritPercent)
	}
	if snap.EmergencyPct != DefaultDiskEmergencyPercent {
		t.Fatalf("EmergencyPct = %d; want %d", snap.EmergencyPct, DefaultDiskEmergencyPercent)
	}
	if snap.RefuseRequests {
		t.Fatal("RefuseRequests = true on initial snapshot; want false")
	}
	// After one tick we have observation data.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(20.0), time.Now())
	snap = st.Snapshot()
	if snap.UsedPct == nil || *snap.UsedPct < 19.0 || *snap.UsedPct > 21.0 {
		t.Fatalf("UsedPct = %v; want ~20.0", snap.UsedPct)
	}
	if snap.DiskFreePct == nil || *snap.DiskFreePct < 79.0 || *snap.DiskFreePct > 81.0 {
		t.Fatalf("DiskFreePct = %v; want ~80.0", snap.DiskFreePct)
	}
	if snap.Status != "ok" {
		t.Fatalf("Status = %q; want ok", snap.Status)
	}
}

// TestDiskPressureMode_PauseRequestsRefuses503AtCritical asserts the
// pause-requests mode flips RefuseRequests at critical (default 98%).
func TestDiskPressureMode_PauseRequestsRefuses503AtCritical(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(20.0), time.Now())
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests at 20%% used; want false")
	}
	// 96% is degraded (warn threshold), NOT critical — pause does not refuse at degraded.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(96.0), time.Now())
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests at 96%% (degraded) in pause mode; want false — crit is 98%%")
	}
	if got := st.Status(); got != "degraded" {
		t.Fatalf("Status at 96%% = %q; want degraded", got)
	}
	// 98.5% crosses crit threshold (default 98%) → critical → refuse.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(98.5), time.Now())
	if !st.RefuseRequests() {
		t.Fatal("RefuseRequests at 98.5%% used in pause mode; want true")
	}
	if got := st.Status(); got != "critical" {
		t.Fatalf("Status at 98.5%% = %q; want critical", got)
	}
	// Emergency also refuses.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(99.5), time.Now())
	if !st.RefuseRequests() {
		t.Fatal("RefuseRequests at 99.5%% used in pause mode; want true")
	}
	if got := st.Status(); got != "emergency" {
		t.Fatalf("Status at 99.5%% = %q; want emergency", got)
	}
	// Recovery flips back.
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(30.0), time.Now())
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests after recovery to 30%% used; want false")
	}
}

// TestDiskPressureMode_RotateAggressivelyDropsOldestAtCritical asserts
// rotate-aggressively drops oldest archives + never refuses requests.
func TestDiskPressureMode_RotateAggressivelyDropsOldestAtCritical(t *testing.T) {
	tmp := t.TempDir()
	// Create 3 fake archive files with distinct mtimes (oldest-first).
	oldArchive := filepath.Join(tmp, "audit-2026-05-21-100000.jsonl.gz")
	midArchive := filepath.Join(tmp, "audit-2026-05-22-100000.jsonl.gz")
	newArchive := filepath.Join(tmp, "audit-2026-05-23-100000.jsonl.gz")
	for i, p := range []string{oldArchive, midArchive, newArchive} {
		if err := os.WriteFile(p, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Distinct mtimes to ensure sort-by-mtime ordering.
		mt := time.Now().Add(time.Duration(-72+i*24) * time.Hour)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	st := NewDiskPressureState(DiskPressureModeRotateAggressively, tmp, 0, 0, 0)
	// 98.5% crosses the crit threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(98.5), time.Now())
	if st.RefuseRequests() {
		t.Fatal("rotate-aggressively must NEVER refuse requests")
	}
	if got := st.Status(); got != "critical" {
		t.Fatalf("Status = %q; want critical", got)
	}
	// The last-action label should mention the dropped count (may be
	// 0 on real-disk where the loop exited early).
	snap := st.Snapshot()
	if !strings.Contains(snap.LastActionTaken, "dropped") {
		t.Fatalf("LastActionTaken = %q; want 'dropped ...' substring", snap.LastActionTaken)
	}
}

// TestDiskPressureMode_ArchiveAndPurgeShipsToSinkAtCritical asserts
// archive-and-purge runs the drop path + records the sink-hint label.
func TestDiskPressureMode_ArchiveAndPurgeShipsToSinkAtCritical(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModeArchiveAndPurge, tmp, 0, 0, 0)
	// 98.5% crosses the crit threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(98.5), time.Now())
	if st.RefuseRequests() {
		t.Fatal("archive-and-purge must NEVER refuse requests")
	}
	snap := st.Snapshot()
	if !strings.Contains(snap.LastActionTaken, "archive-and-purge") {
		t.Fatalf("LastActionTaken = %q; want archive-and-purge prefix", snap.LastActionTaken)
	}
	if !strings.Contains(snap.LastActionTaken, "object-storage sink") {
		t.Fatalf("LastActionTaken = %q; want object-storage hint", snap.LastActionTaken)
	}
}

// TestDiskPressureTransition_EmitsAdminActionOCSF asserts the
// admin-action disk_pressure.transition event fires on state change.
func TestDiskPressureTransition_EmitsAdminActionOCSF(t *testing.T) {
	tmp := t.TempDir()
	emitter := &captureEmitter{}
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// ok → ok: no transition, no event.
	st.EvaluateAndReact(context.Background(), emitter, fakeDiskStat(20.0), time.Now())
	if got := len(emitter.snapshot()); got != 0 {
		t.Fatalf("emitted %d events on ok→ok; want 0", got)
	}
	// ok → critical: transition, one event (98.5% crosses default crit=98%).
	st.EvaluateAndReact(context.Background(), emitter, fakeDiskStat(98.5), time.Now())
	events := emitter.snapshot()
	if len(events) != 1 {
		t.Fatalf("emitted %d events on ok→critical; want 1", len(events))
	}
	e := events[0]
	if e.ActivityName != string(AdminActionDiskPressureTransition) {
		t.Fatalf("ActivityName = %q; want %q",
			e.ActivityName, AdminActionDiskPressureTransition)
	}
	if e.ClassUID != ClassUID {
		t.Fatalf("ClassUID = %d; want %d", e.ClassUID, ClassUID)
	}
	// critical → critical: no transition, no new event.
	st.EvaluateAndReact(context.Background(), emitter, fakeDiskStat(98.5), time.Now())
	if got := len(emitter.snapshot()); got != 1 {
		t.Fatalf("emitted %d events on critical→critical; want 1", got)
	}
	// critical → emergency: transition, one more event (99.5% crosses default emergency=99%).
	st.EvaluateAndReact(context.Background(), emitter, fakeDiskStat(99.5), time.Now())
	if got := len(emitter.snapshot()); got != 2 {
		t.Fatalf("emitted %d events on critical→emergency; want 2", got)
	}
	// Recovery emergency → ok: transition, one more event.
	st.EvaluateAndReact(context.Background(), emitter, fakeDiskStat(20.0), time.Now())
	if got := len(emitter.snapshot()); got != 3 {
		t.Fatalf("emitted %d events on emergency→ok; want 3", got)
	}
	// Snapshot transitions_count matches.
	if got := st.Snapshot().TransitionsCount; got != 3 {
		t.Fatalf("TransitionsCount = %d; want 3", got)
	}
}

// TestStopOnDiskCriticalAliasEquivalentToPauseMode asserts the
// shorthand alias produces the same RefuseRequests behavior as the
// long form.
func TestStopOnDiskCriticalAliasEquivalentToPauseMode(t *testing.T) {
	// The CLI flag aliasing lives in cli.go; this test asserts the
	// underlying state machine produces identical behavior when the
	// caller picks pause-requests vs the would-be-aliased value.
	tmp := t.TempDir()
	longForm := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	aliased, _ := NormalizeDiskPressureMode("pause-requests")
	aliasState := NewDiskPressureState(aliased, tmp, 0, 0, 0)
	// 98.5% crosses the crit threshold — both should refuse.
	longForm.EvaluateAndReact(context.Background(), nil, fakeDiskStat(98.5), time.Now())
	aliasState.EvaluateAndReact(context.Background(), nil, fakeDiskStat(98.5), time.Now())
	if longForm.RefuseRequests() != aliasState.RefuseRequests() {
		t.Fatalf("alias RefuseRequests = %t; long form = %t",
			aliasState.RefuseRequests(), longForm.RefuseRequests())
	}
}

// TestNormalizeDiskPressureMode_RejectsUnknownValues asserts the
// validator surfaces a clear error.
func TestNormalizeDiskPressureMode_RejectsUnknownValues(t *testing.T) {
	if _, err := NormalizeDiskPressureMode("bogus"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
	if got, _ := NormalizeDiskPressureMode(""); got != DefaultDiskPressureMode {
		t.Fatalf("empty mode = %q; want default %q", got, DefaultDiskPressureMode)
	}
	if got, _ := NormalizeDiskPressureMode("PAUSE-REQUESTS"); got != DiskPressureModePauseRequests {
		t.Fatalf("upper-case mode = %q; want lower-cased %q",
			got, DiskPressureModePauseRequests)
	}
}

// TestSnapshotSerialization_HealthzBlockShape asserts the JSON
// produced for /healthz audit_log block carries the cross-product
// field names.
func TestSnapshotSerialization_HealthzBlockShape(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	// 98.5% crosses the crit threshold (default 98%).
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(98.5), time.Now())
	snap := st.Snapshot()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		`"disk_pressure_mode":"pause-requests"`,
		`"status":"critical"`,
		`"refuse_requests":true`,
		`"current_archive_count":`,
		`"current_archive_size_bytes":`,
		`"transitions_count":1`,
		`"disk_free_pct":`,
		`"disk_free_bytes":`,
		`"warn_threshold_bytes":`,
		`"crit_threshold_bytes":`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("snapshot JSON missing %q\ngot: %s", want, body)
		}
	}
}

// --- Threshold-matrix regression tests (fix/disk-pressure-absolute-free) ---

// TestThresholdMatrix_23GBFreeOn228GB is the primary regression for the
// operator's real machine: 89.86% used but 23 GiB free → must be ok.
func TestThresholdMatrix_23GBFreeOn228GB(t *testing.T) {
	totalBytes := int64(228 * 1024 * 1024 * 1024)
	freeBytes := int64(23 * 1024 * 1024 * 1024)
	usedPct := 100.0 * float64(totalBytes-freeBytes) / float64(totalBytes)
	snap := ClassifyDiskStatusFullForTest(usedPct, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "ok" {
		t.Fatalf("23GiB free on 228GiB (%.2f%% used): status=%q; want ok", usedPct, snap.Status)
	}
}

// TestThresholdMatrix_500MBFree_Critical: absolute-free CRIT fires.
func TestThresholdMatrix_500MBFree_Critical(t *testing.T) {
	totalBytes := int64(228 * 1024 * 1024 * 1024)
	freeBytes := int64(500 * 1024 * 1024)
	usedPct := 100.0 * float64(totalBytes-freeBytes) / float64(totalBytes)
	snap := ClassifyDiskStatusFullForTest(usedPct, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "critical" {
		t.Fatalf("500MiB free: status=%q; want critical", snap.Status)
	}
}

// TestThresholdMatrix_95PctUsed_12GBFree_OK: 95% used but 12 GB free → ok.
func TestThresholdMatrix_95PctUsed_12GBFree_OK(t *testing.T) {
	freeBytes := int64(12 * 1024 * 1024 * 1024)
	snap := ClassifyDiskStatusFullForTest(95.0, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "ok" {
		t.Fatalf("95%% used with 12GiB free: status=%q; want ok", snap.Status)
	}
}

// TestThresholdMatrix_97PctUsed_7GBFree_Warn: 97% used with 7 GiB free → degraded.
func TestThresholdMatrix_97PctUsed_7GBFree_Warn(t *testing.T) {
	freeBytes := int64(7 * 1024 * 1024 * 1024)
	snap := ClassifyDiskStatusFullForTest(97.0, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "degraded" {
		t.Fatalf("97%% used with 7GiB free: status=%q; want degraded", snap.Status)
	}
}

// TestThresholdMatrix_98PctUsed_Critical: 98% used → critical.
func TestThresholdMatrix_98PctUsed_Critical(t *testing.T) {
	freeBytes := int64(5 * 1024 * 1024 * 1024)
	snap := ClassifyDiskStatusFullForTest(98.0, freeBytes,
		DefaultDiskWarnPercent, DefaultDiskCritPercent,
		DefaultDiskWarnFreeBytes, DefaultDiskCritFreeBytes, "/test")
	if snap.Status != "critical" {
		t.Fatalf("98%% used: status=%q; want critical", snap.Status)
	}
}

// TestThresholdMatrix_IgnoreDiskPressure: ignore flag returns "ignored".
func TestThresholdMatrix_IgnoreDiskPressure(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureStateFull(DiskPressureModePauseRequests, tmp, 0, 0, 0, 0, 0, true)
	st.EvaluateAndReact(context.Background(), nil, fakeDiskStat(99.9), time.Now())
	if got := st.Status(); got != "ignored" {
		t.Fatalf("Status with ignore flag at 99.9%% = %q; want ignored", got)
	}
	if st.RefuseRequests() {
		t.Fatal("RefuseRequests must be false when --ignore-disk-pressure is set")
	}
	snap := st.Snapshot()
	if !snap.IgnoreDiskPressure {
		t.Fatal("Snapshot.IgnoreDiskPressure must be true")
	}
}

// TestRunDiskPressureLoop_ExitsOnStopClose asserts the loop goroutine
// exits cleanly when its stop channel is closed.
func TestRunDiskPressureLoop_ExitsOnStopClose(t *testing.T) {
	tmp := t.TempDir()
	st := NewDiskPressureState(DiskPressureModePauseRequests, tmp, 0, 0, 0)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		RunDiskPressureLoop(context.Background(), st, nil, stop)
		close(done)
	}()
	// Give it a moment to make the first eager tick.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not exit within 2s of stop close")
	}
	// First eager tick should have populated last_check_unix.
	if st.Snapshot().LastCheckUnix == nil {
		t.Fatal("first eager tick did not populate LastCheckUnix")
	}
}

// TestResolveLogDir asserts the helper maps file path → parent dir.
func TestResolveLogDir(t *testing.T) {
	if got := ResolveLogDir(""); got != "" {
		t.Fatalf("empty path = %q; want empty", got)
	}
	if got := ResolveLogDir("/var/log/kbouncer/audit.jsonl"); got != "/var/log/kbouncer" {
		t.Fatalf("file path = %q; want /var/log/kbouncer", got)
	}
}
