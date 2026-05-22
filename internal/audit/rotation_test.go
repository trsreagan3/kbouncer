// Tests for #311 / §A10 — audit-log rotation, retention, recovery.
//
// Mirrors the ibounce test surface in
// iam-roles/tests/bouncer/test_audit_export_rotation.py so the
// cross-product behaviour is verifiable side-by-side. A
// regression in either repo's rotation surface fails its tests +
// the operator-facing runbook in iam-roles/docs/LOG-RETENTION.md
// stays accurate across products.

package audit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------
// Size + age triggers
// -----------------------------------------------------------------

func TestShouldRotateBySize_True(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 2*1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ShouldRotateBySize(p, 1) {
		t.Fatal("expected rotation trigger at 2MB > 1MB")
	}
}

func TestShouldRotateBySize_False(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ShouldRotateBySize(p, 1) {
		t.Fatal("expected no trigger at 5 bytes")
	}
}

func TestShouldRotateBySize_DisabledWhenZero(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 50*1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if ShouldRotateBySize(p, 0) {
		t.Fatal("maxMB=0 must disable the trigger")
	}
}

func TestShouldRotateByAge_TrueWhenOld(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if !ShouldRotateByAge(p, 7, time.Now()) {
		t.Fatal("expected rotation trigger at 10d > 7d")
	}
}

func TestShouldRotateByAge_FalseWhenFresh(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ShouldRotateByAge(p, 7, time.Now()) {
		t.Fatal("expected no trigger at age=0d")
	}
}

// -----------------------------------------------------------------
// Rotate()
// -----------------------------------------------------------------

func TestRotate_MovesAndGzips(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	original := []byte(`{"id":1}` + "\n" + `{"id":2}` + "\n")
	if err := os.WriteFile(p, original, 0o600); err != nil {
		t.Fatal(err)
	}
	archive, err := Rotate(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if archive == "" {
		t.Fatal("expected archive path")
	}
	if !strings.HasSuffix(archive, ".jsonl.gz") {
		t.Fatalf("expected .jsonl.gz suffix, got %s", archive)
	}
	if !strings.HasPrefix(filepath.Base(archive), "audit-") {
		t.Fatalf("expected audit- prefix, got %s", archive)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("active file should be removed after rotation")
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(gz)
	if !bytes.Equal(body, original) {
		t.Fatalf("archive content mismatch: got %q want %q", body, original)
	}
}

func TestRotate_NoopOnMissing(t *testing.T) {
	dir := t.TempDir()
	archive, err := Rotate(filepath.Join(dir, "absent.jsonl"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if archive != "" {
		t.Fatalf("expected empty archive on missing file, got %s", archive)
	}
}

func TestRotate_NoopOnEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	archive, err := Rotate(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if archive != "" {
		t.Fatal("empty file should not produce an archive")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("empty active file should remain in place")
	}
}

// -----------------------------------------------------------------
// RecoverPartialTail()
// -----------------------------------------------------------------

func TestRecoverPartialTail_CleanFileNoop(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte(`{"id":1}`+"\n"+`{"id":2}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := RecoverPartialTail(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 trimmed on clean file, got %d", n)
	}
}

func TestRecoverPartialTail_TruncatesCorruptTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	body := []byte(`{"id":1}` + "\n" + `{"id":2}` + "\n" + `{"id":3`)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := RecoverPartialTail(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(`{"id":3`)) {
		t.Fatalf("expected %d trimmed bytes, got %d", len(`{"id":3`), n)
	}
	after, _ := os.ReadFile(p)
	want := []byte(`{"id":1}` + "\n" + `{"id":2}` + "\n")
	if !bytes.Equal(after, want) {
		t.Fatalf("expected clean body, got %q", after)
	}
}

func TestRecoverPartialTail_MissingFile(t *testing.T) {
	dir := t.TempDir()
	n, err := RecoverPartialTail(filepath.Join(dir, "absent.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("missing file should return 0")
	}
}

func TestRecoverPartialTail_AppendStillWorks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte(`{"id":1}`+"\n"+`{"corrupt`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverPartialTail(p); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"id":2}` + "\n")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	data, _ := os.ReadFile(p)
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("line %q is not valid JSON post-recovery: %v", line, err)
		}
	}
}

// -----------------------------------------------------------------
// PurgeLogsOlderThan()
// -----------------------------------------------------------------

func TestPurgeLogsOlderThan_ReapsOldArchive(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "audit-2026-01-01-000000.jsonl.gz")
	if err := os.WriteFile(archive, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(archive, old, old); err != nil {
		t.Fatal(err)
	}
	removed, err := PurgeLogsOlderThan(dir, 7, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != archive {
		t.Fatalf("expected purge of %s, got %v", archive, removed)
	}
}

func TestPurgeLogsOlderThan_NeverTouchesActive(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(active, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(active, old, old); err != nil {
		t.Fatal(err)
	}
	removed, err := PurgeLogsOlderThan(dir, 7, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("active file must never be purged, got %v", removed)
	}
	if _, err := os.Stat(active); err != nil {
		t.Fatal("active file must still exist")
	}
}

func TestPurgeLogsOlderThan_ReapsDBArchives(t *testing.T) {
	dir := t.TempDir()
	dbArchive := filepath.Join(dir, "audit-2026-01-01.db.gz")
	if err := os.WriteFile(dbArchive, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-60 * 24 * time.Hour)
	if err := os.Chtimes(dbArchive, old, old); err != nil {
		t.Fatal(err)
	}
	removed, err := PurgeLogsOlderThan(dir, 7, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 {
		t.Fatalf("expected db archive purge, got %v", removed)
	}
}

// -----------------------------------------------------------------
// DiskStatus
// -----------------------------------------------------------------

func TestClassifyDiskStatus_OK(t *testing.T) {
	s := ClassifyDiskStatusForTest(50.0, 85, 95, "/tmp")
	if s.Status != "ok" {
		t.Fatalf("expected ok, got %s", s.Status)
	}
}

func TestClassifyDiskStatus_Degraded(t *testing.T) {
	s := ClassifyDiskStatusForTest(90.0, 85, 95, "/tmp")
	if s.Status != "degraded" {
		t.Fatalf("expected degraded at 90%%, got %s", s.Status)
	}
}

func TestClassifyDiskStatus_Critical(t *testing.T) {
	s := ClassifyDiskStatusForTest(98.0, 85, 95, "/tmp")
	if s.Status != "critical" {
		t.Fatalf("expected critical at 98%%, got %s", s.Status)
	}
}

// -----------------------------------------------------------------
// VerifyIntegrity
// -----------------------------------------------------------------

func TestVerifyIntegrity_Clean(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(active, []byte(`{"id":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "audit-2026-01-01-000000.jsonl.gz")
	if err := writeGzippedJSONL(archive, []byte(`{"id":2}`+"\n")); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyIntegrity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("expected ok, got failures: %v", res.Failures)
	}
	if res.FilesChecked != 2 {
		t.Fatalf("expected 2 files, got %d", res.FilesChecked)
	}
}

func TestVerifyIntegrity_CorruptGzip(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "audit-2026-01-01-000000.jsonl.gz")
	if err := os.WriteFile(archive, []byte("not a gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyIntegrity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("expected failure on corrupt archive")
	}
}

func writeGzippedJSONL(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	_, err = gz.Write(body)
	return err
}

// -----------------------------------------------------------------
// ArchiveLogs
// -----------------------------------------------------------------

func TestArchiveLogs_BundlesAudit(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "audit.jsonl"), []byte(`{"id":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeGzippedJSONL(filepath.Join(src, "audit-2026-01-01-000000.jsonl.gz"), []byte(`{"id":2}`+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "ignore.txt"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := ArchiveLogs(src, out, true); err != nil {
		t.Fatal(err)
	}
	names := tarContents(t, out)
	if !containsString(names, "audit.jsonl") || !containsString(names, "audit-2026-01-01-000000.jsonl.gz") {
		t.Fatalf("expected audit files in bundle, got %v", names)
	}
	if containsString(names, "ignore.txt") {
		t.Fatalf("non-audit file must not be bundled: %v", names)
	}
}

func TestArchiveLogs_ExcludeActive(t *testing.T) {
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "audit.jsonl"), []byte(`{"id":1}`+"\n"), 0o600)
	_ = writeGzippedJSONL(filepath.Join(src, "audit-2026-01-01-000000.jsonl.gz"), []byte(`{"id":2}`+"\n"))
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := ArchiveLogs(src, out, false); err != nil {
		t.Fatal(err)
	}
	names := tarContents(t, out)
	if containsString(names, "audit.jsonl") {
		t.Fatal("include_active=false must skip the active file")
	}
}

func tarContents(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
	return names
}

func containsString(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------
// LogWriter integration — rotation guard fires
// -----------------------------------------------------------------

func TestLogWriter_RotatesOnSizeOverflow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rotated := make(chan string, 4)
	lw, err := NewLogWriter(ctx, LogWriterOptions{
		Path:       p,
		QueueDepth: 2000,
		MaxSizeMB:  1,
		OnRotation: func(arc string) { rotated <- arc },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()
	// Write enough chunky events to exceed 1MB raw. We pace the
	// writes so the worker has a chance to drain — a 400-event
	// burst into a 100-slot queue would drop the bulk of them
	// before rotation could fire on disk-written bytes.
	big := strings.Repeat("y", 4096)
	for i := 0; i < 400; i++ {
		_ = lw.Write(ctx, Event{DecisionID: int64(i), StatusDetail: big})
		if i%50 == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	deadline := time.After(5 * time.Second)
	for lw.Rotations() == 0 {
		select {
		case <-deadline:
			t.Fatalf("rotation did not fire; total=%d dropped=%d", lw.Total(), lw.Dropped())
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case arc := <-rotated:
		if !strings.HasSuffix(arc, ".jsonl.gz") {
			t.Fatalf("rotation callback got %s", arc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rotation callback did not fire")
	}
}

func TestLogWriter_RecoversPartialTailOnStart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte(`{"id":1}`+"\n"+`{"id":2}`+"\n"+`{"partial`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recovered := make(chan int64, 1)
	lw, err := NewLogWriter(ctx, LogWriterOptions{
		Path:       p,
		QueueDepth: 10,
		OnRecovery: func(n int64) { recovered <- n },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()
	select {
	case n := <-recovered:
		if n != int64(len(`{"partial`)) {
			t.Fatalf("expected %d bytes recovered, got %d", len(`{"partial`), n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery callback did not fire")
	}
	if lw.PartialBytesRecovered() == 0 {
		t.Fatal("PartialBytesRecovered must be non-zero post-recovery")
	}
	// Active file's content is now clean — append should succeed.
	body, _ := os.ReadFile(p)
	for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("residual partial line: %q", line)
		}
	}
}

// -----------------------------------------------------------------
// ParseDuration
// -----------------------------------------------------------------

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"7d", 7 * 24 * time.Hour},
		{"24h", 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"60s", 60 * time.Second},
		{"3", 3 * 24 * time.Hour},
	}
	for _, c := range cases {
		got, err := ParseDuration(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("%s: got %s want %s", c.in, got, c.want)
		}
	}
}
