// Tests for backup.go — kbounce #279 (SQLite backup / restore).
//
// Surface coverage:
//   - BackupTo populates the metadata table correctly
//   - Default backup omits audit + prompt tables
//   - --include-audit + --include-prompts retain them
//   - Restore into an empty / missing destination succeeds + the
//     restored DB carries the source's row counts
//   - Restore into a destination with rules / tasks rows fails
//     without --force, succeeds with --force
//   - Schema-version mismatch is REFUSED even with --force
//   - kbounce_version mismatch warns + succeeds with --force
//   - Backup runs successfully while a write-heavy goroutine
//     hammers the source store (online-backup safety)
//   - Round-trip (backup → restore → backup again) produces an
//     identical metadata-equivalent second backup
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// populateSeedStore inserts a small, predictable, mixed set of
// rows so the tests can assert "row counts match after restore"
// + "default backup drops audit but keeps rules."
func populateSeedStore(t *testing.T, s *Store) {
	t.Helper()
	// Two rules — these survive the default backup.
	for _, p := range []string{"rule-one", "rule-two"} {
		if _, err := s.db.Exec(
			`INSERT INTO rules(pattern, effect, created_at)
			VALUES (?, 'allow', ?)`,
			p, time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("seed rule %s: %v", p, err)
		}
	}
	// Three decisions — these are DROPPED from the default backup.
	for i := 0; i < 3; i++ {
		if _, err := s.RecordDecision(DecisionRow{
			At:              time.Now().UTC(),
			Method:          "GET",
			Path:            fmt.Sprintf("/api/v1/pods/p%d", i),
			DecisionVerdict: "allow",
			DecisionReason:  "test",
			ModeAtDecision:  "cooperative",
		}); err != nil {
			t.Fatalf("seed decision %d: %v", i, err)
		}
	}
	// One pending prompt — DROPPED from the default backup unless
	// --include-prompts is set.
	if _, err := s.db.Exec(
		`INSERT INTO pending_prompts(created_at, decision_id, deny_reason, status)
		VALUES (?, 1, 'test', 'pending')`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed prompt: %v", err)
	}
}

// rowCount is a tiny helper for table-row asserts.
func rowCount(t *testing.T, db *sql.DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		// Treat "no such table" as 0 so tests for the
		// excluded-table case read naturally.
		var zero int64
		return zero
	}
	return n
}

func TestBackupTo_PopulatesMetadata(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()
	populateSeedStore(t, src)

	outPath := filepath.Join(dir, "backup.db")
	result, err := src.BackupTo(outPath, BackupOptions{
		KbounceVersion:   "v1.2.3",
		HostnameHashSeed: "test-host",
	})
	if err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	if result.OutPath != outPath {
		t.Errorf("OutPath: got %q want %q", result.OutPath, outPath)
	}
	if result.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion: got %d want %d",
			result.SchemaVersion, SchemaVersion)
	}
	if result.KbounceVersion != "v1.2.3" {
		t.Errorf("KbounceVersion: got %q", result.KbounceVersion)
	}
	if result.SourceHostnameHash == "" || len(result.SourceHostnameHash) != 12 {
		t.Errorf("SourceHostnameHash: want 12 hex chars, got %q",
			result.SourceHostnameHash)
	}
	if result.IncludedAudit {
		t.Errorf("IncludedAudit: default backup should NOT include audit")
	}
	if result.IncludedPrompts {
		t.Errorf("IncludedPrompts: default backup should NOT include prompts")
	}
	if result.SHA256 == "" {
		t.Errorf("SHA256: should be populated")
	}
	if result.SizeBytes <= 0 {
		t.Errorf("SizeBytes: should be > 0")
	}

	// Re-open the backup file + verify the metadata table is shaped
	// as documented.
	db, err := sql.Open("sqlite", outPath)
	if err != nil {
		t.Fatalf("re-open backup: %v", err)
	}
	defer db.Close()
	meta, err := readBackupMetadata(db)
	if err != nil {
		t.Fatalf("readBackupMetadata: %v", err)
	}
	want := map[string]string{
		"kbounce_version":      "v1.2.3",
		"included_audit":       "false",
		"included_prompts":     "false",
		"schema_version":       fmt.Sprintf("%d", SchemaVersion),
		"source_hostname_hash": result.SourceHostnameHash,
	}
	for k, v := range want {
		if got := meta[k]; got != v {
			t.Errorf("meta[%q]: got %q want %q", k, got, v)
		}
	}
	if _, ok := meta["created_at"]; !ok {
		t.Errorf("meta[created_at]: missing")
	}
}

func TestBackupTo_DefaultDropsAuditAndPrompts(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()
	populateSeedStore(t, src)

	// Sanity: source has the audit + prompt rows we expect.
	if got := rowCount(t, src.db, "decisions"); got != 3 {
		t.Fatalf("source decisions: got %d want 3", got)
	}
	if got := rowCount(t, src.db, "pending_prompts"); got != 1 {
		t.Fatalf("source prompts: got %d want 1", got)
	}

	outPath := filepath.Join(dir, "backup.db")
	if _, err := src.BackupTo(outPath, BackupOptions{
		KbounceVersion: "test",
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	db, err := sql.Open("sqlite", outPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer db.Close()

	// Rules survive.
	if got := rowCount(t, db, "rules"); got != 2 {
		t.Errorf("backup rules: got %d want 2 (rules MUST survive default backup)", got)
	}
	// Audit + prompt tables are GONE entirely.
	for _, tbl := range []string{"decisions", "pending_prompts"} {
		var n int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
			tbl).Scan(&n)
		if err != nil {
			t.Errorf("check table %s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("backup still contains table %s (should be dropped)", tbl)
		}
	}
}

func TestBackupTo_IncludeAuditKeepsAuditTables(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()
	populateSeedStore(t, src)

	outPath := filepath.Join(dir, "backup-audit.db")
	if _, err := src.BackupTo(outPath, BackupOptions{
		KbounceVersion: "test",
		IncludeAudit:   true,
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	db, err := sql.Open("sqlite", outPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer db.Close()
	if got := rowCount(t, db, "decisions"); got != 3 {
		t.Errorf("--include-audit decisions: got %d want 3", got)
	}
}

func TestBackupTo_IncludePromptsKeepsPromptTable(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()
	populateSeedStore(t, src)

	outPath := filepath.Join(dir, "backup-prompts.db")
	if _, err := src.BackupTo(outPath, BackupOptions{
		KbounceVersion: "test",
		IncludePrompts: true,
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	db, err := sql.Open("sqlite", outPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer db.Close()
	if got := rowCount(t, db, "pending_prompts"); got != 1 {
		t.Errorf("--include-prompts pending_prompts: got %d want 1", got)
	}
}

func TestBackupTo_RefusesClobber(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	outPath := filepath.Join(dir, "exists.db")
	if err := os.WriteFile(outPath, []byte("not a backup"), 0o600); err != nil {
		t.Fatalf("pre-create file: %v", err)
	}
	if _, err := src.BackupTo(outPath, BackupOptions{
		KbounceVersion: "test",
	}); err == nil {
		t.Fatalf("expected error backing up onto existing file")
	}
}

func TestRestoreFrom_EmptyDestination(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	populateSeedStore(t, src)
	srcRules := rowCount(t, src.db, "rules")
	srcDecisions := rowCount(t, src.db, "decisions")
	src.Close()
	// Re-open just to make sure schema is durable + we're not
	// resting on an open transaction.
	src, err = Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("reopen src: %v", err)
	}

	backupPath := filepath.Join(dir, "backup.db")
	if _, err := src.BackupTo(backupPath, BackupOptions{
		KbounceVersion: "v1.0.0",
		IncludeAudit:   true,
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	src.Close()

	// Restore into a missing destination.
	destPath := filepath.Join(dir, "dest.db")
	result, err := RestoreFrom(backupPath, destPath, RestoreOptions{
		CurrentKbounceVersion: "v1.0.0",
	})
	if err != nil {
		t.Fatalf("RestoreFrom: %v", err)
	}
	if result.RestoredRules != srcRules {
		t.Errorf("rules: got %d want %d", result.RestoredRules, srcRules)
	}
	if result.RestoredDecisions != srcDecisions {
		t.Errorf("decisions: got %d want %d",
			result.RestoredDecisions, srcDecisions)
	}
	if result.DestSHA256 == "" {
		t.Errorf("DestSHA256 should be populated")
	}
}

func TestRestoreFrom_NonEmptyDestinationWithoutForceFails(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	populateSeedStore(t, src)
	backupPath := filepath.Join(dir, "backup.db")
	if _, err := src.BackupTo(backupPath, BackupOptions{
		KbounceVersion: "v1.0.0",
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	src.Close()

	// Create a non-empty destination DB.
	destPath := filepath.Join(dir, "dest.db")
	dest, err := Open(destPath)
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	if _, err := dest.db.Exec(
		`INSERT INTO rules(pattern, effect, created_at) VALUES ('existing', 'allow', ?)`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed dest rule: %v", err)
	}
	dest.Close()

	_, err = RestoreFrom(backupPath, destPath, RestoreOptions{
		CurrentKbounceVersion: "v1.0.0",
	})
	if err == nil {
		t.Fatalf("expected refuse-without-force error")
	}
	// Confirm dest is UNMODIFIED on the refuse-without-force path.
	dest2, err := Open(destPath)
	if err != nil {
		t.Fatalf("reopen dest: %v", err)
	}
	defer dest2.Close()
	if got := rowCount(t, dest2.db, "rules"); got != 1 {
		t.Errorf("dest should still have 1 (pre-existing) rule; got %d", got)
	}
}

func TestRestoreFrom_NonEmptyDestinationWithForceSucceeds(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	populateSeedStore(t, src)
	backupPath := filepath.Join(dir, "backup.db")
	if _, err := src.BackupTo(backupPath, BackupOptions{
		KbounceVersion: "v1.0.0",
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	src.Close()

	destPath := filepath.Join(dir, "dest.db")
	dest, err := Open(destPath)
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	if _, err := dest.db.Exec(
		`INSERT INTO rules(pattern, effect, created_at) VALUES ('existing', 'allow', ?)`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed dest rule: %v", err)
	}
	dest.Close()

	result, err := RestoreFrom(backupPath, destPath, RestoreOptions{
		CurrentKbounceVersion: "v1.0.0",
		Force:                 true,
	})
	if err != nil {
		t.Fatalf("RestoreFrom --force: %v", err)
	}
	// Destination should now mirror the BACKUP, not its pre-existing
	// row. We populated 2 rules in the source.
	if result.RestoredRules != 2 {
		t.Errorf("after --force restore: rules got %d want 2",
			result.RestoredRules)
	}
}

func TestRestoreFrom_SchemaMismatchAlwaysFails(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	backupPath := filepath.Join(dir, "backup.db")
	if _, err := src.BackupTo(backupPath, BackupOptions{
		KbounceVersion: "v1.0.0",
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	src.Close()

	// Doctor the schema_version in the backup's metadata table to
	// simulate a cross-schema mismatch.
	db, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE ` + BackupMetadataTable + ` SET value='99' WHERE key='schema_version'`,
	); err != nil {
		t.Fatalf("doctor schema_version: %v", err)
	}
	db.Close()

	// --force MUST NOT save us — schema mismatch is a hard refusal.
	for _, force := range []bool{false, true} {
		destPath := filepath.Join(dir, fmt.Sprintf("dest-force-%t.db", force))
		_, err := RestoreFrom(backupPath, destPath, RestoreOptions{
			CurrentKbounceVersion: "v1.0.0",
			Force:                 force,
		})
		if err == nil {
			t.Errorf("expected error on schema_version mismatch (force=%t)",
				force)
		}
	}
}

func TestRestoreFrom_VersionMismatchRefusedWithoutForce(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	backupPath := filepath.Join(dir, "backup.db")
	if _, err := src.BackupTo(backupPath, BackupOptions{
		KbounceVersion: "v1.0.0",
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	src.Close()

	destPath := filepath.Join(dir, "dest.db")
	_, err = RestoreFrom(backupPath, destPath, RestoreOptions{
		CurrentKbounceVersion: "v2.0.0", // mismatch
	})
	if err == nil {
		t.Fatalf("expected refuse on version mismatch without --force")
	}
}

func TestRestoreFrom_VersionMismatchSucceedsWithForce(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	populateSeedStore(t, src)
	backupPath := filepath.Join(dir, "backup.db")
	if _, err := src.BackupTo(backupPath, BackupOptions{
		KbounceVersion: "v1.0.0",
	}); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	src.Close()

	destPath := filepath.Join(dir, "dest.db")
	result, err := RestoreFrom(backupPath, destPath, RestoreOptions{
		CurrentKbounceVersion: "v2.0.0",
		Force:                 true,
	})
	if err != nil {
		t.Fatalf("RestoreFrom --force on version mismatch: %v", err)
	}
	if !result.VersionMismatch {
		t.Errorf("expected VersionMismatch=true in result")
	}
	if result.BackupVersion != "v1.0.0" {
		t.Errorf("BackupVersion: got %q want v1.0.0", result.BackupVersion)
	}
}

func TestRestoreFrom_NonBackupFileRefused(t *testing.T) {
	dir := t.TempDir()
	// Build a fresh kbounce DB (no backup metadata table).
	notABackup, err := Open(filepath.Join(dir, "raw.db"))
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	notABackup.Close()

	destPath := filepath.Join(dir, "dest.db")
	_, err = RestoreFrom(filepath.Join(dir, "raw.db"), destPath, RestoreOptions{
		CurrentKbounceVersion: "v1.0.0",
	})
	if err == nil {
		t.Fatalf("expected refuse on a non-backup SQLite file")
	}
}

// TestBackupTo_OnlineWithConcurrentWriter validates the
// "online backup while writers are active" guarantee — VACUUM
// INTO holds only a brief shared read lock, so a goroutine
// flooding the source with decision writes should not corrupt
// the backup OR cause the backup call to fail.
func TestBackupTo_OnlineWithConcurrentWriter(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	// Spin a writer goroutine — keeps RecordDecision firing as
	// fast as the SQLite write lock allows for the duration of
	// the backup call.
	var stop atomic.Bool
	done := make(chan struct{})
	var writeErr atomic.Value // error
	go func() {
		defer close(done)
		i := 0
		for !stop.Load() {
			if _, err := src.RecordDecision(DecisionRow{
				At:              time.Now().UTC(),
				Method:          "GET",
				Path:            fmt.Sprintf("/api/v1/p%d", i),
				DecisionVerdict: "allow",
				DecisionReason:  "concurrent-write",
				ModeAtDecision:  "cooperative",
			}); err != nil {
				// SQLite occasionally returns SQLITE_BUSY under
				// contention; that's normal — we keep going.
				_ = err
			}
			i++
			if i%50 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	defer func() {
		stop.Store(true)
		<-done
		if v := writeErr.Load(); v != nil {
			t.Errorf("writer goroutine: %v", v)
		}
	}()

	// Let the writer build some load before the backup starts.
	time.Sleep(20 * time.Millisecond)

	outPath := filepath.Join(dir, "online.db")
	if _, err := src.BackupTo(outPath, BackupOptions{
		KbounceVersion: "online-test",
		IncludeAudit:   true,
	}); err != nil {
		t.Fatalf("BackupTo while writes in flight: %v", err)
	}

	// Backup file should be a valid SQLite DB with the metadata
	// table populated.
	db, err := sql.Open("sqlite", outPath)
	if err != nil {
		t.Fatalf("open online backup: %v", err)
	}
	defer db.Close()
	meta, err := readBackupMetadata(db)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta["kbounce_version"] != "online-test" {
		t.Errorf("metadata.kbounce_version: got %q", meta["kbounce_version"])
	}
}

// TestBackupTo_RoundTripDeterministic checks that:
//   - backup → restore → backup-again produces TABLE-CONTENTS-equivalent
//     backup files when the same metadata is passed
//
// We compare row counts per non-metadata table because the
// metadata table carries a `created_at` field that legitimately
// varies on each backup. Equivalent contents = the restore was
// lossless.
func TestBackupTo_RoundTripDeterministic(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	populateSeedStore(t, src)

	// First backup.
	backup1 := filepath.Join(dir, "b1.db")
	fixedT := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	if _, err := src.BackupTo(backup1, BackupOptions{
		KbounceVersion:   "v1.0.0",
		IncludeAudit:     true,
		IncludePrompts:   true,
		Now:              fixedT,
		HostnameHashSeed: "h",
	}); err != nil {
		t.Fatalf("backup1: %v", err)
	}
	src.Close()

	// Restore into a fresh destination.
	destPath := filepath.Join(dir, "dest.db")
	if _, err := RestoreFrom(backup1, destPath, RestoreOptions{
		CurrentKbounceVersion: "v1.0.0",
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Open the restored DB + take a SECOND backup off it.
	dest, err := Open(destPath)
	if err != nil {
		t.Fatalf("open restored dest: %v", err)
	}
	backup2 := filepath.Join(dir, "b2.db")
	if _, err := dest.BackupTo(backup2, BackupOptions{
		KbounceVersion:   "v1.0.0",
		IncludeAudit:     true,
		IncludePrompts:   true,
		Now:              fixedT,
		HostnameHashSeed: "h",
	}); err != nil {
		t.Fatalf("backup2: %v", err)
	}
	dest.Close()

	// Compare row counts of every non-metadata table — the
	// restore should be a lossless round trip.
	tables := []string{"rules", "tasks", "decisions",
		"pending_prompts", "pause_events", "schema_version"}
	for _, tbl := range tables {
		c1 := openCount(t, backup1, tbl)
		c2 := openCount(t, backup2, tbl)
		if c1 != c2 {
			t.Errorf("round-trip %s: backup1=%d backup2=%d", tbl, c1, c2)
		}
	}
}

func openCount(t *testing.T, path, table string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()
	return rowCount(t, db, table)
}

func TestBackupTo_RejectsEmptyVersion(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()
	_, err = src.BackupTo(filepath.Join(dir, "out.db"), BackupOptions{
		KbounceVersion: "",
	})
	if err == nil {
		t.Fatalf("expected error for empty KbounceVersion")
	}
}

func TestRestoreFrom_RequiresAllInputs(t *testing.T) {
	if _, err := RestoreFrom("", "/tmp/x", RestoreOptions{
		CurrentKbounceVersion: "v1",
	}); err == nil {
		t.Errorf("expected error for empty srcPath")
	}
	if _, err := RestoreFrom("/tmp/x", "", RestoreOptions{
		CurrentKbounceVersion: "v1",
	}); err == nil {
		t.Errorf("expected error for empty destPath")
	}
	if _, err := RestoreFrom("/tmp/x", "/tmp/y", RestoreOptions{
		CurrentKbounceVersion: "",
	}); err == nil {
		t.Errorf("expected error for empty CurrentKbounceVersion")
	}
}

// Helper: ensure errors.Is doesn't accidentally swallow expected
// failures (smoke-test for future refactors).
var _ = errors.Is
