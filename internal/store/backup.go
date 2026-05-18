// Backup + restore helpers for the kbounce SQLite store.
//
// kbounce #279 ships two CLI subcommands (`kbounce backup` +
// `kbounce restore`) so operators can move their state across
// machines / preserve it across upgrades / take a snapshot before a
// risky config change WITHOUT the historical "stop the daemon and
// `cp state.db`" footgun (which silently corrupts the audit log if
// anyone forgets the shutdown step).
//
// Approach: SQLite's `VACUUM INTO 'path'` statement (3.27.0+, which
// modernc.org/sqlite implements). VACUUM INTO produces a consistent
// snapshot of the live database into a fresh single file while
// holding only a brief read lock; the running proxy continues to
// serve traffic during the backup. No extra dep, no CGo, no
// sqlite3_backup_init plumbing.
//
// Per [[creates-never-mutates]]: backup is strictly READ-ONLY against
// the source store. The output file is a new DB file we wholly own.
// Per [[self-host-zero-billing-dependency]]: backup + restore are
// entirely local; no network calls.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// BackupMetadataTable is the name of the metadata table embedded in
// every backup file. Reviewers grepping a backup-shaped DB for
// "kbounce_backup_metadata" can confirm it was produced by `kbounce
// backup` (vs. a random SQLite file).
const BackupMetadataTable = "kbounce_backup_metadata"

// BackupExcludedAuditTables names the tables OMITTED from the
// default backup. These are the audit-firehose surfaces:
// per-decision rows + the pending-prompt history. Operators
// usually want config (profiles + rules + presets) backed up but
// not the audit history (it's bulky + often-redundant after a
// rotation policy fires). --include-audit re-includes them.
//
// Cross-product parity per [[cross-product-agent-parity]]: dbounce
// ships the same shape with its own audit-firehose table names.
var BackupExcludedAuditTables = []string{
	"decisions",
	"pause_events",
	"burst_events",
}

// BackupExcludedPromptTables names the prompt-row tables OMITTED
// from the default backup. Pending prompts are runtime state by
// design (a prompt with no live waiter is effectively dead); we
// don't drag them across machines unless the operator opts in via
// --include-prompts.
var BackupExcludedPromptTables = []string{
	"pending_prompts",
}

// BackupOptions controls what `BackupTo` ships in the output file.
type BackupOptions struct {
	// IncludeAudit, when true, retains the BackupExcludedAuditTables
	// rows in the backup output. Default (false) drops them.
	IncludeAudit bool
	// IncludePrompts, when true, retains the BackupExcludedPromptTables
	// rows. Default (false) drops them.
	IncludePrompts bool
	// KbounceVersion is the running binary's version string, stamped
	// into the backup's metadata table so `restore` can warn /
	// refuse on version mismatch. Required; pass "dev" or "unknown"
	// when unstamped.
	KbounceVersion string
	// Now overrides the wall-clock used to stamp created_at. Test
	// hook; production passes a zero time and gets time.Now().UTC().
	Now time.Time
	// HostnameHashSeed overrides the hostname used to derive the
	// source_hostname_hash field. Test hook; production passes "" and
	// gets os.Hostname().
	HostnameHashSeed string
}

// BackupResult is returned by BackupTo + carries the metadata
// values that landed in the output's kbounce_backup_metadata row.
// Tests + the CLI summary read these.
type BackupResult struct {
	OutPath            string
	SizeBytes          int64
	SchemaVersion      int
	KbounceVersion     string
	CreatedAt          time.Time
	SourceHostnameHash string
	IncludedAudit      bool
	IncludedPrompts    bool
	SHA256             string
}

// BackupTo writes a single-file SQLite backup of the live store to
// outPath. Uses `VACUUM INTO` so the snapshot is consistent +
// taken without blocking writers for any meaningful time.
//
// After the VACUUM INTO step we open the output file as a separate
// SQLite handle, DROP the audit / prompt tables (per opts), CREATE
// the metadata table, and INSERT a single metadata row. The output
// then goes back through VACUUM to compact the dropped pages so
// the on-disk file is the size the operator's mental model expects.
//
// Concurrent writes against the SOURCE during the backup are safe
// (SQLite's `VACUUM INTO` takes only a shared read lock for the
// snapshot duration). Concurrent writes to the DESTINATION are
// nonsensical — outPath must not exist when BackupTo runs (the
// function refuses + returns an error if it does, to avoid the
// "did I just nuke yesterday's backup?" footgun).
func (s *Store) BackupTo(outPath string, opts BackupOptions) (*BackupResult, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("kbounce: BackupTo: store is not open")
	}
	if outPath == "" {
		return nil, errors.New("kbounce: BackupTo: outPath is required")
	}
	if opts.KbounceVersion == "" {
		return nil, errors.New("kbounce: BackupTo: KbounceVersion is required")
	}
	// Refuse to clobber an existing file. Operators who genuinely
	// want to overwrite can `rm` first — explicit beats implicit
	// for destructive ops.
	if _, err := os.Stat(outPath); err == nil {
		return nil, fmt.Errorf(
			"kbounce: BackupTo: %s already exists; remove it first or "+
				"pick a different --out path", outPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("kbounce: BackupTo: stat %s: %w", outPath, err)
	}
	// Ensure parent dir exists with private perms; matches the
	// store's own ~/.kbouncer mkdir policy.
	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("kbounce: BackupTo: mkdir %q: %w", dir, err)
		}
	}

	// Step 1: VACUUM INTO produces the consistent snapshot. The
	// argument is a string literal in SQLite syntax; we quote
	// defensively because path could contain spaces. SQLite's
	// VACUUM INTO accepts a single-quoted string literal; embedded
	// single quotes are escaped by doubling.
	//
	// Retry on SQLITE_BUSY: a write-heavy proxy can hold the write
	// lock long enough that the first VACUUM INTO attempt fails.
	// The whole point of this command is to back up while the proxy
	// is RUNNING, so we retry with exponential backoff up to
	// vacuumIntoMaxRetries before bubbling the error.
	escapedPath := escapeSQLiteString(outPath)
	vacuumStmt := `VACUUM INTO '` + escapedPath + `'`
	if err := execWithBusyRetryDB(s.db, vacuumStmt); err != nil {
		return nil, fmt.Errorf("kbounce: BackupTo: VACUUM INTO: %w", err)
	}

	// Step 2: open the snapshot as a separate handle so we can
	// drop excluded tables + stamp metadata without confusing the
	// live store's connection pool.
	dst, err := sql.Open("sqlite", outPath)
	if err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("kbounce: BackupTo: open snapshot: %w", err)
	}
	defer dst.Close()

	// Drop excluded tables. We DROP rather than DELETE so the
	// post-VACUUM file size reflects "the data isn't there"
	// (vs DELETE leaving empty pages behind even after VACUUM).
	excluded := []string{}
	if !opts.IncludeAudit {
		excluded = append(excluded, BackupExcludedAuditTables...)
	}
	if !opts.IncludePrompts {
		excluded = append(excluded, BackupExcludedPromptTables...)
	}
	for _, t := range excluded {
		// DROP TABLE IF EXISTS so a schema-future table that's not
		// yet present on this build doesn't fail the backup.
		if _, err := dst.Exec(`DROP TABLE IF EXISTS ` + t); err != nil {
			_ = os.Remove(outPath)
			return nil, fmt.Errorf("kbounce: BackupTo: drop %s: %w", t, err)
		}
		// Drop the auto-created sqlite_sequence row for the table
		// too (only present when the table had AUTOINCREMENT). The
		// row is harmless but a stale row in a re-created table
		// can confuse a future migration so we clean it up.
		if _, err := dst.Exec(
			`DELETE FROM sqlite_sequence WHERE name = ?`, t); err != nil {
			// Non-fatal: sqlite_sequence is only present when at
			// least one AUTOINCREMENT table exists in the DB.
			// Newly-created or no-autoincrement databases legitimately
			// lack the table; swallow that specific error.
			if !isNoSuchTableErr(err) {
				_ = os.Remove(outPath)
				return nil, fmt.Errorf(
					"kbounce: BackupTo: clean sqlite_sequence for %s: %w", t, err)
			}
		}
	}

	// Step 3: read schema_version from the snapshot (NOT from the
	// live store — they're the same right now but the snapshot is
	// the source of truth for the metadata we're embedding).
	var srcSchemaVer int
	if err := dst.QueryRow(
		`SELECT version FROM schema_version LIMIT 1`).Scan(&srcSchemaVer); err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("kbounce: BackupTo: read schema_version: %w", err)
	}

	// Step 4: build + stamp metadata.
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	hostnameHash := computeHostnameHash(opts.HostnameHashSeed)

	if _, err := dst.Exec(`CREATE TABLE IF NOT EXISTS ` + BackupMetadataTable + ` (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`); err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("kbounce: BackupTo: create metadata table: %w", err)
	}
	meta := map[string]string{
		"kbounce_version":      opts.KbounceVersion,
		"created_at":           now.Format(time.RFC3339),
		"source_hostname_hash": hostnameHash,
		"schema_version":       fmt.Sprintf("%d", srcSchemaVer),
		"included_audit":       boolStr(opts.IncludeAudit),
		"included_prompts":     boolStr(opts.IncludePrompts),
	}
	for k, v := range meta {
		if _, err := dst.Exec(
			`INSERT OR REPLACE INTO `+BackupMetadataTable+`(key, value) VALUES (?, ?)`,
			k, v); err != nil {
			_ = os.Remove(outPath)
			return nil, fmt.Errorf("kbounce: BackupTo: insert metadata %s: %w", k, err)
		}
	}

	// Step 5: VACUUM the destination so the dropped-table pages
	// are reclaimed + the on-disk size matches the operator's
	// intuition.
	if _, err := dst.Exec(`VACUUM`); err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("kbounce: BackupTo: vacuum dest: %w", err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(outPath)
		return nil, fmt.Errorf("kbounce: BackupTo: close dest: %w", err)
	}

	// Step 6: chmod 0o600 (the backup is a copy of audit data +
	// config — same sensitivity as the source DB).
	if err := os.Chmod(outPath, 0o600); err != nil {
		// Non-fatal on platforms where chmod is a no-op (windows);
		// production targets are unix-shaped so a real failure is
		// surfaced.
		return nil, fmt.Errorf("kbounce: BackupTo: chmod %s: %w", outPath, err)
	}

	// Step 7: stat + sha256 for the result struct.
	sizeBytes, sumHex, err := sha256File(outPath)
	if err != nil {
		return nil, fmt.Errorf("kbounce: BackupTo: hash %s: %w", outPath, err)
	}

	return &BackupResult{
		OutPath:            outPath,
		SizeBytes:          sizeBytes,
		SchemaVersion:      srcSchemaVer,
		KbounceVersion:     opts.KbounceVersion,
		CreatedAt:          now,
		SourceHostnameHash: hostnameHash,
		IncludedAudit:      opts.IncludeAudit,
		IncludedPrompts:    opts.IncludePrompts,
		SHA256:             sumHex,
	}, nil
}

// RestoreOptions controls the destination-side gating on `RestoreFrom`.
type RestoreOptions struct {
	// Force, when true, allows restoring into a destination DB that
	// already has rules / tasks rows AND allows a kbounce_version
	// mismatch between the backup metadata + the live binary.
	// Schema-version mismatch is NEVER overridable (cross-schema
	// restore is a migration, not a restore).
	Force bool
	// CurrentKbounceVersion is the live binary's version string,
	// compared against the backup's recorded kbounce_version for
	// the mismatch warning. Required.
	CurrentKbounceVersion string
}

// RestoreResult is returned by RestoreFrom + summarizes how many
// rows landed in the destination's key tables, plus the resulting
// file's sha256 (so the operator can compare across machines).
type RestoreResult struct {
	DestPath           string
	BackupPath         string
	SchemaVersion      int
	BackupVersion      string
	VersionMismatch    bool
	IncludedAudit      bool
	IncludedPrompts    bool
	RestoredRules      int64
	RestoredTasks      int64
	RestoredProfiles   int64
	RestoredDecisions  int64
	RestoredPrompts    int64
	RestoredPauses     int64
	DestSizeBytes      int64
	DestSHA256         string
}

// RestoreFrom replaces the on-disk database at destPath with the
// contents of the backup at srcPath. The current Store handle (if
// any) MUST be closed before calling RestoreFrom — the function
// operates on the destination FILE, not on a live database handle.
//
// Gating (in order — first match wins):
//
//  1. backup file must exist + open as a SQLite DB
//  2. backup must carry the kbounce_backup_metadata table (refuses
//     a random SQLite file masquerading as a backup)
//  3. backup's schema_version MUST equal the live store's
//     SchemaVersion (refused with --force too — cross-schema restore
//     is a separate `kbounce migrate` feature, not a restore)
//  4. backup's kbounce_version SHOULD equal the live binary's
//     version; mismatch is REFUSED unless opts.Force is true
//  5. destination, if it exists + already has rows in `rules` or
//     `tasks`, is REFUSED unless opts.Force is true
//
// Then the destination file is REPLACED by the backup file
// (os.Rename semantics on the same filesystem; falls back to copy
// + remove across devices). Per [[creates-never-mutates]] the
// SOURCE backup file is preserved; only the destination is
// rewritten.
func RestoreFrom(srcPath, destPath string, opts RestoreOptions) (*RestoreResult, error) {
	if srcPath == "" {
		return nil, errors.New("kbounce: RestoreFrom: srcPath is required")
	}
	if destPath == "" {
		return nil, errors.New("kbounce: RestoreFrom: destPath is required")
	}
	if opts.CurrentKbounceVersion == "" {
		return nil, errors.New(
			"kbounce: RestoreFrom: CurrentKbounceVersion is required")
	}

	// Step 1+2: open backup + read its metadata.
	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		return nil, fmt.Errorf("kbounce: RestoreFrom: open backup %s: %w", srcPath, err)
	}
	defer src.Close()

	meta, err := readBackupMetadata(src)
	if err != nil {
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: %s is not a kbounce backup (no %s table or unreadable): %w",
			srcPath, BackupMetadataTable, err)
	}

	// Step 3: schema_version MUST match — overrideable by NOTHING.
	backupSchemaVer := 0
	if s, ok := meta["schema_version"]; ok {
		_, _ = fmt.Sscanf(s, "%d", &backupSchemaVer)
	}
	if backupSchemaVer != SchemaVersion {
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: schema_version mismatch (backup=%d, live=%d); "+
				"cross-schema restore is a migration, not a restore — "+
				"use the appropriate `kbounce migrate` step "+
				"(or downgrade / upgrade the kbounce binary to match)",
			backupSchemaVer, SchemaVersion)
	}

	// Step 4: kbounce_version check.
	backupVer := meta["kbounce_version"]
	versionMismatch := backupVer != opts.CurrentKbounceVersion
	if versionMismatch && !opts.Force {
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: kbounce_version mismatch (backup=%q, live=%q); "+
				"pass --force to restore anyway (schema_version already matched, "+
				"so the restore is safe — this is a soft warning)",
			backupVer, opts.CurrentKbounceVersion)
	}

	// Step 5: dest non-empty check. We open the destination only
	// if it exists — a fresh restore into a missing destPath is
	// the most common shape (operator copies backup.db to a fresh
	// machine + runs `kbounce restore`).
	if _, err := os.Stat(destPath); err == nil {
		ruleCount, taskCount, err := destRuleTaskCounts(destPath)
		if err != nil {
			return nil, fmt.Errorf(
				"kbounce: RestoreFrom: inspect destination %s: %w", destPath, err)
		}
		if (ruleCount > 0 || taskCount > 0) && !opts.Force {
			return nil, fmt.Errorf(
				"kbounce: RestoreFrom: destination %s already has %d rule(s) + "+
					"%d task(s); pass --force to overwrite (the existing rows will "+
					"be replaced by the backup contents)",
				destPath, ruleCount, taskCount)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: stat destination %s: %w", destPath, err)
	}

	// Step 5.5: refuse if a kbounce proxy appears to be running
	// against destPath. We can't introspect lock holders across
	// platforms cheaply, so we probe the default wire/mgmt port
	// (loopback only) at the call site (in the CLI command); the
	// store-level RestoreFrom focuses on file-level mechanics.

	// Step 6: replace destination file. We DO this in two steps —
	// copy backup → tempfile in dest dir, then os.Rename — so a
	// crash during the copy doesn't leave a half-written
	// destination behind.
	if dir := filepath.Dir(destPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf(
				"kbounce: RestoreFrom: mkdir dest dir %s: %w", dir, err)
		}
	}
	tmpDest := destPath + ".kbounce-restore-tmp"
	if err := copyFile(srcPath, tmpDest); err != nil {
		_ = os.Remove(tmpDest)
		return nil, fmt.Errorf("kbounce: RestoreFrom: copy to temp: %w", err)
	}
	if err := os.Chmod(tmpDest, 0o600); err != nil {
		_ = os.Remove(tmpDest)
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: chmod temp %s: %w", tmpDest, err)
	}
	if err := os.Rename(tmpDest, destPath); err != nil {
		_ = os.Remove(tmpDest)
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: rename %s -> %s: %w",
			tmpDest, destPath, err)
	}

	// Step 7: open the now-restored destination and pull row counts.
	dst, err := sql.Open("sqlite", destPath)
	if err != nil {
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: open restored destination: %w", err)
	}
	defer dst.Close()

	res := &RestoreResult{
		DestPath:        destPath,
		BackupPath:      srcPath,
		SchemaVersion:   backupSchemaVer,
		BackupVersion:   backupVer,
		VersionMismatch: versionMismatch,
		IncludedAudit:   meta["included_audit"] == "true",
		IncludedPrompts: meta["included_prompts"] == "true",
	}
	res.RestoredRules = countRowsBestEffort(dst, "rules")
	res.RestoredTasks = countRowsBestEffort(dst, "tasks")
	// "Profiles" in the kbounce model live in profiles.yaml on
	// disk, not in SQLite. We keep the field in the result for
	// cross-product parity (dbounce stores profiles in SQLite) but
	// it's always 0 for kbounce.
	res.RestoredProfiles = 0
	res.RestoredDecisions = countRowsBestEffort(dst, "decisions")
	res.RestoredPrompts = countRowsBestEffort(dst, "pending_prompts")
	res.RestoredPauses = countRowsBestEffort(dst, "pause_events")

	// Final hash for the operator's print-out.
	sizeBytes, sumHex, err := sha256File(destPath)
	if err != nil {
		return nil, fmt.Errorf(
			"kbounce: RestoreFrom: hash dest: %w", err)
	}
	res.DestSizeBytes = sizeBytes
	res.DestSHA256 = sumHex

	return res, nil
}

// readBackupMetadata pulls every (key, value) pair from the
// kbounce_backup_metadata table. Returns an error if the table
// doesn't exist — callers translate that to "not a kbounce
// backup."
func readBackupMetadata(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM ` + BackupMetadataTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// destRuleTaskCounts opens a (presumed-existing) destination DB
// + reports the row counts for the two "config" tables the
// restore-gating checks. We use COUNT(*) rather than a full row
// fetch since we only care whether the destination is empty.
//
// If a table doesn't exist (fresh DB with no migrations run), the
// count is treated as 0 — restore into a never-opened destination
// is the canonical fresh-machine case and should be allowed.
func destRuleTaskCounts(destPath string) (int64, int64, error) {
	db, err := sql.Open("sqlite", destPath)
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()
	rules := countRowsBestEffort(db, "rules")
	tasks := countRowsBestEffort(db, "tasks")
	return rules, tasks, nil
}

// countRowsBestEffort returns COUNT(*) of the table, or 0 if the
// table doesn't exist. Used by the restore summary so a backup
// taken without `--include-audit` still produces a sensible
// "restored 0 audit rows" line.
func countRowsBestEffort(db *sql.DB, table string) int64 {
	var n int64
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		return 0
	}
	return n
}

// computeHostnameHash returns the first 12 hex chars of sha256 of
// the hostname (or override). Stable identifier without exposing
// the hostname itself — per [[opt-in-feedback-pipeline]] privacy
// posture.
func computeHostnameHash(override string) string {
	host := override
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		} else {
			host = "unknown"
		}
	}
	sum := sha256.Sum256([]byte(host))
	return hex.EncodeToString(sum[:6]) // 6 bytes → 12 hex chars
}

// sha256File returns (size, hex-sha256) of the file at path.
func sha256File(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// copyFile is a portable file-copy used by RestoreFrom for its
// temp-file-then-rename step. We don't use os.Rename directly
// across the entire copy because the source + destination may live
// on different filesystems (a backup file living in /tmp + a dest
// in $HOME), in which case rename fails with EXDEV.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// escapeSQLiteString quotes a string for use inside a single-
// quoted SQLite literal: doubles every embedded single quote.
func escapeSQLiteString(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// vacuumIntoMaxRetries caps how many times we retry the VACUUM INTO
// statement when SQLite returns SQLITE_BUSY. With the backoff
// schedule below the total wait is ~ 5 seconds before bubbling the
// failure — enough to ride out a brief burst-write but not so long
// that a stuck writer blocks the operator indefinitely.
const vacuumIntoMaxRetries = 10

// execWithBusyRetryDB runs a single SQL statement against db,
// retrying on SQLITE_BUSY / SQLITE_LOCKED with exponential
// backoff. Returns nil on success, the LAST error on failure.
//
// The retry exists specifically for VACUUM INTO under a hot
// proxy — see the kbounce #279 spec ("Backup works while a write-
// heavy goroutine is running concurrently"). Other store paths
// don't need it because they're SELECT or single-row INSERT. Retries the
// statement on SQLite SQLITE_BUSY (error text contains "database is
// locked" or "SQLITE_BUSY") with exponential backoff: 5ms, 10ms,
// 20ms, ... capped at 1s per try, max vacuumIntoMaxRetries attempts.
func execWithBusyRetryDB(db *sql.DB, stmt string) error {
	delay := 5 * time.Millisecond
	var lastErr error
	for i := 0; i < vacuumIntoMaxRetries; i++ {
		_, err := db.Exec(stmt)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isSQLiteBusyErr(err) {
			return err
		}
		time.Sleep(delay)
		delay *= 2
		if delay > time.Second {
			delay = time.Second
		}
	}
	return lastErr
}

// isSQLiteBusyErr returns true when err carries the SQLITE_BUSY /
// SQLITE_LOCKED text. modernc.org/sqlite doesn't expose a typed
// sentinel; the text-shape match is stable + the comparable
// approach taken by other Go projects on this driver.
func isSQLiteBusyErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return containsCaseInsensitive(msg, "database is locked") ||
		containsCaseInsensitive(msg, "sqlite_busy") ||
		containsCaseInsensitive(msg, "sqlite_locked")
}

// isNoSuchTableErr returns true when the SQLite error text matches
// the standard "no such table" shape. We pattern-match on the
// error message because modernc.org/sqlite doesn't expose a
// strongly-typed sentinel for this case.
func isNoSuchTableErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return containsCaseInsensitive(msg, "no such table")
}

// containsCaseInsensitive is a tiny helper to avoid importing
// strings just for this one check.
func containsCaseInsensitive(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	// Cheap ASCII-only lowering — sufficient for SQLite error text.
	low := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if low(s[i+j]) != low(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
