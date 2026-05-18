// `kbounce backup` + `kbounce restore` — single-file SQLite
// backup / restore for the kbounce store (#279).
//
// Why this exists: until #279 the only way to back the store up
// was to stop the proxy and `cp state.db elsewhere`. Operators
// forget the shutdown step, lose the audit log, copy a half-
// written file. The two subcommands ship the right defaults
// (online backup via `VACUUM INTO`; metadata-table validation on
// restore) so disaster recovery + machine migration is a one-line
// operation.
//
// Per [[creates-never-mutates]]: backup is read-only against the
// source store. Restore IS destructive on the destination, but
// gated behind the existence + non-empty checks so the operator
// can't accidentally clobber a fresh-but-populated DB without
// passing --force.
//
// Per [[self-host-zero-billing-dependency]]: no network calls;
// entirely local.
//
// Per [[cross-product-agent-parity]]: dbounce ships the same CLI
// shape + metadata-table format. Flag names, exit messages, and
// the kbounce_backup_metadata / dbounce_backup_metadata table
// schemas mirror across the two products.
package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// backupHealthzProbeTimeout caps the "is kbounce running" probe
// the restore command runs before touching the destination. Short
// enough that a misconfigured / dead listener doesn't stall the
// command for minutes; long enough that a real running proxy
// answers reliably.
const backupHealthzProbeTimeout = 2 * time.Second

// backupDefaultHealthzURL is the loopback URL we probe to detect a
// running kbounce. Matches the default the proxy binds to (8766
// loopback). Operators who run on a non-default port pass
// --probe-url to override.
const backupDefaultHealthzURL = "http://127.0.0.1:8766/healthz"

// newBackupCmd implements `kbounce backup`. Top-level command (no
// sub-group) since backup is a single verb — matches `dbounce
// backup`.
func newBackupCmd() *cobra.Command {
	var (
		outPath         string
		dbPath          string
		includeAudit    bool
		includePrompts  bool
		auditLogPath    string
		hostnameOverride string // test-only
	)
	cmd := &cobra.Command{
		Use:   "backup --out PATH [--include-audit] [--include-prompts]",
		Short: "Snapshot the kbounce SQLite store to a single file (online; no shutdown)",
		Long: `Produce a single-file SQLite backup of the live kbounce store.

Uses SQLite's ` + "`VACUUM INTO`" + ` so the snapshot is consistent +
taken WITHOUT stopping the running proxy. Output is a normal
SQLite file you can copy / encrypt / ship anywhere.

Default contents: everything EXCEPT audit-event rows + prompt rows
(those are bulky + often-redundant; operators usually want
config + rules + tasks backed up but not the audit firehose).
Opt back in with --include-audit and / or --include-prompts.

The backup file embeds a ` + "`kbounce_backup_metadata`" + ` table with:
  - kbounce_version       (string)
  - created_at            (RFC3339)
  - source_hostname_hash  (sha256 of hostname, first 12 hex)
  - schema_version        (matches the source DB)
  - included_audit        (bool)
  - included_prompts      (bool)

Per [[creates-never-mutates]]: read-only against the source store.
Per [[self-host-zero-billing-dependency]]: no network calls.
Per [[cross-product-agent-parity]]: dbounce + ibounce ship the
same command shape so an operator's muscle memory works across
the suite.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outPath == "" {
				// Generate a default timestamped name in CWD so the
				// operator can omit --out for a quick capture.
				ts := time.Now().UTC().Format("20060102T150405Z")
				outPath = fmt.Sprintf("./kbounce-backup-%s.db", ts)
			}

			// Resolve + open the source store. We honor KBOUNCER_DB
			// env via store.Open's default-path logic.
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("kbounce: backup: open store: %w", err)
			}
			defer st.Close()

			opts := store.BackupOptions{
				IncludeAudit:     includeAudit,
				IncludePrompts:   includePrompts,
				KbounceVersion:   version,
				HostnameHashSeed: hostnameOverride,
			}
			result, err := st.BackupTo(outPath, opts)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.ErrOrStderr(),
				"kbounce: backup written to %s (%d bytes, sha256 %s)\n"+
					"  schema_version=%d kbounce_version=%s "+
					"included_audit=%t included_prompts=%t\n",
				result.OutPath, result.SizeBytes, result.SHA256,
				result.SchemaVersion, result.KbounceVersion,
				result.IncludedAudit, result.IncludedPrompts)

			snapshot := map[string]any{
				"out_path":         result.OutPath,
				"size_bytes":       result.SizeBytes,
				"schema_version":   result.SchemaVersion,
				"included_audit":   result.IncludedAudit,
				"included_prompts": result.IncludedPrompts,
				"sha256":           result.SHA256,
			}
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionStoreBackup,
				Actor:      currentActor(),
				EntityKind: "store_backup",
				EntityName: result.OutPath,
				Source:     audit.AdminActionSourceCLI,
				Before:     nil,
				After:      snapshot,
				ExtraExt: map[string]any{
					"sha256":           result.SHA256,
					"size_bytes":       result.SizeBytes,
					"included_audit":   result.IncludedAudit,
					"included_prompts": result.IncludedPrompts,
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "",
		"Output path (default: ./kbounce-backup-{ISO8601-UTC}.db). "+
			"Refuses to clobber an existing file — `rm` first or "+
			"pick a different path.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path of the source (default: ~/.kbouncer/state.db, "+
			"or KBOUNCER_DB env).")
	cmd.Flags().BoolVar(&includeAudit, "include-audit", false,
		"Include audit-event rows (decisions, pause events, burst "+
			"events) in the backup. Default is to OMIT them — they're "+
			"bulky + often-redundant after a rotation policy fires.")
	cmd.Flags().BoolVar(&includePrompts, "include-prompts", false,
		"Include pending-prompt rows in the backup. Default is to "+
			"OMIT them — pending prompts are runtime state by design.")
	cmd.Flags().StringVar(&hostnameOverride, "hostname-override", "",
		"Test-only: override the hostname used to compute the "+
			"source_hostname_hash field. Operators should leave this "+
			"unset; the default reads os.Hostname().")
	if err := cmd.Flags().MarkHidden("hostname-override"); err == nil {
		// Best-effort; non-fatal if the flag library changes shape.
		_ = err
	}
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

// newRestoreCmd implements `kbounce restore`. Top-level command;
// mirrors `dbounce restore`.
func newRestoreCmd() *cobra.Command {
	var (
		inPath       string
		destPath     string
		force        bool
		probeURL     string
		skipProbe    bool
		auditLogPath string
	)
	cmd := &cobra.Command{
		Use:   "restore --in PATH [--force]",
		Short: "Replace the kbounce SQLite store with the contents of a backup file",
		Long: `Restore the kbounce store from a backup file produced by
` + "`kbounce backup`" + `.

The destination DB file is REPLACED wholesale. The backup's
` + "`kbounce_backup_metadata`" + ` table is validated FIRST:

  - schema_version MUST match the live kbounce binary's
    SchemaVersion. Cross-schema restore is a migration, not a
    restore — refused even with --force.

  - kbounce_version is compared against the live binary. Mismatch
    is REFUSED unless --force is passed (and a warning is printed).

  - If the destination DB already has rows in ` + "`rules`" + ` or
    ` + "`tasks`" + ` the restore is REFUSED unless --force is passed.

Operational pre-flight: the running kbounce proxy MUST be stopped
before restore. The command probes the loopback wire/mgmt port +
refuses if a kbounce listener is detected (override with
--skip-running-probe at your own risk).

After a successful restore the command prints the restored row
counts + the sha256 of the resulting DB file so you can compare
across machines.

Per [[creates-never-mutates]]: the SOURCE backup file is
preserved; only the destination is rewritten.
Per [[cross-product-agent-parity]]: dbounce ships the same flag
shape + the same refuse-without-force semantics.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inPath == "" {
				return errors.New(
					"kbounce: restore: --in PATH is required")
			}
			if destPath == "" {
				p, err := store.DefaultDBPath()
				if err != nil {
					return fmt.Errorf(
						"kbounce: restore: resolve destination: %w", err)
				}
				destPath = p
			}

			// Pre-flight: refuse if a kbounce proxy is currently
			// running against the default port. Operators with a
			// non-default listener pass --probe-url; truly hostile
			// environments pass --skip-running-probe.
			if !skipProbe {
				if probeURL == "" {
					probeURL = backupDefaultHealthzURL
				}
				if running, reason := probeKbounceRunning(probeURL); running {
					return fmt.Errorf(
						"kbounce: restore: a kbounce proxy appears to be "+
							"running (%s); please stop kbounce first "+
							"(or pass --skip-running-probe if you're sure "+
							"the destination DB is not in use)",
						reason)
				}
			}

			result, err := store.RestoreFrom(inPath, destPath, store.RestoreOptions{
				Force:                 force,
				CurrentKbounceVersion: version,
			})
			if err != nil {
				return err
			}

			if result.VersionMismatch {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"kbounce: warning: restored backup was produced by "+
						"kbounce_version=%q; live binary is %q (forced via --force)\n",
					result.BackupVersion, version)
			}

			fmt.Fprintf(cmd.ErrOrStderr(),
				"kbounce: restored %d rule(s), %d task(s), %d profile(s), "+
					"%d audit row(s) (decisions=%d, prompts=%d, pauses=%d)\n"+
					"  destination=%s size=%d bytes sha256=%s\n",
				result.RestoredRules, result.RestoredTasks, result.RestoredProfiles,
				result.RestoredDecisions+result.RestoredPrompts+result.RestoredPauses,
				result.RestoredDecisions, result.RestoredPrompts, result.RestoredPauses,
				result.DestPath, result.DestSizeBytes, result.DestSHA256)

			snapshot := map[string]any{
				"dest_path":          result.DestPath,
				"backup_path":        result.BackupPath,
				"size_bytes":         result.DestSizeBytes,
				"sha256":             result.DestSHA256,
				"backup_version":     result.BackupVersion,
				"version_mismatch":   result.VersionMismatch,
				"restored_rules":     result.RestoredRules,
				"restored_tasks":     result.RestoredTasks,
				"restored_decisions": result.RestoredDecisions,
				"restored_prompts":   result.RestoredPrompts,
				"restored_pauses":    result.RestoredPauses,
			}
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionStoreRestore,
				Actor:      currentActor(),
				EntityKind: "store_restore",
				EntityName: result.DestPath,
				Source:     audit.AdminActionSourceCLI,
				Before:     nil,
				After:      snapshot,
				ExtraExt: map[string]any{
					"sha256":           result.DestSHA256,
					"size_bytes":       result.DestSizeBytes,
					"backup_version":   result.BackupVersion,
					"version_mismatch": result.VersionMismatch,
					"force":            force,
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "",
		"Backup file to restore from (required). Must have been "+
			"produced by `kbounce backup`.")
	cmd.Flags().StringVar(&destPath, "dest", "",
		"Destination DB path to write to (default: ~/.kbouncer/state.db, "+
			"or KBOUNCER_DB env).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Override the destination-non-empty check + override a "+
			"kbounce_version mismatch warning. Does NOT override a "+
			"schema_version mismatch (cross-schema restore is a "+
			"migration, not a restore).")
	cmd.Flags().StringVar(&probeURL, "probe-url", "",
		"Override the loopback URL probed to detect a running "+
			"kbounce. Default: "+backupDefaultHealthzURL+". Use this "+
			"when running on a non-default port.")
	cmd.Flags().BoolVar(&skipProbe, "skip-running-probe", false,
		"Skip the 'is kbounce running' pre-flight check. Use only "+
			"when you're certain the destination DB is not in use by "+
			"a live proxy.")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

// probeKbounceRunning does a quick loopback GET to the kbounce
// healthz endpoint. Returns (true, reason) when the listener
// appears to be up; (false, reason) otherwise. Best-effort by
// design — the worst case is a false positive that forces the
// operator to pass --skip-running-probe, which is preferable to a
// false negative that lets restore stomp a live DB.
//
// We refuse to probe non-loopback URLs (passing --probe-url
// http://example.com would otherwise turn restore into a covert
// outbound-network surface, violating [[self-host-zero-billing-
// dependency]]).
func probeKbounceRunning(probeURL string) (bool, string) {
	u, err := url.Parse(probeURL)
	if err != nil {
		return false, fmt.Sprintf("parse probe URL: %v", err)
	}
	host := u.Hostname()
	if host == "" || !isLoopbackHostForBackup(host) {
		return false, fmt.Sprintf(
			"refusing to probe non-loopback %q (probe is restricted "+
				"to loopback; pass --skip-running-probe if you're sure)",
			host)
	}
	// Belt + suspenders: a low-level TCP connect to the port,
	// then a healthz GET. Either failing means "no proxy here."
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, backupHealthzProbeTimeout)
	if err != nil {
		return false, fmt.Sprintf("no listener at %s: %v", addr, err)
	}
	_ = conn.Close()

	client := &http.Client{Timeout: backupHealthzProbeTimeout}
	ctx, cancel := context.WithTimeout(
		context.Background(), backupHealthzProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		// Listener exists but we couldn't build the request — be
		// conservative + treat as running.
		return true, fmt.Sprintf("listener at %s but request build failed: %v",
			addr, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Listener exists but doesn't speak HTTP — also conservative;
		// some other process owns the port + we shouldn't trample.
		return true, fmt.Sprintf("listener at %s but healthz failed: %v",
			addr, err)
	}
	_ = resp.Body.Close()
	return true, fmt.Sprintf("kbounce listener at %s (HTTP %d)",
		addr, resp.StatusCode)
}

// isLoopbackHostForBackup mirrors cli.go's loopbackHosts allowlist
// but as a function so test fakes can substitute a private map.
// Kept distinct from the cli.go map so a future change to that
// map for run-time binding doesn't accidentally widen what
// backup probing accepts.
func isLoopbackHostForBackup(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1",
		"ip6-localhost", "ip6-loopback":
		return true
	}
	return false
}
