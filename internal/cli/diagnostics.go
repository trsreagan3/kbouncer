// `kbounce diagnostics bundle` — single-command support-package ZIP
// for debugging a kbounce deployment WITHOUT exposing secrets.
//
// Per [[basic-app-hygiene-features]] TIER 1: every well-behaved
// product ships a "give us a ZIP we can debug" command. Until this
// slice, the operator-side answer to "kbounce is hanging / not
// forwarding / blocking the wrong thing" was a multi-step manual
// collection of (1) version, (2) config, (3) audit-log tail,
// (4) /healthz output, (5) system info — and each of those carried
// its own redaction concern (tokens, webhook URLs, k8s node names,
// user identifiers in audit rows). This command does all of it in
// one shot AND applies a uniform redactor so the resulting bundle
// is safe to share with support OR paste to a Claude agent for
// analysis (per [[investigate-with-claude]]).
//
// Bundle contents (each as a separate file in the ZIP):
//
//   00-README.txt                — top-level "what's in this bundle"
//   01-version.txt               — `kbounce version --verbose` output
//   02-config-redacted.json      — `config export --redact-secrets`
//   03-active-profile.json       — name + hash + load timestamp
//   04-audit-tail.jsonl          — last N audit events, redacted
//   05-healthz.json              — output of /healthz (or "unreachable")
//   06-system.txt                — OS / kernel / kubectl / k8s version
//   07-listener.json             — wire/mgmt port + connection count
//   08-panics.txt                — captured panics (if any)
//   09-manifest.json             — file list + sha256 of each
//
// Token-leak invariant: every secret-bearing surface goes through
// the SAME redactor as `config export` (`secretRedactedMarker`) so a
// grep of the bundle for any known token shape returns ZERO hits.
// The test suite enforces this by writing a known-marker token into
// fixtures and grepping the resulting ZIP.
//
// Per [[creates-never-mutates]]: this is a strictly READ-ONLY
// command. It never modifies the store, profiles file, or audit log.
// Per [[self-host-zero-billing-dependency]]: no network calls except
// the LOCAL /healthz GET (loopback only).
package cli

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/profile"
)

// defaultAuditTailLines is the default count of audit-log lines
// included in the bundle's 04-audit-tail.jsonl. Override with
// --include-audit-tail. 200 is small enough that a Claude-agent
// recipient can read the whole thing in one prompt, large enough
// that "the last few interesting decisions before the bug" are
// captured.
const defaultAuditTailLines = 200

// healthzProbeTimeout caps the GET to /healthz inside the bundle.
// Short enough that a misconfigured proxy (wrong port, dead socket)
// doesn't stall the bundle command for minutes.
const healthzProbeTimeout = 3 * time.Second

// userIDHashPrefix is the stable label prepended to the SHA-256 of
// a user identifier when we redact it in the audit tail. The
// truncated hash + label lets a support engineer correlate
// "user-XXXX seen on line 17 + line 42 are the same actor" without
// learning the actual identity.
const userIDHashPrefix = "user-"

// redactedPlaceholder is the sentinel string substituted into the
// bundle wherever a secret-bearing value would otherwise appear.
// Reuses the config-export marker so a SIEM analyst grepping
// across kbounce surfaces sees one uniform redaction token.
const redactedPlaceholder = secretRedactedMarker

// diagnosticsBundleVersion is stamped into the manifest so a
// downstream tool that learns to parse bundles can degrade
// gracefully when the on-disk shape evolves.
const diagnosticsBundleVersion = 1

// newDiagnosticsCmd assembles the `diagnostics` subcommand group +
// its `bundle` action. We register both `diagnostics` and a `diag`
// alias (memorable single-token) so the operator's muscle memory
// for `kbounce diag` works on the first attempt.
func newDiagnosticsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "diagnostics",
		Aliases: []string{"diag"},
		Short:   "Produce a redacted support bundle (ZIP) for debugging",
		Long: `Group for kbounce diagnostics tools. Subcommands:

  bundle   Produce a ZIP containing the operator's redacted config +
           audit-log tail + /healthz snapshot + system info, suitable
           for sharing with support OR pasting to a Claude agent for
           analysis.

Per [[basic-app-hygiene-features]]: every well-behaved product ships
a "give us a ZIP we can debug" command so the operator never has to
hand-assemble debug context one tool at a time. The bundle is
strictly READ-ONLY (no store / profile / audit-log mutations) and
performs no network calls except a single LOCAL /healthz GET.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("diagnostics", cmd)
	cmd.AddCommand(newDiagnosticsBundleCmd())
	return cmd
}

// newDiagnosticsBundleCmd implements `kbounce diagnostics bundle`.
// Honors --out, --include-audit-tail, --no-audit; defaults documented
// in the flag help text.
func newDiagnosticsBundleCmd() *cobra.Command {
	var (
		outPath          string
		includeAuditTail int
		noAudit          bool
		dbPath           string
		profilesPath     string
		auditLogPath     string
		healthzURL       string
		insecure         bool
		panicLogPath     string
	)
	cmd := &cobra.Command{
		Use:   "bundle [--out PATH] [--include-audit-tail N] [--no-audit]",
		Short: "Write a redacted diagnostics ZIP to disk",
		Long: `Produce a ZIP file containing the operator's:

  - kbounce version + build info
  - active config (REDACTED — webhook tokens / license bytes masked)
  - active profile name + hash + load timestamp
  - audit-log tail (default last 200 events, user IDs hashed)
  - /healthz snapshot (or "unreachable" + error reason)
  - recent panics (if any captured)
  - system info (OS / kernel / kubectl / k8s server version)
  - listener status (ports + connection count; NOT remote addresses)
  - file manifest with sha256 of each entry

Default output path: ./kbounce-diagnostics-{ISO8601-UTC}.zip
Override with --out PATH.

--no-audit ships a bundle with everything EXCEPT the audit-log tail,
for paranoid operators who treat the JSONL log as sensitive even
after the user-ID hashing pass.

Per [[creates-never-mutates]]: read-only; no state mutation.
Per [[self-host-zero-billing-dependency]]: no network calls except a
local /healthz GET on the loopback port.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if includeAuditTail < 0 {
				return errors.New(
					"kbounce: --include-audit-tail must be >= 0")
			}
			if includeAuditTail == 0 {
				includeAuditTail = defaultAuditTailLines
			}

			// Resolve the output path. Default = working-dir +
			// timestamp suffix so an operator running back-to-back
			// captures (e.g. before / after a config change) gets
			// distinct files without --out plumbing.
			if outPath == "" {
				ts := time.Now().UTC().Format("20060102T150405Z")
				outPath = fmt.Sprintf("./kbounce-diagnostics-%s.zip", ts)
			}

			opts := BundleOptions{
				OutPath:          outPath,
				IncludeAuditTail: includeAuditTail,
				NoAudit:          noAudit,
				DBPath:           dbPath,
				ProfilesPath:     profilesPath,
				AuditLogPath:     resolveAuditLogPath(auditLogPath),
				HealthzURL:       healthzURL,
				Insecure:         insecure,
				PanicLogPath:     panicLogPath,
				Stderr:           cmd.ErrOrStderr(),
			}

			summary, err := WriteDiagnosticsBundle(opts)
			if err != nil {
				return err
			}

			// One-line stderr summary so the operator sees "where did
			// the bundle land + how big is it" without piping stdout
			// (which is reserved for machine-readable formats in case
			// we add a --format=json later).
			fmt.Fprintf(cmd.ErrOrStderr(),
				"kbounce: diagnostics bundle written to %s "+
					"(%d files, %d bytes, %d audit lines included)\n",
				summary.OutPath, summary.FileCount,
				summary.TotalBytes, summary.AuditLines)

			// Admin-action audit event — fires regardless of --out so
			// a security team has a witness for "who pulled
			// diagnostics + when?" even if the operator captured to
			// stdout in a future revision. EntityName = output path.
			snapshot := map[string]any{
				"file_count":   summary.FileCount,
				"total_bytes":  summary.TotalBytes,
				"audit_lines":  summary.AuditLines,
				"no_audit":     opts.NoAudit,
				"healthz_ok":   summary.HealthzOK,
				"bundle_path":  summary.OutPath,
			}
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionDiagnosticsBundle,
				Actor:      currentActor(),
				EntityKind: "diagnostics_bundle",
				EntityName: summary.OutPath,
				Source:     audit.AdminActionSourceCLI,
				Before:     nil,
				After:      snapshot,
				ExtraExt: map[string]any{
					"audit_lines":   summary.AuditLines,
					"no_audit":      opts.NoAudit,
					"healthz_ok":    summary.HealthzOK,
					"file_count":    summary.FileCount,
				},
			})

			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "",
		"Write the bundle ZIP to this path (default: "+
			"./kbounce-diagnostics-{ISO8601-UTC}.zip). Parent dirs are "+
			"created 0o700; the file is written 0o600.")
	cmd.Flags().IntVar(&includeAuditTail, "include-audit-tail", defaultAuditTailLines,
		"Include the last N audit-log lines (REDACTED). Default 200. "+
			"Pass 0 to use the default; pass --no-audit to skip the "+
			"audit tail entirely.")
	cmd.Flags().BoolVar(&noAudit, "no-audit", false,
		"Skip the audit-log tail entirely. Use when the audit log "+
			"itself is the surface you don't want to ship (paranoid "+
			"operators / regulated environments where even user-ID-"+
			"hashed events are considered sensitive).")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles", "",
		"Profiles YAML path (default: ~/.kbouncer/profiles.yaml, or "+
			"KBOUNCER_PROFILES_PATH env).")
	cmd.Flags().StringVar(&healthzURL, "healthz-url", "http://127.0.0.1:8766/healthz",
		"URL of the running kbounce proxy's /healthz. Bundle records "+
			"\"unreachable\" + the error reason when the GET fails — the "+
			"command does NOT abort.")
	cmd.Flags().BoolVar(&insecure, "insecure-skip-verify", false,
		"Skip TLS verification on the /healthz GET. Useful for dev-cert "+
			"proxies started by `kbounce init-tls`.")
	cmd.Flags().StringVar(&panicLogPath, "panic-log", "",
		"Path to a captured stderr / panic log to include (REDACTED). "+
			"Optional — bundle works without it.")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

// BundleOptions controls a one-shot diagnostics-bundle write. All
// fields except OutPath have sensible defaults; tests pass explicit
// values to keep the run hermetic.
type BundleOptions struct {
	// OutPath is the on-disk ZIP path to write. Required.
	OutPath string
	// IncludeAuditTail is the count of audit lines to include from
	// AuditLogPath. Ignored when NoAudit is true.
	IncludeAuditTail int
	// NoAudit, when true, suppresses the audit-tail section entirely.
	NoAudit bool
	// DBPath is the SQLite file the bundle's config-export step
	// reads. Empty → DefaultDBPath.
	DBPath string
	// ProfilesPath is the profiles.yaml the bundle's profile section
	// reads. Empty → DefaultProfilesPath.
	ProfilesPath string
	// AuditLogPath is the audit JSONL path to tail. Empty → no
	// audit section (treated like NoAudit but with a different
	// reason string in the bundle).
	AuditLogPath string
	// HealthzURL is the local /healthz endpoint to probe. Empty →
	// no health snapshot (recorded as "skipped").
	HealthzURL string
	// Insecure controls TLS verification on the /healthz GET.
	Insecure bool
	// PanicLogPath is an optional captured-panics file path. Empty
	// → the bundle records "no panic-log configured".
	PanicLogPath string
	// Stderr is the writer the bundler logs non-fatal warnings to.
	// Nil → os.Stderr.
	Stderr io.Writer
}

// BundleSummary is returned by WriteDiagnosticsBundle so the CLI
// can print a one-line stderr summary + the admin-action audit
// event has stable fields to hash. The struct is also useful to
// tests that want to assert on the bundle's high-level shape
// without having to re-open the ZIP.
type BundleSummary struct {
	OutPath    string `json:"out_path"`
	FileCount  int    `json:"file_count"`
	TotalBytes int64  `json:"total_bytes"`
	AuditLines int    `json:"audit_lines"`
	HealthzOK  bool   `json:"healthz_ok"`
}

// WriteDiagnosticsBundle is the load-bearing worker. Builds each
// section in turn (collecting errors as warnings, never aborting
// the overall bundle — a partial bundle is more useful than no
// bundle), writes them to the ZIP, then writes the manifest as the
// last entry so its sha256s cover the full set.
//
// Section ordering inside the ZIP is the digit-prefixed filenames
// (00-README → 09-manifest); operators who `unzip -p ... | less`
// see the README first, manifest last.
func WriteDiagnosticsBundle(opts BundleOptions) (*BundleSummary, error) {
	if opts.OutPath == "" {
		return nil, errors.New("kbounce: BundleOptions.OutPath is required")
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	// Resolve the on-disk targets up front so a missing home dir
	// surfaces as one clean error rather than a partial bundle.
	if opts.ProfilesPath == "" {
		if p, err := profile.DefaultProfilesPath(); err == nil {
			opts.ProfilesPath = p
		}
	}

	// Create parent dir + open the ZIP for write.
	if dir := filepath.Dir(opts.OutPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(opts.OutPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", opts.OutPath, err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	// Don't defer zw.Close() — we need its error and must Close()
	// BEFORE os.Stat() to get the on-disk size.

	summary := &BundleSummary{OutPath: opts.OutPath}
	entries := []bundleEntry{}

	// 00-README — top-level explainer so a recipient who unzips
	// without reading any docs still knows what they're looking at.
	readme := buildBundleReadme(opts)
	entries = append(entries, bundleEntry{
		Name: "00-README.txt", Body: []byte(readme),
	})

	// 01-version — versionString + Go runtime info.
	entries = append(entries, bundleEntry{
		Name: "01-version.txt",
		Body: []byte(buildVersionSection()),
	})

	// 02-config-redacted — reuse config-export with redact-secrets.
	cfgBody, cfgErr := buildRedactedConfigSection(opts)
	if cfgErr != nil {
		fmt.Fprintf(opts.Stderr,
			"kbounce: diagnostics: config-export degraded: %v\n", cfgErr)
		cfgBody = []byte(fmt.Sprintf(
			"{\"error\": %q, \"note\": \"config export degraded; partial bundle\"}\n",
			cfgErr.Error()))
	}
	entries = append(entries, bundleEntry{Name: "02-config-redacted.json", Body: cfgBody})

	// 03-active-profile — name + hash + load timestamp.
	entries = append(entries, bundleEntry{
		Name: "03-active-profile.json",
		Body: buildActiveProfileSection(opts),
	})

	// 04-audit-tail — opt-out via --no-audit; uses opts.AuditLogPath.
	auditBody, auditLines := buildAuditTailSection(opts)
	summary.AuditLines = auditLines
	entries = append(entries, bundleEntry{Name: "04-audit-tail.jsonl", Body: auditBody})

	// 05-healthz — local GET; failure is recorded, not fatal.
	healthBody, healthOK := buildHealthzSection(opts)
	summary.HealthzOK = healthOK
	entries = append(entries, bundleEntry{Name: "05-healthz.json", Body: healthBody})

	// 06-system — OS / kernel / kubectl / k8s server version.
	entries = append(entries, bundleEntry{
		Name: "06-system.txt",
		Body: []byte(buildSystemSection()),
	})

	// 07-listener — wire/mgmt port + connection count.
	entries = append(entries, bundleEntry{
		Name: "07-listener.json",
		Body: buildListenerSection(opts),
	})

	// 08-panics — optional; "no panic-log configured" placeholder
	// when unset.
	entries = append(entries, bundleEntry{
		Name: "08-panics.txt",
		Body: buildPanicSection(opts),
	})

	// Write all the leading entries; we'll append the manifest last
	// so it can include sha256s of everything else.
	manifestEntries := []map[string]any{}
	for _, e := range entries {
		if err := writeZipEntry(zw, e.Name, e.Body); err != nil {
			_ = zw.Close()
			return nil, fmt.Errorf("write %s: %w", e.Name, err)
		}
		sum := sha256.Sum256(e.Body)
		manifestEntries = append(manifestEntries, map[string]any{
			"name":   e.Name,
			"size":   len(e.Body),
			"sha256": hex.EncodeToString(sum[:]),
		})
		summary.FileCount++
	}

	// 09-manifest — sha256 of every other entry. Determinism: the
	// manifest's entries list mirrors the write order so a diff
	// across two bundles is line-stable.
	manifestPayload := map[string]any{
		"bundle_version":   diagnosticsBundleVersion,
		"product":          ConfigProduct,
		"binary_version":   version,
		"generated_at":     time.Now().UTC().Format(time.RFC3339),
		"entries":          manifestEntries,
		"redaction_marker": redactedPlaceholder,
	}
	manifestBody, err := json.MarshalIndent(manifestPayload, "", "  ")
	if err != nil {
		_ = zw.Close()
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeZipEntry(zw, "09-manifest.json", manifestBody); err != nil {
		_ = zw.Close()
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	summary.FileCount++

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finalize zip: %w", err)
	}
	if st, serr := f.Stat(); serr == nil {
		summary.TotalBytes = st.Size()
	}

	return summary, nil
}

// bundleEntry is the simple {name, body} pair the bundler walks
// to populate the ZIP. Kept as a tiny inner type so the
// WriteDiagnosticsBundle worker reads top-to-bottom.
type bundleEntry struct {
	Name string
	Body []byte
}

// writeZipEntry creates a zip.FileHeader with a fixed deterministic
// modtime so two bundles built from the same input bytes hash
// identically — useful for "did anything change between captures?"
// diffs.
func writeZipEntry(zw *zip.Writer, name string, body []byte) error {
	hdr := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	// Deterministic modtime keeps the ZIP byte-stable across runs
	// with identical inputs. We pick the kbounce-suite epoch
	// (2026-05-17 bounce-suite rename day) so the timestamp itself
	// is recognizable.
	hdr.Modified = time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)
	hdr.SetMode(0o600)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// buildBundleReadme is the top-of-bundle explainer. Kept short
// + factual so a Claude agent can use the first ~10 lines as
// context.
func buildBundleReadme(opts BundleOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kbounce diagnostics bundle\n")
	fmt.Fprintf(&b, "generated_at: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "bundle_version: %d\n", diagnosticsBundleVersion)
	fmt.Fprintf(&b, "binary_version: %s\n\n", version)
	fmt.Fprintf(&b, "Contents:\n")
	fmt.Fprintf(&b, "  00-README.txt              this file\n")
	fmt.Fprintf(&b, "  01-version.txt             kbounce build info\n")
	fmt.Fprintf(&b, "  02-config-redacted.json    operator config (tokens MASKED)\n")
	fmt.Fprintf(&b, "  03-active-profile.json     loaded profile + hash\n")
	fmt.Fprintf(&b, "  04-audit-tail.jsonl        last N audit events (user IDs hashed)\n")
	fmt.Fprintf(&b, "  05-healthz.json            /healthz snapshot\n")
	fmt.Fprintf(&b, "  06-system.txt              OS / kubectl / k8s versions\n")
	fmt.Fprintf(&b, "  07-listener.json           bind ports + conn count\n")
	fmt.Fprintf(&b, "  08-panics.txt              captured panics (if any)\n")
	fmt.Fprintf(&b, "  09-manifest.json           file list + sha256 of each\n\n")
	fmt.Fprintf(&b, "Redaction:\n")
	fmt.Fprintf(&b, "  - audit-webhook tokens, license bytes, etc. replaced with %q\n", redactedPlaceholder)
	fmt.Fprintf(&b, "  - webhook URLs in audit-export config replaced with %q\n", redactedPlaceholder)
	fmt.Fprintf(&b, "  - user identifiers in audit events replaced with stable hash (user-XXXX)\n")
	fmt.Fprintf(&b, "  - hostnames / IPs / env-var VALUES suppressed (keys only kept)\n")
	if opts.NoAudit {
		fmt.Fprintf(&b, "\nNOTE: --no-audit was passed; 04-audit-tail.jsonl is intentionally empty.\n")
	}
	return b.String()
}

// buildVersionSection captures `kbounce version --verbose` output +
// the Go runtime metadata.
func buildVersionSection() string {
	var b strings.Builder
	fmt.Fprintln(&b, versionString())
	fmt.Fprintf(&b, "go_version: %s\n", runtime.Version())
	fmt.Fprintf(&b, "go_os: %s\n", runtime.GOOS)
	fmt.Fprintf(&b, "go_arch: %s\n", runtime.GOARCH)
	fmt.Fprintf(&b, "num_cpu: %d\n", runtime.NumCPU())
	return b.String()
}

// buildRedactedConfigSection reuses the config-export pipeline
// with --redact-secrets so the bundle's config section is
// byte-identical to what `kbounce config export --redact-secrets`
// would produce. Single source of truth for redaction logic per
// [[deliberate-feature-completion]] — duplicating the redactor
// would let one fork drift relative to the other.
func buildRedactedConfigSection(opts BundleOptions) ([]byte, error) {
	exp, err := BuildExport(ExportOptions{
		ProfilesPath: opts.ProfilesPath,
		DBPath:       opts.DBPath,
		WithSecrets:  false, // FORCED — diagnostics MUST redact
		AuditExport: ConfigAuditExport{
			LogPath: opts.AuditLogPath,
		},
	})
	if err != nil {
		return nil, err
	}
	// Belt-and-suspenders: the BuildExport call ALREADY redacts
	// tokens. We additionally null out webhook URLs (which the
	// config-export path leaves visible because they're the
	// destination, not the credential). For a SHAREABLE bundle
	// the URL is also sensitive: it identifies the operator's
	// SIEM endpoint.
	if exp.AuditExport.WebhookURL != "" {
		exp.AuditExport.WebhookURL = redactedPlaceholder
	}
	return json.MarshalIndent(exp, "", "  ")
}

// buildActiveProfileSection records which profile is loaded + its
// content hash + the load timestamp. Useful for "did the profile
// change between yesterday + today?" diffs without leaking the
// profile bodies themselves (which the redacted config section
// already carries).
func buildActiveProfileSection(opts BundleOptions) []byte {
	out := map[string]any{
		"loaded_at": time.Now().UTC().Format(time.RFC3339),
	}
	profilesPath := opts.ProfilesPath
	if profilesPath == "" {
		if p, err := profile.DefaultProfilesPath(); err == nil {
			profilesPath = p
		}
	}
	if profilesPath == "" {
		out["error"] = "could not resolve profiles path"
		body, _ := json.MarshalIndent(out, "", "  ")
		return body
	}
	out["profiles_path"] = profilesPath
	if raw, err := os.ReadFile(profilesPath); err == nil {
		sum := sha256.Sum256(raw)
		out["sha256"] = hex.EncodeToString(sum[:])
		out["size_bytes"] = len(raw)
	} else if os.IsNotExist(err) {
		out["note"] = "profiles file does not exist (embedded defaults in effect)"
	} else {
		out["error"] = err.Error()
	}
	// We deliberately do NOT include the active-profile NAME since
	// the bundle is one-shot CLI — there's no running-proxy IPC to
	// query "what profile did the daemon resolve?" The name lives
	// in env (KBOUNCER_PROFILE) which we read separately.
	if envVal := os.Getenv("KBOUNCER_PROFILE"); envVal != "" {
		out["env_KBOUNCER_PROFILE"] = envVal
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return body
}

// buildAuditTailSection reads the last N lines from the audit log
// + applies the audit-line redactor. Returns the body + the count
// of lines included so the CLI summary + admin-action event have
// matching numbers.
func buildAuditTailSection(opts BundleOptions) ([]byte, int) {
	if opts.NoAudit {
		return []byte("# --no-audit was passed; audit tail intentionally omitted.\n"), 0
	}
	if opts.AuditLogPath == "" {
		return []byte("# no audit log path configured (KBOUNCER_AUDIT_LOG_PATH unset and " +
			"--audit-log-path not supplied); section empty.\n"), 0
	}
	lines, err := tailLines(opts.AuditLogPath, opts.IncludeAuditTail)
	if err != nil {
		return []byte(fmt.Sprintf(
			"# audit-tail unavailable: %v\n", err)), 0
	}
	var b strings.Builder
	count := 0
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		redacted := redactAuditLine(ln)
		b.WriteString(redacted)
		b.WriteByte('\n')
		count++
	}
	if count == 0 {
		return []byte("# audit log is present but empty (no events to tail).\n"), 0
	}
	return []byte(b.String()), count
}

// buildHealthzSection issues a local GET to opts.HealthzURL +
// records the response body (or an error reason). Always returns a
// non-empty body so the section is never silently missing.
func buildHealthzSection(opts BundleOptions) ([]byte, bool) {
	if opts.HealthzURL == "" {
		return []byte(`{"status": "skipped", "note": "no --healthz-url configured"}` + "\n"), false
	}
	transport := http.DefaultTransport
	if opts.Insecure {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // user opted in
		}
	}
	client := &http.Client{
		Timeout:   healthzProbeTimeout,
		Transport: transport,
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthzProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.HealthzURL, nil)
	if err != nil {
		body := map[string]any{
			"health":  "unreachable",
			"reason":  "build request: " + err.Error(),
			"probed":  opts.HealthzURL,
		}
		out, _ := json.MarshalIndent(body, "", "  ")
		return out, false
	}
	req.Header.Set("User-Agent", "kbounce-diagnostics/"+version)
	resp, err := client.Do(req)
	if err != nil {
		body := map[string]any{
			"health":  "unreachable",
			"reason":  err.Error(),
			"probed":  opts.HealthzURL,
		}
		out, _ := json.MarshalIndent(body, "", "  ")
		return out, false
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	// Try to parse + re-emit pretty so the bundle is human-friendly.
	var parsed map[string]any
	if jerr := json.Unmarshal(bodyBytes, &parsed); jerr == nil {
		wrap := map[string]any{
			"http_status":  resp.StatusCode,
			"probed":       opts.HealthzURL,
			"body":         parsed,
		}
		out, _ := json.MarshalIndent(wrap, "", "  ")
		ok := resp.StatusCode >= 200 && resp.StatusCode < 300
		return out, ok
	}
	wrap := map[string]any{
		"http_status":  resp.StatusCode,
		"probed":       opts.HealthzURL,
		"raw_body":     string(bodyBytes),
	}
	out, _ := json.MarshalIndent(wrap, "", "  ")
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	return out, ok
}

// buildSystemSection runs `uname -a` (best-effort) + `kubectl
// version --client` (best-effort) + records GOOS/GOARCH/Go
// version. Sensitive bits (hostname / FQDN) are scrubbed.
func buildSystemSection() string {
	var b strings.Builder
	fmt.Fprintf(&b, "os: %s\n", runtime.GOOS)
	fmt.Fprintf(&b, "arch: %s\n", runtime.GOARCH)
	fmt.Fprintf(&b, "go_version: %s\n", runtime.Version())
	fmt.Fprintf(&b, "num_cpu: %d\n\n", runtime.NumCPU())

	// uname -a — strip the hostname field (output is
	// "Darwin <host> 24.1.0 ..."; we replace the second token).
	if out, err := runCmdSafe("uname", "-a"); err == nil {
		fmt.Fprintln(&b, "uname:")
		fmt.Fprintln(&b, "  "+scrubHostnameInUname(out))
	} else {
		fmt.Fprintf(&b, "uname: <unavailable: %v>\n", err)
	}

	// kubectl version --client -o yaml — client side only so we
	// don't accidentally pull server-side metadata. Failure is
	// expected on hosts without kubectl installed.
	if out, err := runCmdSafe("kubectl", "version", "--client", "-o", "yaml"); err == nil {
		fmt.Fprintln(&b, "kubectl_version_client:")
		for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			fmt.Fprintln(&b, "  "+ln)
		}
	} else {
		fmt.Fprintf(&b, "kubectl_version_client: <unavailable: %v>\n", err)
	}

	// Env var KEYS only — never values — for any KBOUNCER_*
	// or KUBE* var. Lets a recipient see "operator has
	// KBOUNCER_AUDIT_LOG_PATH set" without learning the path.
	fmt.Fprintln(&b, "\nenv_keys (values intentionally NOT included):")
	keys := []string{}
	for _, e := range os.Environ() {
		eq := strings.IndexByte(e, '=')
		if eq < 0 {
			continue
		}
		k := e[:eq]
		if strings.HasPrefix(k, "KBOUNCER_") ||
			strings.HasPrefix(k, "KBOUNCE_") ||
			strings.HasPrefix(k, "KUBE") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s\n", k)
	}
	if len(keys) == 0 {
		fmt.Fprintln(&b, "  (none)")
	}
	return b.String()
}

// buildListenerSection records the configured wire / mgmt ports
// WITHOUT remote-address info. The CLI side doesn't have IPC into
// the running proxy, so we record what the OPERATOR would
// configure (the standard 8766 wire port + any env override) +
// note that the live connection count requires the proxy to be
// running. Future post-launch: when the proxy exposes a stats
// endpoint, this section can include live data.
func buildListenerSection(opts BundleOptions) []byte {
	listener := map[string]any{
		"default_wire_port":   8766,
		"healthz_url_probed":  opts.HealthzURL,
		"note": "live connection count requires a running proxy with a " +
			"stats endpoint (post-launch). Remote addresses are NEVER " +
			"recorded in this bundle.",
	}
	if v := os.Getenv("KBOUNCER_PORT"); v != "" {
		listener["env_KBOUNCER_PORT"] = v
	}
	body, _ := json.MarshalIndent(listener, "", "  ")
	return body
}

// buildPanicSection includes the captured panic-log file (if
// configured + readable). The body is passed through the audit
// redactor since panic stack frames sometimes carry env-var
// values or partial tokens.
func buildPanicSection(opts BundleOptions) []byte {
	if opts.PanicLogPath == "" {
		return []byte("# no --panic-log configured; section empty.\n")
	}
	raw, err := os.ReadFile(opts.PanicLogPath)
	if err != nil {
		return []byte(fmt.Sprintf(
			"# panic-log unreadable (%s): %v\n", opts.PanicLogPath, err))
	}
	if len(raw) == 0 {
		return []byte("# panic-log is empty (no captured panics).\n")
	}
	// Cap at 256 KiB so a runaway log doesn't bloat the bundle.
	const maxPanicBytes = 256 << 10
	if len(raw) > maxPanicBytes {
		raw = append(raw[:maxPanicBytes], []byte("\n... (truncated)\n")...)
	}
	// Light redaction: scrub URLs + obvious token-shaped strings.
	scrubbed := redactPlainText(string(raw))
	return []byte(scrubbed)
}

// runCmdSafe runs an external command with a short timeout and
// captures stdout. Returns ("", err) on any failure; the caller
// records that as "<unavailable>" rather than aborting.
func runCmdSafe(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// scrubHostnameInUname strips the hostname (2nd whitespace-separated
// token) from a uname -a output. We replace with "<hostname-redacted>"
// rather than deleting so the output's column count stays parseable.
func scrubHostnameInUname(s string) string {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return s
	}
	parts[1] = "<hostname-redacted>"
	return strings.Join(parts, " ")
}

// tailLines reads the last n non-empty lines from a file. Used for
// the audit-tail section. For small N (<= 10_000) we read the whole
// file + slice the tail — keeps the implementation simple at the
// cost of memory for very large logs. The 64 MiB read cap below
// prevents pathological cases.
func tailLines(path string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const maxBytes = 64 << 20 // 64 MiB cap
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() == 0 {
		return nil, nil
	}
	// For larger files seek to the tail region rather than read
	// the whole thing. 1 MiB tail is more than enough for 200
	// audit lines.
	const tailRegion = 1 << 20
	var startOff int64
	if stat.Size() > tailRegion {
		startOff = stat.Size() - tailRegion
		if _, err := f.Seek(startOff, io.SeekStart); err != nil {
			return nil, err
		}
	}
	reader := bufio.NewReader(io.LimitReader(f, maxBytes))
	lines := []string{}
	scanner := bufio.NewScanner(reader)
	// Allow large single-line entries (OCSF events can be several
	// KiB) by raising the scanner buffer.
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 4*1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// If we seeked, the first line is probably partial. Drop it.
	if startOff > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// userIDFields names the JSON keys we treat as user identifiers in
// audit events. Each key encountered in a parsed audit line has its
// value replaced with a stable SHA-256-prefixed hash so two events
// for the same actor produce the same redacted token (cross-event
// correlation is preserved) without leaking the identity itself.
//
// Keys are case-sensitive — OCSF field names are conventionally
// lower-snake; we list both common camelCase variants the audit
// log may carry just in case.
var userIDFields = []string{
	"name",
	"user_name",
	"username",
	"uid",
	"user_uid",
	"sub",
	"email",
}

// urlPattern matches absolute http(s) URLs anywhere in a string.
// Used by redactPlainText for the panic-log scrubber.
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// ipPattern matches IPv4 + IPv6 literals. Loose-but-acceptable:
// the bundle is a debugging artifact, not a court exhibit; false
// positives just over-redact.
var ipPattern = regexp.MustCompile(
	`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+)\b`)

// tokenLikePattern matches common token shapes: long random-looking
// strings of 32+ chars OR a `Bearer <token>` Authorization header.
// Heuristic — we accept false positives over false negatives since
// the bundle is meant to be shared.
var tokenLikePattern = regexp.MustCompile(
	`(?i)(bearer\s+[A-Za-z0-9._\-]+|[A-Za-z0-9+/=_\-]{32,})`)

// redactAuditLine parses one JSONL audit-event line + walks it
// recursively, replacing values under userIDFields with a stable
// hash. Non-JSON lines (operator commentary, malformed entries)
// pass through redactPlainText unchanged so they're still scrubbed
// of obvious tokens / URLs.
func redactAuditLine(line string) string {
	var v any
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		return redactPlainText(line)
	}
	redactWalk(v)
	out, err := json.Marshal(v)
	if err != nil {
		return redactPlainText(line)
	}
	return string(out)
}

// redactWalk recursively descends a parsed JSON value, replacing
// userID-shaped values with a stable hash + scrubbing URLs / IPs
// inside string values that aren't user IDs. Also masks any field
// whose KEY looks token-shaped (token / api_key / secret / bearer /
// authorization) since those are unambiguously sensitive.
func redactWalk(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isUserIDKey(k) {
				if s, ok := val.(string); ok && s != "" {
					t[k] = hashUserID(s)
					continue
				}
			}
			if isURLKey(k) {
				if s, ok := val.(string); ok && s != "" {
					t[k] = redactedPlaceholder
					continue
				}
			}
			if isSensitiveKey(k) {
				// Token / secret / api_key shapes — mask the value
				// regardless of its concrete type so booleans / nested
				// objects under a "secret" key still get redacted.
				t[k] = redactedPlaceholder
				continue
			}
			// String values that aren't categorized above still get a
			// scrub pass so an inline URL / token-shape embedded in a
			// freeform "message" or "raw_data" field is not leaked.
			if s, ok := val.(string); ok {
				t[k] = redactPlainText(s)
				continue
			}
			// Recurse into nested objects / arrays.
			redactWalk(val)
		}
	case []any:
		for i, item := range t {
			if s, ok := item.(string); ok {
				t[i] = redactPlainText(s)
				continue
			}
			redactWalk(item)
		}
	}
}

// isURLKey returns true for any JSON field name that conventionally
// carries a URL (which the bundle treats as sensitive — the URL
// identifies an operator's SIEM / webhook endpoint).
func isURLKey(k string) bool {
	lk := strings.ToLower(k)
	if lk == "url" || lk == "webhook_url" || lk == "endpoint" {
		return true
	}
	return strings.HasSuffix(lk, "_url")
}

// sensitiveKeyFragments names the substrings that mark a field as
// secret-bearing. Case-insensitive substring match: a key like
// "auth_token" or "x-api-key" or "client_secret" matches.
var sensitiveKeyFragments = []string{
	"token",
	"secret",
	"api_key",
	"apikey",
	"password",
	"passwd",
	"bearer",
	"authorization",
	"private_key",
	"webhook_token",
	"hec_token",
}

// isSensitiveKey returns true when the field key contains any of
// the sensitiveKeyFragments (case-insensitive).
func isSensitiveKey(k string) bool {
	lk := strings.ToLower(k)
	for _, frag := range sensitiveKeyFragments {
		if strings.Contains(lk, frag) {
			return true
		}
	}
	return false
}

// isUserIDKey returns true for any audit-event field name that
// carries a user identifier per the OCSF + iam-jit/kbounce
// schemas. Case-insensitive match.
func isUserIDKey(k string) bool {
	lk := strings.ToLower(k)
	for _, f := range userIDFields {
		if lk == f {
			return true
		}
	}
	return false
}

// hashUserID returns a "user-XXXX" stable token for an input
// identifier. Uses the first 8 hex chars of SHA-256 — collision-
// resistant enough for cross-event correlation in a single
// bundle, short enough to read in a terminal.
func hashUserID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return userIDHashPrefix + hex.EncodeToString(sum[:4])
}

// redactPlainText scrubs obvious token / URL / IP shapes from an
// arbitrary string. Used for the panic-log section + as a fallback
// when a "JSONL" audit line failed to parse.
func redactPlainText(s string) string {
	s = urlPattern.ReplaceAllString(s, redactedPlaceholder)
	s = tokenLikePattern.ReplaceAllString(s, redactedPlaceholder)
	s = ipPattern.ReplaceAllString(s, redactedPlaceholder)
	return s
}
