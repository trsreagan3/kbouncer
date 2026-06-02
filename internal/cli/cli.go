// Command kbounce is the local Kubernetes API-call gating proxy.
//
// Run it as a sidecar to kubectl / Helm / a coding agent that points at
// it instead of the real kube-apiserver; kbounce parses each call,
// matches it against gating rules, records the decision, and either
// forwards to the real apiserver or returns 403 to the client (when
// running in transparent mode).
//
// The binary was renamed from `kbouncer` to `kbounce` in the
// 2026-05-17 bounce-suite rename ([[bounce-suite-rename]]). The
// `kbouncer` binary is preserved as a deprecation-warning shim for
// v1.0 (see cmd/kbouncer/) and removed in v1.1.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/caveats"
	"github.com/trsreagan3/kbouncer/internal/dynamicdeny"
	"github.com/trsreagan3/kbouncer/internal/kbenv"
	"github.com/trsreagan3/kbouncer/internal/mcp"
	"github.com/trsreagan3/kbouncer/internal/mcpinstall"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/profileallow"
	"github.com/trsreagan3/kbouncer/internal/proxy"
	"github.com/trsreagan3/kbouncer/internal/store"
	"github.com/trsreagan3/kbouncer/internal/tlsmat"
	"github.com/trsreagan3/kbouncer/internal/upstream"
)

// loopbackHosts mirrors iam-jit-bouncer's CRIT-32-02 closure: kbounce
// holds inbound client bearer tokens long enough to forward; binding
// externally exposes that surface to anyone on the network. Refuse
// non-loopback bindings unless the operator passed
// --i-know-this-binds-externally to acknowledge they read the threat
// model.
var loopbackHosts = map[string]struct{}{
	"127.0.0.1":     {},
	"::1":           {},
	"localhost":     {},
	"ip6-localhost": {},
	"ip6-loopback":  {},
}

// envProfileVar is the CANONICAL env-var name used to select the active
// profile when --profile is not passed. Documented in the README + on
// the run subcommand's flag help text. The KBOUNCER_ prefix is the
// documented canonical (per [[bounce-suite-rename]] decision #6) but
// reads go through kbenv.Get, which ALSO accepts the KBOUNCE_ alias so
// `export KBOUNCE_PROFILE=...` (dropping the trailing 'R' to match the
// binary name) is no longer a silent no-op.
const envProfileVar = "KBOUNCER_PROFILE"

// envUpstreamCABundleVar is the env-var fallback for --upstream-ca-bundle
// (#379). When the flag is empty this env var is consulted; the flag
// wins when both are set. Canonical KBOUNCER_ prefix; the KBOUNCE_ alias
// also resolves via kbenv (flagOrEnv → kbenv.Get).
const envUpstreamCABundleVar = "KBOUNCER_UPSTREAM_CA_BUNDLE"

// envAuditEventsTokenVar is the env-var fallback for --audit-events-token
// (#380). Passing the token as a CLI flag leaks it into `ps` /process
// listings; the env var keeps it out of the process table. The flag
// wins when both are set. Canonical KBOUNCER_ prefix; the KBOUNCE_ alias
// also resolves via kbenv (flagOrEnv → kbenv.Get).
const envAuditEventsTokenVar = "KBOUNCER_AUDIT_EVENTS_TOKEN"

// dbFlagHelp documents the --db flag + the container-friendly default
// resolution implemented in store.DefaultDBPath (#381). Shared by every
// subcommand that opens the store so the help text never drifts.
const dbFlagHelp = "SQLite DB path. An explicit value overrides everything. " +
	"When unset the default resolves in order: $KBOUNCER_DB, then " +
	"$XDG_STATE_HOME/kbounce/state.db, then ~/.kbouncer/state.db (when " +
	"$HOME is set), else /var/lib/kbounce/state.db (rootless containers " +
	"with no HOME). Parent dirs are created 0700."

// flagOrEnv returns the flag value when it is non-empty, otherwise the
// value of the named environment variable. This is the canonical
// "flag wins, env is the fallback" resolution used by --audit-events-
// token (#380) and --upstream-ca-bundle (#379). Keeping it in one
// helper means the precedence is identical everywhere and unit-testable
// without standing up the whole run command.
//
// envName may be a base name ("PROFILE") or a legacy full var name
// ("KBOUNCER_PROFILE"); either resolves under both the KBOUNCER_ and
// KBOUNCE_ prefixes via kbenv (kbenv.Get strips a known prefix).
func flagOrEnv(flagVal, envName string) string {
	if flagVal != "" {
		return flagVal
	}
	return kbenv.Get(envName)
}

// version is overridden at build time via
// -ldflags "-X github.com/trsreagan3/kbouncer/internal/cli.version=..."
// for release builds. Unstamped builds report "dev".
var version = "dev"

// commit is the git SHA the binary was built from. Set via
// -ldflags "-X github.com/trsreagan3/kbouncer/internal/cli.commit=...".
// Unset → "none".
var commit = "none"

// buildTime is the ISO-8601 UTC timestamp the binary was built at.
// Set via -ldflags "-X github.com/trsreagan3/kbouncer/internal/cli.buildTime=...".
// Unset → "unknown".
var buildTime = "unknown"

// Main is the package's exported entry point so both binaries
// (`cmd/kbounce` and the legacy `cmd/kbouncer` deprecation shim)
// run the same code path. Keeps the single source of truth for
// command wiring + makes drift between the two binaries impossible.
func Main() {
	proxy.EnsureLogger()
	// Thread the linker-stamped binary version into the audit-export
	// OCSF metadata.product.version field. Done here (one site) so
	// audit/event.go doesn't have to import cli (avoiding a cycle).
	audit.SetBuildVersion(version)
	if err := newRootCmd().Execute(); err != nil {
		// cobra already prints to stderr; exit 1 so shell scripts can
		// distinguish success.
		os.Exit(1)
	}
}

// versionString returns the human-readable version string surfaced via
// `kbounce --version`. Format: `kbounce <version> (commit X, built Y)`.
// Closes UAT-K2 HIGH-K2-06.
func versionString() string {
	return fmt.Sprintf("kbounce %s (commit %s, built %s)", version, commit, buildTime)
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "kbounce",
		Short:         "Local Kubernetes API-call gating proxy",
		Long:          rootLongHelp,
		Version:       versionString(),
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	// UAT-K2 HIGH-K2-06: surface version via "kbounce <version> (...)"
	// rather than just a bare semver string.
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newRunCmd())
	root.AddCommand(newProfileCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newAuditExportCmd())
	root.AddCommand(newAuditWebhookCmd())
	root.AddCommand(newPauseCmd())
	root.AddCommand(newPromptsCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newTasksCmd())
	root.AddCommand(newPresetsCmd())
	root.AddCommand(newInitTLSCmd())
	root.AddCommand(newMCPCmd())
	root.AddCommand(newVersionCheckCmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newDiagnosticsCmd())
	// #304 — `kbounce doctor caveats` surfaces the §B entries from
	// KNOWN-CAVEATS.md that apply to kbounce. Sibling Bounce products
	// ship the same shape per [[cross-product-agent-parity]].
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newInvestigateCmd())
	root.AddCommand(newBackupCmd())
	root.AddCommand(newRestoreCmd())
	root.AddCommand(newSessionCmd())
	// #311 / §A10 — `kbounce logs {purge,archive,verify}` audit-log
	// retention surface. Ships in lockstep with the sibling products
	// + the cross-product runbook at iam-roles/docs/LOG-RETENTION.md.
	root.AddCommand(newLogsCmd())
	// #383 / §A42 — `kbounce posture` per-bouncer posture surface.
	// Cross-product parity command per [[cross-product-agent-parity]];
	// every Bounce (ibounce/kbounce/dbounce/gbounce) ships the same
	// `<bouncer> posture` shape so an operator's muscle memory works
	// across protocols. For the cross-product roll-up use
	// `iam-jit posture` from iam-roles.
	root.AddCommand(newPostureCmd())
	return root
}

const rootLongHelp = `kbounce is a local proxy that sits between your kubectl / Helm /
coding agent and the real kube-apiserver. It parses every request,
records the decision in an audit log, and (in transparent mode) can
deny calls that don't match its rule set.

Two operating modes (the same shape as iam-jit-bouncer):

  cooperative   parse + log every call, but always forward (advisory)
  transparent   DENY verdicts return 403 to the client; ALLOW verdicts
                forward unchanged

Profile defaults (2026-05-17 reshape per [[bounce-default-profile-pattern]] +
Opus readonly-profile audit closure):

  full-user     passthrough (no rules). Default when --profile / KBOUNCER_PROFILE
                is unset. Calls forwarded as-is + audit-logged.
  safe-default  cross-product safe-by-default. Blocks operations whose blast
                radius is high enough that the average operator wants them
                gated: mutating verbs (delete/patch/create/update/
                deletecollection), destructive non-writes (exec/portforward/
                attach/eviction), state-changers (status/scale/finalize),
                privilege primitives (proxy/token/binding/
                ephemeralcontainers/impersonation), CRD-defined mutating
                subresources (long-tail safety net). NOT a confidentiality
                boundary — reads of sensitive data still pass.

Opt into safe-default with --profile safe-default OR
export KBOUNCER_PROFILE=safe-default in your shell rc. Environment-specific
profiles (staging-work, dev-only, incident-response) install via
` + "`kbounce profile install --from URL`" + ` (see community-profiles/ in
the kbounce repo).

Legacy aliases (v1.0 backward-compat; removed v1.1): "readonly" →
"safe-default", "prod-readonly" → "safe-default", "none" → "full-user".`

func newRunCmd() *cobra.Command {
	var (
		port               int
		host               string
		modeStr            string
		defaultPolStr      string
		dbPath             string
		profileName        string
		profilesPath       string
		cluster            string
		promptOnDeny       bool
		syncPromptOnDeny   bool
		syncPromptTimeout  time.Duration
		syncPromptDefault  string
		upstreamURL        string
		kubeconfigPath     string
		insecureSkipVerify bool
		upstreamCABundle   string
		forceExternalBind  bool
		forwardTimeoutSecs int
		tlsCertPath        string
		tlsKeyPath         string
		requireClientCert  string
		// Slice 1 of #252 — security-team audit-export. Two channels
		// (operator picks one or both); webhook flags are license-
		// gated for Enterprise per [[security-team-audit-export]].
		auditLogPath     string
		auditLogFsync    bool
		noAuditChain     bool
		manifestInterval int64
		// #311 / §A10 — rotation thresholds. 0 disables the trigger;
		// negative values (sentinel for "operator didn't pass the flag")
		// fall back to the audit-package defaults via the env-var
		// resolution. Names match the cross-product spec at
		// iam-roles/docs/LOG-RETENTION.md per [[cross-product-agent-
		// parity]] (sibling products ship the same flag names + env-var
		// names so a single playbook covers all four).
		auditLogMaxSizeMB         int64
		auditLogMaxAgeDays        int
		auditDBRetentionDays      int
		auditWebhookURL           string
		auditWebhookToken         string
		auditWebhookBatch         int
		allowInternalWebhook      bool
		auditWebhookPreset        string
		auditWebhookTags          string
		auditWebhookSentinelTable string
		// Slice 2 of #252 — suspicious-activity alert rule engine.
		// YAML config path; built-in defaults active when absent. The
		// engine wraps the audit Manager so alerts ride the same
		// JSONL log + HTTPS webhook transport as decision events.
		// Enterprise-tier (license-gated; placeholder error until #235).
		auditAlertRulesPath string
		// #280 — per-org notification routing engine. YAML config path;
		// nil disables the engine (the single --audit-webhook-url path
		// stays available). Enterprise-tier (license-gated; placeholder
		// error until #235 license-file plumbing lands).
		auditAlertRoutesPath string
		// Heartbeat cadence per [[prompt-injection-disable-bouncer-
		// threat]] + [[audit-export-failure-visibility]]. 0 = OFF
		// (default; safety-not-surveillance positioning); 30s
		// recommended for Enterprise.
		auditHeartbeatInterval time.Duration
		// Bulk-answer burst-detector tuning per [[bulk-prompt-answer-ux]].
		// All three zero-valued = use the proxy package defaults (5
		// prompts in 60s, 5-minute cool-down).
		bulkAnswerThreshold int
		bulkAnswerWindow    time.Duration
		bulkAnswerCooldown  time.Duration
		// #271 — bearer token for GET /audit/events when the proxy is
		// bound off-loopback. Empty = loopback-only (no auth gate).
		auditEventsToken string
		// #254 — deployment preset. Single-flag shortcut for a common
		// deployment shape (only `security-observe` in v1.0). Resolved
		// BEFORE downstream validation so license / SSRF / loopback
		// gates see the preset-resolved values.
		deploymentPreset string
		// #285 — per-session NDJSON recordings directory. Empty disables
		// the channel. Replayable via `iam-jit session replay <FILE>`.
		recordSessionsDir string
		// #258 — AWS Security Lake adapter. All four fields off by
		// default. Per [[no-hosted-saas]] + [[self-host-zero-billing-
		// dependency]] the bucket lives in the operator's AWS account;
		// iam-jit-the-company never receives the data.
		securityLakeBucket          string
		securityLakeRegion          string
		securityLakeRoleARN         string
		securityLakeRotationSeconds int
		// #317 — cloud-neutral S3-compatible NDJSON object-storage
		// sink. All fields OFF by default. Per [[self-host-zero-
		// billing-dependency]] the bucket is operator-owned.
		auditObjectStorageEndpoint        string
		auditObjectStorageBucket          string
		auditObjectStoragePrefix          string
		auditObjectStorageRegion          string
		auditObjectStorageCredentialsFile string
		auditObjectStorageRotationMinutes int
		auditObjectStorageMaxSizeMB       int
		auditObjectStorageInstanceID      string
		// #324b — dynamic-deny YAML path. Default is
		// ~/.iam-jit/dynamic-denies.yaml (also honors
		// $IAM_JIT_DYNAMIC_DENIES_PATH). The --disable-dynamic-denies
		// boolean turns the channel off entirely for operators who
		// haven't installed the cross-product CLI yet.
		dynamicDeniesPath    string
		disableDynamicDenies bool
		// #461 / §A63c — disk-pressure circuit-breaker. Mode +
		// thresholds match the cross-product spec; kbouncer defaults
		// to rotate-aggressively per the spec's "dev workflows trend
		// toward rotate-aggressively" note.
		diskPressureMode          string
		diskPressureWarnPct       int
		diskPressureCritPct       int
		diskPressureEmergPct      int
		stopOnDiskCritical        bool
		ignoreDiskPressure        bool
		diskPressureWarnFreeBytes int64
		diskPressureCritFreeBytes int64
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the HTTP proxy server",
		Long: `Start the kbounce HTTP proxy.

The server binds to 127.0.0.1:8766 by default (local-only — kbounce
is a credential-handling surface and must NEVER bind externally
without explicit operator opt-in).

Point your kubectl / Helm / agent at it via the standard kubeconfig
+ env-var indirection. Ctrl+C exits cleanly (graceful shutdown).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// #254 — deployment preset resolution. Runs BEFORE any
			// downstream parsing / validation so the preset-resolved
			// values flow through everything that follows (mode parse,
			// license gate, bind validation, etc.). HARD-override
			// conflicts (e.g. --preset security-observe --mode
			// cooperative) fail-fast here with a "drop one OR the
			// other" message. SOFT overrides flow through. The
			// preset's BANNER lines are stashed for printing alongside
			// the existing startup banner so the operator sees what
			// changed.
			var presetBannerLines []string
			if deploymentPreset != "" {
				preset := GetPreset(deploymentPreset, "kbounce")
				if preset == nil {
					return fmt.Errorf(
						"kbounce: unknown --preset %q; available: security-observe",
						deploymentPreset)
				}
				operatorChanged := map[string]bool{
					"mode":               cmd.Flags().Changed("mode"),
					"default-policy":     cmd.Flags().Changed("default-policy"),
					"audit-log-path":     cmd.Flags().Changed("audit-log-path"),
					"alert-rules":        cmd.Flags().Changed("alert-rules"),
					"heartbeat-interval": cmd.Flags().Changed("heartbeat-interval"),
				}
				currentValues := map[string]string{
					"mode":               modeStr,
					"default-policy":     defaultPolStr,
					"audit-log-path":     auditLogPath,
					"alert-rules":        auditAlertRulesPath,
					"heartbeat-interval": auditHeartbeatInterval.String(),
				}
				// #254 + #235 — license-file plumbing retained for any
				// future paid tier per project_oss_only_launch_decision.md
				// but does NOT gate features at v1.0; the current code
				// path returns ErrAlertRulesLicenseRequired pending the
				// license-disable refactor. The preset SKIPS this setting in v1.0
				// per the spec's "if a product doesn't support a
				// canonical setting, skip + annotate in the banner;
				// don't error" guidance. When #235 lands, drop this
				// skip set so the preset wires --alert-rules through
				// like the other settings.
				skipKeys := map[string]bool{"alert-rules": true}
				res, err := ApplyPreset(preset, operatorChanged, currentValues, skipKeys)
				if err != nil {
					return err
				}
				// Rebind the locals from the preset where the operator
				// did not override.
				for _, key := range res.DerivedKeys {
					pv := preset.Values[key]
					switch key {
					case "mode":
						modeStr = pv.Value
					case "default-policy":
						defaultPolStr = pv.Value
					case "audit-log-path":
						auditLogPath = pv.Value
						// Pre-create the parent dir so the JSONL
						// writer's open() does not fail on first run.
						if d := filepath.Dir(auditLogPath); d != "" {
							_ = os.MkdirAll(d, 0o700)
						}
					case "alert-rules":
						auditAlertRulesPath = pv.Value
					case "heartbeat-interval":
						auditHeartbeatInterval = MustParseDuration(pv.Value)
					}
				}
				presetBannerLines = FormatBanner(preset, res)
			}

			mode, err := proxy.ParseMode(modeStr)
			if err != nil {
				return err
			}
			defaultPol, err := proxy.ParseDefaultPolicy(defaultPolStr)
			if err != nil {
				return err
			}

			// #203 — sync deny-prompt flag validation. Mutually
			// exclusive with --prompt-on-deny so the operator picks
			// one UX explicitly. In cooperative mode the deny is
			// advisory, so the sync flag is silently ignored with a
			// banner-level warning printed later — but we still
			// validate the value range here so a bad --sync-prompt-
			// timeout is surfaced eagerly.
			if promptOnDeny && syncPromptOnDeny {
				return fmt.Errorf(
					"kbounce: --prompt-on-deny and --sync-prompt-on-deny are mutually exclusive; " +
						"pick one (async = caller is denied + operator answers later; " +
						"sync = caller is blocked until operator answers or timeout fires)")
			}
			var syncPromptDefaultPol proxy.DefaultPolicy
			if syncPromptOnDeny {
				if syncPromptTimeout < proxy.MinSyncPromptTimeout ||
					syncPromptTimeout > proxy.MaxSyncPromptTimeout {
					return fmt.Errorf(
						"kbounce: --sync-prompt-timeout must be between %s and %s (got %s)",
						proxy.MinSyncPromptTimeout, proxy.MaxSyncPromptTimeout, syncPromptTimeout)
				}
				syncPromptDefaultPol, err = proxy.ParseDefaultPolicy(syncPromptDefault)
				if err != nil {
					return fmt.Errorf(
						"kbounce: --sync-prompt-default must be 'allow' or 'deny' (got %q)",
						syncPromptDefault)
				}
			}

			// #380 — env-var fallback for the /audit/events bearer token.
			// Passing it via --audit-events-token leaks it into `ps` /
			// process listings; KBOUNCER_AUDIT_EVENTS_TOKEN keeps it out
			// of the process table. The flag wins when both are set; the
			// env var only fires when the flag is empty. Resolved BEFORE
			// the loopback/external-bind gate below so the gate sees the
			// effective token regardless of where it came from.
			auditEventsToken = flagOrEnv(auditEventsToken, envAuditEventsTokenVar)

			// #379 — env-var fallback for the upstream CA bundle path.
			// Flag wins; env var only fires when the flag is empty.
			upstreamCABundle = flagOrEnv(upstreamCABundle, envUpstreamCABundleVar)

			// CRIT-32-02 (mirrored from iam-jit-bouncer): refuse to bind
			// externally without explicit operator acknowledgement.
			// kbounce holds inbound client bearer tokens long enough to
			// forward them; an externally-bound listener exposes that
			// surface to anyone on the network.
			if _, ok := loopbackHosts[host]; !ok && !forceExternalBind {
				fmt.Fprintf(os.Stderr,
					"refusing to bind to %q: this exposes kbounce's "+
						"credential-handling surface to the network.\n\n"+
						"If you genuinely need to bind externally (test VM with "+
						"no real cluster credentials, network-segmented dev box), "+
						"re-run with --i-know-this-binds-externally AND read the "+
						"SECURITY threat model first.\n", host)
				os.Exit(2)
			}
			// #271 — GET /audit/events lives on the same port; an
			// external bind without a bearer token would expose recent
			// audit events (URL paths can be sensitive). Refuse to
			// start in that shape.
			if _, ok := loopbackHosts[host]; !ok && auditEventsToken == "" {
				return fmt.Errorf(
					"kbounce: --audit-events-token TOKEN is required when --host %q is non-loopback "+
						"(GET /audit/events would otherwise be exposed without auth)",
					host)
			}

			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			// Resolve the upstream kube-apiserver target. Best-effort —
			// failure to resolve is logged at DEBUG level (UAT-K2
			// HIGH-K2-04: don't panic new users on a missing kubeconfig)
			// + the proxy starts in observation-only mode (JSON-body
			// fallback). The startup banner makes the consequence clear.
			upOpts := upstream.Options{
				UpstreamURL:           upstreamURL,
				KubeconfigPath:        kubeconfigPath,
				InsecureSkipTLSVerify: insecureSkipVerify,
				UpstreamCABundlePath:  upstreamCABundle,
				ForwardTimeout:        time.Duration(forwardTimeoutSecs) * time.Second,
			}
			up, upErr := upstream.Resolve(upOpts)
			if upErr != nil {
				// #379 — a misconfigured --upstream-ca-bundle is an
				// operator error that MUST fail loudly at startup, never
				// be demoted to observation-only (silently forwarding
				// unverified against the wrong trust anchor would be the
				// exact silent-degradation we're guarding against). The
				// CA-bundle path errors are distinct from the benign
				// no-upstream case, so we only demote when the operator
				// did NOT pin a CA bundle.
				if upstreamCABundle != "" && errors.Is(upErr, upstream.ErrCABundle) {
					return fmt.Errorf(
						"kbounce: --upstream-ca-bundle is set but the upstream "+
							"could not be resolved with it: %w", upErr)
				}
				// HIGH-K2-04: demote no-upstream warn to debug. New
				// users running `kbounce run` for the first time
				// without a kubeconfig were being scared by a WARN-
				// level JSON dump. The banner below ("upstream: <none>
				// — observation-only mode; no kubectl traffic will
				// reach an apiserver") is the consequence-clear
				// surface for the same fact.
				log.Debug().Err(upErr).
					Msg("kbounce: no upstream resolved; running observation-only")
			}

			// Profile resolution. Precedence: --profile flag > KBOUNCER_PROFILE
			// env var. The env-var fallback intentionally only fires when
			// the flag is unset so a shell-wide default can be overridden
			// per-invocation without unsetting the env var.
			//
			// Profiles.yaml is auto-created from embedded defaults on first
			// run so a fresh install always has something to point --profile
			// at. Existing files are NEVER overwritten — operator edits
			// survive upgrades.
			profileFromFlag := profileName != ""
			if profileName == "" {
				profileName = kbenv.Get(envProfileVar)
			}
			resolvedProfilesPath := profilesPath
			if resolvedProfilesPath == "" {
				resolvedProfilesPath, err = profile.DefaultProfilesPath()
				if err != nil {
					return fmt.Errorf("resolve profiles path: %w", err)
				}
			}
			if written, ferr := profile.EnsureDefaultProfilesFile(resolvedProfilesPath); ferr != nil {
				// Non-fatal: a write failure (read-only home, etc.) must
				// not prevent the proxy starting. Log + continue with
				// embedded defaults.
				log.Warn().Err(ferr).Str("path", resolvedProfilesPath).
					Msg("kbounce: could not write default profiles.yaml; using embedded defaults")
			} else if written {
				fmt.Fprintf(os.Stderr,
					"kbounce: wrote default profiles to %s\n", resolvedProfilesPath)
			}
			profiles, err := profile.LoadProfiles(resolvedProfilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			activeProfile, err := profiles.Active(profileName)
			if err != nil {
				return fmt.Errorf("select profile: %w", err)
			}

			// K-Slice 4: mTLS coherency. --tls-cert + --tls-key MUST be
			// paired (one without the other is a configuration error,
			// not a partial fallback). --require-client-cert without
			// TLS at all is meaningless; refuse fast so an operator
			// doesn't get a silently-ignored flag.
			if (tlsCertPath != "") != (tlsKeyPath != "") {
				return fmt.Errorf(
					"kbounce: --tls-cert and --tls-key must both be set or both "+
						"omitted (got cert=%q key=%q)", tlsCertPath, tlsKeyPath)
			}
			if requireClientCert != "" && tlsCertPath == "" {
				return fmt.Errorf(
					"kbounce: --require-client-cert requires --tls-cert + --tls-key " +
						"(mTLS without TLS is meaningless); run `kbounce init-tls` first")
			}

			// Slice 1 of #252 — wire the audit-export channels.
			// Both channels are opt-in; the SQLite audit row written
			// via writeDecisionForTask is the canonical source of
			// truth regardless. Webhook flags require an Enterprise
			// license (placeholder error until #235 license-file
			// plumbing lands).
			// #311 / §A10 — env-var fallback for the rotation trio. CLI
			// flag wins; env var fills in when the operator didn't pass
			// it; sentinel -1 left intact for downstream "use default"
			// resolution. Env-var names match the cross-product spec at
			// iam-roles/docs/LOG-RETENTION.md.
			// An explicit --flag wins; otherwise fall back to the env
			// var (envBase resolves under both KBOUNCER_ and KBOUNCE_
			// via kbenv.Get). flagName is the cobra flag to test for an
			// explicit set.
			resolveInt64Env := func(flagVal int64, flagName, envBase string) int64 {
				if cmd.Flags().Changed(flagName) {
					return flagVal
				}
				if v := kbenv.Get(envBase); v != "" {
					if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
						return parsed
					}
				}
				return flagVal
			}
			resolveIntEnv := func(flagVal int, flagName, envBase string) int {
				if cmd.Flags().Changed(flagName) {
					return flagVal
				}
				if v := kbenv.Get(envBase); v != "" {
					if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
						return parsed
					}
				}
				return flagVal
			}
			effAuditLogMaxSizeMB := resolveInt64Env(auditLogMaxSizeMB, "audit-log-max-size-mb", "AUDIT_LOG_MAX_SIZE_MB")
			effAuditLogMaxAgeDays := resolveIntEnv(auditLogMaxAgeDays, "audit-log-max-age-days", "AUDIT_LOG_MAX_AGE_DAYS")
			effAuditDBRetentionDays := resolveIntEnv(auditDBRetentionDays, "audit-db-retention-days", "AUDIT_DB_RETENTION_DAYS")
			auditEmitter, auditHealth, auditCloser, auditErr := buildAuditManager(
				cmd.Context(),
				auditLogPath, auditLogFsync,
				effAuditLogMaxSizeMB, effAuditLogMaxAgeDays, effAuditDBRetentionDays,
				auditWebhookURL, auditWebhookToken, auditWebhookBatch,
				allowInternalWebhook,
				auditWebhookPreset, auditWebhookTags, auditWebhookSentinelTable,
				auditAlertRulesPath,
				auditAlertRoutesPath,
				auditHeartbeatInterval,
				recordSessionsDir,
				securityLakeBucket, securityLakeRegion, securityLakeRoleARN,
				securityLakeRotationSeconds,
				auditObjectStorageEndpoint, auditObjectStorageBucket,
				auditObjectStoragePrefix, auditObjectStorageRegion,
				auditObjectStorageCredentialsFile,
				auditObjectStorageRotationMinutes,
				auditObjectStorageMaxSizeMB,
				auditObjectStorageInstanceID,
				noAuditChain,
				manifestInterval,
			)
			if auditErr != nil {
				return auditErr
			}
			defer auditCloser()

			// #324b — dynamic-deny watcher. Constructed BEFORE
			// proxy.NewServer so the watcher's initial in-memory
			// snapshot is the one the proxy sees on its first request.
			// Default path is `~/.iam-jit/dynamic-denies.yaml`; the
			// `--dynamic-denies-path PATH` flag overrides; the
			// `--disable-dynamic-denies` flag turns the channel off
			// entirely (the watcher goroutine never starts).
			var ddWatcher *dynamicdeny.Watcher
			var ddBannerLine string
			if !disableDynamicDenies {
				ddPath := dynamicDeniesPath
				if ddPath == "" {
					ddPath = dynamicdeny.ResolveDefaultPath()
				}
				if ddPath != "" {
					// emitFunc is wired AFTER NewServer below so we can
					// reference the Server's counter-bump methods +
					// audit-log sink. For now construct with nil.
					w, loadErr := dynamicdeny.NewWatcher(ddPath, nil)
					if loadErr != nil {
						// The watcher object is still returned so the
						// banner reports "0 rules (parse error)"; the
						// watcher goroutine won't start until Start()
						// is called.
						fmt.Fprintf(os.Stderr,
							"kbouncer: dynamic-denies: initial load of %q failed: %v\n",
							ddPath, loadErr)
					}
					ddWatcher = w
				}
			}

			// #461 / §A63c — resolve the disk-pressure mode + build the
			// state container. --stop-on-disk-critical is a shorthand
			// for --disk-pressure-mode pause-requests; when both are
			// passed pause-requests wins. Empty audit-log-path means
			// no logDir → state is a no-op (Snapshot still surfaces
			// the mode but RefuseRequests is always false).
			effectiveDPMode := diskPressureMode
			if stopOnDiskCritical {
				effectiveDPMode = audit.DiskPressureModePauseRequests
			}
			normalizedMode, dpErr := audit.NormalizeDiskPressureMode(effectiveDPMode)
			if dpErr != nil {
				return fmt.Errorf("kbouncer: --disk-pressure-mode: %w", dpErr)
			}
			if ignoreDiskPressure {
				fmt.Fprintf(os.Stderr, "⚠ Disk-pressure check DISABLED via --ignore-disk-pressure. Audit writes may fail if disk fills.\n")
			}
			diskPressureState := audit.NewDiskPressureStateFull(
				normalizedMode,
				audit.ResolveLogDir(resolveAuditLogPath(auditLogPath)),
				diskPressureWarnPct,
				diskPressureCritPct,
				diskPressureEmergPct,
				diskPressureWarnFreeBytes,
				diskPressureCritFreeBytes,
				ignoreDiskPressure,
			)

			cfg := proxy.Config{
				Host:                    host,
				Port:                    port,
				Mode:                    mode,
				DefaultPolicy:           defaultPol,
				ActiveProfile:           activeProfile,
				Cluster:                 cluster,
				PromptOnDeny:            promptOnDeny,
				SyncPromptOnDeny:        syncPromptOnDeny,
				SyncPromptTimeout:       syncPromptTimeout,
				SyncPromptDefault:       syncPromptDefaultPol,
				Upstream:                up,
				TLSCertPath:             tlsCertPath,
				TLSKeyPath:              tlsKeyPath,
				RequireClientCertCAPath: requireClientCert,
				AuditEmitter:            auditEmitter,
				AuditHealthCheck:        auditHealth,
				BulkAnswerThreshold:     bulkAnswerThreshold,
				BulkAnswerWindow:        bulkAnswerWindow,
				BulkAnswerCooldown:      bulkAnswerCooldown,
				AuditEventsToken:        auditEventsToken,
				DynamicDenyWatcher:      ddWatcher,
				DiskPressure:            diskPressureState,
			}.Normalize()

			// Cooperative mode + --sync-prompt-on-deny: per spec the
			// flag is silently ignored (cooperative DENYs are advisory
			// so there's nothing to block on) with a one-line warning
			// so the operator notices they probably wanted transparent
			// mode.
			if syncPromptOnDeny && cfg.Mode != proxy.ModeTransparent {
				fmt.Fprintln(os.Stderr,
					"kbounce: --sync-prompt-on-deny has no effect in cooperative mode "+
						"(cooperative DENYs are advisory; there is no 403 to block). "+
						"Re-run with --mode transparent to enable the sync deny-prompt UX.")
			}

			s := proxy.NewServer(cfg, st)

			// #718 ADOPT-4 — wire the Phase H behavioral-deviation /
			// anomaly detector when the operator opted in via env
			// (IAM_JIT_ANOMALY_DETECTION=1 / mode / sensitivity).
			// Frictionless per [[lightweight-frictionless-principle]];
			// DISABLED by default + ALERT (never block) when enabled per
			// [[safety-mode-lean-permissive]].
			if acfg, aerr := proxy.AnomalyConfigFromEnv(); aerr != nil {
				return fmt.Errorf("anomaly_detection config: %w", aerr)
			} else if acfg.Enabled {
				proxy.SetAnomalyDetector(proxy.NewAnomalyDetector(acfg))
				fmt.Fprintf(os.Stderr,
					"anomaly detection: ENABLED (mode=%s, sensitivity=%s) — surfaces a neutral signal for review, does not block by default\n",
					acfg.Mode, acfg.Sensitivity)
			}

			// #324b — wire the watcher's emit callback now that the
			// Server exists. Each reload bumps the matching counter +
			// tees an OCSF admin-action event into the audit log so a
			// SIEM dashboard sees activity. Mirrors gbounce #324d wiring.
			if ddWatcher != nil {
				ddWatcher.SetStderr(os.Stderr)
				emitCtx := cmd.Context()
				auditSink := auditEmitter
				emit := func(reason dynamicdeny.ReloadReason, rs *dynamicdeny.RuleSet, parseErr error) {
					switch reason {
					case dynamicdeny.ReasonParseError:
						s.BumpDynamicDenyParseError()
					default:
						s.BumpDynamicDenyReload()
					}
					action := audit.AdminActionDynamicDenyReloaded
					if reason == dynamicdeny.ReasonParseError {
						action = audit.AdminActionDynamicDenyParseError
					}
					extra := map[string]any{
						"dynamic_deny_reload_reason": string(reason),
					}
					if rs != nil {
						extra["dynamic_denies_count"] = len(rs.Rules)
						extra["dynamic_denies_path"] = rs.SourcePath
					}
					if parseErr != nil {
						extra["dynamic_deny_parse_error"] = parseErr.Error()
					}
					audit.EmitAdminAction(emitCtx, auditSink, audit.AdminActionInput{
						Action:     action,
						Source:     audit.AdminActionSourceCLI,
						EntityKind: "dynamic_denies_file",
						EntityName: ddWatcher.Path(),
						ExtraExt:   extra,
					})
				}
				ddWatcher.SetEmitFunc(emit)
				if startErr := ddWatcher.Start(cmd.Context()); startErr != nil {
					fmt.Fprintf(os.Stderr,
						"kbouncer: dynamic-denies: watcher failed to start: %v\n", startErr)
				}
				snap := ddWatcher.Snapshot()
				ruleCount := 0
				if snap != nil {
					ruleCount = len(snap.Rules)
				}
				ddBannerLine = fmt.Sprintf(
					"dynamic-denies: %d rules loaded from %s (%d applied to kbouncer; watching for changes)",
					ruleCount, ddWatcher.Path(), ruleCount)
			}

			// Print a friendly startup banner to stderr so stdout stays
			// clean for tools that might pipe kbounce's output.
			scheme := "http"
			if cfg.TLSCertPath != "" {
				scheme = "https"
			}
			// [[discovery-first-default]] (2026-05-22): surface
			// default_mode (discovery|profile) on the headline banner
			// so operators immediately see the operating shape. discovery
			// = no profile selected (full-user); profile = operator
			// explicitly picked a named profile via --profile NAME or
			// KBOUNCER_PROFILE env var. Cross-product parity with
			// ibounce + dbounce + gbounce per [[cross-product-agent-
			// parity]].
			defaultModeLabel := "discovery"
			if activeProfile != nil && activeProfile.Name != "" &&
				activeProfile.Name != "full-user" && activeProfile.Name != "none" {
				defaultModeLabel = "profile"
			}
			fmt.Fprintf(os.Stderr,
				"kbounce proxy starting on %s://%s:%d (mode=%s, default-policy=%s, profile=%s, default_mode=%s)\n",
				scheme, cfg.Host, cfg.Port, cfg.Mode, cfg.DefaultPolicy, activeProfile.Name, defaultModeLabel)
			// #324b — dynamic-deny banner. One line per
			// [[cross-product-agent-parity]]; identical shape on the
			// other Bounce products. Quiet when --disable-dynamic-denies
			// or when the path can't be resolved (Watcher is nil).
			if ddBannerLine != "" {
				fmt.Fprintln(os.Stderr, ddBannerLine)
			}
			// #254 — preset-derivation banner sits RIGHT AFTER the
			// address line so the operator immediately sees which
			// settings came from the preset. Same format across all
			// four Bounce products per [[cross-product-agent-parity]].
			for _, line := range presetBannerLines {
				fmt.Fprintln(os.Stderr, line)
			}
			if cfg.TLSCertPath != "" {
				fmt.Fprintf(os.Stderr, "tls cert: %s\n", cfg.TLSCertPath)
				fmt.Fprintf(os.Stderr, "tls key:  %s\n", cfg.TLSKeyPath)
				if cfg.RequireClientCertCAPath != "" {
					fmt.Fprintf(os.Stderr,
						"mTLS:     ENFORCED (client cert must be signed by %s)\n",
						cfg.RequireClientCertCAPath)
				}
			}
			fmt.Fprintf(os.Stderr, "audit db: %s\n", st.Path())
			if auditEmitter != nil {
				status := auditEmitter.Status()
				if status.LogConfigured {
					fmt.Fprintf(os.Stderr,
						"audit log: %s (fsync=%t)\n", status.LogPath, auditLogFsync)
				}
				if status.WebhookConfigured {
					// MaskedURL strips userinfo + query; token is
					// NEVER printed (kept only in the WebhookPusher's
					// outgoing Authorization header).
					presetLabel := auditWebhookPreset
					if presetLabel == "" {
						presetLabel = string(audit.PresetGeneric)
					}
					fmt.Fprintf(os.Stderr,
						"audit webhook: %s (preset=%s, token=***, batch=%d)\n",
						status.WebhookMaskedURL, presetLabel, auditWebhookBatch)
				}
				if status.AlertsEnabled {
					fmt.Fprintf(os.Stderr,
						"audit alerts: enabled (rules=admin_fallback_burst, pause_long, "+
							"non_org_profile_install, unusual_high_risk_action, heartbeat_gap, "+
							"audit_export_degraded)\n")
				}
				if status.HeartbeatEnabled {
					fmt.Fprintf(os.Stderr,
						"audit heartbeat: enabled (interval=%ds; /healthz returns 503 "+
							"+ stderr fires on heartbeat_gap)\n",
						status.HeartbeatIntervalSeconds)
				}
				if status.SecurityLake.Configured {
					// #258 — Security Lake banner. AWS account + caller
					// ARN come from sts:GetCallerIdentity at the writer's
					// Start(); printing here matches the "log AWS account
					// + role at startup banner" requirement.
					roleLabel := status.SecurityLake.RoleARN
					if roleLabel == "" {
						roleLabel = "(default-chain)"
					}
					fmt.Fprintf(os.Stderr,
						"audit security-lake: s3://%s/ (region=%s, account=%s, "+
							"caller=%s, role=%s, rotation=%ds)\n",
						status.SecurityLake.Bucket,
						status.SecurityLake.Region,
						status.SecurityLake.AccountID,
						status.SecurityLake.CallerARN,
						roleLabel,
						status.SecurityLake.RotationSeconds)
				}
			}
			fmt.Fprintf(os.Stderr, "profiles: %s\n", resolvedProfilesPath)
			if up != nil {
				insecureNote := ""
				if up.InsecureSkipTLSVerify {
					insecureNote = " (TLS VERIFY DISABLED)"
				}
				fmt.Fprintf(os.Stderr,
					"upstream: %s (source=%s)%s\n",
					up.URL.String(), up.Source, insecureNote)
			} else {
				// HIGH-K2-04: be explicit about the consequence so the
				// missing-upstream state surfaces clearly without a
				// scary JSON warning.
				fmt.Fprintln(os.Stderr,
					"upstream: <none> — observation-only mode; no kubectl traffic will reach an apiserver")
			}
			// [[discovery-first-default]] (2026-05-22): banner copy
			// explicitly names this DISCOVERY MODE (the canonical
			// cross-product term) — observe + audit + pass-through.
			// Named profiles (e.g. safe-default) stay first-class via
			// `--profile NAME` opt-in. Per [[security-team-positioning-
			// safety-not-surveillance]]: framed as audit transparency
			// NOT "we're not enforcing anything." Closes the K1/K3
			// NEGATIVE-VALUE failures from the 2026-05-22 role-
			// effectiveness eval — see KNOWN-CAVEATS §A21.
			if !profileFromFlag && kbenv.Get(envProfileVar) == "" {
				fmt.Fprintln(os.Stderr,
					"profile: no profile selected.")
				fmt.Fprintln(os.Stderr,
					"  default mode: discovery — observing all requests, denying none.")
				fmt.Fprintln(os.Stderr,
					"    every kubectl call is parsed, audit-logged, and forwarded "+
						"verbatim to the apiserver.")
				fmt.Fprintln(os.Stderr,
					"    full OCSF event stream + recommender operate as usual.")
				fmt.Fprintln(os.Stderr,
					"    To block write/destructive verbs + privilege primitives, "+
						"run with --profile safe-default OR "+
						"`export KBOUNCER_PROFILE=safe-default` in your shell rc.")
			}
			// #304 — known-caveats banner. kbounce surfaces §B5
			// (apiserver-edge shape; pod-to-pod traffic not seen)
			// because that property is structural — the operator
			// should know it from line one of every startup. Per the
			// founder direction "the signal should be useful, not
			// noise"; we don't spam other §B entries here. Full list
			// available via `kbounce doctor caveats`.
			activeProfileName := ""
			if activeProfile != nil {
				activeProfileName = activeProfile.Name
			}
			for _, line := range caveats.BannerLines(caveats.Trigger{
				SafeDefaultProfile: activeProfileName == "safe-default",
			}) {
				fmt.Fprintln(os.Stderr, line)
			}
			// §A19 profile-upgrade-blindness banner (#321). Only fires
			// when the operator's installed profile is missing a
			// safety-floor field AND they haven't acknowledged the
			// current shipped-defaults version. Convenience / detection
			// / audit misses don't trigger startup line — operators see
			// those on explicit `kbounce profile doctor`.
			if line := profile.StartupBannerLine("kbounce", resolvedProfilesPath); line != "" {
				fmt.Fprintln(os.Stderr, line)
			}
			fmt.Fprintln(os.Stderr, "Ctrl+C to stop.")

			// Run Serve in a goroutine so we can intercept signals and
			// initiate a graceful shutdown.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			serveErr := make(chan error, 1)
			go func() {
				err := s.Serve()
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					serveErr <- err
					return
				}
				serveErr <- nil
			}()

			select {
			case <-ctx.Done():
				log.Info().Msg("kbounce received shutdown signal")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := s.Shutdown(shutdownCtx); err != nil {
					return fmt.Errorf("shutdown: %w", err)
				}
				// Wait for Serve to return so we don't leak the goroutine.
				if err := <-serveErr; err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "kbounce stopped.")
				return nil
			case err := <-serveErr:
				return err
			}
		},
	}

	cmd.Flags().IntVar(&port, "port", 8766,
		"TCP port to listen on (loopback only by default).")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1",
		"Interface to bind. Defaults to 127.0.0.1 (loopback). Binding "+
			"to anything else exposes kbounce's credential-handling "+
			"surface to the network.")
	cmd.Flags().StringVar(&modeStr, "mode", "cooperative",
		"cooperative | transparent. cooperative = parse + log + always "+
			"forward (advisory). transparent = DENY verdicts return 403 "+
			"to the client.")
	cmd.Flags().StringVar(&defaultPolStr, "default-policy", "deny",
		"allow | deny. What transparent mode does when no rule matches.")
	cmd.Flags().StringVar(&dbPath, "db", "", dbFlagHelp)
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Active environment profile. Built-in: 'full-user' (passthrough, "+
			"default) and 'safe-default' (block mutating verbs + destructive "+
			"non-writes + privilege primitives + impersonation + CRD long-tail). "+
			"Community profiles install via `kbounce profile install --from URL`. "+
			"Falls back to "+envProfileVar+" env var; defaults to 'full-user' "+
			"if neither is set. Profile denies are a hard floor — a permissive "+
			"task scope CANNOT override them. See `kbounce profile list`. "+
			"Legacy aliases ('readonly', 'prod-readonly', 'none') still resolve "+
			"in v1.0 and are removed in v1.1.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml). "+
			"Honors KBOUNCER_PROFILES_PATH env var if --profiles-path unset.")
	cmd.Flags().StringVar(&cluster, "cluster", "",
		"Kubeconfig cluster name surfaced to profile evaluation for "+
			"only_clusters and the 'cluster' keyword target. Explicit "+
			"pass-through for now; auto-detection from kubeconfig "+
			"ships post-v1.0.")
	cmd.Flags().BoolVar(&promptOnDeny, "prompt-on-deny", false,
		// MED-K2-03: dropped the leading "#5" issue-marker — that was an
		// internal task reference, not user-facing detail.
		"Async deny-prompt UX: when set, every transparent-mode "+
			"DENY also writes a pending_prompts row so the operator can "+
			"later answer (always-allow / add-to-profile / ignore) via "+
			"`kbounce prompts answer`. The agent is still denied "+
			"immediately; the answer takes effect on the NEXT call of "+
			"the same shape. Defaults off — opt-in to avoid noisy queues. "+
			"Mutually exclusive with --sync-prompt-on-deny.")

	// #203 — synchronous deny-prompt v1.1 flags.
	cmd.Flags().BoolVar(&syncPromptOnDeny, "sync-prompt-on-deny", false,
		"Synchronous deny-prompt UX (v1.1): when set in transparent "+
			"mode, every DENY enqueues a pending_prompts row AND blocks "+
			"the request goroutine for up to --sync-prompt-timeout "+
			"waiting for the operator's answer via `kbounce prompts "+
			"answer`. Answer always/profile → forward + return upstream's "+
			"response. Answer ignore or timeout → return the original "+
			"403 (per --sync-prompt-default). Mutually exclusive with "+
			"--prompt-on-deny. Silently ignored in cooperative mode "+
			"(cooperative DENYs are advisory; nothing to block on).")
	cmd.Flags().DurationVar(&syncPromptTimeout, "sync-prompt-timeout", proxy.DefaultSyncPromptTimeout,
		"Maximum wall-clock the request goroutine waits for an operator "+
			"answer when --sync-prompt-on-deny fires. Must be between 5s "+
			"and 300s. Shorter is faster for the agent; longer gives the "+
			"operator more room to context-switch + answer. Ignored when "+
			"--sync-prompt-on-deny is off.")
	cmd.Flags().StringVar(&syncPromptDefault, "sync-prompt-default", string(proxy.DefaultPolicyDeny),
		"Verdict applied when --sync-prompt-on-deny times out without an "+
			"operator answer: 'allow' = forward to upstream as if the "+
			"answer had been always/profile; 'deny' = return the original "+
			"403. Default 'deny' matches the secure-default convention "+
			"throughout kbounce.")

	// K-Slice 2 forwarding flags.
	cmd.Flags().StringVar(&upstreamURL, "upstream", "",
		"Kube-apiserver URL to forward ALLOW verdicts to. When unset, "+
			"the apiserver is resolved from the kubeconfig (see --kubeconfig). "+
			"This URL is the OUTBOUND ALLOWLIST: kbounce refuses to forward "+
			"anywhere else even if a client's Host header points elsewhere.")
	cmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", "",
		"Path to a kubeconfig file. Defaults to KUBECONFIG env var, then "+
			"~/.kube/config. The current-context's cluster.server is the "+
			"apiserver URL; cluster.certificate-authority-data is the CA "+
			"bundle used to verify the apiserver's TLS cert.")
	cmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-tls-verify", false,
		"Skip TLS verification on the OUTBOUND connection to the "+
			"kube-apiserver. Mirrors the kubeconfig flag of the same "+
			"name. NEVER inferred — always explicit. Use ONLY for local "+
			"clusters with self-signed certs that aren't in the kubeconfig.")
	cmd.Flags().StringVar(&upstreamCABundle, "upstream-ca-bundle", "",
		"#379 — path to a PEM file whose certificates verify the "+
			"kube-apiserver's TLS cert. For private / self-signed kube CAs "+
			"not present in the kubeconfig (e.g. a custom --upstream behind "+
			"an internal CA). When set, these certs REPLACE the kubeconfig "+
			"CA as the trust anchor. A missing / unreadable / non-PEM file "+
			"is a HARD startup failure — kbounce NEVER falls back to system "+
			"roots. Falls back to the "+envUpstreamCABundleVar+" env var "+
			"when unset (the flag wins). Has no effect on a plain-http "+
			"upstream (set one but not the other and kbounce errors).")
	cmd.Flags().IntVar(&forwardTimeoutSecs, "forward-timeout", 30,
		"Per-request timeout (seconds) on outbound forwards to the "+
			"apiserver. Watch / long-poll requests bypass this; short-"+
			"lived REST calls use it.")
	cmd.Flags().BoolVar(&forceExternalBind, "i-know-this-binds-externally", false,
		"Required acknowledgement when --host is anything other than "+
			"127.0.0.1 / ::1 / localhost. Binding the proxy externally "+
			"exposes inbound client bearer tokens + the forwarding "+
			"surface to the network. Don't pass this unless you have a "+
			"specific reason (test VM, network-segmented dev box).")

	// K-Slice 4 — inbound TLS listener.
	cmd.Flags().StringVar(&tlsCertPath, "tls-cert", "",
		"Path to the server certificate (PEM) for the inbound HTTPS "+
			"listener. Pair with --tls-key. When both are set, kbounce "+
			"listens on HTTPS instead of plain HTTP — recommended for "+
			"kubectl + agent clients that expect HTTPS. Generate with "+
			"`kbounce init-tls`.")
	cmd.Flags().StringVar(&tlsKeyPath, "tls-key", "",
		"Path to the server private key (PEM) for the inbound HTTPS "+
			"listener. Pair with --tls-cert.")
	cmd.Flags().StringVar(&requireClientCert, "require-client-cert", "",
		"Path to a CA bundle (PEM). When set, inbound TLS clients MUST "+
			"present a client certificate signed by this bundle. "+
			"Locks the proxy down to 'only my kubectl context can "+
			"connect'. Requires --tls-cert + --tls-key. Operator-supplied "+
			"CA — kbounce does NOT issue client certs.")

	// Slice 1 of #252 — security-team audit-export channels.
	// See [[security-team-audit-export]] memo for the design.
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Append-only JSONL audit log path. One JSON event per decision "+
			"(verb, resource, verdict, profile, mode, etc.). Free across "+
			"all tiers. Unset → no JSONL export (the SQLite audit row in "+
			"--db is still written; the JSONL is a shipping convenience). "+
			"NO ROTATION built in — point logrotate / Fluent Bit / Vector "+
			"at the file. Append-only (O_APPEND|O_CREATE|O_WRONLY, mode 0600).")
	cmd.Flags().BoolVar(&auditLogFsync, "audit-log-fsync", false,
		"Call fsync(2) after every JSONL line. Default off for throughput "+
			"(buffered writes are durable to a crash but not a power loss). "+
			"Opt in for compliance-grade durability at the cost of ~10x "+
			"per-line write latency.")
	cmd.Flags().BoolVar(&noAuditChain, "no-audit-chain", false,
		"Disable the tamper-evident hash-chain + Ed25519-signed manifests on "+
			"the audit-log JSONL (ADOPT-10/#734; on by default when "+
			"--audit-log-path is set).")
	cmd.Flags().Int64Var(&manifestInterval, "manifest-interval", 0,
		"Emit a signed chain-checkpoint manifest every N events (ADOPT-10/#734; "+
			"0 = default 1000). Lower it on low-traffic deployments so a signed "+
			"checkpoint lands without waiting for 1000 events.")
	// #311 / §A10 — rotation thresholds. Sentinel value -1 = "operator
	// didn't pass the flag → use the audit package default (100 MB / 7
	// days / 30 days)." 0 = "operator explicitly disabled this trigger."
	// Same names across all four Bounce products per
	// [[cross-product-agent-parity]].
	cmd.Flags().Int64Var(&auditLogMaxSizeMB, "audit-log-max-size-mb", -1,
		"#311 — rotate the JSONL audit log when it exceeds N MB. 0 disables "+
			"size-triggered rotation. Default 100 (matches the cross-product "+
			"LOG-RETENTION.md spec). Rotated files are gzip'd in-place and "+
			"remain until `kbounce logs purge` reaps them (per [[creates-"+
			"never-mutates]] the active log is never destroyed automatically). "+
			"Honors $KBOUNCE_AUDIT_LOG_MAX_SIZE_MB for non-flag overrides.")
	cmd.Flags().IntVar(&auditLogMaxAgeDays, "audit-log-max-age-days", -1,
		"#311 — rotate the JSONL audit log when its mtime is older than N "+
			"days. 0 disables age-triggered rotation. Default 7 (matches the "+
			"cross-product LOG-RETENTION.md spec). Pairs with --audit-log-"+
			"max-size-mb; whichever fires first wins. Honors "+
			"$KBOUNCE_AUDIT_LOG_MAX_AGE_DAYS for non-flag overrides.")
	cmd.Flags().IntVar(&auditDBRetentionDays, "audit-db-retention-days", -1,
		"#311 — purge rotated audit DB archives older than N days. 0 "+
			"disables DB retention. Default 30 (matches the cross-product "+
			"LOG-RETENTION.md spec). Active audit DB is NEVER deleted by "+
			"this path; only rotated archives are eligible. Honors "+
			"$KBOUNCE_AUDIT_DB_RETENTION_DAYS for non-flag overrides.")
	// #461 / §A63c — disk-pressure circuit breaker. kbouncer's default
	// is rotate-aggressively per the §A63c note "dev workflows trend
	// toward rotate-aggressively." Operators in compliance-heavy
	// deployments should pass --disk-pressure-mode pause-requests OR
	// the shorthand --stop-on-disk-critical to honor audit integrity
	// over liveness. Per [[cross-product-agent-parity]] the flag
	// names match dbounce + gbounce + ibounce.
	cmd.Flags().StringVar(&diskPressureMode, "disk-pressure-mode",
		audit.DiskPressureModeRotateAggressively,
		"#461 — disk-pressure response mode. One of: "+
			"pause-requests (compliance-heavy: refuses new requests with 503 at "+
			"critical), rotate-aggressively (default for kbouncer: drops oldest "+
			"archives at critical), archive-and-purge (drops oldest archives + "+
			"signals operator-configured object-storage sink should ship before "+
			"next tick). Cross-product field name matches ibounce + dbounce + "+
			"gbounce so a single playbook covers all four.")
	cmd.Flags().BoolVar(&stopOnDiskCritical, "stop-on-disk-critical", false,
		"#461 — shorthand for --disk-pressure-mode pause-requests. Equivalent "+
			"to setting disk-pressure-mode to pause-requests. When both flags "+
			"are passed pause-requests wins (the more conservative choice).")
	cmd.Flags().IntVar(&diskPressureWarnPct, "disk-pressure-warn-pct", audit.DefaultDiskWarnPercent,
		"#461 — disk-usage percent at which the audit_log status flips to "+
			"degraded (informational; no behavior change). Default 96. "+
			"Used together with --disk-pressure-warn-free-bytes; either trigger is sufficient.")
	cmd.Flags().IntVar(&diskPressureCritPct, "disk-pressure-crit-pct", audit.DefaultDiskCritPercent,
		"#461 — disk-usage percent at which the operator-declared mode reacts. Default 98.")
	cmd.Flags().IntVar(&diskPressureEmergPct, "disk-pressure-emergency-pct", audit.DefaultDiskEmergencyPercent,
		"#461 — disk-usage percent at which the bouncer surfaces an emergency "+
			"status (always honored regardless of mode). Default 99.")
	cmd.Flags().Int64Var(&diskPressureWarnFreeBytes, "disk-pressure-warn-free-bytes", audit.DefaultDiskWarnFreeBytes,
		"#461 — absolute free-space floor (bytes) below which audit_log flips to degraded. Default 1073741824 (1 GiB).")
	cmd.Flags().Int64Var(&diskPressureCritFreeBytes, "disk-pressure-crit-free-bytes", audit.DefaultDiskCritFreeBytes,
		"#461 — absolute free-space floor (bytes) below which the mode reacts. Default 524288000 (512 MiB).")
	cmd.Flags().BoolVar(&ignoreDiskPressure, "ignore-disk-pressure", false,
		"#461 — disable the disk-pressure check entirely. /healthz shows 'ignored'. "+
			"Emits a loud warning at startup. Use when volume has enough headroom and you want to bypass the circuit breaker.")
	cmd.Flags().StringVar(&auditWebhookURL, "audit-webhook-url", "",
		"HTTPS URL of an operator-owned audit-event collector. Each decision "+
			"event POSTed as JSON. Ships in the v1.0 free + open-source release "+
			"(license-file plumbing #235 retained for any future paid tier per "+
			"project_oss_only_launch_decision.md but does NOT gate this "+
			"flag at v1.0). Bounded queue + "+
			"exponential backoff retry + drop-on-overflow with synthetic "+
			"AUDIT_DROPPED marker so consumers see the gap. SSRF-gated: "+
			"refuses RFC1918 / loopback / .internal / .local without "+
			"--allow-internal-webhook.")
	cmd.Flags().StringVar(&auditWebhookToken, "audit-webhook-token", "",
		"Bearer token sent on the Authorization header of every webhook "+
			"POST. Required when --audit-webhook-url is set. NEVER logged, "+
			"NEVER printed in banners or errors, NEVER serialized into "+
			"event bodies.")
	cmd.Flags().IntVar(&auditWebhookBatch, "audit-webhook-batch-size", 1,
		"Events per webhook POST. Default 1 = one decision per request "+
			"(simplest consumer shape). Increase for high-throughput orgs "+
			"that have a batching collector.")
	cmd.Flags().BoolVar(&allowInternalWebhook, "allow-internal-webhook", false,
		"Opt-out of the SSRF gate on --audit-webhook-url. Required when "+
			"the collector is on an intranet (RFC1918 / .internal / etc.). "+
			"Default refuses; the gate mirrors dbounce's MED-D8-06 closure.")
	// Slice 2 of #252 — per [[audit-webhook-presets]] (#257). Vendor
	// adapters that reshape the webhook body + auth header to match a
	// SIEM's native intake. The canonical OCSF event on the JSONL log
	// file is UNCHANGED — only the webhook body is vendor-shaped.
	cmd.Flags().StringVar(&auditWebhookPreset, "audit-webhook-preset", "generic",
		"Webhook body + auth shape. One of: generic | datadog | splunk-hec | "+
			"sentinel. 'generic' (default) preserves the Slice 1 wire shape "+
			"(Bearer + JSON array of OCSF events). 'datadog' sets DD-API-KEY + "+
			"overlays ddsource/service/ddtags/status/host/message per event. "+
			"'splunk-hec' sends NDJSON with 'Authorization: Splunk <token>'. "+
			"'sentinel' HMAC-SHA256-signs SharedKey auth for Log Analytics "+
			"Workspace ingest (--audit-webhook-token must be the base64 "+
			"workspace shared key for sentinel). The OCSF event in the JSONL "+
			"log file is unchanged regardless of preset.")
	cmd.Flags().StringVar(&auditWebhookTags, "audit-webhook-tags", "",
		"Free-form comma-separated tag string appended to Datadog's ddtags. "+
			"Example: env:prod,team:platform. Ignored by other presets.")
	cmd.Flags().StringVar(&auditWebhookSentinelTable, "audit-webhook-sentinel-table",
		audit.SentinelDefaultTable,
		"Log Analytics custom-log table name for the sentinel preset. "+
			"Becomes the Log-Type header on every POST; Sentinel auto-creates "+
			"the table on first ingest. Ignored by other presets.")
	// Slice 2 of #252 — suspicious-activity alert rule engine.
	cmd.Flags().StringVar(&auditAlertRoutesPath, "alert-routes", "",
		"#280 — YAML file describing "+
			"per-org notification routing. Ships in the v1.0 free + open-source "+
			"release (license-file plumbing #235 retained for any future "+
			"paid tier per project_oss_only_launch_decision.md but does "+
			"NOT gate this flag at v1.0). When set, the multi-destination "+
			"routing engine activates: each event is matched against the "+
			"configured routes' match blocks + dispatched to the route's "+
			"destinations (webhook / pagerduty / slack). When unset, the "+
			"existing single-webhook --audit-webhook-url path stays exactly "+
			"as today (zero regression). Secrets must use ${ENV_VAR} "+
			"interpolation; literal tokens in the YAML are refused. Use "+
			"`kbounce config preview-routes` to dry-run a sample event "+
			"against the file before deploying. Setting BOTH --alert-routes "+
			"and --audit-webhook-url ignores the latter (with a warning).")
	cmd.Flags().StringVar(&auditAlertRulesPath, "alert-rules", "",
		"Path to a YAML file tuning the audit alert-rule engine "+
			"(admin_fallback_burst / pause_long / non_org_profile_install / "+
			"unusual_high_risk_action / heartbeat_gap). Set to the empty "+
			"string (default) to DISABLE the rule engine entirely; set to a "+
			"path to ENABLE with the YAML's thresholds layered over the "+
			"built-in defaults (so an empty file enables all five rules with "+
			"their defaults). Alert events ride the same JSONL log + HTTPS "+
			"webhook transport as decision events (OCSF class 6003, "+
			"activity_id 99, activity_name 'anomaly_detected'). v1.0 free + open-"+
			"source release (license-file plumbing #235 retained for any future "+
			"paid tier per project_oss_only_launch_decision.md but does "+
			"NOT gate this flag at v1.0).")
	// Heartbeat liveness emitter — per [[prompt-injection-disable-
	// bouncer-threat]] + [[audit-export-failure-visibility]]. OFF
	// by default; 30s recommended for Enterprise.
	// Bulk-answer burst-detector tuning per [[bulk-prompt-answer-ux]].
	// Zero values fall back to the proxy package defaults
	// (BurstThresholdDefault / BurstWindowDefault / BurstCooldownDefault).
	cmd.Flags().IntVar(&bulkAnswerThreshold, "bulk-answer-threshold", 0,
		"Prompt count that trips the bulk-answer burst detector. "+
			"Default 5: when 5 DENY prompts are enqueued within "+
			"--bulk-answer-window seconds, the proxy records a "+
			"BURST_DETECTED event surfaced by `kbounce prompts bulk-"+
			"answer`. Per [[bulk-prompt-answer-ux]]: this is the safety "+
			"valve for the 'block-happy = uninstalled' failure mode.")
	cmd.Flags().DurationVar(&bulkAnswerWindow, "bulk-answer-window", 0,
		"Sliding-window length over which the burst detector counts "+
			"prompt enqueues. Default 60s.")
	cmd.Flags().DurationVar(&bulkAnswerCooldown, "bulk-answer-cooldown", 0,
		"How long the burst detector stays silent after emitting one "+
			"event before it can fire again. Default 5m. Prevents one "+
			"sustained burst from emitting dozens of identical events.")
	cmd.Flags().DurationVar(&auditHeartbeatInterval, "heartbeat-interval", 0,
		"Audit-export heartbeat cadence. When non-zero, a background "+
			"goroutine emits a HEARTBEAT OCSF event at this interval so a "+
			"downstream SIEM has a positive liveness signal for the audit-"+
			"export channel. Recommended: 30s for compliance-heavy deployments. "+
			"Default 0 (DISABLED) per [[security-team-positioning-safety-"+
			"not-surveillance]] — opt in once the SIEM has a `heartbeat_gap` "+
			"rule wired. Pairs with the local heartbeat_gap rule (enabled "+
			"via --alert-rules) which flips /healthz to 503 + writes to "+
			"stderr when the watchdog detects a missed-tick gap (the audit-"+
			"export channel itself may be the failure source, so the "+
			"fallback surfaces must not ride through it). Minimum 1s; "+
			"requires --alert-rules to be a non-empty path for the local "+
			"gap detection.")
	cmd.Flags().StringVar(&auditEventsToken, "audit-events-token", "",
		"Bearer token required for GET /audit/events (#271) when the "+
			"proxy is bound externally. Empty + loopback bind = no auth "+
			"required (the loopback bind is the trust anchor). Empty + "+
			"external bind = kbounce refuses to start. #380 — falls back "+
			"to the "+envAuditEventsTokenVar+" env var when the flag is "+
			"empty (the flag wins). Prefer the env var: a flag value leaks "+
			"the token into `ps` / process listings.")
	cmd.Flags().StringVar(&recordSessionsDir, "record-sessions-dir", "",
		"#285 — per-session NDJSON recording directory. When set, every "+
			"audit event is also written to {dir}/{agent.session_id}.ndjson "+
			"(one file per agent session). Replayable via `iam-jit session "+
			"replay <FILE>`. File mode 0o600. Default off; the recorder "+
			"captures agent identity + operation details so it ships opt-in.")
	// #258 — AWS Security Lake audit-export adapter. Per [[no-hosted-
	// saas]] + [[self-host-zero-billing-dependency]] the bucket lives
	// in the operator's AWS account; iam-jit-the-company never
	// receives the data.
	cmd.Flags().StringVar(&securityLakeBucket, "security-lake-bucket", "",
		"#258 — name of the operator-owned S3 bucket that AWS Security "+
			"Lake auto-ingests from. When set, every OCSF event is also "+
			"written as a parquet file at `s3://<bucket>/region=<r>/"+
			"eventday=<YYYYMMDD>/eventhour=<HH>/api_activity-<unix-ms>."+
			"parquet`. Requires --security-lake-region; honours "+
			"--security-lake-role-arn if set otherwise uses the default "+
			"AWS credential chain.")
	cmd.Flags().StringVar(&securityLakeRegion, "security-lake-region", "",
		"#258 — AWS region the Security Lake bucket lives in. Required "+
			"when --security-lake-bucket is set. Becomes the `region=<r>` "+
			"partition key on every parquet file.")
	cmd.Flags().StringVar(&securityLakeRoleARN, "security-lake-role-arn", "",
		"#258 — optional IAM role to assume for Security Lake writes "+
			"(STS AssumeRole). When unset the default AWS credential chain "+
			"is used. Recommended for cross-account deployments where the "+
			"bucket lives in a dedicated security account.")
	cmd.Flags().IntVar(&securityLakeRotationSeconds,
		"security-lake-rotation-seconds", audit.SecurityLakeDefaultRotationSeconds,
		"#258 — how often the in-memory parquet batch flushes to S3. "+
			"Default 300 (5 minutes) matches the Security Lake custom-"+
			"source ingest cadence. A 10 MiB size cap also forces a flush, "+
			"whichever fires first.")
	// #317 — cloud-neutral S3-compatible NDJSON object-storage sink.
	// All fields OFF by default. Per [[self-host-zero-billing-
	// dependency]] the bucket is operator-owned. Per [[don't-tailor-
	// to-lighthouse]]: generic S3-compat (AWS S3 native + GCS interop
	// + Azure Blob S3-compat layer + MinIO + R2 + B2 + DigitalOcean
	// Spaces). Per [[cross-product-agent-parity]] the flag shape is
	// identical to ibounce + dbounce + gbounce.
	cmd.Flags().StringVar(&auditObjectStorageEndpoint,
		"audit-object-storage-endpoint", "",
		"#317 — S3 API endpoint URL. Required when "+
			"--audit-object-storage-bucket is set. Examples: "+
			"https://s3.us-east-1.amazonaws.com (AWS S3); "+
			"https://<accountid>.r2.cloudflarestorage.com (Cloudflare R2); "+
			"https://minio.internal:9000 (MinIO); "+
			"https://storage.googleapis.com (GCS interop); "+
			"https://s3.us-west-002.backblazeb2.com (Backblaze B2); "+
			"https://nyc3.digitaloceanspaces.com (DigitalOcean Spaces).")
	cmd.Flags().StringVar(&auditObjectStorageBucket,
		"audit-object-storage-bucket", "",
		"#317 — name of the operator-owned bucket the writer appends "+
			"NDJSON files into. Operator creates the bucket; kbounce "+
			"NEVER creates buckets. When set, every OCSF event is also "+
			"written as a gzip-compressed NDJSON line into "+
			"`{prefix}/year=YYYY/month=MM/day=DD/hour=HH/"+
			"kbounce-{instance_id}-{timestamp}.jsonl.gz`. Hive-style "+
			"partitioning lets Athena / BigQuery / Spark / Trino query "+
			"the bucket directly; collectors do LIST + GET against the "+
			"prefix at predictable cadence.")
	cmd.Flags().StringVar(&auditObjectStoragePrefix,
		"audit-object-storage-prefix", "",
		"#317 — key prefix inside the bucket (e.g. `bounce-audit/prod`). "+
			"Empty = bucket root. Hive partition directories are "+
			"appended under the prefix.")
	cmd.Flags().StringVar(&auditObjectStorageRegion,
		"audit-object-storage-region", audit.ObjectStorageDefaultRegion,
		"#317 — region for the SigV4 signature. AWS S3: real region "+
			"(`us-east-1`, `eu-west-1`, ...). Cloudflare R2: `auto`. "+
			"MinIO / vendor-specific: pick whatever the vendor docs say.")
	cmd.Flags().StringVar(&auditObjectStorageCredentialsFile,
		"audit-object-storage-credentials-file", "",
		"#317 — optional explicit credentials file (overrides env vars). "+
			"YAML or INI shape with keys `access_key_id`, "+
			"`secret_access_key`, optional `session_token`. When absent, "+
			"reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / "+
			"AWS_SESSION_TOKEN env vars.")
	cmd.Flags().IntVar(&auditObjectStorageRotationMinutes,
		"audit-object-storage-rotation-minutes",
		audit.ObjectStorageDefaultRotationMinutes,
		"#317 — rotate the active NDJSON file when N minutes elapse OR "+
			"--audit-object-storage-max-size-mb fires, whichever first. "+
			"Lower values mean smaller files + faster collector "+
			"visibility; higher values mean fewer / larger files "+
			"(better scan efficiency).")
	cmd.Flags().IntVar(&auditObjectStorageMaxSizeMB,
		"audit-object-storage-max-size-mb",
		audit.ObjectStorageDefaultMaxSizeMB,
		"#317 — rotate the active NDJSON file when its in-memory size "+
			"estimate crosses N megabytes. Default 16. Works together "+
			"with --audit-object-storage-rotation-minutes; whichever cap "+
			"fires first triggers a flush.")
	cmd.Flags().StringVar(&auditObjectStorageInstanceID,
		"audit-object-storage-instance-id", "",
		"#317 — override the auto-generated instance identifier "+
			"(hostname-pid) used in the object key. Useful for operators "+
			"with ephemeral hostnames (containers / k8s pods) who want "+
			"the path stable across restarts.")
	// #324b — cross-product dynamic-deny YAML.
	cmd.Flags().StringVar(&dynamicDeniesPath, "dynamic-denies-path", "",
		"#324b — path to the cross-product dynamic-deny rules YAML. "+
			"Default ~/.iam-jit/dynamic-denies.yaml (also honors "+
			"$IAM_JIT_DYNAMIC_DENIES_PATH). The file is shared with "+
			"ibounce / kbouncer / dbounce / gbounce; rules whose "+
			"applied_to list excludes kbouncer are silently skipped. "+
			"Hot-reloaded on disk change (fsnotify-driven). The "+
			"unified `iam-jit deny add` CLI for editing the file lands "+
			"in #324e; today the file is hand-edited (or written by "+
			"agents via the cross-product MCP path).")
	cmd.Flags().BoolVar(&disableDynamicDenies, "disable-dynamic-denies", false,
		"#324b — disable the dynamic-deny channel entirely. The "+
			"watcher goroutine never starts; the proxy behaves "+
			"byte-identically to the pre-#324b shape. Useful for "+
			"operators who haven't installed the cross-product CLI.")
	// #254 — deployment preset. Single-flag shortcut for a common
	// deployment shape. v1.0 ships only `security-observe` per
	// [[deliberate-feature-completion]]; the framework supports more
	// (see docs/DEPLOYMENT-PRESETS.md for the roadmap).
	cmd.Flags().StringVar(&deploymentPreset, "preset", "",
		"#254 — single-flag shortcut for a common deployment shape. "+
			"security-observe = transparent mode + JSONL audit + alert "+
			"rules (defaults) + 30s heartbeat. Designed for the security-"+
			"team 'gather data first; author profile second' starting "+
			"shape per [[bouncer-mode-selection-for-agents]]. Some preset "+
			"values are HARD (e.g. --mode for security-observe — the "+
			"entire point of the preset is transparent); passing them "+
			"with a different value is an error. Others are SOFT (e.g. "+
			"--audit-log-path); the operator's value wins. Startup banner "+
			"shows which settings are derived from the preset.")
	return cmd
}

// buildAuditManager wires the --audit-log-path / --audit-webhook-* /
// --alert-rules / --heartbeat-interval flags into an audit.Emitter +
// an optional health-check func + a closer the caller defers.
// Returns (nil, nil, no-op, nil) when no audit-export channel is
// configured.
//
// License gate: webhook flags + alert-rules require an Enterprise
// license file. kbounce does not yet have license-file plumbing
// (tracked in #235); until that lands, the affected flags surface
// audit.ErrLicenseRequired / ErrAlertRulesLicenseRequired so an
// operator who tries to use the Enterprise feature without the
// license-file infrastructure gets a clear error rather than a
// silent bypass.
//
// v1.0 update per [[oss-only-launch-decision]]: license enforcement
// is DISABLED at v1.0; the webhook + alert-rules + alert-routes
// transports ship FREE in the OSS-only launch. The license error
// sentinels (ErrLicenseRequired / ErrAlertRulesLicenseRequired /
// ErrRoutesLicenseRequired) + the audit.LoadLicense scaffolding
// remain in the repo for the future v1.1+ paid tier (per the memo,
// "license code stays but does NOT enforce"). When that paid tier
// lands the gate sites below re-introduce a `licensed()` check;
// today they wire the transport unconditionally + emit an INFO log
// noting the feature is FREE at v1.0.
//
// Heartbeat wiring per [[prompt-injection-disable-bouncer-threat]]:
// when --heartbeat-interval is non-zero, a Heartbeater goroutine is
// launched against the returned emitter + bound to the rule engine
// (if one was built) so the local heartbeat_gap rule's stderr +
// /healthz 503 fallbacks fire when a gap is detected.
func buildAuditManager(
	ctx context.Context,
	logPath string, logFsync bool,
	logMaxSizeMB int64, logMaxAgeDays int, dbRetentionDays int,
	webhookURL, webhookToken string, webhookBatch int,
	allowInternal bool,
	webhookPreset, webhookTags, webhookSentinelTable string,
	alertRulesPath string,
	alertRoutesPath string,
	heartbeatInterval time.Duration,
	recordSessionsDir string,
	securityLakeBucket, securityLakeRegion, securityLakeRoleARN string,
	securityLakeRotationSeconds int,
	auditObjectStorageEndpoint, auditObjectStorageBucket,
	auditObjectStoragePrefix, auditObjectStorageRegion,
	auditObjectStorageCredentialsFile string,
	auditObjectStorageRotationMinutes int,
	auditObjectStorageMaxSizeMB int,
	auditObjectStorageInstanceID string,
	noAuditChain bool,
	manifestInterval int64,
) (audit.Emitter, func() bool, func(), error) {
	noop := func() {}
	// #258 — Security Lake parse-time validation. Bucket without region
	// (or vice versa) is a misconfiguration; fail-fast so the operator
	// fixes it once rather than seeing a credential probe failure deep
	// in startup. Validated BEFORE the early-return so passing only
	// --security-lake-region (which would otherwise no-op) surfaces
	// the missing-bucket error.
	if securityLakeBucket != "" && securityLakeRegion == "" {
		return nil, nil, noop, fmt.Errorf(
			"kbounce: --security-lake-bucket requires --security-lake-region " +
				"(the region becomes the `region=<r>` partition key on every " +
				"parquet file)")
	}
	if securityLakeRegion != "" && securityLakeBucket == "" {
		return nil, nil, noop, fmt.Errorf(
			"kbounce: --security-lake-region requires --security-lake-bucket " +
				"(passing region without a target bucket has no effect)")
	}
	// #317 — object-storage parse-time validation. Bucket without
	// endpoint (or vice versa) is a misconfiguration; fail-fast.
	if auditObjectStorageBucket != "" && auditObjectStorageEndpoint == "" {
		return nil, nil, noop, fmt.Errorf(
			"kbounce: --audit-object-storage-bucket requires " +
				"--audit-object-storage-endpoint (the S3 API endpoint URL " +
				"for the operator's cloud provider — examples: " +
				"https://s3.us-east-1.amazonaws.com for AWS S3; " +
				"https://<accountid>.r2.cloudflarestorage.com for " +
				"Cloudflare R2; https://storage.googleapis.com for GCS " +
				"interop)")
	}
	if auditObjectStorageEndpoint != "" && auditObjectStorageBucket == "" {
		return nil, nil, noop, fmt.Errorf(
			"kbounce: --audit-object-storage-endpoint requires " +
				"--audit-object-storage-bucket (passing an endpoint " +
				"without a target bucket has no effect)")
	}
	if logPath == "" && webhookURL == "" && alertRulesPath == "" &&
		alertRoutesPath == "" &&
		heartbeatInterval == 0 && recordSessionsDir == "" &&
		securityLakeBucket == "" && auditObjectStorageBucket == "" {
		return nil, nil, noop, nil
	}
	// #280 — per-org routing engine. Per [[oss-only-launch-decision]]
	// this ships FREE at v1.0; the prior license gate (which returned
	// audit.ErrRoutesLicenseRequired) was a calibration-drift gap vs
	// the help-text claim that the feature is free at v1.0 per
	// [[ibounce-honest-positioning]]. When the v1.1+ paid tier lands,
	// reinstate the gate here; today the routes engine wires
	// unconditionally.
	var routesEngine *audit.RoutesEngine
	if alertRoutesPath != "" {
		log.Info().
			Str("path", alertRoutesPath).
			Msg("kbounce: --alert-routes ships FREE at v1.0 per [[oss-only-launch-decision]] (license enforcement disabled; sentinel audit.ErrRoutesLicenseRequired retained for future v1.1+ paid tier)")
		routesCfg, err := audit.LoadRoutesConfig(alertRoutesPath)
		if err != nil {
			return nil, nil, noop, fmt.Errorf("kbounce: --alert-routes: %w", err)
		}
		eng, err := audit.NewRoutesEngine(ctx, audit.RoutesEngineOptions{
			Cfg:     routesCfg,
			Product: "kbouncer",
		})
		if err != nil {
			return nil, nil, noop, fmt.Errorf("kbounce: routes engine: %w", err)
		}
		routesEngine = eng
	}
	// Validate the preset name up front so a typo surfaces before
	// the license gate (gives the operator a single clear error per
	// run rather than fixing one then hitting the next).
	if _, err := audit.ParsePreset(webhookPreset); err != nil {
		return nil, nil, noop, err
	}
	// Validate heartbeat interval shape up front (the audit package
	// clamps below MinHeartbeatInterval defensively; we reject the
	// flag here for a clearer error).
	if heartbeatInterval != 0 && heartbeatInterval < audit.MinHeartbeatInterval {
		return nil, nil, noop, fmt.Errorf(
			"kbounce: --heartbeat-interval must be 0 (disabled) or >= %s; got %s",
			audit.MinHeartbeatInterval, heartbeatInterval)
	}
	// Slice 2 of #252 — alert-rule engine. Per
	// [[oss-only-launch-decision]] this ships FREE at v1.0; the prior
	// license gate (which returned audit.ErrAlertRulesLicenseRequired)
	// was a calibration-drift gap vs the help-text claim per
	// [[ibounce-honest-positioning]]. When the v1.1+ paid tier lands,
	// reinstate the gate here; today the rule engine wires
	// unconditionally. Rules are loaded here so a YAML parse error
	// surfaces at startup; the RuleEngine itself is constructed after
	// the underlying Manager (it wraps the Manager as the Emitter).
	var alertRulesCfg *audit.RulesConfig
	if alertRulesPath != "" {
		log.Info().
			Str("path", alertRulesPath).
			Msg("kbounce: --alert-rules ships FREE at v1.0 per [[oss-only-launch-decision]] (license enforcement disabled; sentinel audit.ErrAlertRulesLicenseRequired retained for future v1.1+ paid tier)")
		c, err := audit.LoadRulesConfig(alertRulesPath)
		if err != nil {
			return nil, nil, noop, fmt.Errorf("kbounce: --alert-rules: %w", err)
		}
		alertRulesCfg = c
	}
	var logWriter *audit.LogWriter
	var webhookPusher *audit.WebhookPusher
	if logPath != "" {
		// #311 / §A10 — sentinel -1 means "use the audit-package default
		// (matches LOG-RETENTION.md)." 0 means "operator explicitly
		// disabled the trigger." Same resolution pattern across all
		// four Bounce products per [[cross-product-agent-parity]].
		effSize := logMaxSizeMB
		if effSize < 0 {
			effSize = audit.DefaultMaxSizeMB
		}
		effAge := logMaxAgeDays
		if effAge < 0 {
			effAge = audit.DefaultMaxAgeDays
		}
		// dbRetentionDays is consumed by the on-demand purge subcommand,
		// not the live writer; surface it on stderr so the operator sees
		// the resolved value at startup but don't fail-fast on it here
		// (the writer doesn't sweep the DB).
		_ = dbRetentionDays
		// ADOPT-10 / #734 — tamper-evident hash-chain + signed manifests,
		// ON BY DEFAULT when audit logging is on (cheap + safe per
		// [[v1-scope-bar]]). --no-audit-chain disables. Chain state lives
		// alongside the JSONL; the Ed25519 keypair lives in
		// ~/.kbouncer/audit-keys (override via KBOUNCER_AUDIT_KEYS_DIR).
		// The private key is never logged or committed.
		var chain *audit.ChainState
		var signer *audit.ManifestSigner
		logDir := audit.ResolveLogDir(logPath)
		if !noAuditChain && logDir != "" {
			chain = audit.LoadChainState(logDir, 0)
			keysDir := os.Getenv("KBOUNCER_AUDIT_KEYS_DIR")
			if keysDir == "" {
				if home, herr := os.UserHomeDir(); herr == nil {
					keysDir = filepath.Join(home, ".kbouncer", "audit-keys")
				}
			}
			if keysDir != "" {
				interval := int64(audit.DefaultManifestIntervalEvents)
				if manifestInterval > 0 {
					interval = manifestInterval
				}
				s, serr := audit.NewManifestSigner(
					logDir, "kbouncer",
					interval,
					keysDir, audit.DefaultKeypairName,
				)
				if serr != nil {
					fmt.Fprintf(os.Stderr,
						"kbouncer: warn: audit-manifest keypair init failed: %v "+
							"(hash-chain still active; no signed manifests)\n", serr)
				} else {
					signer = s
				}
			}
		}
		lw, err := audit.NewLogWriter(ctx, audit.LogWriterOptions{
			Path:       logPath,
			Fsync:      logFsync,
			MaxSizeMB:  effSize,
			MaxAgeDays: effAge,
			Chain:      chain,
			Signer:     signer,
		})
		if err != nil {
			return nil, nil, noop, err
		}
		logWriter = lw
	}
	if webhookURL != "" {
		// Per [[oss-only-launch-decision]] the audit-export webhook
		// transport ships FREE at v1.0; the prior license gate (which
		// returned audit.ErrLicenseRequired) was a calibration-drift
		// gap vs the help-text claim per
		// [[ibounce-honest-positioning]]. When the v1.1+ paid tier
		// lands, reinstate a licensed() check here; today the webhook
		// pusher wires unconditionally. Token required for auth (an
		// unauthenticated webhook would surface audit events to anyone
		// who guesses the URL — defense-in-depth that's orthogonal to
		// licensing).
		log.Info().
			Str("url", webhookURL).
			Msg("kbounce: --audit-webhook-url ships FREE at v1.0 per [[oss-only-launch-decision]] (license enforcement disabled; sentinel audit.ErrLicenseRequired retained for future v1.1+ paid tier)")
		preset, err := audit.ParsePreset(webhookPreset)
		if err != nil {
			return nil, nil, noop, err
		}
		sentinelTable := webhookSentinelTable
		if sentinelTable == "" {
			sentinelTable = audit.SentinelDefaultTable
		}
		wp, err := audit.NewWebhookPusher(ctx, audit.WebhookOptions{
			URL:           webhookURL,
			Token:         webhookToken,
			AllowInternal: allowInternal,
			BatchSize:     webhookBatch,
			Preset:        preset,
			Tags:          webhookTags,
			SentinelTable: sentinelTable,
		})
		if err != nil {
			return nil, nil, noop, fmt.Errorf("kbounce: audit-webhook pusher: %w", err)
		}
		webhookPusher = wp
	}
	// #285 — per-session NDJSON recorder. Default off; only constructed
	// when the operator passed --record-sessions-dir. Start() creates
	// the dir + recovers any stale .partial files. Fatal on failure so
	// an unwritable dir surfaces immediately.
	var sessRecorder *audit.SessionRecorder
	if recordSessionsDir != "" {
		sr, err := audit.NewSessionRecorder(audit.SessionRecorderOptions{
			Dir:            recordSessionsDir,
			BouncerProduct: "kbouncer",
		})
		if err != nil {
			return nil, nil, noop, err
		}
		if err := sr.Start(); err != nil {
			return nil, nil, noop, err
		}
		sessRecorder = sr
	}
	// #258 — Security Lake parquet writer. Default OFF; only
	// constructed when --security-lake-bucket is set. Start() probes
	// credentials (default chain or AssumeRole when --security-lake-
	// role-arn is set) and refuses to start with a clear error if
	// none are reachable. Per [[no-hosted-saas]] + [[self-host-zero-
	// billing-dependency]] the bucket lives in the operator's AWS
	// account; iam-jit-the-company never receives the data.
	var securityLakeWriter *audit.SecurityLakeWriter
	if securityLakeBucket != "" {
		slw, err := audit.NewSecurityLakeWriter(audit.SecurityLakeWriterOptions{
			Bucket:          securityLakeBucket,
			Region:          securityLakeRegion,
			RoleARN:         securityLakeRoleARN,
			RotationSeconds: securityLakeRotationSeconds,
		})
		if err != nil {
			return nil, nil, noop, err
		}
		if err := slw.Start(ctx); err != nil {
			return nil, nil, noop, fmt.Errorf(
				"kbounce: Security Lake writer failed to start: %w", err)
		}
		securityLakeWriter = slw
	}
	// #317 — cloud-neutral S3-compat NDJSON object-storage writer.
	// Default OFF; only constructed when --audit-object-storage-bucket
	// is set. Start() probes the bucket (HeadBucket) so credential /
	// endpoint / bucket-name misconfigurations surface immediately
	// rather than at first flush. Per [[self-host-zero-billing-
	// dependency]] the bucket is operator-owned (operator creates;
	// kbouncer never creates).
	var objectStorageWriter *audit.ObjectStorageWriter
	if auditObjectStorageBucket != "" {
		osCreds, err := audit.LoadObjectStorageCredentials(
			auditObjectStorageCredentialsFile)
		if err != nil {
			return nil, nil, noop, err
		}
		osw, err := audit.NewObjectStorageWriter(audit.ObjectStorageWriterOptions{
			EndpointURL:     auditObjectStorageEndpoint,
			Bucket:          auditObjectStorageBucket,
			Prefix:          auditObjectStoragePrefix,
			Region:          auditObjectStorageRegion,
			Credentials:     osCreds,
			Product:         "kbounce",
			InstanceID:      auditObjectStorageInstanceID,
			RotationMinutes: auditObjectStorageRotationMinutes,
			MaxSizeMB:       auditObjectStorageMaxSizeMB,
		})
		if err != nil {
			return nil, nil, noop, err
		}
		if err := osw.Start(ctx); err != nil {
			return nil, nil, noop, fmt.Errorf(
				"kbounce: object-storage writer failed to start: %w", err)
		}
		objectStorageWriter = osw
	}
	mgr := audit.NewManager(audit.ManagerOptions{
		LogWriter:           logWriter,
		WebhookPusher:       webhookPusher,
		RoutesEngine:        routesEngine,
		SecurityLakeWriter:  securityLakeWriter,
		ObjectStorageWriter: objectStorageWriter,
		SessionRecorder:     sessRecorder,
	})
	// Rule engine wraps the Manager so registered alert rules observe
	// every event emitted into the manager + can re-emit synthesized
	// alert events back through the same fan-out. Per
	// [[oss-only-launch-decision]] the engine is unconditionally wired
	// when --alert-rules is set (license enforcement disabled at
	// v1.0). The emitter handed to the proxy / heartbeater is the
	// RuleEngine when alert-rules is on, the Manager otherwise.
	var ruleEng *audit.RuleEngine
	var emitter audit.Emitter = mgr
	if alertRulesCfg != nil {
		rules := audit.BuildBuiltinRules(alertRulesCfg)
		eng, err := audit.NewRuleEngine(mgr, rules)
		if err != nil {
			return nil, nil, noop, fmt.Errorf("kbounce: rule engine: %w", err)
		}
		ruleEng = eng
		emitter = ruleEng
	}
	// Heartbeat wiring. When the rule engine is enabled (now
	// available at v1.0 per [[oss-only-launch-decision]]), bind the
	// heartbeater into it so the heartbeat_gap rule can flip /healthz
	// on a missed tick. Without the engine, the heartbeater still
	// emits HEARTBEAT events so the SIEM-side gap rule has its
	// liveness signal, and Healthy() always reports true (no local
	// watchdog without the rule engine — the gap is observable on
	// the SIEM side via the missing seq numbers).
	var hb *audit.Heartbeater
	if heartbeatInterval > 0 {
		hb = audit.NewHeartbeater(emitter, heartbeatInterval)
		// Bind into the Manager so its Status() surfaces the
		// heartbeat fields for the MCP audit-export status tool +
		// the startup banner — symmetric with the engine-wrapped
		// path.
		mgr.BindHeartbeater(hb)
		if ruleEng != nil {
			ruleEng.BindHeartbeater(hb)
		}
		hb.Start(ctx)
	}
	// Per [[audit-export-failure-visibility]]: /healthz flips to 503
	// when the heartbeat watchdog OR the audit-export channel-write
	// health predicate fires (either-or, both independent of each
	// other). The combined callback fans the two surfaces into a
	// single bool the proxy.Config.AuditHealthCheck consumes —
	// channel-write degradation is detected via the Manager's status
	// snapshot (consec-failure threshold + 5-min stale-success
	// window from computeAuditExportHealth) so /healthz, the MCP
	// status tool, the `kbounce audit-export health` CLI, and the
	// audit_export_degraded alert rule all read the same predicate.
	healthCheck := func() bool {
		if mgr != nil {
			st := mgr.Status()
			if !st.AuditExportHealthy {
				return false
			}
		}
		if hb != nil && !hb.Healthy() {
			return false
		}
		return true
	}
	closer := func() {
		if hb != nil {
			hb.Close()
		}
		if routesEngine != nil {
			routesEngine.Close()
		}
		mgr.Close()
	}
	return emitter, healthCheck, closer, nil
}

// newInitTLSCmd implements `kbounce init-tls`. One-time setup that
// generates a CA + server cert into ~/.kbouncer/tls/ so the operator
// can add the CA to their kubectl context's certificate-authority
// field and run `kbounce run --tls-cert ... --tls-key ...` afterward.
func newInitTLSCmd() *cobra.Command {
	var (
		dir            string
		force          bool
		additionalSANs []string
	)
	cmd := &cobra.Command{
		Use:   "init-tls",
		Short: "Generate a local CA + server cert for the inbound HTTPS listener",
		Long: `Generate the TLS material kbounce's inbound listener uses to
speak HTTPS to kubectl / Helm / a coding agent.

One-time setup. Writes four files into ~/.kbouncer/tls/ (or --dir):

  ca.key      local CA private key (mode 0400 — operator-only read)
  ca.crt      local CA certificate (add to kubectl context's
              certificate-authority field)
  server.key  server private key (mode 0400)
  server.crt  server cert, signed by ca.crt; SAN includes
              127.0.0.1, ::1, localhost

Then run:

  kbounce run \
    --tls-cert ~/.kbouncer/tls/server.crt \
    --tls-key  ~/.kbouncer/tls/server.key

And in your kubeconfig, point the cluster's server at
https://127.0.0.1:8766 and set certificate-authority to
~/.kbouncer/tls/ca.crt.

Without --force, init-tls refuses to overwrite existing files
(surprise key rotation invalidates any kubectl context that pinned
the prior CA).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := tlsmat.Init(tlsmat.InitOptions{
				Dir:            dir,
				Force:          force,
				AdditionalSANs: additionalSANs,
			})
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "wrote TLS material into %s:\n", res.Dir)
			fmt.Fprintf(w, "  %s\n", res.CAKeyPath)
			fmt.Fprintf(w, "  %s\n", res.CACertPath)
			fmt.Fprintf(w, "  %s\n", res.ServerKeyPath)
			fmt.Fprintf(w, "  %s\n", res.ServerCertPath)
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Next steps:")
			fmt.Fprintln(w, "  1. Add the CA to your kubectl context:")
			fmt.Fprintf(w, "       certificate-authority: %s\n", res.CACertPath)
			fmt.Fprintln(w, "     Or pass it on the kubectl command line:")
			fmt.Fprintf(w, "       kubectl --certificate-authority %s ...\n", res.CACertPath)
			fmt.Fprintln(w, "  2. Start the proxy with TLS:")
			fmt.Fprintf(w, "       kbounce run --tls-cert %s --tls-key %s\n",
				res.ServerCertPath, res.ServerKeyPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "",
		"Directory to write the four PEM files into "+
			"(default: ~/.kbouncer/tls, or KBOUNCER_TLS_DIR env).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite existing files. Default refuses to avoid surprise "+
			"key rotation that would invalidate kubectl contexts.")
	cmd.Flags().StringSliceVar(&additionalSANs, "additional-san", nil,
		"Extra DNS name or IP to add to the server cert SAN list, on "+
			"top of the loopback defaults (127.0.0.1, ::1, localhost). "+
			"Repeatable. Rare; only useful when the proxy is fronted "+
			"by a hostname-based reverse proxy on the same box.")
	return cmd
}

// newProfileCmd implements `kbounce profile ...` subcommands.
// Subcommands: list, show, install.
func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage kbounce environment profiles",
		Long: `kbounce environment profiles add an environment-aware deny
layer that fires BEFORE per-task scopes and global rules. A profile
deny is a hard floor — a permissive task scope cannot override it.

Use ` + "`kbounce profile list`" + ` to see the available profiles and
which one would be active given the current --profile flag /
` + envProfileVar + ` env var. ` + "`kbounce profile show NAME`" + `
prints the full record for a single profile.`,
		Args: cobra.NoArgs,
	}
	// UAT-K2 BLOCKER-K2-02: print a clear error when an unknown
	// sub-subcommand is given (rather than silently exiting 0).
	cmd.RunE = parentRequiresSubcommand("profile", cmd)
	cmd.AddCommand(newProfileListCmd())
	cmd.AddCommand(newProfileShowCmd())
	cmd.AddCommand(newProfileInstallCmd())
	cmd.AddCommand(newProfileInstallDefaultsCmd())
	cmd.AddCommand(newProfileDoctorCmd())
	cmd.AddCommand(newProfileAllowCmd())
	cmd.AddCommand(newDeniesCmd())
	return cmd
}

// newProfileAllowCmd implements `kbounce profile allow` per #386 /
// §A25 Phase 2. Mirrors the iam-jit Python `iam-jit profile allow`
// shape so the cross-bouncer fan-out from iam-jit sees an
// identical surface in kbounce. Per [[cross-product-agent-parity]].
func newProfileAllowCmd() *cobra.Command {
	var (
		target       string
		actions      []string
		reason       string
		duration     string
		profileName  string
		profilesPath string
		jsonOut      bool
	)
	cmd := &cobra.Command{
		Use:   "allow",
		Short: "Add an allow rule to a kbounce profile (operator easy-allow)",
		Long: `Append a profile allow rule with provenance metadata.

  kbounce profile allow --target 'namespaces/staging' \
    --action 'apps/deployments:get' \
    --reason "agent reads staging deployments for synthesis"

Refuses --target '*' (force operator specificity) + actions without a
':' separator. Refuses to mutate org-distributed profiles
(operators create a local override profile to layer on top).

--target is ENFORCED as a namespace floor when it names a K8s namespace
('namespaces/<ns>', '<ns>/<name>', a bare '<ns>', or a glob like
'staging-*') — a namespace-scoped allow does NOT leak to other
namespaces. Any other target (or 'namespaces/*') is advisory-only
metadata and the command WARNS you so the scope is never silently
ignored.

The provenance note format is:
  [easy_allow] <reason> -- by=<actor> via=cli [duration=... | expires=...]

Mirrors the iam-jit Python CLI surface 1:1 per
[[cross-product-agent-parity]].`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := profileallow.AddProfileAllowRule(profileallow.Options{
				Target:       target,
				Actions:      actions,
				Reason:       reason,
				Duration:     duration,
				ProfileName:  profileName,
				ProfilesPath: profilesPath,
				Source:       profileallow.SourceCLI,
			})
			if err != nil {
				return err
			}
			// Honest scope feedback: the evaluator ENFORCES --target as a
			// namespace floor only when it cleanly names a namespace
			// (e.g. 'namespaces/staging', 'default/foo', or a glob like
			// 'staging-*'). Any other target is advisory-only metadata —
			// warn so the operator doesn't believe a non-namespace target
			// narrows the allow when it doesn't.
			if !profile.TargetEnforcedAsNamespace(target) {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"⚠ --target %q is advisory-only: it does not name a K8s "+
						"namespace, so the evaluator will NOT scope this allow "+
						"to it. Scoping comes from the action's resource half + "+
						"a namespace-shaped target (e.g. 'namespaces/<ns>').\n",
					target)
			}
			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(res)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"kbounce: %s allow rule(s) appended to profile %q (now %d rule(s))\n"+
					"  target  : %s\n"+
					"  actions : %s\n"+
					"  reason  : %s\n"+
					"  written : %s\n",
				res.Status, res.ProfileName, res.RuleCountAfter,
				res.Target, strings.Join(res.Actions, ", "),
				res.Reason, res.ProfilePath)
			if res.ExpiresAt != "" {
				fmt.Fprintf(cmd.OutOrStdout(),
					"  expires : %s (advisory metadata; remove via YAML edit)\n",
					res.ExpiresAt)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "",
		"Target to allow (e.g. 'namespaces/staging'); enforced as a namespace "+
			"floor when namespace-shaped, else advisory (warns). '*' is refused.")
	cmd.Flags().StringSliceVar(&actions, "action", nil,
		"One or more 'verb:resource' strings (repeat to pass multiple).")
	cmd.Flags().StringVar(&reason, "reason", "",
		"Operator-supplied explanation (surfaces in note + audit event).")
	cmd.Flags().StringVar(&duration, "duration", "",
		"Optional Go-style duration ('3h', '7d'); empty/'permanent' = permanent.")
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Profile to mutate (default: active profile).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml).")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of human-readable output.")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("action")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

// newDeniesCmd implements `kbounce denies recent` per #386 / §A25
// Phase 2. Reads from the local SQLite store + projects DENY rows
// into the cross-product shape (when, action, resource, deny_reason,
// deny_source, suggested_allow_command).
func newDeniesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "denies",
		Short: "Inspect recent DENY decisions",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("denies", cmd)
	cmd.AddCommand(newDeniesRecentCmd())
	return cmd
}

func newDeniesRecentCmd() *cobra.Command {
	var (
		dbPath         string
		since          string
		limit          int
		jsonOut        bool
		agentSessionID string
	)
	cmd := &cobra.Command{
		Use:   "recent",
		Short: "List recent DENY decisions from the local audit store",
		Long: `Reads from ~/.kbouncer/audit.db and projects each DENY row
into the cross-product DenyRow shape (matches the iam-jit Python
denies module byte-for-byte). Each row carries a
suggested_allow_command an operator can copy-paste to lift the deny
via 'kbounce profile allow'.

  kbounce denies recent --since 5m
  kbounce denies recent --agent-session <id> --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbPath == "" {
				p, err := store.DefaultDBPath()
				if err != nil {
					return err
				}
				dbPath = p
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("kbounce: open store at %s: %w", dbPath, err)
			}
			defer st.Close()
			lower, perr := parseSinceFlag(since)
			if perr != nil {
				return perr
			}
			rows, err := profileallow.RecentDenies(profileallow.RecentDeniesOptions{
				Store:          st,
				Since:          lower,
				AgentSessionID: agentSessionID,
				Limit:          limit,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "kbounce: no recent denies")
				return nil
			}
			for _, r := range rows {
				fmt.Fprintf(cmd.OutOrStdout(),
					"%s  action=%s  resource=%s  source=%s  reason=%s\n  suggested: %s\n",
					r.When, r.Action, r.Resource, r.DenySource, r.DenyReason, r.SuggestedAllowCommand)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", dbFlagHelp)
	cmd.Flags().StringVar(&since, "since", "5m",
		"Lower bound for `at` ('5m'/'1h'/'1d') or ISO 8601 timestamp.")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max rows to return.")
	cmd.Flags().StringVar(&agentSessionID, "agent-session", "",
		"Filter to one MCP session id.")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON.")
	return cmd
}

// parseSinceFlag converts '5m'/'1h'/'1d' or an ISO 8601 timestamp
// into a time.Time lower bound.
func parseSinceFlag(spec string) (time.Time, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return time.Time{}, nil
	}
	if strings.Contains(s, "T") || (len(s) >= 10 && s[4] == '-') {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("kbounce: --since %q: %w", spec, err)
		}
		return t, nil
	}
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("kbounce: --since %q: too short", spec)
	}
	unit := s[len(s)-1]
	qty, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return time.Time{}, fmt.Errorf("kbounce: --since %q: %w", spec, err)
	}
	var d time.Duration
	switch unit {
	case 's':
		d = time.Duration(qty) * time.Second
	case 'm':
		d = time.Duration(qty) * time.Minute
	case 'h':
		d = time.Duration(qty) * time.Hour
	case 'd':
		d = time.Duration(qty) * 24 * time.Hour
	case 'w':
		d = time.Duration(qty) * 7 * 24 * time.Hour
	default:
		return time.Time{}, fmt.Errorf("kbounce: --since %q: unknown unit %q", spec, string(unit))
	}
	return time.Now().UTC().Add(-d), nil
}

// newProfileInstallDefaultsCmd implements `kbounce profile install-
// defaults` per [[cross-product-agent-parity]] (matches dbounce +
// ibounce). Writes the embedded default profiles to disk iff the file
// doesn't already exist, so an operator who wants to review / edit
// the defaults BEFORE starting the proxy can materialize the file
// on demand. `kbounce run` does the same write transparently on its
// first launch; this surface is for the "I want to see what gets
// shipped" workflow.
func newProfileInstallDefaultsCmd() *cobra.Command {
	var (
		profilesPath string
		force        bool
	)
	cmd := &cobra.Command{
		Use:   "install-defaults",
		Short: "Materialize the built-in profiles.yaml on disk",
		Long: `Write the embedded default profiles (full-user +
safe-default) to ~/.kbouncer/profiles.yaml. NEVER overwrites an
existing file unless --force is set (operator edits to community-
installed profiles must survive). Convenient when operators want
to review or edit profiles.yaml before starting the proxy.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			if force {
				_ = os.Remove(profilesPath)
			}
			written, err := profile.EnsureDefaultProfilesFile(profilesPath)
			if err != nil {
				return err
			}
			if written {
				fmt.Fprintf(cmd.OutOrStdout(),
					"kbounce: wrote default profiles to %s\n", profilesPath)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(),
					"kbounce: profiles.yaml already exists at %s "+
						"(pass --force to overwrite)\n", profilesPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite an existing profiles.yaml at the target path.")
	return cmd
}

// newProfileDoctorCmd implements `kbounce profile doctor` per task
// #321 / KNOWN-CAVEATS §A19. Diff-checks the operator's installed
// profile YAML against embedded defaults + reports missing fields
// without overwriting. Operator opts in to merging via --apply or
// silences via --acknowledge.
//
// Exit codes:
//
//	0  current OR --apply succeeded OR --acknowledge succeeded
//	1  filesystem error
//	2  doctor found missing fields AND neither --apply nor
//	   --acknowledge was given
func newProfileDoctorCmd() *cobra.Command {
	var (
		profilesPath string
		apply        bool
		acknowledge  bool
		showDiff     bool
		checkOnly    bool
		jsonOut      bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diff installed profile against shipped defaults + report missing fields",
		Long: `Compare ~/.kbouncer/profiles.yaml against the shipped defaults
and report any fields the operator's local file is missing. kbounce
NEVER auto-overwrites profiles.yaml — operator edits survive
upgrades — but that means new safety floors added to embedded
defaults AFTER your file was written go unnoticed.

  kbounce profile doctor              # report missing fields (no write)
  kbounce profile doctor --apply      # additively merge missing fields + back up prior file
  kbounce profile doctor --acknowledge # silence the warning for this defaults version
  kbounce profile doctor --diff       # show the YAML delta --apply would write
  kbounce profile doctor --check      # silent; exit 2 if gaps found (script-friendly)

Per [[creates-never-mutates]]: --apply is ADDITIVE only. If you set
a deny field to false deliberately, --apply skips it.

Per [[security-team-positioning-safety-not-surveillance]]: framed
as "your profile is behind" not "you are non-compliant."`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if apply && acknowledge {
				return fmt.Errorf("--apply and --acknowledge are mutually exclusive")
			}
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			rep, err := profile.Check(profilesPath)
			if err != nil {
				return err
			}
			if apply {
				result, aerr := profile.Apply(profilesPath, profile.ApplyOptions{})
				if aerr != nil {
					return aerr
				}
				if len(result.AppliedFields) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(),
						"kbounce: profile doctor — nothing to apply; installed profile matches shipped defaults (version %s).\n",
						profile.ShippedDefaultsVersion)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"kbounce: profile doctor --apply — added %d field(s); backup at %s\n",
					len(result.AppliedFields), result.BackupPath)
				for _, g := range result.AppliedFields {
					fmt.Fprintf(cmd.OutOrStdout(),
						"  + %s.%s = %v   [%s] %s\n",
						g.ProfileName, g.Field, g.DefaultValue, g.Category, g.AddedIn)
				}
				return nil
			}
			if acknowledge {
				path, aerr := profile.Acknowledge(profilesPath)
				if aerr != nil {
					return aerr
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"kbounce: profile doctor --acknowledge — recorded %s at %s\n",
					profile.ShippedDefaultsVersion, path)
				fmt.Fprintln(cmd.OutOrStdout(),
					"future `kbounce run` startup banners will skip the §A19 warning "+
						"until a new shipped-defaults version bumps the stamp.")
				return nil
			}
			if checkOnly {
				if len(rep.MissingFields) > 0 {
					os.Exit(2)
				}
				return nil
			}
			if jsonOut {
				type jsonGap struct {
					Profile  string `json:"profile"`
					Field    string `json:"field"`
					Category string `json:"category"`
					Why      string `json:"why"`
					AddedIn  string `json:"added_in"`
					Default  any    `json:"default"`
				}
				out := struct {
					Version       string    `json:"shipped_defaults_version"`
					InstalledPath string    `json:"installed_path"`
					Missing       []jsonGap `json:"missing"`
				}{Version: rep.ShippedDefaultsVersion, InstalledPath: rep.InstalledPath}
				for _, g := range rep.MissingFields {
					out.Missing = append(out.Missing, jsonGap{
						Profile: g.ProfileName, Field: g.Field,
						Category: string(g.Category), Why: g.WhyMatters,
						AddedIn: g.AddedIn, Default: g.DefaultValue,
					})
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				if len(rep.MissingFields) > 0 {
					os.Exit(2)
				}
				return nil
			}
			fmt.Fprint(cmd.OutOrStdout(), profile.FormatReport("kbounce", rep))
			if showDiff {
				fmt.Fprintln(cmd.OutOrStdout(), "--- YAML that --apply would add ---")
				for _, g := range rep.MissingFields {
					fmt.Fprintf(cmd.OutOrStdout(),
						"profiles.%s.%s: %v\n",
						g.ProfileName, g.Field, g.DefaultValue)
				}
			}
			if len(rep.MissingFields) > 0 {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml).")
	cmd.Flags().BoolVar(&apply, "apply", false,
		"Additively merge missing default fields into profiles.yaml + back up prior file.")
	cmd.Flags().BoolVar(&acknowledge, "acknowledge", false,
		"Record the current shipped-defaults version as acknowledged.")
	cmd.Flags().BoolVar(&showDiff, "diff", false,
		"Print the YAML fragment --apply would add.")
	cmd.Flags().BoolVar(&checkOnly, "check", false,
		"Silent mode: exit 0 if current, exit 2 if gaps found.")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"Emit machine-readable JSON. Exit 2 if gaps found.")
	return cmd
}

// parentRequiresSubcommand returns a RunE that prints a clear error +
// returns exit 1 when a cobra parent command is invoked without a
// known sub-subcommand. Closes UAT-K2 BLOCKER-K2-02.
//
// cobra's default behavior with no Run / no Args check is to print the
// help text + exit 0, which lets scripts swallow typos like
// `kbounce profile lst` silently. We instead surface "unknown
// subcommand 'lst'; see `kbounce profile --help`" + exit 1.
func parentRequiresSubcommand(parent string, cmd *cobra.Command) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, args []string) error {
		if len(args) == 0 {
			fmt.Fprintf(c.ErrOrStderr(),
				"kbounce: missing subcommand for %q; see `kbounce %s --help` for valid subs\n",
				parent, parent)
			os.Exit(1)
		}
		fmt.Fprintf(c.ErrOrStderr(),
			"kbounce: unknown subcommand %q for %q; see `kbounce %s --help` for valid subs\n",
			args[0], parent, parent)
		os.Exit(1)
		return nil
	}
}

// newProfileInstallCmd implements `kbounce profile install --from URL`.
//
// Symmetric with iam-jit-bouncer's `profile install` command and built
// on the package-level Install function so test coverage lives in
// internal/profile/install_test.go rather than here.
//
// Exit codes (mirror Python):
//
//	0  success
//	1  payload / fetch problem (malformed YAML, validation error,
//	   fetch failed) — usually an upstream-curator issue
//	2  operator-fixable problem (http:// URL, sha256 mismatch,
//	   conflict without --force)
func newProfileInstallCmd() *cobra.Command {
	var (
		fromURL        string
		expectedSHA256 string
		force          bool
		timeoutSecs    int
		profilesPath   string
		auditLogPath   string
	)
	cmd := &cobra.Command{
		Use:   "install --from URL_OR_PATH [--sha256 HEX] [--force] [--timeout 10]",
		Short: "Fetch + install profiles from a URL or local path",
		Long: `Install profiles from any of:

  * an HTTPS URL — preferred + recommended distribution channel
    (IT teams publish curated profiles at an internal URL, engineers
    install them on day 1).

      kbounce profile install --from https://internal.example/profiles.yaml

  * an HTTP URL — accepted for local-dev parity with the
    audit-export HTTP surface. A one-line WARN fires for non-
    loopback hosts; loopback gets a silent pass.

  * file:///abs/path/...  or a bare local path (relative or
    absolute) — accepts a single YAML file OR a bundle directory
    produced by ` + "`iam-jit profile generate-from-audit`" + `; the
    directory form looks for ` + "`kbounce.yaml`" + ` first then
    falls back to ` + "`index.yaml`" + ` + the bouncer entry naming
    kbounce.

      kbounce profile install --from ./profiles/

The source string becomes the ` + "`source`" + ` of each installed
profile. Profiles with a non-local source are READ-ONLY at the CLI
surface — engineers cannot edit them to bypass org guardrails (the
canonical write entry point, UpsertProfile, refuses to overwrite).

Conflict policy: if a profile of the same name already exists,
install refuses without --force. --force overrides the conflict
gate but still records the new source.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := profile.InstallOptions{
				From:           fromURL,
				ExpectedSHA256: expectedSHA256,
				Force:          force,
				Timeout:        time.Duration(timeoutSecs) * time.Second,
				ProfilesPath:   profilesPath,
			}
			// Per §A26 (#350) print a WARN for non-loopback HTTP. The
			// profile package itself accepts http:// without gating;
			// surfacing the warning at the CLI keeps the package
			// purely-functional + makes the message visible to the
			// operator who's actually running the command.
			if parsed, perr := neturl.Parse(fromURL); perr == nil &&
				strings.EqualFold(parsed.Scheme, "http") {
				host := parsed.Hostname()
				isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
				if !isLoopback {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"WARN: fetching %q over plaintext HTTP — a network "+
							"attacker can MITM-substitute a permissive profile. "+
							"Prefer https:// for IT-distributed profiles. This "+
							"warning does NOT block the install (per §A26 local-"+
							"dev parity with audit-export HTTP).\n", fromURL)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "loading %s ...\n", fromURL)
			result, err := profile.Install(cmd.Context(), opts)
			if err != nil {
				var ie *profile.InstallError
				if errors.As(err, &ie) {
					// Print the structured message to stderr + use the
					// install-specific exit code. cobra would prepend
					// "Error:" if we returned the error directly, so we
					// print + os.Exit ourselves.
					fmt.Fprintln(cmd.ErrOrStderr(), ie.Message)
					os.Exit(ie.ExitCode)
				}
				return err
			}

			// Admin-action audit event per [[basic-app-hygiene-features]]
			// TIER 1 — distinct from the synthetic EventTypeProfileInstall
			// that drives the non_org_profile_install alert rule (#270).
			// This event is the "who installed what" config-change row.
			// Both fire on a successful install + ride the same audit-
			// export channel.
			emitAdminAction(cmd, auditLogPath, audit.AdminActionInput{
				Action:     audit.AdminActionProfileInstall,
				Actor:      currentActor(),
				EntityKind: "profile",
				EntityName: strings.Join(result.InstalledNames, ","),
				Source:     audit.AdminActionSourceCLI,
				// Before: pre-install state captured implicitly as
				// EmptyStateHash (no profile bundle) for first install,
				// or the prior on-disk content for an --force overwrite.
				// We keep the hash inputs lightweight (names + source)
				// rather than re-reading the full YAML to avoid
				// double-hashing the bundle bytes that the proxy already
				// records.
				Before: nil,
				After: map[string]any{
					"installed_profiles": result.InstalledNames,
					"source":             result.SourceURL,
					"sha256":             result.SHA256,
				},
				ExtraExt: map[string]any{
					"source":          result.SourceURL,
					"sha256":          result.SHA256,
					"sha256_verified": result.SHA256Verified,
					"installed_count": len(result.InstalledNames),
					"profiles_path":   result.ProfilesPath,
				},
			})

			if result.SHA256Verified {
				fmt.Fprintf(cmd.OutOrStdout(), "sha256 verified: %s\n", result.SHA256)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "sha256 (no pin given): %s\n", result.SHA256)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"installed %d profile(s) into %s:\n",
				len(result.InstalledNames), result.ProfilesPath)
			for _, name := range result.InstalledNames {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", name)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Activate one with:")
			fmt.Fprintf(cmd.OutOrStdout(),
				"  kbounce run --profile %s\n", result.InstalledNames[0])
			fmt.Fprintln(cmd.OutOrStdout(),
				"These profiles are READ-ONLY (sourced from URL); "+
					"edit the upstream YAML + re-install to update.")
			return nil
		},
	}
	cmd.Flags().StringVar(&fromURL, "from", "",
		"HTTPS URL of a profiles.yaml fragment. Required. http:// is refused.")
	_ = cmd.MarkFlagRequired("from")
	cmd.Flags().StringVar(&expectedSHA256, "sha256", "",
		"Optional SHA-256 (hex) of the fetched bytes. Mismatch → exit 2. "+
			"Defends against a compromised distribution server swapping the file.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite existing profiles of the same name. Without --force, "+
			"install refuses on conflict.")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 10,
		"HTTPS fetch timeout in seconds.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml). "+
			"Honors KBOUNCER_PROFILES_PATH env var if unset.")
	addAdminAuditFlag(cmd, &auditLogPath)
	return cmd
}

func newProfileListCmd() *cobra.Command {
	var (
		profileName  string
		profilesPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available profiles and show which is active",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if profileName == "" {
				profileName = kbenv.Get(envProfileVar)
			}
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			profiles, err := profile.LoadProfiles(profilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			active, _ := profiles.Active(profileName) // err only on unknown name; we still want to list
			source := "embedded defaults"
			if profiles.Path != "" {
				source = profiles.Path
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"kbounce profiles (source: %s)\n", source)
			if profileName != "" && active == nil {
				fmt.Fprintf(cmd.OutOrStdout(),
					"WARNING: requested profile %q is not in this file. "+
						"`kbounce run` would refuse to start.\n", profileName)
			}
			for _, name := range profiles.NamesSorted() {
				p := profiles.All[name]
				marker := "  "
				if active != nil && p.Name == active.Name && profileName != "" {
					marker = "* "
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s%-20s %s\n", marker, name, p.Description)
				if len(p.DenyKeywords) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    deny_keywords: %s\n", strings.Join(p.DenyKeywords, ", "))
				}
				if len(p.DenyVerbs) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    deny_verbs:    %s\n", strings.Join(p.DenyVerbs, ", "))
				}
				if len(p.OnlyClusters) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    only_clusters: %s\n", strings.Join(p.OnlyClusters, ", "))
				}
				if len(p.Exceptions) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    exceptions:    %s\n", strings.Join(p.Exceptions, ", "))
				}
			}
			if profileName == "" {
				fmt.Fprintln(cmd.OutOrStdout(),
					"\n(no profile selected; pass --profile NAME or set "+envProfileVar+")")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Profile to mark as active in the listing. Falls back to "+envProfileVar+".")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml).")
	return cmd
}

// newProfileShowCmd implements `kbounce profile show NAME`. Loads the
// profile file, looks up NAME, and pretty-prints the full record.
// Closes UAT-K2 HIGH-K2-02.
func newProfileShowCmd() *cobra.Command {
	var profilesPath string
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show full detail for a single profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			profiles, err := profile.LoadProfiles(profilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			p, err := profiles.Active(name)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"kbounce: profile %q not found (loaded: %s)\n",
					name, strings.Join(profiles.NamesSorted(), ", "))
				os.Exit(1)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "name:         %s\n", p.Name)
			if p.Description != "" {
				fmt.Fprintf(w, "description:  %s\n", p.Description)
			}
			source := p.Source
			if source == "" {
				source = "local"
			}
			fmt.Fprintf(w, "source:       %s\n", source)
			if len(p.DenyKeywords) > 0 {
				fmt.Fprintf(w, "deny_keywords: %s\n", strings.Join(p.DenyKeywords, ", "))
			}
			if p.KeywordMatch != "" {
				fmt.Fprintf(w, "keyword_match: %s\n", p.KeywordMatch)
			}
			if len(p.KeywordTargets) > 0 {
				targets := make([]string, 0, len(p.KeywordTargets))
				for _, t := range p.KeywordTargets {
					targets = append(targets, string(t))
				}
				fmt.Fprintf(w, "keyword_targets: %s\n", strings.Join(targets, ", "))
			}
			if len(p.DenyVerbs) > 0 {
				fmt.Fprintf(w, "deny_verbs:   %s\n", strings.Join(p.DenyVerbs, ", "))
			}
			if len(p.OnlyClusters) > 0 {
				fmt.Fprintf(w, "only_clusters: %s\n", strings.Join(p.OnlyClusters, ", "))
			}
			if len(p.Exceptions) > 0 {
				fmt.Fprintf(w, "exceptions:   %s\n", strings.Join(p.Exceptions, ", "))
			}
			if n := len(p.AllowRules); n > 0 {
				fmt.Fprintf(w, "allow_rules:  %d\n", n)
				for _, r := range p.AllowRules {
					fmt.Fprintf(w, "  - %s\n", r.Pattern)
					if r.Note != "" {
						fmt.Fprintf(w, "      # %s\n", r.Note)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml).")
	return cmd
}

// newAuditCmd implements `kbounce audit ...`. Ships `tail` only —
// the highest-leverage operator workflow ("show me what just happened
// on the proxy"). Later may add `search` and `diff` against a prior
// known-good baseline.
//
// The tail subcommand (see audit_tail.go) covers the full operator-
// facing surface: paginated rows, live --follow, OCSF-shaped --filter
// expressions, --summary counts, and --export {jsonl,csv,ocsf-bundle}
// so a local operator can pipe the same data downstream tools consume.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the kbounce decision audit log",
		Long: `kbounce records every evaluated request in a local SQLite
audit log at ~/.kbouncer/state.db. ` + "`kbounce audit tail`" + ` is the
fastest way to see what kubectl / Helm / an agent just sent through
the proxy and what verdict each call got.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("audit", cmd)
	cmd.AddCommand(newAuditTailCmd())
	return cmd
}

// newMCPCmd implements `kbounce mcp` — a command group for the
// MCP-over-stdio server an agent (Claude Code, Cursor, Codex, Devin)
// connects to so it can introspect + scope itself via the kbounce_*
// tool family.
//
// Subcommands:
//
//	kbounce mcp serve                 — start the JSON-RPC stdio server
//	kbounce mcp install-claude-code   — wire kbounce into Claude Code / Desktop
//	kbounce mcp install-cursor        — wire kbounce into Cursor
//	kbounce mcp install-codex         — wire kbounce into Codex (manual snippet)
//	kbounce mcp install-devin         — print the Devin (cloud agent) recipe
//	kbounce mcp show-config           — print the canonical JSON snippet
//	kbounce mcp list-tools            — print the tool list (name + summary)
//
// Backward compatibility (per #229): `kbounce mcp` with no subcommand
// still starts the server (same as `kbounce mcp serve`). The install-*
// commands generate configs that point at `kbounce mcp serve` (NOT
// bare `kbounce mcp`) so the generated configs don't depend on the
// back-compat bare-default shape — if we ever change that default
// later, configs already written to operator laptops keep working.
//
// Server-config flags (--db, --profile, --profiles-path, --mode,
// --default-policy, --owner, --actor) live on the `serve` subcommand
// and are mirrored on bare `kbounce mcp` so existing scripts that
// invoke `kbounce mcp --db ...` keep working.
//
// Cross-product agent parity (per [[cross-product-agent-parity]]):
// these subcommands match the shape of `ibounce mcp install-*` on
// the iam-jit side — same flag names (--path, --force), same path-
// detection logic, same atomic-write pattern, same show-config /
// list-tools output structure. The MCP server entrypoint command +
// tool-name prefix differ (kbounce vs ibounce; kbounce_* vs
// ibounce_*); everything else is the same shape.
func newMCPCmd() *cobra.Command {
	// Shared serve flag values, bound on both the parent (back-compat
	// for `kbounce mcp --db ...`) and the `serve` subcommand.
	var (
		dbPath          string
		profileName     string
		profilesPath    string
		modeStr         string
		defaultPolStr   string
		owner           string
		actor           string
		bulkAnswerToken string
	)

	runServe := func(cmd *cobra.Command, args []string) error {
		mode, err := proxy.ParseMode(modeStr)
		if err != nil {
			return err
		}
		defaultPol, err := proxy.ParseDefaultPolicy(defaultPolStr)
		if err != nil {
			return err
		}
		st, err := store.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer st.Close()

		if profileName == "" {
			profileName = kbenv.Get(envProfileVar)
		}
		resolvedProfilesPath := profilesPath
		if resolvedProfilesPath == "" {
			resolvedProfilesPath, err = profile.DefaultProfilesPath()
			if err != nil {
				return fmt.Errorf("resolve profiles path: %w", err)
			}
		}
		profiles, err := profile.LoadProfiles(resolvedProfilesPath)
		if err != nil {
			return fmt.Errorf("load profiles: %w", err)
		}
		activeProfile, _ := profiles.Active(profileName) // err on unknown; we still want to serve

		srv := mcp.NewServer(mcp.Config{
			Store:           st,
			ActiveProfile:   activeProfile,
			ProfilesPath:    resolvedProfilesPath,
			Mode:            mode,
			DefaultPolicy:   defaultPol,
			TaskOwner:       owner,
			Actor:           actor,
			BulkAnswerToken: bulkAnswerToken,
		})

		fmt.Fprintf(os.Stderr,
			"kbounce mcp serving on stdio (mode=%s, profile=%s, db=%s)\n",
			mode, profileName, st.Path())
		fmt.Fprintln(os.Stderr, "Press Ctrl+D / close stdin to stop.")

		return srv.Serve(os.Stdin, os.Stdout)
	}

	addServeFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&dbPath, "db", "",
			dbFlagHelp+" MUST match the path the running proxy uses for live "+
				"audit-log access via kbounce_tail_decisions.")
		cmd.Flags().StringVar(&profileName, "profile", "",
			"Active environment profile name (mirror of `kbounce run --profile`). "+
				"Surfaced by kbounce_active_profile.")
		cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
			"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml).")
		cmd.Flags().StringVar(&modeStr, "mode", "cooperative",
			"Mode the running proxy is in (cooperative | transparent). "+
				"Returned by kbounce_active_mode.")
		cmd.Flags().StringVar(&defaultPolStr, "default-policy", "deny",
			"Default policy the running proxy is in (allow | deny).")
		cmd.Flags().StringVar(&owner, "owner", "",
			"Task-owner slot. Empty = default-owner slot (single-laptop).")
		cmd.Flags().StringVar(&actor, "actor", "",
			"Actor name recorded in audit rows when MCP-initiated mutations land "+
				"(default: 'kbounce-mcp').")
		cmd.Flags().StringVar(&bulkAnswerToken, "bulk-answer-mcp-token", "",
			"Shared secret that enables the kbounce_prompts_bulk_answer MCP "+
				"tool per [[bulk-prompt-answer-ux]]. Default empty = the bulk-"+
				"answer tool refuses every call (operator-in-loop). Pick a "+
				"strong value once + paste the SAME value into the agent UI's "+
				"tools/auth arguments (args.operator_token) so the agent's "+
				"bulk-answer calls match. Read-only kbounce_prompts_bulk_pending "+
				"is always available regardless.")
	}

	parent := &cobra.Command{
		Use:   "mcp",
		Short: "MCP-over-stdio server + agent-client install helpers",
		Long: `MCP-over-stdio server + install helpers for the common agent
clients (Claude Code, Cursor, Codex).

Subcommands:

  kbounce mcp serve                 start the JSON-RPC stdio server
  kbounce mcp install-claude-code   wire kbounce into Claude Code / Desktop
  kbounce mcp install-cursor        wire kbounce into Cursor
  kbounce mcp install-codex         print Codex TOML snippet (manual install)
  kbounce mcp install-devin         print the Devin (cloud agent) recipe
  kbounce mcp show-config           print the canonical JSON / YAML snippet
  kbounce mcp list-tools            print the kbounce_* tool list

For backward compatibility ` + "`kbounce mcp`" + ` with no subcommand
still starts the server (same as ` + "`kbounce mcp serve`" + `).

The MCP server reads the SAME on-disk state the running proxy uses
(--db + --profiles-path). It does NOT start a proxy listener of its
own — run ` + "`kbounce run`" + ` separately for the gating + forwarding
layer.

stdin/stdout are reserved for the JSON-RPC stream; logs + banner go
to stderr so they don't poison the wire.`,
		Args: cobra.ArbitraryArgs,
		// Back-compat: bare `kbounce mcp` starts the server. cobra will
		// route to subcommands when args[0] matches a known sub.
		RunE: runServe,
	}
	addServeFlags(parent)

	// Canonical `mcp serve` subcommand. install-* commands point at this
	// in the generated MCP config so the config isn't pinned to the
	// back-compat bare-default shape.
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP-over-stdio server (canonical name)",
		Long: `Run the kbounce MCP server on stdin/stdout (canonical name;
` + "`kbounce mcp`" + ` with no subcommand still works for back-compat).

This is the command the install-* subcommands generate config for —
the agent spawns ` + "`kbounce mcp serve`" + ` and speaks JSON-RPC 2.0
on stdin/stdout.`,
		Args: cobra.NoArgs,
		RunE: runServe,
	}
	addServeFlags(serveCmd)
	parent.AddCommand(serveCmd)

	parent.AddCommand(newMCPInstallClaudeCodeCmd())
	parent.AddCommand(newMCPInstallCursorCmd())
	parent.AddCommand(newMCPInstallCodexCmd())
	parent.AddCommand(newMCPInstallDevinCmd())
	parent.AddCommand(newMCPShowConfigCmd())
	parent.AddCommand(newMCPListToolsCmd())
	return parent
}

// newMCPInstallClaudeCodeCmd implements `kbounce mcp install-claude-code`.
func newMCPInstallClaudeCodeCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-claude-code",
		Short: "Install kbounce as an MCP server in Claude Code / Claude Desktop",
		Long: `Add (or update) the ` + "`kbounce`" + ` MCP server entry in your
Claude Code / Claude Desktop MCP config file.

Default config path detection (first that exists wins; otherwise the
first candidate is used as a fresh-install target):

  macOS    ~/Library/Application Support/Claude/claude_desktop_config.json
           ~/.config/claude-code/mcp.json
           ~/.claude.json
  Linux    ~/.config/Claude/claude_desktop_config.json
           ~/.config/claude-code/mcp.json
           ~/.claude.json
  Windows  %APPDATA%/Claude/claude_desktop_config.json
           ~/.claude.json

Override with --path. The merge preserves any OTHER mcpServers
entries; the kbounce entry is REPLACED (not appended) so re-running
is idempotent. --force overrides a malformed-existing-config refusal.

After install, restart your MCP client so it re-reads the config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallClaudeCode(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the auto-detected config path.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing config without prompting. The merge "+
			"never overwrites OTHER mcpServers entries regardless of this flag.")
	return cmd
}

// newMCPInstallCursorCmd implements `kbounce mcp install-cursor`.
func newMCPInstallCursorCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-cursor",
		Short: "Install kbounce as an MCP server in Cursor",
		Long: `Add (or update) the ` + "`kbounce`" + ` MCP server entry in your
Cursor MCP config.

Default config path: ~/.cursor/mcp.json (global). Pass --path to
target a workspace-local .cursor/mcp.json instead.

The merge preserves any OTHER mcpServers entries; the kbounce entry
is REPLACED (not appended) so re-running is idempotent.

After install, restart Cursor so it re-reads the config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallCursor(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the auto-detected config path (default: ~/.cursor/mcp.json).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing config without prompting.")
	return cmd
}

// newMCPInstallCodexCmd implements `kbounce mcp install-codex`.
func newMCPInstallCodexCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-codex",
		Short: "Print the Codex MCP server snippet (manual install)",
		Long: `Codex stores MCP config in TOML (~/.codex/config.toml). To avoid
corrupting unrelated keys in the operator's TOML config, kbounce
refuses to edit the TOML file in place + instead prints a snippet
the operator pastes into their Codex config.

If you maintain a JSON-shaped Codex config elsewhere, pass
--path /full/path/to/file.json — kbounce installs into JSON files
the same way it does for Claude Code / Cursor.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallCodex(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the default Codex config path. Pass a .json path to "+
			"install into a JSON-shaped Codex MCP config; .toml paths "+
			"are not edited in place.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing JSON config without prompting "+
			"(no effect on the TOML manual-snippet path).")
	return cmd
}

// newMCPInstallDevinCmd implements `kbounce mcp install-devin`.
//
// Devin is a cloud-hosted agent (Cognition's sandbox), so there is no
// local config file to write — the command prints the wiring recipe.
// Mirrors ibounce's `ibounce mcp install-devin`
// (per [[cross-product-agent-parity]]). The load-bearing difference
// from the loopback installers: kbounce must be reachable at a HOST
// address, never 127.0.0.1, because the cloud sandbox cannot route to
// the operator's loopback.
func newMCPInstallDevinCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install-devin",
		Short: "Print the Devin (cloud agent) wiring recipe — no local config to write",
		Long: `Devin is a cloud-hosted agent — it runs in Cognition's sandboxed
environment, not on your machine, so there is no local config file
for kbounce to write into. This command prints the two supported
wiring paths instead of editing a config:

  PATH A  MCP server entry in Devin's MCP settings (when Devin's MCP
          support is enabled). Same snippet shape as
          ` + "`kbounce mcp show-config`" + `, stamped with the "devin" agent
          attribution.

  PATH B  Transparent proxy at a HOST address (supported today): run
          kbounce bound off-loopback with TLS and point Devin's
          kubectl/KUBECONFIG at the proxy host:port.

Load-bearing caveat: a kbounce on 127.0.0.1 is NOT visible to Devin's
cloud sandbox — kbounce must be bound to a host the sandbox can reach
over the network.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallDevin(mcpinstall.Options{
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	return cmd
}

// newMCPShowConfigCmd implements `kbounce mcp show-config`.
func newMCPShowConfigCmd() *cobra.Command {
	var shape string
	cmd := &cobra.Command{
		Use:   "show-config",
		Short: "Print the canonical MCP server config snippet",
		Long: `Print the JSON (or YAML, with --shape yaml) snippet for any
custom MCP client. Vendor-neutral — paste into any MCP-compatible
agent's config.

For the common MCP clients, use the install-* subcommands which
detect the right config path + merge into the existing config
preserving other mcpServers entries:

  kbounce mcp install-claude-code
  kbounce mcp install-cursor
  kbounce mcp install-codex

For a cloud-hosted agent (no local config), see:

  kbounce mcp install-devin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcpinstall.ShowConfig(cmd.OutOrStdout(), mcpinstall.Shape(shape))
		},
	}
	cmd.Flags().StringVar(&shape, "shape", string(mcpinstall.ShapeJSON),
		"Output shape: json | yaml.")
	return cmd
}

// newMCPListToolsCmd implements `kbounce mcp list-tools`.
//
// Reads the live tool list from internal/mcp.ToolDescriptors() so the
// output matches what an agent would see via `tools/list`. Useful for
// operators verifying their install worked + for cross-product parity
// audits.
func newMCPListToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-tools",
		Short: "Print the kbounce_* MCP tool list (name + 1-line summary)",
		Long: `Print the tool descriptors served by the kbounce MCP server
as a 2-column table (name + 1-line summary).

The list is the same one ` + "`tools/list`" + ` returns to an agent client,
so an operator who ran ` + "`kbounce mcp install-claude-code`" + ` can
verify their install worked without restarting their agent.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			descriptors := mcp.ToolDescriptors()
			entries := make([]mcpinstall.ToolListEntry, 0, len(descriptors))
			for _, d := range descriptors {
				name, _ := d["name"].(string)
				desc, _ := d["description"].(string)
				entries = append(entries, mcpinstall.ToolListEntry{
					Name:        name,
					Description: desc,
				})
			}
			return mcpinstall.FormatToolList(cmd.OutOrStdout(), entries)
		},
	}
	return cmd
}

// ensure unused imports stay used. zerolog is imported in case a future
// command needs structured logging without going through the proxy
// package; remove if/when unused.
var _ = zerolog.GlobalLevel
