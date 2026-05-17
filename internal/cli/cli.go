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
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/mcp"
	"github.com/trsreagan3/kbouncer/internal/mcpinstall"
	"github.com/trsreagan3/kbouncer/internal/profile"
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
	"127.0.0.1":      {},
	"::1":            {},
	"localhost":      {},
	"ip6-localhost":  {},
	"ip6-loopback":   {},
}

// envProfileVar is the env-var name used to select the active profile
// when --profile is not passed. Documented in the README + on the run
// subcommand's flag help text. The KBOUNCER_ prefix is preserved
// (rather than KBOUNCE_) so existing shell configs keep working; see
// [[bounce-suite-rename]] decision #6.
const envProfileVar = "KBOUNCER_PROFILE"

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
	root.AddCommand(newPauseCmd())
	root.AddCommand(newPromptsCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newTasksCmd())
	root.AddCommand(newPresetsCmd())
	root.AddCommand(newInitTLSCmd())
	root.AddCommand(newMCPCmd())
	root.AddCommand(newVersionCheckCmd())
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
		upstreamURL        string
		kubeconfigPath     string
		insecureSkipVerify bool
		forceExternalBind  bool
		forwardTimeoutSecs int
		tlsCertPath        string
		tlsKeyPath         string
		requireClientCert  string
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
			mode, err := proxy.ParseMode(modeStr)
			if err != nil {
				return err
			}
			defaultPol, err := proxy.ParseDefaultPolicy(defaultPolStr)
			if err != nil {
				return err
			}

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
				ForwardTimeout:        time.Duration(forwardTimeoutSecs) * time.Second,
			}
			up, upErr := upstream.Resolve(upOpts)
			if upErr != nil {
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
				profileName = os.Getenv(envProfileVar)
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
					"kbounce: --tls-cert and --tls-key must both be set or both " +
						"omitted (got cert=%q key=%q)", tlsCertPath, tlsKeyPath)
			}
			if requireClientCert != "" && tlsCertPath == "" {
				return fmt.Errorf(
					"kbounce: --require-client-cert requires --tls-cert + --tls-key " +
						"(mTLS without TLS is meaningless); run `kbounce init-tls` first")
			}

			cfg := proxy.Config{
				Host:                    host,
				Port:                    port,
				Mode:                    mode,
				DefaultPolicy:           defaultPol,
				ActiveProfile:           activeProfile,
				Cluster:                 cluster,
				PromptOnDeny:            promptOnDeny,
				Upstream:                up,
				TLSCertPath:             tlsCertPath,
				TLSKeyPath:              tlsKeyPath,
				RequireClientCertCAPath: requireClientCert,
			}.Normalize()

			s := proxy.NewServer(cfg, st)

			// Print a friendly startup banner to stderr so stdout stays
			// clean for tools that might pipe kbounce's output.
			scheme := "http"
			if cfg.TLSCertPath != "" {
				scheme = "https"
			}
			fmt.Fprintf(os.Stderr,
				"kbounce proxy starting on %s://%s:%d (mode=%s, default-policy=%s, profile=%s)\n",
				scheme, cfg.Host, cfg.Port, cfg.Mode, cfg.DefaultPolicy, activeProfile.Name)
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
			// Default-profile guidance banner per [[bounce-default-profile-pattern]]:
			// when the operator didn't explicitly opt into a profile,
			// print a one-line reminder that they're in passthrough mode
			// + the two ways to opt into readonly.
			if !profileFromFlag && os.Getenv(envProfileVar) == "" {
				fmt.Fprintln(os.Stderr,
					"profile: no profile selected; calls forwarded as-is + audit-logged. "+
						"To block write/destructive verbs + privilege primitives, "+
						"run with --profile safe-default OR "+
						"`export KBOUNCER_PROFILE=safe-default` in your shell rc.")
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
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
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
			"the same shape. Defaults off — opt-in to avoid noisy queues.")

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
	return cmd
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
	)
	cmd := &cobra.Command{
		Use:   "install --from URL [--sha256 HEX] [--force] [--timeout 10]",
		Short: "Fetch + install profiles from an HTTPS URL",
		Long: `Fetch a profiles.yaml fragment from an HTTPS URL and install
the profiles it contains. Composes with the enterprise-profile-
distribution onboarding pattern: IT teams publish curated profiles
at an internal URL, and engineers install them on day 1.

  kbounce profile install --from https://internal.example/profiles.yaml

The fetched URL becomes the ` + "`source`" + ` of each installed profile.
Profiles with a non-local source are READ-ONLY at the CLI surface —
engineers cannot edit them to bypass org guardrails (the canonical
write entry point, UpsertProfile, refuses to overwrite them).

HTTPS-only: http:// URLs are refused because plaintext distribution
is MITM-substitutable. IT teams should ALSO pin --sha256 in their
onboarding docs to defend against a compromised distribution server.

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
			fmt.Fprintf(cmd.OutOrStdout(), "fetching %s ...\n", fromURL)
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
				profileName = os.Getenv(envProfileVar)
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
// on the proxy"). Later may add `search`, `export`, and `diff`
// against a prior known-good baseline.
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

func newAuditTailCmd() *cobra.Command {
	var (
		limit  int
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent N decisions (newest first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// UAT-K2 HIGH-K2-03: validate --limit range at parse time.
			// `--limit 0` silently no-op'd before; `--limit 2000` was
			// accepted (but the store clamps at 1000 internally). Reject
			// both with a clear message so operators understand the bound.
			if limit < 1 || limit > 1000 {
				return fmt.Errorf("--limit must be in 1-1000 (got %d)", limit)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rows, err := st.RecentDecisions(limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no decisions recorded yet)")
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-9s  %s\n",
				"AT (UTC)", "MODE", "VERDICT", "SOURCE", "REQUEST")
			for _, r := range rows {
				at := r.At.UTC().Format("2006-01-02 15:04:05")
				src := r.DecisionSource
				if src == "" {
					src = "-"
				}
				req := r.Method + " " + r.Path
				if len(req) > 60 {
					req = req[:57] + "..."
				}
				fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-9s  %s\n",
					at, r.ModeAtDecision, r.DecisionVerdict, src, req)
				if r.DecisionReason != "" {
					reason := r.DecisionReason
					if len(reason) > 80 {
						reason = reason[:77] + "..."
					}
					fmt.Fprintf(w, "%48s  %s\n", "↳", reason)
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50,
		"Max rows to return (1-1000). Default 50.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env).")
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
		dbPath        string
		profileName   string
		profilesPath  string
		modeStr       string
		defaultPolStr string
		owner         string
		actor         string
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
			profileName = os.Getenv(envProfileVar)
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
			Store:         st,
			ActiveProfile: activeProfile,
			ProfilesPath:  resolvedProfilesPath,
			Mode:          mode,
			DefaultPolicy: defaultPol,
			TaskOwner:     owner,
			Actor:         actor,
		})

		fmt.Fprintf(os.Stderr,
			"kbounce mcp serving on stdio (mode=%s, profile=%s, db=%s)\n",
			mode, profileName, st.Path())
		fmt.Fprintln(os.Stderr, "Press Ctrl+D / close stdin to stop.")

		return srv.Serve(os.Stdin, os.Stdout)
	}

	addServeFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&dbPath, "db", "",
			"SQLite DB path (default: ~/.kbouncer/state.db, or KBOUNCER_DB env). "+
				"MUST match the path the running proxy uses for live audit-log "+
				"access via kbounce_tail_decisions.")
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
  kbounce mcp install-codex`,
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
