// Command kbouncer is the local Kubernetes API-call gating proxy.
//
// Run it as a sidecar to kubectl / Helm / a coding agent that points at
// it instead of the real kube-apiserver; kbouncer parses each call,
// matches it against gating rules, records the decision, and (from
// K-Slice 2 forward) either forwards to the real apiserver or returns
// 403 to the client.
//
// K-Slice 1 (this build) ships the foundation: HTTP server + URL
// parser + audit store + CLI. No upstream forwarding yet. Useful as
// a pure observability tool to see exactly what kubectl is asking your
// cluster to do.
package main

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

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/proxy"
	"github.com/trsreagan3/kbouncer/internal/store"
	"github.com/trsreagan3/kbouncer/internal/tlsmat"
	"github.com/trsreagan3/kbouncer/internal/upstream"
)

// loopbackHosts mirrors iam-jit-bouncer's CRIT-32-02 closure: kbouncer
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
// subcommand's flag help text.
const envProfileVar = "KBOUNCER_PROFILE"

// version is overridden at build time via -ldflags "-X main.version=..."
// for release builds. Unstamped builds report "dev".
var version = "dev"

func main() {
	proxy.EnsureLogger()
	if err := newRootCmd().Execute(); err != nil {
		// cobra already prints to stderr; exit 1 so shell scripts can
		// distinguish success.
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "kbouncer",
		Short:         "Local Kubernetes API-call gating proxy",
		Long:          rootLongHelp,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newRunCmd())
	root.AddCommand(newProfileCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newPauseCmd())
	root.AddCommand(newPromptsCmd())
	root.AddCommand(newRulesCmd())
	root.AddCommand(newTasksCmd())
	root.AddCommand(newInitTLSCmd())
	return root
}

const rootLongHelp = `kbouncer is a local proxy that sits between your kubectl / Helm /
coding agent and the real kube-apiserver. It parses every request,
records the decision in an audit log, and (in transparent mode) can
deny calls that don't match its rule set.

Two operating modes (the same shape as iam-jit-bouncer):

  cooperative   parse + log every call, but always forward (advisory)
  transparent   DENY verdicts return 403 to the client; ALLOW verdicts
                forward unchanged

K-Slice 1 (current build) ships the foundation: parser, audit store,
HTTP server, CLI. Upstream forwarding lands in K-Slice 2.`

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
		Long: `Start the kbouncer HTTP proxy.

The server binds to 127.0.0.1:8766 by default (local-only — kbouncer
is a credential-handling surface and must NEVER bind externally
without explicit operator opt-in).

Point your kubectl / Helm / agent at it:
  export HTTPS_PROXY=http://127.0.0.1:8766     (when K-Slice 2 lands)
or for K-Slice 1's observation-only mode, use curl / httpie to feed
fake requests and inspect the proxy's parsed verdicts.

Ctrl+C exits cleanly (graceful shutdown).`,
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
			// kbouncer holds inbound client bearer tokens long enough to
			// forward them; an externally-bound listener exposes that
			// surface to anyone on the network.
			if _, ok := loopbackHosts[host]; !ok && !forceExternalBind {
				fmt.Fprintf(os.Stderr,
					"refusing to bind to %q: this exposes kbouncer's "+
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

			// K-Slice 2: resolve the upstream kube-apiserver target.
			// Best-effort — failure to resolve is logged + the proxy
			// starts in K-Slice 1 observation-only mode (the JSON-body
			// fallback). Preserves the "useful as a pure observability
			// tool" boot path for operators with no kubeconfig + lets
			// the proxy come up even when the apiserver is briefly
			// unreachable. Operators who want a hard fail can grep the
			// startup line for "observation-only".
			upOpts := upstream.Options{
				UpstreamURL:           upstreamURL,
				KubeconfigPath:        kubeconfigPath,
				InsecureSkipTLSVerify: insecureSkipVerify,
				ForwardTimeout:        time.Duration(forwardTimeoutSecs) * time.Second,
			}
			up, upErr := upstream.Resolve(upOpts)
			if upErr != nil {
				log.Warn().Err(upErr).
					Msg("kbouncer: no upstream resolved; running in K-Slice 1 observation-only mode (no forwarding)")
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
					Msg("kbouncer: could not write default profiles.yaml; using embedded defaults")
			} else if written {
				fmt.Fprintf(os.Stderr,
					"kbouncer: wrote default profiles to %s\n", resolvedProfilesPath)
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
					"kbouncer: --tls-cert and --tls-key must both be set or both " +
						"omitted (got cert=%q key=%q)", tlsCertPath, tlsKeyPath)
			}
			if requireClientCert != "" && tlsCertPath == "" {
				return fmt.Errorf(
					"kbouncer: --require-client-cert requires --tls-cert + --tls-key " +
						"(mTLS without TLS is meaningless); run `kbouncer init-tls` first")
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
			// clean for tools that might pipe kbouncer's output.
			scheme := "http"
			if cfg.TLSCertPath != "" {
				scheme = "https"
			}
			fmt.Fprintf(os.Stderr,
				"kbouncer proxy starting on %s://%s:%d (mode=%s, default-policy=%s, profile=%s)\n",
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
				fmt.Fprintln(os.Stderr,
					"upstream: <none> — running in K-Slice 1 observation-only mode")
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
				log.Info().Msg("kbouncer received shutdown signal")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := s.Shutdown(shutdownCtx); err != nil {
					return fmt.Errorf("shutdown: %w", err)
				}
				// Wait for Serve to return so we don't leak the goroutine.
				if err := <-serveErr; err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "kbouncer stopped.")
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
			"to anything else exposes kbouncer's credential-handling "+
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
		"Active environment profile (e.g. staging-work, prod-readonly, "+
			"sandbox, incident-response, none). Falls back to "+
			envProfileVar+" env var; defaults to 'none' if neither is set. "+
			"Profile denies are a hard floor — a permissive task scope "+
			"CANNOT override them. See `kbouncer profile list`.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.kbouncer/profiles.yaml). "+
			"Honors KBOUNCER_PROFILES_PATH env var if --profiles-path unset.")
	cmd.Flags().StringVar(&cluster, "cluster", "",
		"Kubeconfig cluster name surfaced to profile evaluation for "+
			"only_clusters and the 'cluster' keyword target. K-Slice 7 "+
			"requires explicit pass-through; auto-detection from kubeconfig "+
			"ships in K-Slice 8.")
	cmd.Flags().BoolVar(&promptOnDeny, "prompt-on-deny", false,
		"#5 async deny-prompt UX: when set, every transparent-mode "+
			"DENY also writes a pending_prompts row so the operator can "+
			"later answer (always-allow / add-to-profile / ignore) via "+
			"`kbouncer prompts answer`. The agent is still denied "+
			"immediately; the answer takes effect on the NEXT call of "+
			"the same shape. Defaults off — opt-in to avoid noisy queues.")

	// K-Slice 2 forwarding flags.
	cmd.Flags().StringVar(&upstreamURL, "upstream", "",
		"Kube-apiserver URL to forward ALLOW verdicts to. When unset, "+
			"the apiserver is resolved from the kubeconfig (see --kubeconfig). "+
			"This URL is the OUTBOUND ALLOWLIST: kbouncer refuses to forward "+
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
			"apiserver. Watch / long-poll requests bypass this in K-Slice 5; "+
			"short-lived REST calls use it.")
	cmd.Flags().BoolVar(&forceExternalBind, "i-know-this-binds-externally", false,
		"Required acknowledgement when --host is anything other than "+
			"127.0.0.1 / ::1 / localhost. Binding the proxy externally "+
			"exposes inbound client bearer tokens + the forwarding "+
			"surface to the network. Don't pass this unless you have a "+
			"specific reason (test VM, network-segmented dev box).")

	// K-Slice 4 — inbound TLS listener.
	cmd.Flags().StringVar(&tlsCertPath, "tls-cert", "",
		"Path to the server certificate (PEM) for the inbound HTTPS "+
			"listener. Pair with --tls-key. When both are set, kbouncer "+
			"listens on HTTPS instead of plain HTTP — recommended for "+
			"kubectl + agent clients that expect HTTPS. Generate with "+
			"`kbouncer init-tls`.")
	cmd.Flags().StringVar(&tlsKeyPath, "tls-key", "",
		"Path to the server private key (PEM) for the inbound HTTPS "+
			"listener. Pair with --tls-cert.")
	cmd.Flags().StringVar(&requireClientCert, "require-client-cert", "",
		"Path to a CA bundle (PEM). When set, inbound TLS clients MUST "+
			"present a client certificate signed by this bundle. "+
			"Locks the proxy down to 'only my kubectl context can "+
			"connect'. Requires --tls-cert + --tls-key. Operator-supplied "+
			"CA — kbouncer does NOT issue client certs.")
	return cmd
}

// newInitTLSCmd implements `kbouncer init-tls`. One-time setup that
// generates a CA + server cert into ~/.kbouncer/tls/ so the operator
// can add the CA to their kubectl context's certificate-authority
// field and run `kbouncer run --tls-cert ... --tls-key ...` afterward.
func newInitTLSCmd() *cobra.Command {
	var (
		dir            string
		force          bool
		additionalSANs []string
	)
	cmd := &cobra.Command{
		Use:   "init-tls",
		Short: "Generate a local CA + server cert for the inbound HTTPS listener",
		Long: `Generate the TLS material kbouncer's inbound listener uses to
speak HTTPS to kubectl / Helm / a coding agent.

One-time setup. Writes four files into ~/.kbouncer/tls/ (or --dir):

  ca.key      local CA private key (mode 0400 — operator-only read)
  ca.crt      local CA certificate (add to kubectl context's
              certificate-authority field)
  server.key  server private key (mode 0400)
  server.crt  server cert, signed by ca.crt; SAN includes
              127.0.0.1, ::1, localhost

Then run:

  kbouncer run \
    --tls-cert ~/.kbouncer/tls/server.crt \
    --tls-key  ~/.kbouncer/tls/server.key

And in your kubeconfig, point the cluster's server at
https://127.0.0.1:8766 and set certificate-authority to
~/.kbouncer/tls/ca.crt.

Without --force, init-tls refuses to overwrite existing files
(surprise key rotation invalidates any kubectl context that pinned
the prior CA).`,
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
			fmt.Fprintf(w, "       kbouncer run --tls-cert %s --tls-key %s\n",
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

// newProfileCmd implements `kbouncer profile ...` subcommands. K-Slice 7
// ships `list` only; later slices may add `show`, `validate`, and
// `set-default`.
func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage kbouncer environment profiles",
		Long: `kbouncer environment profiles add an environment-aware deny
layer that fires BEFORE per-task scopes and global rules. A profile
deny is a hard floor — a permissive task scope cannot override it.

Use ` + "`kbouncer profile list`" + ` to see the available profiles and
which one would be active given the current --profile flag /
` + envProfileVar + ` env var.`,
	}
	cmd.AddCommand(newProfileListCmd())
	cmd.AddCommand(newProfileInstallCmd())
	return cmd
}

// newProfileInstallCmd implements `kbouncer profile install --from URL`.
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

  kbouncer profile install --from https://internal.example/profiles.yaml

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
				"  kbouncer run --profile %s\n", result.InstalledNames[0])
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
				"kbouncer profiles (source: %s)\n", source)
			if profileName != "" && active == nil {
				fmt.Fprintf(cmd.OutOrStdout(),
					"WARNING: requested profile %q is not in this file. "+
						"`kbouncer run` would refuse to start.\n", profileName)
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

// newAuditCmd implements `kbouncer audit ...`. K-Slice 1 ships `tail`
// only — the highest-leverage operator workflow ("show me what just
// happened on the proxy"). Later slices may add `search`, `export`,
// and `diff` against a prior known-good baseline.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the kbouncer decision audit log",
		Long: `kbouncer records every evaluated request in a local SQLite
audit log at ~/.kbouncer/state.db. ` + "`kbouncer audit tail`" + ` is the
fastest way to see what kubectl / Helm / an agent just sent through
the proxy and what verdict each call got.`,
	}
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
		RunE: func(cmd *cobra.Command, args []string) error {
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
