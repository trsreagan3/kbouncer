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
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/proxy"
	"github.com/trsreagan3/kbouncer/internal/store"
)

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
		port          int
		host          string
		modeStr       string
		defaultPolStr string
		dbPath        string
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

			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			cfg := proxy.Config{
				Host:          host,
				Port:          port,
				Mode:          mode,
				DefaultPolicy: defaultPol,
			}.Normalize()

			s := proxy.NewServer(cfg, st)

			// Print a friendly startup banner to stderr so stdout stays
			// clean for tools that might pipe kbouncer's output.
			fmt.Fprintf(os.Stderr,
				"kbouncer proxy starting on http://%s:%d (mode=%s, default-policy=%s)\n",
				cfg.Host, cfg.Port, cfg.Mode, cfg.DefaultPolicy)
			fmt.Fprintf(os.Stderr, "audit db: %s\n", st.Path())
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
	return cmd
}
