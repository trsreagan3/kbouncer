// `kbounce audit-export health` — explicit operator-facing check for
// the running kbounce proxy's audit-export channel health.
//
// Per [[audit-export-failure-visibility]]: an operator who wants to
// wire kbounce health into a shell pipeline / cron monitor / a CI
// post-deploy check needs a non-zero exit when the channel is
// degraded. /healthz already returns 503 on the same predicate, but
// piping `curl -fsS .../healthz` into a script is fiddly (TLS
// material, certificate trust, the bouncer's mTLS listener may
// require a client cert); a first-class CLI subcommand that does the
// HTTP + parse + exit-code wiring is the cleanest operator UX.
//
// Exits 0 when audit-export is healthy; exits 1 with a one-line
// reason on stderr when degraded; exits 2 on transport / parse
// errors (the running proxy could not be reached or returned a body
// the command could not interpret).
//
// Cross-product parity per [[cross-product-agent-parity]]: ibounce
// (Python) + dbounce ship the same subcommand with the same exit-
// code shape so an operator who knows one knows them all.
package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// auditExportHealthTimeout caps the outbound /healthz GET. 5s
// matches the version-check sibling + is well above a healthy local
// proxy's response time.
const auditExportHealthTimeout = 5 * time.Second

// auditExportHealthTransport is overridden in tests to a mock
// http.RoundTripper so the test suite never hits a real socket.
// nil → http.DefaultTransport (production path).
var auditExportHealthTransport http.RoundTripper

// newAuditExportCmd implements the `kbounce audit-export` subcommand
// group. Ships `health` only — explicit operator-facing
// health-check that exits non-zero when degraded. See package-doc
// for the exit-code shape.
func newAuditExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-export",
		Short: "Inspect audit-export channel health on a running kbounce proxy",
		Long: `Group for audit-export operator-facing tools. Subcommands:

  health   Hit the running proxy's /healthz endpoint and exit non-zero
           when the audit-export channel is degraded (writes_ok=false,
           consecutive_failures > 3, or no successful write in the last
           5 minutes — per [[audit-export-failure-visibility]]).

Cross-product parity: ` + "`ibounce audit-export health`" + ` +
` + "`dbounce audit-export health`" + ` ship the same exit-code shape.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("audit-export", cmd)
	cmd.AddCommand(newAuditExportHealthCmd())
	return cmd
}

// newAuditExportHealthCmd implements `kbounce audit-export health`.
// Exits 0 when audit-export is healthy, 1 when degraded, 2 on
// transport / parse errors.
func newAuditExportHealthCmd() *cobra.Command {
	var (
		url      string
		insecure bool
	)
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check audit-export health on a running kbounce proxy (exit 1 when degraded)",
		Long: `Hit the running kbounce proxy's /healthz endpoint and report
audit-export channel health. Exits:

  0   audit-export is healthy (writes_ok=true, consecutive_failures
      below threshold, last successful write within the 5-minute
      window, heartbeat watchdog reports live)
  1   audit-export is degraded — degradation reason printed to stderr
  2   transport or parse error — the running proxy could not be
      reached, or returned a body the command could not interpret

The check honors the same predicate as /healthz HTTP status code +
the audit_export_degraded alert rule (per [[audit-export-failure-
visibility]]) so an operator who sees a 1 here can expect the SAME
state to be visible in the SIEM via the alert event.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runAuditExportHealth(cmd.Context(), url, insecure,
				cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				// Honor the typed exit code so a shell-script wrapper
				// can distinguish "degraded" (1) from "transport / parse
				// failure" (2). cobra's default RunE-error path would
				// always exit 1, so we exit ourselves; the error
				// message has already been printed to stderr inside
				// runAuditExportHealth.
				var aehe *auditExportHealthError
				if errors.As(err, &aehe) {
					os.Exit(aehe.exitCode)
				}
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&url, "url", "http://127.0.0.1:8766/healthz",
		"URL of the running kbounce proxy's /healthz endpoint. Default "+
			"matches the loopback bind on the standard port. Override when "+
			"running with --tls-cert / a non-default --port / a non-loopback "+
			"--host.")
	cmd.Flags().BoolVar(&insecure, "insecure-skip-verify", false,
		"Skip TLS verification when --url is https://. Useful when the "+
			"running proxy uses a CA the operator hasn't installed locally "+
			"(self-signed dev cert from `kbounce init-tls`). NEVER use in "+
			"production — defeats the TLS gate.")
	return cmd
}

// auditExportHealthExitCode is the typed exit-code surface so the
// CLI's RunE can return a special error that the main loop honors.
// Cobra's main path turns any non-nil RunE return into exit-1, which
// is fine for the degraded path; we need a distinct exit-2 for
// transport errors so a shell script can tell "kbounce is fine but
// audit-export is degraded" apart from "kbounce isn't running".
type auditExportHealthError struct {
	exitCode int
	msg      string
}

func (e *auditExportHealthError) Error() string { return e.msg }

// ExitCode implements the optional cobra error.ExitCode interface so
// `kbounce audit-export health` exits with the right code without
// requiring the caller to wrap os.Exit themselves.
func (e *auditExportHealthError) ExitCode() int { return e.exitCode }

// runAuditExportHealth is the testable entry point. Returns nil on
// the healthy path; a *auditExportHealthError with ExitCode 1 on the
// degraded path; a *auditExportHealthError with ExitCode 2 on
// transport / parse errors.
func runAuditExportHealth(ctx context.Context, url string, insecure bool,
	stdout, stderr io.Writer) error {
	transport := auditExportHealthTransport
	if transport == nil && insecure {
		// Build a fresh transport with TLS verification disabled so
		// the dev-cert path works without the operator installing the
		// CA locally. Production / cron paths should leave the flag
		// unset.
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // user opted in via --insecure-skip-verify
		}
	}
	client := &http.Client{
		Timeout:   auditExportHealthTimeout,
		Transport: transport,
	}
	reqCtx, cancel := context.WithTimeout(ctx, auditExportHealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintf(stderr, "audit-export health: build request: %v\n", err)
		return &auditExportHealthError{exitCode: 2, msg: "build request"}
	}
	req.Header.Set("User-Agent", "kbounce-audit-export-health/"+version)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr,
			"audit-export health: could not reach %s: %v "+
				"(is kbounce running? try `--url http://127.0.0.1:<port>/healthz`)\n",
			url, err)
		return &auditExportHealthError{exitCode: 2, msg: "transport error"}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) // 64 KiB cap
	if err != nil {
		fmt.Fprintf(stderr, "audit-export health: read response body: %v\n", err)
		return &auditExportHealthError{exitCode: 2, msg: "read body"}
	}
	var payload struct {
		Status                    string `json:"status"`
		AuditExportHealthy        bool   `json:"audit_export_healthy"`
		AuditExportDegradedReason string `json:"audit_export_degraded_reason"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		fmt.Fprintf(stderr,
			"audit-export health: parse /healthz JSON: %v (body=%q)\n",
			err, truncateForError(string(body), 200))
		return &auditExportHealthError{exitCode: 2, msg: "parse response"}
	}
	if resp.StatusCode == http.StatusServiceUnavailable || !payload.AuditExportHealthy {
		// Degraded path. Print the reason to stderr so a shell script
		// can capture it cleanly + exit 1. Per the memo, the same
		// reason string appears in the audit_export_degraded alert
		// event so the SIEM-side correlation is byte-identical.
		reason := payload.AuditExportDegradedReason
		if reason == "" {
			reason = "(no reason surfaced by /healthz; check the proxy's stderr)"
		}
		fmt.Fprintf(stderr, "audit-export health: DEGRADED (%s)\n", reason)
		return &auditExportHealthError{exitCode: 1, msg: "degraded"}
	}
	fmt.Fprintln(stdout, "audit-export health: OK")
	return nil
}

// truncateForError clamps a long error-context string so a 50KB JSON
// body doesn't drown the terminal on a parse-failure log line.
func truncateForError(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}
