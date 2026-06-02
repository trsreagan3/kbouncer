// admin_action.go wires the one-shot admin-action emit helper used by
// every `kbounce` subcommand that mutates kbounce's config (pause,
// rules, presets, profile install / delete, future license install /
// alert-rule edit / profile assign / config import / export).
//
// Per [[basic-app-hygiene-features]] TIER 1 + [[security-team-audit-
// export]]: until this slice landed, ONLY proxy DECISIONS rode the
// OCSF audit-export channel. Config changes were silent — security
// teams couldn't answer "who installed this profile? who paused the
// bouncer?" The admin-action event closes that gap.
//
// Wiring model: one-shot CLI subcommands don't have a long-running
// audit Manager; the run-daemon path does. To let an admin-action
// event reach the SAME JSONL log file the proxy writes to, every
// admin-action subcommand accepts a --audit-log-path flag (default
// empty / KBOUNCER_AUDIT_LOG_PATH env-var fallback). When set, the
// CLI opens a one-shot LogWriter, emits the admin-action event,
// Close()s the writer (which flushes), and exits. Token-leak invariant
// per [[security-team-audit-export]]: the LogWriter writes the OCSF
// wire shape verbatim, and admin_action.go in the audit package
// already strips license_content / license_bytes / etc. before the
// event is built.
//
// Webhook gating: the one-shot path does NOT wire the HTTPS webhook
// pusher (the proxy daemon owns the webhook channel — admin-action
// events from the CLI land in the JSONL log, which an operator-side
// log-shipper / vector / fluent-bit forwards onward). Keeps the CLI
// invocation latency to disk-write only.
package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/kbenv"
)

// envAdminAuditLogPath is the env-var fallback for --audit-log-path on
// admin-action subcommands. Lets operators export the path once in
// their shell rc + every subcommand picks it up without re-typing.
// Mirrors the KBOUNCER_PROFILE / KBOUNCER_DB env pattern other
// subcommands already use.
const envAdminAuditLogPath = "KBOUNCER_AUDIT_LOG_PATH"

// addAdminAuditFlag registers --audit-log-path on a cobra subcommand
// + binds it to the passed pointer. Common helper so every admin-
// action subcommand (pause, rules, presets apply, profile install /
// delete, ...) uses the same flag name + help text.
func addAdminAuditFlag(cmd *cobra.Command, dst *string) {
	cmd.Flags().StringVar(dst, "audit-log-path", "",
		"Append the admin-action OCSF event to this JSONL audit log. "+
			"Honors "+envAdminAuditLogPath+" if unset. When empty, the "+
			"admin action is performed but NOT recorded in the audit-"+
			"export channel (the SQLite store still carries the underlying "+
			"change). For security-team visibility, point this at the same "+
			"file the proxy daemon's --audit-log-path uses so all events "+
			"land in one stream.")
}

// emitAdminAction is the one-shot helper every admin-action subcommand
// calls AFTER the underlying mutation succeeds. Resolves the audit-log
// path (flag, then env), opens a one-shot LogWriter, emits the OCSF
// event, and closes the writer. All errors are non-fatal — the
// underlying admin action already succeeded, and a failure to record
// the audit event should not surface to the operator as if the action
// failed. We DO print a one-line stderr warning so the operator knows
// the audit channel didn't carry the event.
//
// When no audit-log path is configured (neither flag nor env set), the
// function is a no-op — the operator who didn't wire the audit channel
// gets the historical behavior.
//
// Per [[deliberate-feature-completion]]: ships now even though the
// hosted-control-plane / MCP-tool paths are post-launch. The CLI
// subcommand wire-up is the load-bearing piece for self-hosted users.
func emitAdminAction(cmd *cobra.Command, auditLogPathFlag string, in audit.AdminActionInput) {
	path := auditLogPathFlag
	if path == "" {
		path = kbenv.Get(envAdminAuditLogPath)
	}
	if path == "" {
		return
	}
	ctx := context.Background()
	lw, err := audit.NewLogWriter(ctx, audit.LogWriterOptions{
		Path:  path,
		Fsync: true,
	})
	if err != nil {
		// Non-fatal: the admin action succeeded; a stderr warning is
		// enough so the operator notices the audit channel didn't
		// record this event.
		cmd.PrintErrf("kbounce: warn: open audit-log %q failed: %v "+
			"(admin action completed; event NOT recorded)\n", path, err)
		return
	}
	defer lw.Close()
	mgr := audit.NewManager(audit.ManagerOptions{LogWriter: lw})
	audit.EmitAdminAction(ctx, mgr, in)
}
