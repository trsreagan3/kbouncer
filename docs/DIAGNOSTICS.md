# kbounce diagnostics bundle

`kbounce diagnostics bundle` (alias: `kbounce diag bundle`) produces a
single redacted ZIP containing everything a support engineer — or you
yourself, or a Claude agent acting on your behalf — needs to debug a
kbounce deployment WITHOUT shipping any secrets.

```
kbounce diagnostics bundle [--out PATH] [--include-audit-tail N] [--no-audit]
kbounce diag bundle ...    # same; short alias
```

## What's in the bundle

The output is a ZIP with one file per section, numerically prefixed so
`unzip -l` shows them in read order:

| Entry                        | Contents                                                                   |
|------------------------------|----------------------------------------------------------------------------|
| `00-README.txt`              | Top-level explainer + the redaction policy in this bundle.                 |
| `01-version.txt`             | `kbounce version --verbose` output + Go runtime metadata.                  |
| `02-config-redacted.json`    | Byte-identical to `kbounce config export --redact-secrets`.                |
| `03-active-profile.json`     | Profiles path + sha256 + the `KBOUNCER_PROFILE` env value (if set).        |
| `04-audit-tail.jsonl`        | Last N audit events (default 200), with user identifiers stably hashed.    |
| `05-healthz.json`            | Output of a local `/healthz` GET, OR `{"health":"unreachable", ...}`.      |
| `06-system.txt`              | OS / arch / Go / `uname -a` (hostname scrubbed) / `kubectl version --client`. |
| `07-listener.json`           | Bind ports + the configured `--healthz-url`. Never remote addresses.       |
| `08-panics.txt`              | Optional `--panic-log` file contents, scrubbed of URLs / tokens / IPs.     |
| `09-manifest.json`           | File list + sha256 of every other entry + the bundle's schema version.    |

## What gets redacted

- **Audit-webhook tokens** and license bytes are replaced with
  `***REDACTED***` (same sentinel as `kbounce config export
  --redact-secrets` — there is exactly one redactor pipeline).
- **Webhook URLs** in `02-config-redacted.json` and inside any audit
  event field whose key ends in `_url` (or equals `url` / `endpoint` /
  `webhook_url`) are replaced with `***REDACTED***`. The URL is the
  destination, which is itself sensitive (it identifies an operator's
  SIEM endpoint).
- **User identifiers** in audit events (`name`, `user_name`,
  `username`, `uid`, `user_uid`, `sub`, `email`) are replaced with a
  stable `user-XXXX` hash. Two events for the same actor produce the
  same hash so cross-event correlation survives the redaction, but
  the original identity does not leak.
- **Any field whose key contains** `token`, `secret`, `api_key`,
  `password`, `bearer`, `authorization`, or `private_key` is masked
  regardless of value type.
- **Hostnames** in `uname -a` output are replaced with
  `<hostname-redacted>`.
- **Environment variable values** are NEVER included. Only the KEYS
  of `KBOUNCER_*` / `KBOUNCE_*` / `KUBE*` env vars appear in
  `06-system.txt`.
- **IPs** and token-shaped strings inside freeform text fields (e.g.
  the panic log) are scrubbed via regex pass.

If you're unsure whether a field would leak, the bundle errs toward
redaction.

## When to use it

- **Debugging a hang or weird denial.** Capture a bundle while the
  proxy is wedged + share with whoever you're asking for help.
- **Sharing with support.** Email / upload the ZIP — there are no
  tokens, no URLs, no IPs, no usernames inside.
- **Sharing with a Claude agent** (per the [investigate-with-claude]
  pattern). Paste the bundle contents into a long-context prompt;
  the agent has everything it needs to reason about the deployment
  WITHOUT you having to manually scrub.

## The `--no-audit` flag

By default the bundle ships the last 200 audit-log lines (with user
identifiers hashed). Pass `--no-audit` to suppress the audit-tail
section entirely. Use this when:

- Regulated environment policy prohibits any audit-log content from
  leaving the host, even after pseudonymization.
- You are debugging something that does NOT need decision history
  (e.g. a startup configuration problem) and want a leaner bundle.

The bundle still produces all other sections — only
`04-audit-tail.jsonl` is empty (with an explanatory annotation
inside).

## Common flags

| Flag                     | Default                                       | Purpose                                                        |
|--------------------------|-----------------------------------------------|----------------------------------------------------------------|
| `--out PATH`             | `./kbounce-diagnostics-{ISO8601-UTC}.zip`     | Override output path. Parent dirs created `0o700`; file `0o600`. |
| `--include-audit-tail N` | `200`                                         | How many audit-log lines to include in `04-audit-tail.jsonl`.  |
| `--no-audit`             | off                                           | Suppress the audit-tail section entirely.                      |
| `--db PATH`              | `~/.kbouncer/state.db` (or `KBOUNCER_DB`)     | SQLite store path (read-only access).                          |
| `--profiles PATH`        | `~/.kbouncer/profiles.yaml`                   | Profiles YAML path.                                            |
| `--healthz-url URL`      | `http://127.0.0.1:8766/healthz`               | Local `/healthz` to probe. Failure is recorded, not fatal.     |
| `--insecure-skip-verify` | off                                           | Skip TLS verify on the `/healthz` GET (dev certs).             |
| `--panic-log PATH`       | empty                                         | Optional captured-panics file to include (scrubbed).           |
| `--audit-log-path PATH`  | `KBOUNCER_AUDIT_LOG_PATH`                     | Where to write the admin-action OCSF event for the bundle run. |

## Inspecting a bundle

```bash
# List entries
unzip -l kbounce-diagnostics-20260518T123456Z.zip

# Read a section without extracting
unzip -p kbounce-diagnostics-20260518T123456Z.zip 00-README.txt
unzip -p kbounce-diagnostics-20260518T123456Z.zip 09-manifest.json | jq .

# Verify the manifest sha256s match (defensive — the bundle
# command writes a deterministic ZIP modtime so this is normally
# unnecessary).
unzip -p kbounce-diagnostics-20260518T123456Z.zip 05-healthz.json | sha256sum
```

## Read-only invariant

The diagnostics bundle is strictly **read-only**:

- Never modifies the SQLite store.
- Never modifies the profiles file.
- Never modifies the audit log (the admin-action event APPENDS one
  line documenting that the bundle was produced).
- Never makes network calls except the single LOCAL `/healthz` GET
  on the loopback port.

This matches the [creates-never-mutates] + [self-host-zero-billing-
dependency] product invariants — running the bundle command is
always safe, even in production, even during an incident.

## Cross-product parity

The same shape ships in `ibounce diagnostics bundle` + `dbounce
diagnostics bundle` (per the cross-product-agent-parity decision).
An operator who knows one bundle layout knows them all.
