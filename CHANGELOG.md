# kbounce changelog

All notable changes to `kbounce` (formerly `kbouncer`) get recorded
here. Versioning follows semver from v1.0.0 onward.

## Unreleased

### Same-class audit of ibounce #272 root-path shadowing fix (2026-05-19)

Cross-product triage after the ibounce sibling fix at iam-roles
commit `d045eee` (ibounce #272 audit-stream UI was silently
shadowing AWS SDK root-path calls — S3 ListBuckets, presigned-URL
redirects, opaque proxy traffic — because the UI route registered
at `GET /` on the proxy port matched every bare-root request
unconditionally with no Accept-header sniff).

**Determination: kbounce is NOT affected.** No code fix shipped.

Three structural reasons the ibounce bug does not apply:

1. The Kubernetes apiserver protocol never routes a kubectl /
   client-go call to bare `GET /`. Every legitimate client request
   targets `/api`, `/apis`, `/api/{ver}/...`,
   `/apis/{group}/{ver}/...`, `/healthz`, `/readyz`, `/livez`,
   `/version`, `/openapi/v2`, `/openapi/v3`, or `/metrics`. There
   is no API operation whose request-line target is `/`.
2. The existing `auditEventsUIRoot` wrapper in
   `internal/proxy/events_ui.go` uses an EXACT-path match
   (`r.URL.Path == "/"`) — not a prefix or aiohttp-style catch-
   all. Any other path falls through to `s.handle` untouched.
3. Defense in depth: even if a request did arrive at bare `/`,
   `parser.Parse()` rejects it as `ErrMalformedURL`, routing it
   through the default-policy opaque path rather than letting it
   slip through unevaluated.

The ibounce sniff-the-`Accept`-header pattern is therefore not
applicable here — the Go `http.ServeMux` + exact-path wrapper
combination is the right shape for kbounce's protocol.

New test pins the assumption: `TestAuditEventsUIRoot_KubernetesProtocolNeverHitsBareRoot`
in `internal/proxy/events_ui_test.go` exercises 21 canonical
kubectl + client-go request paths (core / named-group discovery,
list / get / create / delete / patch / exec / log on pods +
secrets + deployments + clusterroles, plus `/healthz`, `/readyz`,
`/livez`, `/version`, `/openapi/v2`, `/openapi/v3`, `/metrics`),
each asserting the UI handler never fires and the proxy fallback
runs exactly once. If kubernetes ever shipped a bare-root API
operation, this test would fail and force a re-evaluation of the
wrapper (which would then need the ibounce Accept-header sniff
pattern).

Per `[[creates-never-mutates]]` this triage is read-only — no
proxy code changed; only test + CHANGELOG. Per `[[deliberate-
feature-completion]]` triage shipped as a discrete unit (test +
CHANGELOG entry + cross-product reasoning recorded). Per
`[[push-policy-public-repo]]` diff scanned before push; no
sensitive data.

### Per-org notification routing engine (2026-05-19, #280; ENTERPRISE tier)

- **`kbounce run --alert-routes ROUTES.yaml`** activates the multi-
  destination routing engine. Each event is matched against the
  YAML's `routes:` list (per-route `match` block with `equals` /
  `gte` / `lte` / `gt` / `lt` / `in` / `match` (regex) / `glob`
  operators; AND-within / OR-across); matching routes dispatch the
  event to their declared `destinations:` (`webhook` per #257 preset,
  `pagerduty` via the documented Events API v2, `slack` via incoming-
  webhook). No SDK deps; raw HTTP POSTs against the documented
  vendor endpoints.
- `on_match: stop` (**default**) short-circuits subsequent routes;
  `on_match: continue` enables fan-out for catch-all archive routes.
- Secrets resolved via `${ENV_VAR}` interpolation; literal tokens in
  the YAML are refused at load time. Resolved secrets render as
  `<8-char-prefix>***` in the dry-run output + status surfaces; raw
  tokens never appear in logs, status, or error messages.
- **`kbounce config preview-routes --routes ROUTES.yaml --event sample.json`**
  dry-runs a sample event against the file and prints which routes
  matched + the masked destinations each match would dispatch to.
  Mandatory pre-deploy validation; no HTTP traffic is sent.
- Backward compat: when `--alert-routes` is unset, the existing
  `--audit-webhook-url` path is unchanged. When BOTH are set, the
  routing engine wins + the single-webhook is ignored with a
  warning at startup.
- Per `[[enterprise-self-host-only]]`: ENTERPRISE-tier feature;
  license gate currently surfaces `ErrRoutesLicenseRequired`
  (placeholder until #235 license-file plumbing lands — same shape
  as the existing webhook + alert-rules gates).
- Per `[[creates-never-mutates]]` the engine never mutates the event
  it routes. Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-
  dependency]]` every destination is operator-configured.
- Per `[[cross-product-agent-parity]]` ibounce + dbounce ship the
  same `--alert-routes` flag name + YAML schema + match operators +
  destination types.
- Documented at `docs/PER-ORG-NOTIFICATION-ROUTING.md`; the canonical
  cross-product reference lives at the iam-roles repo
  `docs/PER-ORG-NOTIFICATION-ROUTING.md`.

### AWS Security Lake audit-export adapter (2026-05-19, #258)

- **`kbounce run --security-lake-bucket BUCKET --security-lake-region REGION
  [--security-lake-role-arn ARN] [--security-lake-rotation-seconds N]`** —
  writes OCSF v1.1.0 class 6003 events as parquet files into a
  Security-Lake-compatible S3 bucket layout
  (`region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/api_activity-
  <unix-ms>.parquet`). Per-class in-memory batching with rotation
  on the configured interval (default 300s) OR a 10 MiB size cap,
  whichever fires first; `Close()` flushes pending batches
  synchronously. Credentials via STS AssumeRole when
  `--security-lake-role-arn` is set, otherwise the default
  aws-sdk-go-v2 credential chain; refuses to start with a clear
  error if no credentials are reachable.
- Cross-product parity per `[[cross-product-agent-parity]]`:
  ibounce + dbounce ship the same adapter with byte-identical
  column set + partition layout. `SecurityLakeColumnNames` in the
  audit package locks the schema; the cross-product test fixture
  asserts it.
- Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-dependency]]`
  the bucket lives in the operator's AWS account; iam-jit-the-
  company never receives the data.
- Per `[[creates-never-mutates]]` every S3 operation is `PutObject`
  only; rotation timestamps guarantee unique keys per flush.
- Documented in `docs/SECURITY-LAKE-INTEGRATION.md`.

### Per-session recording (2026-05-19, #285)

- **`kbounce run --record-sessions-dir PATH`** — tees every audit
  event into a per-session NDJSON file at
  `{dir}/{agent.session_id}.ndjson`. Each file starts with a `_meta`
  header (recording_schema_version, session_id, agent_name,
  bouncer_product, recording_started_at) followed by one OCSF event
  per line. `.partial` suffix while in-flight; atomic rename to
  `.ndjson` on clean shutdown or heartbeat-timeout finalisation.
  File mode 0o600.
- **`kbounce session list / show / export / purge`** — read-only
  inspection of recordings. Same subcommand names + flag shape as
  ibounce / dbounce / gbounce per `[[cross-product-agent-parity]]`.
- Cross-product **`iam-jit session replay <FILE>`** CLI (lives in
  iam-roles) consumes kbouncer recordings unchanged via the shared
  on-disk shape.
- See `docs/SESSION-REPLAY.md` in iam-roles for the cross-product
  documentation; the recorder code is `internal/audit/recorder.go`.

### `--preset security-observe` deployment preset (2026-05-19, #254)

- **`kbounce run --preset security-observe`** — single-flag shortcut
  for the canonical security-team observation deployment shape.
  Equivalent to the explicit flag bundle `--mode transparent
  --default-policy allow --audit-log-path ~/.kbouncer/audit/kbounce.jsonl
  --alert-rules defaults --heartbeat-interval 30s`. Designed for the
  "gather data first; author profile second" starting position per
  `[[bouncer-mode-selection-for-agents]]` + the cross-product
  security-team audit-export memo.
- HARD override on `--mode` (the entire point of the preset is
  transparent); passing `--preset security-observe --mode cooperative`
  errors fast with a clear "drop the preset OR drop the explicit flag"
  message.
- SOFT overrides on `--audit-log-path` / `--alert-rules` /
  `--heartbeat-interval` / `--default-policy` (operators have
  different SIEM destinations + tunings).
- Startup banner names the preset + every derived setting with
  hard/soft annotation. Same preset name + same override semantics
  ship across `ibounce` / `dbounce` / `gbounce` per
  `[[cross-product-agent-parity]]`.
- Framework + the post-v1.0 roadmap (`dev-loop`, `production-strict`,
  `compliance-audit`) are documented in `docs/DEPLOYMENT-PRESETS.md`
  but explicitly NOT shipped in this slice per
  `[[deliberate-feature-completion]]`.
- Per `[[security-team-positioning-safety-not-surveillance]]`: preset
  description + banner use neutral language.
- Per `[[self-host-zero-billing-dependency]]`: the preset does NOT
  configure `--audit-webhook-url`; a self-hosted security-observe
  deployment phones home to nothing without an operator action.

### Schema endpoint + audit-webhook presets surface (2026-05-18, #276 + #259)

Cross-product `[[cross-product-agent-parity]]` rollout matching the
ibounce + dbounce siblings:

- **`GET /schemas/config` HTTP endpoint** (#276) — kbounce's proxy
  port serves the embedded `kbounce-config.schema.json` byte-for-byte
  at `Content-Type: application/schema+json`. Agents that want to
  validate a proposed `kbounce config import` payload against the
  LIVE bouncer's accepted shape fetch this rather than relying on a
  stale GitHub URL. READ-only (PUT/POST/DELETE return 405); no auth
  (matches `/healthz` — the schema is non-sensitive metadata). The
  served bytes are an in-tree build-time copy of
  `schemas/kbounce-config.schema.json`; a test asserts byte-equality
  so a drift between the embedded copy + the published copy fails
  the build.
- **`kbounce audit-webhook presets list`** (#259) — operator-facing
  subcommand that prints the four webhook preset shapes the binary
  speaks (`generic`, `datadog`, `splunk-hec`, `sentinel`) + each
  preset's required + optional flags + auth header + body shape.
  `--json` flag emits the structured descriptor list for agent
  consumption. Mirrors the new `list_audit_webhook_presets` MCP tool
  + the matching `ibounce` + `dbounce` subcommands. Per
  `[[audit-webhook-presets]]`.
- **`list_audit_webhook_presets` MCP tool** (#259) — agent-facing
  surface returning the same descriptor list `kbounce audit-webhook
  presets list --json` emits. Identical JSON shape across `ibounce`
  / `kbounce` / `dbounce` so cross-product orchestration code calls
  the matching tool on each bouncer and collates the results
  uniformly.
- **`audit.PresetDescriptors()` shared helper** — single source of
  truth for the preset descriptor list. Both `internal/cli/audit_webhook.go`
  + `internal/mcp/server.go` import it so the CLI surface + MCP
  surface can never drift. A test asserts every name in
  `audit.AllPresets()` shows up in the descriptor list (cross-pack
  drift guard).

### Persist agent identity in the SQLite decisions table (2026-05-18, #289)

Closes the `[[kbounce-agent-identity-sqlite-gap]]` parity gap: until
now, the JSONL audit log + HTTPS webhook persisted the per-call
agent name + per-MCP-session id, but the SQLite `decisions` table
dropped them. The four read surfaces backed by SQLite — `kbounce
audit tail`, `kbounce investigate`, `GET /audit/events` (#271), and
the web UI (#272) — all rendered `agent.name="unknown"` even when
the in-memory identity was high-fidelity. Schema bumped to v8: two
additive `ALTER TABLE decisions ADD COLUMN` statements
(`agent_name`, `agent_session_id`); both nullable. Pre-#289 rows
keep NULL columns + surface as the default
`{name:"unknown", detected_from:"unknown"}` agent block — accurate,
since we never had the identity to record. No backfill, no
destructive ops, no network calls. The fingerprinted `AgentInfo`
already resolved at the proxy hot-path is now threaded through
`writeDecision`/`writeDecisionForTask`/`writeDecisionForTaskMaybe`
into the row. The four read surfaces compose for free through the
shared `FromDecision` wrapper: `unmapped.iam_jit.agent.{name,
session_id}` always populated, `actor.user.name` mirrors
`agent_name` when no K8s principal is extracted (Slice 1 default).
Closes the cross-product parity gap with ibounce + dbounce +
gbounce per `[[cross-product-agent-parity]]`.

New tests: schema-version bump pin, insert-with-agent round-trip,
anonymous-row NULL-column guard, user-agent-only shape,
forward-migration data-preservation test (drops the v8 columns,
rolls schema_version back to 7, re-opens, asserts the additive
migration re-adds the columns + preserves the legacy row),
proxy-hot-path SQLite persistence guard, `/audit/events` JSONL
shape guard, three `audit/event.go` precedence tests
(agent → actor.user.name, principal wins over agent, unknown agent
leaves actor empty), three CLI `decisionRowToEvent` round-trip
tests, end-to-end `audit tail` smoke test covering both
MCP-session and user-agent shapes.

Files: `internal/store/store.go` (schema + DecisionRow +
RecordDecision + RecentDecisions), `internal/store/store_test.go`,
`internal/audit/event.go` (buildActor precedence),
`internal/audit/event_test.go`, `internal/proxy/proxy.go`
(write-helper threading), `internal/proxy/proxy_test.go`,
`internal/proxy/audit_events.go` (read-path agent rebuild),
`internal/proxy/audit_events_test.go`,
`internal/cli/audit_tail.go` (read-path agent rebuild +
file-doc), `internal/cli/audit_tail_test.go`.

### Live audit-stream web UI at `GET /` (2026-05-18, #272)

kbounce now serves a minimal vanilla-JS web UI at `GET /` on its
existing port (`8766`) alongside `/healthz` and `/audit/events`.
The page is a single self-contained HTML+CSS+JS file (no build step,
no CDN, no Google Fonts, no analytics, no telemetry), under 500
lines. Long-polls `/audit/events?since=<cursor>` every two seconds
and renders a colour-coded table with top-bar event counters,
filter input (same syntax as `/audit/events?filter=`), pause +
clear controls, mobile-responsive layout.

Wire model: long-polling rather than SSE — the existing
`auditEventsHandler` doesn't ship streaming response semantics
today and the operator UX is identical at 2 s tick. A future bump
can swap the JS polling loop for `EventSource` without touching the
server contract.

The UI handler intercepts ONLY exact `GET /` (a browser landing
path); every k8s API request (`/api/v1/...`, `/apis/...`, etc.)
and every non-GET verb falls through to the existing proxy catch-
all unchanged, so kubectl traffic is untouched.

Same auth model as `/audit/events`: loopback no auth; external bind
takes the bearer token through the URL `#token=...` fragment so the
HTML body never embeds the secret. Strict `Content-Security-Policy`
header. Cross-product-identical HTML shape with ibounce / dbounce
/ gbounce per `[[cross-product-agent-parity]]`.

Per `[[creates-never-mutates]]` the UI is read-only — no button
mutates kbounce state. Per `[[security-team-positioning-safety-not-
surveillance]]` event labels use "deny" / "allow", never
"violation" / "infraction" / "unauthorized". Per `[[self-host-zero-
billing-dependency]]` no CDN dependencies; everything inline.

New file: `internal/proxy/events_ui.go`. Tests:
`internal/proxy/events_ui_test.go`. Doc section in
`docs/QUERYING-AUDIT-LOGS.md`.

The cross-bouncer TUI sibling (`iam-jit audit stream`) merges live
streams from every reachable bouncer into one terminal table; see
`iam-roles/docs/AUDIT-STREAM-TUI.md`.

### HTTP `/audit/events` endpoint (2026-05-18, #271)

GET `/audit/events` ships on the existing proxy port (`8766`)
alongside `/healthz`. Same filter language as `kbounce audit tail
--filter`, same supported field catalog, same OCSF v1.1.0 wire
shape. Query parameters: `since` / `until` (ISO 8601), `filter`
(repeatable; `field=value` / `field~regex` / `field>=N` /
`field<=N`), `limit` (default 100, max 1000), `format` (`jsonl`
default | `ocsf-bundle`). Loopback bind requires no auth (matches
the existing trust anchor); external bind requires a bearer token
via the new `kbounce run --audit-events-token TOKEN` flag (refuses
to start in external-bind mode without it). Filter parsing lives
in the new `internal/audit/filter.go` so both the CLI surface and
the HTTP surface call the same parser. Powers the cross-bouncer
`iam-jit audit query` CLI which queries every reachable bouncer in
parallel + merges results. Per `[[cross-product-agent-parity]]` +
`[[creates-never-mutates]]` (read-only) + `[[self-host-zero-billing-
dependency]]` (operator-controlled port; no phone-home).

### Investigate-with-Claude workflow (2026-05-18, #273)

`kbounce investigate` composes the existing `audit tail --export
ocsf-bundle` (#268) and `diagnostics bundle` (#277) into a single
"land a Claude-ready evidence pack" subcommand. Operator drops the
two artifacts into THEIR local Claude client (Claude Code, Cursor's
Claude integration, desktop Claude, the Anthropic console —
whichever they use) and asks an investigative prompt; kbounce never
calls Anthropic. Per `[[self-host-zero-billing-dependency]]` the
only network call is the same local /healthz GET `diagnostics
bundle` makes. Per `[[creates-never-mutates]]` it's read-only.

Cross-product alignment per `[[cross-product-agent-parity]]` —
ibounce / dbounce / gbounce ship the same subcommand shape with
the same `--out-dir` / `--time-range` / `--filter` / `--print-
prompts` flag set.

- Writes `kbounce-investigation.ndjson` (OCSF v1.1.0 class 2004
  Detection Finding wrapping filtered audit events) +
  `kbounce-investigation-context.zip` (the standard diagnostics
  bundle with `--no-audit` — the evidence file already carries the
  audit content).
- `--print-prompts` lists the 10 starter investigative prompts as a
  paste-able block without writing artifact files.
- `--time-range 24h|7d|4w` filters the evidence to a recent window;
  translates to a `time>=cutoff` filter on the OCSF wire shape.
- Per `[[don't-tailor-to-lighthouse]]` the prompts are generic — no
  specific Claude surface is named.
- Per `[[security-team-positioning-safety-not-surveillance]]` the
  prompts stay in the "denial / scope mismatch / policy mismatch"
  vocabulary; nothing reads as accusation.

Docs: `docs/INVESTIGATE-WITH-CLAUDE.md` — workflow walkthrough,
the 10 starter prompts, privacy story, and cross-bouncer parity
notes.

### Local-operator `audit tail` UX — follow / filter / summary / export (2026-05-18, #268)

Closes `[[cross-product-agent-parity]]`-#268. `kbounce audit tail`
grows from "print last N rows" to the full local-operator workflow
the spec lays out — the same shape `ibounce audit tail` +
`dbounce audit tail` ship. Per founder direction: this is a SELLING
surface ("users being able to see a stream of requests coming from
their agent via UI, or in the terminal will be very helpful for
selling the product even if its not something new").

- **`--follow`** — live tail the SQLite audit DB; 500ms poll cadence;
  Ctrl-C / SIGINT exits cleanly. Banner + close-out marker frame the
  stream so the operator knows the loop is alive.
- **`--filter EXPR`** — repeatable; AND-combined. Three operators:
  `field=value` (string equality), `field~regex` (RE2), `field>=N` /
  `field<=N` (numeric). The filter language operates against the
  OCSF wire shape (the same one downstream SIEMs key off) so the
  filter expressions an operator learns locally transfer directly to
  their Splunk / Datadog / Sentinel queries. Supported field catalog
  matches the cross-product spec + adds kbounce-native
  `resource.namespace`/`.name`/`.type` and the
  `unmapped.iam_jit.{verdict,mode,profile,enforced}` quartet.
- **`--summary`** — count-summary instead of rows. Four groupings:
  by `event_type`, `severity`, `actor`, `api.operation`. Mutually
  exclusive with `--follow` (summary is a terminal aggregation).
- **`--export {jsonl,csv,ocsf-bundle} --out PATH`** —
  - `jsonl` round-trips through `jq` (one OCSF API Activity event per
    line; mirrors the wire shape your SIEM ingests).
  - `csv` defaults to a conservative column set
    (`timestamp,severity,event_type,actor,operation,verdict,agent.name,
    agent.session_id`); PII fields (`actor.user.{name,uid}`,
    `agent.{process_exe,parent_exe,user_agent_raw}`) are opt-in via
    `--csv-columns LIST`.
  - `ocsf-bundle` wraps the events in an OCSF Detection Finding
    (class 2004) for SIEM batch import.
- **Agent-identity caveat** — SQLite-sourced rows render
  `unmapped.iam_jit.agent.name = "unknown"` because the agent block is
  in-memory only (only the JSONL log + HTTPS webhook persist it).
  Documented in docs/QUERYING-AUDIT-LOGS.md so operators reach for
  `jq` over the JSONL stream when they need agent-scoped filtering.
- **Tests** — 18 new tests in
  `internal/cli/audit_tail_test.go` cover the filter parser (every
  operator + the unknown-field error path), --summary counts (incl.
  empty DB), --follow (printing + cancel), all three export formats
  with format-validation round-trips, and the
  `--follow` × `--summary` mutex.
- **Docs** — `docs/QUERYING-AUDIT-LOGS.md` adds a "Live tail +
  filtering + summary + export" section with worked examples + the
  cross-product parity table; README's `audit tail` entry is rewritten
  to describe the full flag set + links to the deep doc.

### Cross-product config-export wire reconciliation (2026-05-18, #288)

Closes `[[cross-product-agent-parity]]`-#288. The `kbounce config
export/import` wire shape now matches ibounce + gbounce + dbounce
exactly so a single cross-product backup workflow targets every Bounce
product with one CLI shape.

- **`schema_version`** is now `"1.0"` (string semver) instead of `1`
  (int). Bumps to `"1.1"` (additive) or `"2.0"` (breaking) preserve
  the parser shape across version drift.
- **`--in PATH`** is the primary `config import` flag (matches
  ibounce + gbounce + dbounce). `--from PATH` stays as a DEPRECATED
  alias — still works, prints a stderr deprecation warning.
- **Backwards compat** — pre-#288 exports with `schema_version: 1`
  (int) import cleanly into the new binary. The importer normalizes
  the field to `"1.0"` before schema validation runs + prints a
  stderr deprecation warning. The compat window stays open across
  the full v1.x line.
- **Testdata fixture** —
  `internal/cli/testdata/legacy-int-schema_version.json` pins a
  pre-#288 export as a regression watchdog; a future schema-validator
  change cannot silently drop legacy compat without the new test
  surfacing the regression.
- **Docs** — new `docs/CONFIG-EXPORT-IMPORT.md` covers the wire shape,
  the CLI flags, the cross-product parity contract, and the
  backwards-compat window.

### SQLite backup + restore (2026-05-18, #279)

Closes `[[deliberate-feature-completion]]`-#279. Single-file SQLite
backup + restore for the kbounce store so operators can migrate to
a new machine, recover from disaster, or preserve the audit trail
across a risky config change WITHOUT the historical "stop the
daemon and `cp state.db`" footgun.

- **`kbounce backup --out PATH [--include-audit] [--include-prompts]`**
  — Online backup via SQLite `VACUUM INTO`; running proxy is not
  interrupted. Retries on SQLITE_BUSY with exponential backoff so
  a hot writer doesn't fail the first attempt. Embeds a
  `kbounce_backup_metadata` table with `kbounce_version`,
  `created_at`, `source_hostname_hash` (sha256 of hostname,
  privacy-preserving), `schema_version`, `included_audit`,
  `included_prompts`. Default excludes audit-firehose tables
  (`decisions`, `pause_events`, `burst_events`, `pending_prompts`);
  opt back in with the matching flags. Refuses to clobber an
  existing output file.
- **`kbounce restore --in PATH [--dest PATH] [--force]`** —
  Validates backup metadata first; refuses on `schema_version`
  mismatch ALWAYS (cross-schema restore is a migration, not a
  restore); refuses on `kbounce_version` mismatch unless `--force`;
  refuses if destination DB has rules / tasks rows unless
  `--force`. Pre-flight probes loopback `/healthz` + refuses if a
  kbounce listener is detected (`--skip-running-probe` overrides;
  `--probe-url` retargets). Prints restored row counts + sha256 of
  the resulting DB file.
- **OCSF admin-action events** — new `store.backup` (Informational)
  + `store.restore` (High) AdminAction enum values; both fire when
  `--audit-log-path` / `KBOUNCER_AUDIT_LOG_PATH` is configured so
  security teams have a witness for backup + restore operations.
- **docs/BACKUP-RESTORE.md** — full operator-facing reference
  including sample migration session.
- **Cross-product parity** — dbounce ships the same CLI shape
  (`--out`, `--in`, `--force`, `--include-audit`,
  `--include-prompts`) + the same metadata-table format per
  `[[cross-product-agent-parity]]`.

### Audit-export failure visibility (2026-05-18, #265 Slice 8)

Closes `[[audit-export-failure-visibility]]`. Surfaces export-channel
write health on three independent operator surfaces so a silent
audit-export outage cannot pass undetected.

- **Manager.Status() extensions** — `log_writes_ok`,
  `log_consecutive_failures`, `log_last_success_unix_milli`,
  `webhook_writes_ok`, `webhook_consecutive_failures`,
  `webhook_last_success_unix_milli`, plus the aggregate verdict
  `audit_export_healthy` + `audit_export_degraded_reason`.
  `LogWriter` + `WebhookPusher` track the per-channel counters; the
  Manager pure-functionally computes the aggregate via
  `computeAuditExportHealth`. Independent of the heartbeat-watchdog
  503 surface (either-or 503 per the memo).
- **`/healthz` extension** — returns 503 with `audit_export_healthy:
  false` when ANY configured channel trips `writes_ok=false`,
  `consecutive_failures > 3`, or `last_success` age > 5 minutes.
  External supervisors (k8s liveness probes, monit, supervisor
  scripts) see the same signal the SIEM-side `audit_export_degraded`
  rule trips on.
- **`kbounce audit-export health` CLI subcommand** — explicit
  operator-facing check that hits the running proxy's `/healthz`
  endpoint. Exits 0 (healthy), 1 (degraded — degradation reason on
  stderr), or 2 (transport / parse error — distinct so a shell
  script can tell "kbounce isn't running" apart from "kbounce is
  fine but audit-export is degraded"). `--insecure-skip-verify` for
  the dev-cert path; `--url` for non-default ports / TLS bindings.
- **`audit_export_degraded` alert rule** — 6th built-in alert (after
  `heartbeat_gap`). Severity Medium. Edge-triggered (one alert per
  outage window, not one per event). Writes a one-line operator-
  facing notice to stderr INDEPENDENT of the audit-export channel
  itself so an operator monitoring container logs sees the alert
  even when the JSONL log + HTTPS webhook are both down. Wired into
  the engine via `RuleEngine.BindStatusSource`. YAML override via
  `audit_export_degraded.consec_failure_threshold`.
- **Tests** — F1-F8 failure-mode coverage in
  `internal/audit/audit_export_failure_test.go` (queue-full + retry-
  exhaustion + recovery + stale-success + heartbeat-OR-in +
  end-to-end engine wiring + token-mask discipline + read-only-dir
  open-failure). CLI exit-code shape in
  `internal/cli/audit_export_health_test.go`.

Per `[[security-team-positioning-safety-not-surveillance]]` every
operator-facing string stays neutral; the `audit_export_degraded`
alert payload is scanned for forbidden words by the neutral-language
test. Per `[[push-policy-public-repo]]` no operator paths /
environment specifics in the new code.

### Audit-export webhook presets (2026-05-18, #257)

Adds `--audit-webhook-preset` so the webhook body + auth header can
match a SIEM's native intake without an external transformer. The
canonical OCSF event written to the JSONL log file is UNCHANGED —
only the webhook body gets vendor-shaped at send-time.

Supported presets:

- `generic` (default) — backward-compat. `Authorization: Bearer
  <token>` + `Content-Type: application/json` + JSON-array body of
  OCSF events. Byte-identical to the Slice 1 (#252) wire shape.
- `datadog` — `DD-API-KEY: <token>` header. Per-event overlay layers
  `ddsource`, `service`, `ddtags`, `status` (derived from OCSF
  `status_id`), `host` (from `src_endpoint`), and a neutral
  `message` summary line. OCSF originals are preserved (vendor-
  reserved field collisions get shadow-copied under `ocsf.<name>`).
  Operator-supplied tags via `--audit-webhook-tags`.
- `splunk-hec` — `Authorization: Splunk <token>` header. NDJSON
  body where each line wraps the OCSF event under the HEC `event`
  field with `sourcetype` (`iam_jit:bouncer:kbounce`), `source`,
  `host`, and `time` (unix seconds derived from OCSF `time`).
- `sentinel` — HMAC-SHA256-signed `SharedKey` Authorization for the
  Log Analytics Workspace Data Collector API. Workspace ID is
  extracted from the URL host; `--audit-webhook-token` must be the
  base64 workspace shared key. Log-Type table name configurable via
  `--audit-webhook-sentinel-table` (default `IamJitBouncer`).

Per `[[scorer-is-ground-truth]]`: the adapter is pure transformation
— no scoring, no LLM, no re-evaluation of severity / status /
verdict. Per `[[security-team-positioning-safety-not-surveillance]]`:
overlay language stays neutral. License-gate placeholder unchanged
(real Ed25519 plumbing per #235); presets are orthogonal. Security
Lake adapter ships in a separate slice (#258 — S3 + parquet,
different transport).

### Cross-product agent-parity closure (2026-05-17)

Closes the two pre-launch parity gaps with `ibounce` flagged by
`[[cross-product-agent-parity]]`:

- **`kbounce rules recommend`** — synthesizes draft rules from
  observed audit-log traffic. Mirrors `ibounce recommend`'s flag set
  exactly (`--since` / `--until` / `--min-support` / `--limit` /
  `--apply` / `--apply-only` / `--include-task-scoped` /
  `--save-as-profile` / `--profile-description` / `--json`).
  Deterministic: groups ALLOW decisions by (resource, verb), thresholds
  on min-support, applies LCP detection for namespace + resource-name
  scopes (≥50% observable-data fraction floor).
- **`--save-as-profile` auto-naming** per `[[profile-auto-naming]]`:
  NAME is OPTIONAL. With a TTY kbounce prompts with a context-
  suggested default (`auto-YYYY-MM-DD-{top-resources}-readonly`);
  without a TTY it auto-generates the name + prints it to stderr.
  Collision-avoid via `-2` / `-3` suffix. Refuses to overwrite an
  org-sourced profile (read-only invariant from
  `[[enterprise-profile-distribution]]`).
- **`kbounce presets {list, show, apply}`** — five curated starter
  rule packs ship embedded in the binary:
  `cluster-admin-minus-destructive`, `eks-cluster-survey`,
  `argocd-app-controller`, `gke-developer`, `incident-response-readonly`.
  Presets are SEPARATE from the `safe-default` profile (per
  `[[safe-default-is-readonly-admin-minus]]`): the profile is a hard
  floor; presets are global-rule starters the operator applies +
  customizes. They compose.
- **Three new MCP tools** for agent symmetry:
  - `kbounce_recommend_rules` — read-only synthesis preview.
  - `kbounce_list_presets` — discover available curated packs.
  - `kbounce_apply_preset` — apply a preset to the global rule table.

MCP tool family now stands at 15 — closing the parity gap with
`ibounce`'s 16 (the missing slot is the future `bouncer_*` tool
that captures a recommendation directly into a profile via a single
MCP call; deferred until use-case demand surfaces).

### Opus readonly-profile audit closure (2026-05-17)

The Opus readonly-profile audit ([#222]) found `readonly` not fit-for-
purpose as a launch safety opt-in. The name oversold the guarantee
(reads of sensitive data still pass), the verb list missed eight
high-blast-radius primitives, and the parser ignored impersonation
headers entirely. This change renames + hardens.

**Rename: `readonly` → `safe-default`**

- Canonical built-in defaults are now `full-user` (passthrough) +
  `safe-default` (cross-product safe-by-default deny layer).
- Description rewritten to name what the layer actually is: a blast-
  radius floor, NOT a confidentiality boundary.
- Aliases that still resolve in v1.0 (one-line deprecation banner;
  removed v1.1):
  - `none` → `full-user`
  - `prod-readonly` → `safe-default`
  - `readonly` → `safe-default`  **(NEW alias from this change)**

**Hardened `safe-default.deny_verbs` (Gap-K-1..K-7, K-12)**

Adds 8 verbs to the existing 8:

| Verb | Gap | Why |
| --- | --- | --- |
| `proxy` | Gap-K-1 | `/pods\|services\|nodes/{name}/proxy` — RBAC bypass tunnel; nodes/proxy = kubelet API arbitrary exec |
| `eviction` | Gap-K-2 | Pod deletion by another name |
| `scale` | Gap-K-3 | Replica-count mutation (scale-to-0 DoS; scale-to-large cost attack) |
| `status` | Gap-K-4 | Controller-state poisoning |
| `finalize` | Gap-K-5 | Bypass deletion protection |
| `ephemeralcontainers` | Gap-K-6 | Debug-container injection = exec equivalent |
| `token` | Gap-K-7 | TokenRequest = credential minting (POST `/serviceaccounts/{name}/token`) |
| `binding` | Gap-K-12 | Manual scheduling bypass (POST `/pods/{name}/binding`) |

**New Profile schema fields**

- `exempt_resources_for_verb_deny: {verb: [group/resource, ...]}` —
  carves SSAR / SAR / TokenReview / SelfSubjectRulesReview out of
  the `create` verb deny so `kubectl auth can-i` keeps working.
  Match is on the FULL `group/resource` pair so a CRD with a
  colliding resource name in a different group is NOT exempted.
- `deny_on_impersonation: bool` — when true, requests carrying any
  of the `Impersonate-User` / `Impersonate-Group` / `Impersonate-Uid`
  / `Impersonate-Extra-*` header family are denied regardless of
  verb (Gap-K-9). Default true under `safe-default`.
- `deny_subresource_writes: bool` — long-tail safety net for CRD-
  defined mutating subresources not enumerated in `deny_verbs`.
  POST/PUT/PATCH/DELETE against ANY subresource (except `log` /
  `logs` per False-positive-K-1) is denied (Gap-K-14). Default true
  under `safe-default`.

**Parser: impersonation header parsing**

`parser.ParsedRequest` gains `IsImpersonation`, `ImpersonatedUser`,
`ImpersonatedGroups`. The `Impersonate-Extra-*` family uses a
header-name PREFIX (not a fixed name); the parser scans all header
names for the prefix so an Extra-* prefix-only request is still
flagged.

**Profile evaluator: dry-run carve-out**

`?dryRun=All` requests (which the apiserver returns as previews
without persisting state) short-circuit profile evaluation at
order-1, bypassing `deny_verbs` so `kubectl apply --dry-run` +
agent plan-capture flows keep working (False-positive-K-3).

**Audit-cadence self-check (per `feedback_audit_cadence_discipline`)**

- (a) `Impersonate-Extra-*` family: the parser iterates all header
  names with the canonical prefix and flips `IsImpersonation` even
  when only Extra-* is present. Pinned by parser test
  `Impersonate-Extra-* prefix only`.
- (b) SSAR exemption check uses the FULL `group/resource` string,
  not just resource name. A CRD shipping `example.com/tokenreviews`
  is still denied. Pinned by profile test
  `TestSafeDefault_SSARExempt_DoesNotLeakAcrossGroups`.
- (c) The `log` / `logs` subresource carve-out is case-insensitive
  and covers both singular + plural across GET/POST shapes. Pinned
  by `TestSafeDefault_SubresourceLongTail_PreservesLogCarveOut`.

### Bounce-suite rename (2026-05-17)

Renamed `kbouncer` → `kbounce` as part of the Bounce-suite rename
([[bounce-suite-rename]] memo). Backward-compat preserved for v1.0;
removed in v1.1.

- **Binary**: `kbounce` is the canonical binary. `kbouncer` is a
  v1.0 deprecation shim that prints a one-line warning + delegates
  to the same code path. Both built from the same `internal/cli`
  package so they can never drift.
- **Go module path**: unchanged (`github.com/trsreagan3/kbouncer`)
  for v1.0 to minimize downstream import-path breakage.
- **Environment variables**: `KBOUNCER_DB` / `KBOUNCER_PROFILE` /
  `KBOUNCER_PROFILES_PATH` / `KBOUNCER_TLS_DIR` remain canonical; no
  `KBOUNCE_*` aliases added pre-launch.
- **Filesystem paths**: `~/.kbouncer/state.db` / `~/.kbouncer/profiles.yaml`
  / `~/.kbouncer/tls/` unchanged for backward compat with existing
  installs.
- **HTTP headers + JSON fields**: `x-kbouncer-*` headers and
  `kbouncer_*` JSON detail fields are preserved as on-the-wire API
  contracts.
- **MCP tools**: already `kbounce_*` per the K-Slice 6 ship; no
  rename required.
- **Default profile reshape** ([[bounce-default-profile-pattern]]):
  - `none` → `full-user` (rename; passthrough semantics unchanged)
  - `prod-readonly` → `readonly` (rename; verb-deny set unchanged)
  - REMOVED from embedded defaults: `staging-work` / `dev-only` /
    `sandbox` / `incident-response`. They now live under
    `community-profiles/` in this repo and install via
    `kbounce profile install --from URL`.
  - Embedded defaults reduce to TWO: `full-user` (passthrough,
    default) + `readonly` (write/destructive verb deny, opt-in via
    `--profile readonly` or `KBOUNCER_PROFILE=readonly`).
  - `kbounce run` without `--profile` prints a one-line banner with
    the two ways to opt into `readonly`.
- **Profile aliases**: `none` resolves to `full-user`; `prod-readonly`
  resolves to `readonly`. One-line deprecation notice printed to
  stderr. v1.1 removes the alias path.

### UAT-K2 closures (bundled into the rename)

Closes the BLOCKER + HIGH-UX findings from the 2026-05-17 UAT-K2
report.

**BLOCKER**
- BLOCKER-K2-01: full README rewrite covering every subcommand + the
  default-profile pattern + the new banner UX + the env-var override.
- BLOCKER-K2-02: every cobra parent command (`profile`, `audit`,
  `prompts`, `pause`, `rules`, `tasks`) now rejects unknown sub-
  subcommands with `kbounce: unknown subcommand "foo" for "bar"` +
  exit 1, instead of silently exiting 0 with the help text.

**HIGH-UX**
- HIGH-K2-01: task shorthand parser rejects `@ns=value` / `#name=value`
  with a clear pointer at the correct shape (`@prod-billing`). The
  legacy `ParseShorthand` keeps its signature; new
  `ParseShorthandStrict` returns the validation error. CLI uses the
  strict variant.
- HIGH-K2-02: added `kbounce profile show NAME` subcommand. Loads the
  profile file, prints the full record (name, description, source,
  deny_keywords, deny_verbs, only_clusters, exceptions, allow_rules).
  Exits 1 if NAME not found.
- HIGH-K2-03: `kbounce audit tail --limit` validates at parse time;
  out-of-range values (0, negative, > 1000) are rejected with
  `--limit must be in 1-1000`.
- HIGH-K2-04: demoted no-kubeconfig WARN to DEBUG; the startup banner
  now reads `upstream: <none> — observation-only mode; no kubectl
  traffic will reach an apiserver` so the consequence is consequence-
  clear without a scary JSON warning on first run.
- HIGH-K2-05: URL parser sets `IsStream` + `StreamKind` for exec /
  attach / portforward subresources, `?follow=true` log streams, and
  `?watch=true` lists. Proxy continues to combine this with the
  header-based classifier; the URL-level signal is the floor.
- HIGH-K2-06: `kbounce --version` now prints `kbounce <version>
  (commit X, built Y)`. Set at build time via
  `-ldflags "-X github.com/trsreagan3/kbouncer/internal/cli.commit=...
  -X github.com/trsreagan3/kbouncer/internal/cli.buildTime=..."`.

**MED-UX**
- MED-K2-01: `kbounce rules add` strips one `kbounce:` prefix layer
  from the rejected-rule error so it doesn't read
  `rejected: kbounce: invalid rule: kbounce: invalid rule pattern ...`.
- MED-K2-03: dropped the `#5` task-marker prefix from the
  `--prompt-on-deny` flag description.
- MED-K2-04: renamed the observation-only JSON wrapper field from
  `_slice1_note` to `_observation_only_note` and rephrased the value
  in user-visible terms (no more "K-Slice 1" / "K-Slice 2" internal
  task references).
- MED-K2-06: `/healthz` now exposes `lookup_errors_counter` mirroring
  the Python `bounce` healthz shape. Increments on pause-lookup,
  active-task lookup, ruleset load, prompt enqueue, audit-write
  failures.

### Compatibility

- Existing scripts invoking `kbouncer run` keep working (deprecation
  warn).
- Existing profiles using `none` / `prod-readonly` names keep working
  (alias resolution).
- Existing `~/.kbouncer/` state files (state.db, profiles.yaml, tls/)
  are read in place — no migration step required.
- All previous tests still pass + new tests pin every closure above.
