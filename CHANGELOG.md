# kbounce changelog

All notable changes to `kbounce` (formerly `kbouncer`) get recorded
here. Versioning follows semver from v1.0.0 onward.

## Unreleased

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
