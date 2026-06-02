# kbounce changelog

All notable changes to `kbounce` (formerly `kbouncer`) get recorded
here. Versioning follows semver from v1.0.0 onward.

## Unreleased — v1.0 launch prep (2026-05)

### Added

- **#379 — `--upstream-ca-bundle PATH` for private kube CAs** (2026-06-02) —
  The `run` subcommand now accepts `--upstream-ca-bundle PATH` (env
  fallback `KBOUNCER_UPSTREAM_CA_BUNDLE`; flag wins). The PEM file is
  loaded into an `x509.CertPool` and wired into the upstream HTTP
  client's `tls.Config.RootCAs`, REPLACING the kubeconfig CA so an
  operator with a private / self-signed kube CA not present in their
  kubeconfig can verify the apiserver. A missing, unreadable, or
  non-PEM bundle is a hard startup failure (classified via the new
  `upstream.ErrCABundle` sentinel) — kbounce never silently falls back
  to system roots. Supplying a CA bundle for a plain-`http` upstream is
  also rejected rather than silently ignored.

- **#380 — `KBOUNCER_AUDIT_EVENTS_TOKEN` env fallback for the
  `/audit/events` bearer token** (2026-06-02) — `--audit-events-token`
  now falls back to the `KBOUNCER_AUDIT_EVENTS_TOKEN` env var when the
  flag is empty (flag wins when both are set). Prefer the env var: a
  flag value leaks the secret into `ps` / process listings. Resolved
  before the external-bind auth gate so it satisfies the
  off-loopback-requires-a-token check.

- **#381 — container-friendly default DB path** (2026-06-02) —
  `store.DefaultDBPath` now resolves the default (when `--db` is not
  set) in order: `$KBOUNCER_DB` → `$XDG_STATE_HOME/kbounce/state.db` →
  `~/.kbouncer/state.db` (when `$HOME` is set; historical default
  preserved exactly) → `/var/lib/kbounce/state.db` (rootless containers
  with no `$HOME`). Parent dirs are created `0700`. An explicit
  `--db PATH` still overrides everything. Centralized so every
  subcommand that opens the store shares the resolution.

### Changed

- **Tier rescope: v1.0 ships fully free + open source** (2026-05-23) —
  Per `[[oss-only-launch-decision]]`: all features previously labeled
  ENTERPRISE tier in --help text + audit-package docstrings (the
  `--audit-webhook-url`, `--audit-webhook-token`, `--alert-rules`,
  `--alert-routes`, `--heartbeat-interval` flags) now framed as v1.0
  free + open-source ships per cross-product alignment with iam-roles
  README. License-file plumbing (#235) retained in code path but does
  NOT gate features at v1.0; refactor to remove the gate is queued for
  a follow-up. Mirrors the iam-roles + dbounce changes in the same
  sweep.

### Docs

- **#367 / §A36 — Docker bind-mount UID 65532 + colima caveat documented in README** (2026-05-23) —
  The distroless `:nonroot` runtime runs as UID 65532 (non-root for
  security). Operators bind-mounting a host directory hit a cryptic
  `open store: unable to open database file` because the host dir
  wasn't writable by 65532, and the existing Docker docs gave no
  fix-it hint. This slice adds a **"Bind-mounting volumes (UID 65532)"**
  section showing two remediation paths (`chown 65532:65532 <hostdir>`
  OR `--user $(id -u):$(id -g)`), a docker-compose example with
  matching `user:` setting + pre-up chown comment, a **macOS / colima
  caveat** about `/Users/*` paths being the only reliable bind-mount
  surface (mounts under `/tmp`, `/var`, `/private` silently diverge),
  and a **"Common errors"** table mapping the store-open error and
  three other usual-suspect symptoms back to the bind-mount section.
  Closes the gap an operator following docs-as-written would hit on
  their first `docker run` with persistence enabled.

### CI

- **#368 / §A37 — docker-publish smoke now boots proxy + asserts audit DB written** (2026-05-23) —
  Previously the smoke between local build and multi-arch push was
  `--version` + `--help` only. Per the auditor that smoke would NOT
  have caught the Helm-chart flag drift surfaced in §A33
  (`--active-profile` vs `--profile`) if the binary changed — running
  `--help` proves the binary starts, not that any `run`-time flag
  actually wires through. This slice adds a **Real-deploy smoke**
  step after the size report: boots `kbounce run` in a container
  with a chown'd bind-mounted host data dir (mirroring the
  bind-mount docs that just landed for §A36), waits up to 30s for
  `/healthz` to answer, asserts the response is HTTP 200, and asserts
  `state.db` exists on the host bind-mount (proving the binary
  actually opened the SQLite store under `run`). If `run` rejects a
  flag, fails to bind, or silently never opens persistence, the
  smoke fails before the multi-arch push fires. The step block is
  annotated with `RUN_LOCALLY:` comments so operators can copy-run
  the same smoke against `ghcr.io/trsreagan3/kbounce:latest` on a
  dev machine. Validated by yaml-parse smoke locally.

### Fixed

- **#375 / §A35b — kbounce mcp install-* now ACTUALLY emits agent-attribution env block** (2026-05-23) —
  The 2026-05-22 #308 entry (lines 436-461 below) claimed
  `kbounce mcp install-*` stamped `KBOUNCE_AGENT_NAME` +
  `KBOUNCE_AGENT_SESSION_ID` env vars on the generated MCP server
  entry, but the actual code path in
  `internal/mcpinstall/install.go` emitted `"env": map[string]any{}`
  on every install (claude-code / cursor / codex JSON + TOML +
  show-config YAML). Same regression #366 fixed on dbounce two days
  ago — kbouncer's slice landed without the wiring. This slice:
  adds `DefaultAgentName` + `AgentNameEnvVar` ("KBOUNCE_AGENT_NAME") +
  `AgentSessionIDEnvVar` ("KBOUNCE_AGENT_SESSION_ID") constants;
  splits `ServerConfigDict` / `ServerEntry` into base + `*ForAgent`
  variants so the JSON snippet construction mirrors dbounce; adds
  `agentNameForClient` for the per-client mapping (claude-code →
  "claude-code", cursor → "cursor", codex → "openai-codex"); updates
  the `installJSON` write path to call `ServerEntryForAgent(agentNameForClient(clientName))`;
  updates `snippetTOML` to include the `[mcp_servers.kbounce.env]`
  block; updates `ShowConfig` YAML branch to render the populated env
  block (was `env: {}`); updates the show-config footer to point at
  `iam-roles/docs/AGENT-ATTRIBUTION.md`. Validated by 7 new tests in
  `internal/mcpinstall/install_test.go`
  (`TestInstallJSON_EmitsAgentEnv_ClaudeCode`,
  `TestInstallJSON_EmitsAgentEnv_Cursor`,
  `TestInstallJSON_EmitsAgentEnv_Codex`,
  `TestInstallCodex_TOMLSnippet_ContainsAgentEnv`,
  `TestShowConfig_YAML_ContainsEnvBlock`,
  `TestShowConfig_JSON_ContainsEnvBlock`,
  `TestAgentNameForClient_KnownClients`) + tightening of the
  existing `TestServerConfigDict_Shape` env assertion. Smoke
  verified: `kbounce mcp install-claude-code --path /tmp/kb.json`
  → `jq .mcpServers.kbounce.env` → `{"KBOUNCE_AGENT_NAME":
  "claude-code", "KBOUNCE_AGENT_SESSION_ID": ""}` (cursor →
  `"cursor"`, codex → `"openai-codex"`). Per
  `[[cross-product-agent-parity]]` + `[[deliberate-feature-completion]]`:
  the CHANGELOG promise from #308 now matches behavior. Ibounce
  (`iam-roles/src/iam_jit/bouncer_cli.py:_ibounce_mcp_config_dict`)
  was independently verified during the #375 audit and already
  emits the populated env block — no parallel fix needed there.

### Changed

- **#296 / §A22 — SQLite store concurrency hardening (CRITICAL audit-loss fix)** (2026-05-22) —
  kbouncer's `internal/store/store.go` `Open()` now applies
  `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`,
  `foreign_keys=1` via DSN PRAGMA bindings so EVERY connection in the
  `sql.DB` pool inherits the settings. Pre-#296 kbouncer used the
  modernc.org/sqlite defaults (rollback-journal + synchronous=FULL +
  no busy_timeout); a 20-session load probe lost **11,791 of 12,000
  audit rows** to `SQLITE_BUSY` because two pool goroutines could
  simultaneously attempt `BEGIN IMMEDIATE` on different connections.
  After the DSN tuning: 12,000/12,000 committed at 20 writers, 0
  errors, p99 = 10ms (was effectively unbounded due to the lost
  writes). The new posture matches dbounce's PRAGMA shape (which
  already had busy_timeout) with the WAL addition shared across all
  three Go bouncers per `[[cross-product-agent-parity]]`. No schema
  change; no public API change; data on existing DBs is preserved
  verbatim (WAL mode is per-database, sticky on first connection +
  retained by SQLite across opens). Verified by
  `internal/store/concurrency_load_test.go` (build-tagged `loadtest`
  so normal `go test ./...` skips it). Lifts §B13's "1-3 concurrent
  terminals in v1.0" caveat — the new measured ceiling at the audit-
  write layer is **30+ concurrent agent sessions on one machine** with
  zero dropped audit events.

### Added

- **#342 / §A23 — Formal Apache-2.0 LICENSE + NOTICE + README license attribution** (2026-05-23) —
  kbouncer had NO `LICENSE` file at all (the most acute gap surfaced
  by the 2026-05-23 verification; technically rendered the repo
  all-rights-reserved by default per Berne Convention despite the
  "open source" positioning). This slice ships the canonical
  Apache-2.0 LICENSE text with `Copyright 2026 trsreagan3` (founder
  direction), a `NOTICE` file with per-product attribution
  (`kbouncer — Kubernetes API bouncer (part of the iam-jit Bouncer
  suite)`), and a new `## License` section in the README. Same change
  shipped in iam-roles + gbounce + dbounce so the Bounce suite
  presents one coherent license posture per
  `[[cross-product-agent-parity]]`. Unblocks: Anthropic Cyber
  Verification Program application + iam-jit-vs-OneCLI competitive-
  matrix accuracy + pkg.go.dev license badge (Go tooling reads
  LICENSE directly — no go.mod change needed). Per-source-file
  SPDX-License-Identifier headers DEFERRED to v1.1 per
  `[[deliberate-feature-completion]]`.

- **#324b — dynamic-deny YAML watcher + matcher + mgmt-port reload endpoint** (2026-05-22) —
  kbouncer now consumes the cross-product
  `~/.iam-jit/dynamic-denies.yaml` file. The on-disk shape + cross-bouncer
  resolver semantics live in the canonical design doc at
  `iam-roles/docs/DYNAMIC-DENY-RULES.md`; the JSON Schema lives at
  `iam-roles/docs/schemas/dynamic-denies-v1.json`. This slice ships the
  kbouncer consumer (#324b only — sibling slices #324a/c/d cover
  ibounce + dbounce + gbounce; #324e ships the unified CLI + MCP
  fan-out; #324f embeds the same denies into JIT-issued roles).

  Surface:

  - New package `internal/dynamicdeny` — loader + watcher + matcher.
    The loader validates the YAML against the v1.0 schema shape
    (rule-id pattern, duration grammar, applied-to bouncer enum,
    duplicate-id rejection, product-magic discriminator) + filters
    down to rules whose `applied_to` list includes `"kbouncer"`
    (the historical `kbounce` alias is also accepted). Per
    `[[ibounce-honest-positioning]]` the loader rejects malformed
    YAML rather than silently dropping rules.
  - Three kbouncer-shaped target pattern kinds: `namespace:<glob>`,
    `cluster:<glob>`, and exact `<group>/<version>/<resource>`
    triples. `namespace` + `cluster` patterns support exact match,
    leading-`*.` suffix glob, and trailing `<prefix>-*` glob. Resource
    triples are exact (with `core` as a canonical synonym for the
    empty group the parser emits for core-API requests).
  - fsnotify-driven watcher (`fsevents` on macOS, `inotify` on Linux).
    Watches the parent directory so atomic-rename writes (`write-tmp +
    rename onto live path`) are caught. Rapid sequential writes are
    coalesced with a 100ms debounce quiet-period.
  - Parse errors on reload RETAIN the previous in-memory snapshot
    (fail-CLOSED per `[[ibounce-honest-positioning]]`) + emit a
    `dynamic_deny.parse_error` admin-action OCSF event so a SIEM
    surfaces the bad-file event without an operator having to grep.
  - The proxy's evaluator consults the snapshot AFTER profile +
    meta-discovery short-circuits but BEFORE per-task + global rule
    evaluation. A dynamic-deny match short-circuits to DENY with
    `decision_source="dynamic-deny"`, `deny_source="dynamic"`, and
    `dynamic_deny_rule_id="dd_..."`. Per the cross-product design
    doc: deny always wins over allow — dynamic-deny beats
    profile-allow + task-allow + global-allow.
  - Deny audit events now carry `unmapped.iam_jit.ext.deny_source` +
    `unmapped.iam_jit.ext.dynamic_deny_rule_id` so a SIEM analyst can
    pivot on either field. Mirrors gbounce #324d byte-for-byte per
    `[[cross-product-agent-parity]]`.
  - New flag `kbounce run --dynamic-denies-path PATH` (default
    `~/.iam-jit/dynamic-denies.yaml`; also honors
    `$IAM_JIT_DYNAMIC_DENIES_PATH`). Companion flag
    `--disable-dynamic-denies` turns the channel off for operators
    who haven't installed the cross-product CLI yet.
  - Startup banner emits one line per `[[cross-product-agent-parity]]`:
    `dynamic-denies: N rules loaded from PATH (M applied to kbouncer;
    watching for changes)`.
  - New endpoint `POST /admin/dynamic-denies/reload` on the mgmt port
    (the kbouncer proxy port doubles as the mgmt port). Triggers an
    immediate reload from disk + returns
    `{"reloaded":true,"rules_count":N,"rules_applied_to_kbouncer":M,
    "path":"..."}`. Parse errors return 422 with the structured
    error. Useful for the cross-bouncer fan-out CLI (#324e), which
    writes the YAML then POSTs each Bounce product's mgmt port to
    confirm the rules are live.
  - `/healthz` now reports `dynamic_denies_enabled`,
    `dynamic_denies_count`, `dynamic_denies_path`,
    `total_dynamic_deny_matches`, `total_dynamic_deny_reloads`, and
    `total_dynamic_deny_parse_errors`. Counter naming mirrors the
    cross-product spec.
  - New admin-action constants `audit.AdminActionDynamicDenyReloaded`
    + `audit.AdminActionDynamicDenyParseError`. The CLI wires an
    emit-callback on the watcher that tees a `dynamic_deny.reloaded`
    OR `dynamic_deny.parse_error` admin-action event with
    `unmapped.iam_jit.ext.dynamic_deny_reload_reason ∈ {file_created,
    file_modified, file_removed, reload_requested, parse_error}` per
    the canonical design doc.

  Tests:

  - `internal/dynamicdeny/loader_test.go` — 18 tests (valid YAML;
    missing-file = no error; 6 schema-violation rejections;
    applied-to filter; namespace glob matrix; cluster glob matrix;
    resource-triple matrix including the empty-group `core` alias;
    expired-rule filter; unrecognized-target silent skip; kbounce
    alias acceptance; round-trip JSON/YAML shape; env-var path).
  - `internal/dynamicdeny/watcher_test.go` — 6 tests (file creation;
    file modification; rapid-write debounce; parse-error retain;
    manual ReloadNow; empty-path no-op).
  - `internal/proxy/dynamic_deny_test.go` — 13 tests covering
    namespace match, cluster match, resource-triple match (with
    no-match negative), precedence over profile-allow, callback
    bump, OCSF ext audit shape, reload-endpoint E2E (200 / non-POST
    / 503-no-watcher / 422-parse-error), and /healthz dynamic-deny
    surface.
  - 38 new tests; existing K-Slice 1-8 + #271 + #311 + #318 + #320
    regression suites continue to pass unchanged.

  New runtime dependency: `github.com/fsnotify/fsnotify v1.7.0` (one
  module — already a transitive dep of common Go ecosystem packages;
  same library + version gbounce + dbounce adopted for their #324c/d
  slices per `[[cross-product-agent-parity]]`).

  Per `[[creates-never-mutates]]`: this slice is additive — when the
  watcher is disabled (no path configured, file absent, or
  `--disable-dynamic-denies` set) the proxy's evaluator behavior is
  byte-identical to the pre-#324b shape.

  Per `[[deliberate-feature-completion]]`: this slice complete =
  loader + watcher + matcher + evaluator integration + CLI flags +
  mgmt endpoint + tests + CHANGELOG + README link.

  See `iam-roles/docs/DYNAMIC-DENY-RULES.md` for the cross-bouncer
  design + `iam-roles/docs/tasks/324-dynamic-deny-rules.md` for the
  per-slice tracking.

### Changed

### BREAKING — §A21 / [[discovery-first-default]] — default flips to DISCOVERY MODE — Shipped 2026-05-22

Per the role-effectiveness eval at
`iam-roles/tests/dogfood/role-effectiveness-grades.md`, kbouncer's v1.0
safe-default landed at 0% hit-rate against the 50% launch bar: both K1
(`rollout restart` PATCH) and K3 (`apply Deployment`) were NEGATIVE-VALUE
(legit DevOps refused alongside adversarial actions), and K2
(secret-pivot via `kubectl get secret -A`) was THEATER. gbounce alone
hit 66.7% with deny_hosts + MITM URL+method primitives — operator-set
OPT-IN denies, not blanket safe-defaults.

The pivot flips kbouncer's runtime default to match: observe + audit +
pass-through (the `full-user` profile, which is already the default when
no `--profile` is set). Named profiles (`safe-default` + any custom)
stay first-class via explicit opt-in (`kbounce run --profile <name>` or
`export KBOUNCER_PROFILE=<name>`).

- **internal/cli/cli.go (banner):** headline banner now surfaces
  `default_mode=discovery|profile` alongside mode + default-policy +
  profile. Discovery fires when `activeProfile.Name` is empty,
  `full-user`, or the legacy `none` alias. The "no profile selected"
  block expands to explicitly name discovery mode (the canonical
  cross-product term) + frame as audit transparency per
  `[[security-team-positioning-safety-not-surveillance]]`.
- **No code path lost:** safe-default profile, OCSF audit, recommender,
  agent attribution (#318/#320), kubectl meta-discovery (#301) all
  continue to fire as before. The change is which DEFAULT rule layer
  is active out of the box. K8s API pass-through verified against the
  dogfood kind cluster.

**BREAKING-CHANGE for operators upgrading from pre-pivot v1.0 builds**
that auto-applied or framed `safe-default` as the v1.0 default.
Fresh installs + upgrades now land in discovery mode by default. To
keep pre-pivot behavior pin `kbounce run --profile safe-default` or
`export KBOUNCER_PROFILE=safe-default` in your shell rc. See
`iam-roles/docs/PROFILE-UPGRADE.md` + iam-roles KNOWN-CAVEATS §A21 for
the cross-product upgrade path; the re-graded corpus lives at
`iam-roles/tests/dogfood/role-effectiveness-grades-post-pivot.md`.

### #321 / §A19 — `kbounce profile doctor` upgrade-blindness fix — Shipped 2026-05-22

Cross-product fix for silent profile-upgrade-blindness across the
Bounce suite. kbouncer was vulnerable to the same shape that the
role-effectiveness eval 2026-05-22 surfaced on dbounce (D3): operators
who installed kbouncer before later-shipped safety floors (e.g.
`deny_subresource_writes` from #286) silently ran without those
floors because `~/.kbouncer/profiles.yaml` is intentionally never
overwritten (operator edits must survive).

- **internal/profile/doctor.go (new):** `Check()` diff-checks the
  installed profile YAML against a curated catalog of shipped default
  fields (`deny_subresource_writes`, `deny_on_impersonation` in v1.0).
  `Apply()` additively merges missing fields into the on-disk YAML +
  backs up the prior file (`<path>.bak-YYYYMMDD-HHMMSS`) before
  writing. `Acknowledge()` writes a per-operator stamp to suppress
  the startup banner until a new `ShippedDefaultsVersion` re-arms
  it. Per [[creates-never-mutates]]: additive only — operator-
  customized field values are never overwritten.
- **internal/cli/cli.go (extended):** `kbounce profile doctor`
  subcommand with `--apply` / `--acknowledge` / `--diff` / `--check`
  / `--json` flags. Same flag shape across all 4 Bounce products
  per [[cross-product-agent-parity]]. Also adds `kbounce profile
  install-defaults` (parity with dbounce + ibounce — was previously
  only writeable transparently via `kbounce run`).
- **internal/cli/cli.go (extended):** `kbounce run` startup-banner
  hook calls `profile.StartupBannerLine` after the existing caveats
  block. The one-line warning fires only when a safety-floor field
  is missing AND the operator hasn't acknowledged the current
  shipped-defaults version. Per
  [[security-team-positioning-safety-not-surveillance]]: framed as
  "your profile is behind" not "you are non-compliant."
- **internal/profile/doctor_test.go (new):** 7 tests cover fresh
  profile / missing-safety-floor / missing-convenience / apply-
  additive / apply-backs-up / acknowledge-silences /
  catalog-covers-embedded-defaults.

### #320 / §A18 — `/audit/events` wire-shape parity fix — Shipped 2026-05-22

Closes a UAT-discovered CRIT: the HTTP `/audit/events` projection
heuristically guessed `detected_from=mcp_clientinfo` whenever an
`agent_session_id` was persisted, mis-labelling http_header-detected
requests as MCP-detected. SIEM filters that distinguish "agent
declared via HTTP header" from "agent declared via MCP handshake"
silently lied.

- **store/store.go:** SchemaVersion bumped to 9. Adds
  `decisions.detected_from TEXT NOT NULL DEFAULT 'unknown'` via
  idempotent `ALTER TABLE` migration (v8 #289 columns landed without
  it). Pre-#320 rows surface "unknown" via the schema-level DEFAULT
  — historical events stay honest per `[[scorer-is-ground-truth]]`.
- **proxy/proxy.go:** `writeDecisionForTask` persists `DetectedFrom`
  from the AgentInfo built by `resolveAgentInfo` (the same source
  the JSONL log + webhook stream consume).
- **proxy/audit_events.go:** `agentInfoFromDecisionRow` replaced the
  heuristic with a stored-column read. Empty `DetectedFrom` falls
  through to `DetectionSourceUnknown` so handler code never has to
  nil-check.
- **cli/audit_tail.go:** Mirror change to `agentInfoFromRow` so
  audit-tail, investigate, web UI, /audit/events all read the same
  shape (cross-surface invariant).
- **audit/agent_context.go:** `AgentInfo` struct gains a
  `HeaderRejection any` field for §A18 structured rejection
  breadcrumbs (set by `resolveAgentInfo` when an inbound X-Agent-*
  header fails validation). `[[cross-product-agent-parity]] with
  ibounce + dbounce + gbounce.
- **audit/agent_header_rejection.go (new):** Cross-product bounded
  enum + classifier helpers (`invalid_name_charset` /
  `invalid_name_length` / `invalid_session_id_format` /
  `invalid_session_id_length`). Raw rejected value NEVER emitted;
  only its length, for safe forensics.
- **audit/event.go:** `FromDecision` splices the breadcrumb into
  `unmapped.iam_jit.ext.agent_header_rejection` when present.
- New regression test:
  `TestAuditEvents_320_DetectedFromReadsStoredColumn` in
  `internal/proxy/audit_events_test.go`. Existing
  `TestDecisionRowToEvent_*` tests updated to set `DetectedFrom`
  explicitly (no longer inferred).
- Closes `[[cross-product-agent-parity]]` parity with dbounce v7 +
  gbounce + ibounce.

### #317 / §A15 — cloud-neutral S3-compatible NDJSON object-storage sink — Shipped 2026-05-22

Closes the headline cloud-neutrality gap surfaced by founder
direction 2026-05-22: bouncers other than ibounce are
cloud-neutral; the AWS-only Security Lake adapter (#258) alone
doesn't serve operators on GCS / Azure Blob / MinIO / R2 / B2 /
DigitalOcean Spaces. kbouncer ships the new sink alongside the
existing JSONL + webhook + Security Lake transports per
[[creates-never-mutates]] (additive composition).

- **`kbounce run --audit-object-storage-endpoint URL
  --audit-object-storage-bucket NAME
  --audit-object-storage-prefix PREFIX
  --audit-object-storage-region REGION
  --audit-object-storage-credentials-file PATH
  --audit-object-storage-rotation-minutes N
  --audit-object-storage-max-size-mb N
  --audit-object-storage-instance-id ID`** — generic S3-compat
  sink. Per [[cross-product-agent-parity]] the flag shape is
  identical on ibounce + dbounce + gbounce.
- New package symbols: `audit.ObjectStorageWriter` +
  `audit.ObjectStorageCredentials` +
  `audit.LoadObjectStorageCredentials` +
  `audit.NewObjectStorageWriter` +
  `audit.ObjectStorageStatus` +
  `audit.ObjectStorageDefaultRotationMinutes` +
  `audit.ObjectStorageDefaultMaxSizeMB` +
  `audit.ObjectStorageDefaultRegion` +
  `audit.ErrObjectStorageNoCredentials` +
  `audit.ErrObjectStorageBucketUnreachable`. The writer is
  background-rotated; refuses to start when HeadBucket fails (so
  credential / endpoint / bucket-name misconfigurations surface
  immediately, not at first flush); fail-soft on Write; flushes
  synchronously on Close.
- Output layout: NDJSON (one OCSF event per line),
  gzip-compressed, Hive-partitioned at
  `{prefix}/year=YYYY/month=MM/day=DD/hour=HH/kbounce-{instance_id}-{timestamp}.jsonl.gz`.
  Athena / BigQuery / Spark / Trino auto-discover the partitions;
  SIEM collectors `LIST + GET` against the prefix.
- Per-instance file naming derives `instance_id` from
  `hostname-pid` (override with `--audit-object-storage-instance-id`).
- Additive `audit.Manager` field
  `ObjectStorageWriter *ObjectStorageWriter` + `ManagerOptions.
  ObjectStorageWriter`. `Manager.Emit` fans new events to the
  writer alongside the JSONL + webhook + Security Lake channels;
  `Manager.Close` flushes the writer synchronously. The aggregate
  `Status.ObjectStorage` embeds the writer's snapshot for the MCP
  audit-export status tool.
- Per [[self-host-zero-billing-dependency]]: destination is
  operator-owned (operator creates the bucket; kbounce never
  creates buckets). Per [[don't-tailor-to-lighthouse]]: generic
  S3-compat covers AWS S3 (native), GCS (S3 interop / HMAC), Azure
  Blob (S3-compat layer), MinIO, Cloudflare R2, Backblaze B2,
  DigitalOcean Spaces.

**What does NOT ship in v1.0** (deferred to v1.1 per
[[don't-tailor-to-lighthouse]]): native GCS auth (Workload
Identity) + native Azure Blob auth (Managed Identity). S3 interop
covers ~95% of operators today.

**Regression tests:** `internal/audit/object_storage_test.go` — 19
tests cover defaults, credentials resolution (env + YAML + INI),
partition path format, construction refusal, write/flush happy
path, status surface, size-cap synchronous flush,
drop-on-buffer-full, write-before-start no-op,
close-flushes-pending, put_object failure -> writes_ok=false, and
the rotation timer triggering a background flush.

**Task:** #317 — completed 2026-05-22.

### #319 / §A17 — UAT findings cluster: cross-product CLI parity (kbounce slice) — Fixed 2026-05-22

- **F-311-4 (HIGH)** — added `--audit-log-max-size-mb` + `--audit-log-max-age-days` + `--audit-db-retention-days` flags on `kbounce run` with matching `KBOUNCE_AUDIT_LOG_MAX_SIZE_MB` / `_MAX_AGE_DAYS` / `_DB_RETENTION_DAYS` env-var overrides. CLI flag wins when explicitly set; env var fills in otherwise; audit-package default (matches iam-roles/docs/LOG-RETENTION.md) wins last. Sentinel -1 = "use audit-pkg default"; 0 = "operator explicitly disabled trigger." Threaded through `buildAuditManager` into `audit.LogWriterOptions.{MaxSizeMB,MaxAgeDays}` so the live writer enforces both triggers. DB-retention is consumed by the on-demand `kbounce logs purge` subcommand (no writer-side DB sweep — `[[creates-never-mutates]]` keeps the live SQLite intact).
- **F-311-3 / F-304-1 / F-304-2 verified** — kbounce already ships `kbounce logs {archive,purge,verify}` + `kbounce doctor {caveats,logs}` + the `caveats.BannerLines(caveats.Trigger{SafeDefaultProfile: ...})` startup hook (verified via `/tmp/kbounce --help`). The §A17 findings doc was stale on these three items; documented as such in `iam-roles/docs/KNOWN-CAVEATS.md` §A17 closure notes.

Regression coverage: new `TestRunCmdRegistersRotationFlags` in `internal/cli/security_lake_test.go`. Existing `buildAuditManager` test callers updated to thread the new positional args.

### #318 / §A16 — cross-bouncer X-Agent-Session-Id header parity (2026-05-22)

Closes the headline cross-bouncer correlation gap surfaced by the
NanoClaw integration test. kbouncer now reads inbound `X-Agent-Name` +
`X-Agent-Session-Id` headers at HIGHEST detection precedence (above
the existing `X-Kbouncer-Session-Id` MCP registry lookup + the
User-Agent fingerprint fallback). Mirrors gbounce's #308 pattern
byte-for-byte so a SIEM query on `unmapped.iam_jit.agent.session_id=X`
is portable across all four Bounce products.

- `internal/audit/agent_context.go`:
  - New `IsValidAgentName()` mirroring gbounce + ibounce's regex
    `^[A-Za-z0-9._-]{1,64}$` byte-for-byte.
  - New `DetectionSourceHTTPHeader` + `DetectionSourceHTTPHeaderNameOnly`
    constants so the OCSF event surfaces the right detection source.
- `internal/proxy/proxy.go`:
  - `resolveAgentInfo` reads `X-Agent-Name` + `X-Agent-Session-Id`
    BEFORE the registry / UA fallback chain. Invalid headers are
    dropped (audited as `name="unknown"` / `detected_from="unknown"`)
    and never written to the audit event; the rejection callback
    bumps a per-Server `totalAgentHeadersRejected` counter + logs the
    truncated raw value (control chars replaced with `?`) so a
    malicious header can't reposition the operator's terminal cursor.
  - When `X-Agent-Session-Id` is valid but `X-Agent-Name` falls
    through to MCP / UA, the validated session_id overlays the
    downstream block so cross-bouncer correlation works.
  - `EvalOptions.RecordRejectedAgentHeader` callback for the
    rejection counter; `Server.recordRejectedAgentHeader` is the
    wired-up implementation.
  - `/healthz` payload now includes `total_agent_headers_rejected`
    (matches gbounce + ibounce fields of the same name).
- New tests in `internal/proxy/agent_headers_318_test.go` —
  canonical cross-product names `TestAgentHeaders_HappyPath`,
  `TestAgentHeaders_NoHeaders_FallbackToUserAgent`,
  `TestAgentHeaders_InvalidName_Rejected`,
  `TestAgentHeaders_NameOnly_PartialDetection`, plus
  `TestAgentHeaders_InvalidSessionID_Rejected`,
  `TestIsValidAgentName_MatchesGbounceRegex`,
  `TestAgentHeaders_UUIDv4_Accepted` (operators may use v4 or v7).

`docs/AGENT-ATTRIBUTION.md` + `docs/KNOWN-CAVEATS.md` §A16 live in the
iam-roles repo (cross-product reference); they're updated alongside
this slice. Cross-product integration test at
`iam-roles/tests/integration/cross_bouncer_session_id_parity_test.py`
fires one request through each Bouncer with the same session_id and
asserts the unified `iam-jit audit query` returns one event per
bouncer.

### #311 / §A10 — robust audit-log retention (2026-05-22)

Cross-product launch-blocker resolved. `kbounce` now rotates `audit.jsonl`
automatically at 100 MB or 7 days (whichever first), gzipping to
`audit-{YYYY-MM-DD-HHMMSS}.jsonl.gz` in the same dir. New surface:

- `kbounce logs purge --older-than 7d --yes` — retention sweep of rotated
  archives (never touches the active `audit.jsonl`)
- `kbounce logs archive --out FILE` — tar.gz bundle for SIEM hand-off
- `kbounce logs verify` — gzip + JSONL integrity check
- `kbounce doctor logs` — integrity + freshness + retention + disk checks
  (exits non-zero on any failure)
- Crash recovery: partial JSONL tail truncated on startup; emits
  `audit.log.recovered_partial` admin-action
- Rotation lifecycle admin-actions: `audit.log.rotated`,
  `audit.log.rotation_failed`, `audit.log.recovered_partial`
- LogWriter Options: `MaxSizeMB`, `MaxAgeDays`, `OnRotation`,
  `OnRotationFailure`, `OnRecovery`
- Status getters: `Rotations()`, `RotationFailures()`,
  `LastRotationPath()`, `PartialBytesRecovered()`, `MaxSizeMB()`,
  `MaxAgeDays()`
- Cross-product runbook: `iam-roles/docs/LOG-RETENTION.md`
- 21 new tests in `internal/audit/rotation_test.go`

### #308 — cross-bouncer agent-attribution env-var injection (2026-05-22)

`kbounce mcp install-*` now stamps `KBOUNCE_AGENT_NAME` +
`KBOUNCE_AGENT_SESSION_ID` env vars on the generated MCP server entry
so the agent runtime carries the same identity into outbound HTTP
calls. Per-client defaults:

- `install-claude-code` → `KBOUNCE_AGENT_NAME=claude-code`
- `install-cursor`       → `KBOUNCE_AGENT_NAME=cursor`
- `install-codex`        → `KBOUNCE_AGENT_NAME=openai-codex`

`KBOUNCE_AGENT_SESSION_ID` is left empty in the static snippet — the
agent runtime mints a fresh UUID v7 per session. New
`ServerConfigDictForAgent(agentName)` + `ServerEntryForAgent(agentName)`
+ `agentNameForClient(clientName)` helpers in
`internal/mcpinstall/install.go`; the existing `ServerConfigDict()` +
`ServerEntry()` calls fall through to `DefaultAgentName="claude-code"`
so external callers are unaffected. `kbounce mcp show-config` footer
points operators at `iam-roles/docs/AGENT-ATTRIBUTION.md` for the
per-runtime header-injection patterns. Mirrors the parallel ibounce
slice on the iam-roles side.

Per `[[cross-product-agent-parity]]`: the gbounce side of this same
work ships under the same task #308 ticket; the on-disk OCSF wire
shape is identical across kbounce + gbounce so a SIEM operator's
saved query reads the agent block uniformly across products.

### #304 — KNOWN-CAVEATS discoverability surfaces (2026-05-22)

Per founder direction 2026-05-22: caveats must be easily discoverable to
users + agents, not buried in `docs/KNOWN-CAVEATS.md`. This slice ships
four surfaces:

- `internal/caveats/` — new package centralizes the kbounce-relevant
  §B entries (B5 product-specific; B13 + B14 + B15 cross-product) + the
  GitHub markdown anchors. `caveats.BannerLines(Trigger)` returns the
  startup-banner lines to emit; `caveats.DoctorEntries()` returns the
  full applicable list; `caveats.LinkSuffix(id)` produces an inline
  `(see KNOWN-CAVEATS §X: <URL>)` suffix.
- **README "Known limitations" section** — top 3 kbounce-relevant §B
  entries (B5 / B13 / B14) linked to the canonical doc.
- **Startup banner** — `kbounce run` emits the §B5 line on every
  startup (kbounce's apiserver-edge shape is structural — the operator
  should see the caveat from line one of every run). Quiet otherwise
  per the founder's "useful, not noise" directive.
- **`kbounce doctor caveats`** — new subcommand under the `doctor`
  command group (added alongside `doctor logs` from #311). Same shape
  across the Bounce suite per `[[cross-product-agent-parity]]`.
- **MCP tool descriptions** — `kbounce_active_mode` description now
  embeds a §B5 reference + link (agents reading `tools/list` see the
  caveat at registration time, before the first tool call). The
  `kbounce_active_profile` description gets a verb-level / pair-with-
  iam-jit note per the founder direction in #304.

### #306 + #307 — canonicalize `go install` as the install path; no checked-in `bin/` (2026-05-22)

Closes KNOWN-CAVEATS §A8. The repository never tracked `bin/kbounce`
(it was gitignored via the existing `bin/` pattern in `.gitignore`),
but the README still led with `go build ./cmd/kbounce` followed by
`./kbounce run`, which papered over the canonical install story and
left the door open for someone to commit a stale binary in the future.

- **README "Install" section** — rewrites the Quickstart lead to
  `go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest` as
  the canonical first-time-install path. Every user who follows the
  README gets a fresh build straight from source; no pre-built binary
  can lag the codebase. Local-dev iteration via `make build` /
  `go build -o bin/kbounce ./cmd/kbounce` is documented in a separate
  subsection with an explicit reminder that `bin/` is gitignored.
- **Makefile `install` target** — wraps `go install ./cmd/kbounce` +
  `./cmd/kbouncer` so local-dev iteration can match the canonical
  install path without re-typing the module URL.
- **Makefile `build` target** — now drops binaries into `./bin/`
  (gitignored) instead of the working directory, so source-tree
  iteration produces a predictable artifact location that won't
  collide with git tracking.
- Per `[[creates-never-mutates]]` this slice is hygiene-only — no
  surrounding code touched. Per `[[push-policy-public-repo]]` diff
  scanned for sensitive data before push.

### #301 — kubectl OpenAPI discovery + apiserver meta paths classified as IsMetaRead (2026-05-22)

UAT-2026-05-22 (Variants A + C) surfaced that every `kubectl`
invocation through kbounce under `--profile safe-default` failed at
step 12 with an `unclassifiable URL shape` deny. Root cause: the
first thing kubectl does on EVERY call is hit `/openapi/v3/<group>`
for API discovery (1.24+ default); `client-go` similarly hits
`/api`, `/apis`, `/api/v1`, `/apis/{group}/{version}` to enumerate
the API surface. kbounce's parser only knew about resource-shaped
URLs (`/api/{v}/{res}/...`, `/apis/{g}/{v}/{res}/...`), so every
discovery path returned `ErrMalformedURL` → `unclassifiable` →
default-deny under safe-default. The UAT's "blocked Deployment
apply" finding was actually the OpenAPI bootstrap call being
denied, not the Deployment create.

CRITICAL severity — made kbounce unusable with kubectl on
safe-default, the very profile we recommend to most operators.

**Fix shape, per `[[scorer-is-ground-truth]]`:** parser-side
recognition of the meta-discovery URL shapes; we did NOT widen
safe-default's `deny_verbs` carve-outs to compensate.

Parser changes (`internal/parser/parser.go`):

- New `ParsedRequest.IsMetaRead bool` field. Set to true when the
  request targets a kube-apiserver meta/discovery surface rather
  than an API resource.
- New `classifyMetaPath(method, segments)` helper. Runs BEFORE the
  `/api`/`/apis` segment switch. Recognizes (GET only):
    - `/openapi/v2[/...]` and `/openapi/v3[/...]` → `meta:openapi-schema`
    - `/api` → `meta:api-discovery`
    - `/api/{version}` (e.g. `/api/v1`) → `meta:api-version-discovery`
    - `/apis` → `meta:api-discovery`
    - `/apis/{group}` and `/apis/{group}/{version}` → `meta:api-group-discovery`
    - `/version` → `meta:version`
    - `/healthz`, `/readyz`, `/livez`, including subprobes
      (`/healthz/etcd`, `/readyz/poststarthook/...`) → `meta:health`
    - `/metrics` → `meta:metrics`
- Meta-classified requests populate `Verb=get`, `Group=""`,
  `Resource="meta:<kind>"`, `IsMetaRead=true`, with empty
  Namespace/Name/Subresource. The path's full RawPath is preserved
  in the audit row.
- Writes (POST/PUT/PATCH/DELETE) on the same prefixes stay
  unclassifiable. Per `[[creates-never-mutates]]` the fast-path is
  read-only; the apiserver itself 405s writes on these surfaces, so
  refusing to widen the carve-out is the safe default.
- The existing `/api` + `/apis` resource-tail branches tightened
  their length checks (`< 3` for `/api`, `< 4` for `/apis`) so the
  meta-discovery surfaces no longer leak into the resource-shape
  parser. /api/v1/pods and /apis/apps/v1/deployments are unaffected.

Proxy changes (`internal/proxy/proxy.go`):

- New `SourceMetaDiscovery = "meta-discovery"` decision-source
  constant. Surfaced on the audit row + `x-kbouncer-decision-source`
  header so reviewers can filter discovery noise out of decision
  queries with `WHERE decision_source != 'meta-discovery'`.
- Short-circuit branch immediately AFTER profile evaluation: when
  `parsed.IsMetaRead==true` and the profile abstained, the proxy
  emits `VerdictAllow` + `SourceMetaDiscovery` + a self-describing
  reason. Pause / task-scope / global-rule / default-policy
  composition order is unchanged for every non-meta request.
- The carve-out sits AFTER profile evaluation, so a custom profile
  that adds `deny_keywords: [discovery]` (or any other layer)
  retains hard-floor control — `IsMetaRead` is a fall-through
  allow, not an override.

Regression tests:

- `internal/parser/parser_test.go`:
    - `TestParse_MetaDiscoveryPaths` — 17 GET cases (all meta
      shapes incl. dotted-group OpenAPI per-document URLs) +
      24 write cases asserting writes stay unclassifiable.
    - `TestParse_ResourceTailNotMistakenForMeta` — 4 real-resource
      shapes (`/api/v1/pods`, `/apis/apps/v1/deployments`, etc.)
      confirming the length-check tightening didn't swallow real
      resource calls.
    - `TestParse_MalformedURLs` updated to drop /healthz, /metrics,
      /api, /api/v1, /apis/apps from the malformed set (they're
      now meta-reads) and added /swagger.json + /foobar as the
      residual unclassifiable shapes.
- `internal/proxy/proxy_test.go`:
    - `TestEvaluateRequest_MetaDiscoveryAllowedUnderSafeDefault` —
      14 meta paths × asserts `VerdictAllow` +
      `DecisionSource=SourceMetaDiscovery` under
      `safe-default` profile + `DefaultPolicyDeny`. This is the
      primary #301 closure test.
    - `TestEvaluateRequest_MetaDiscoveryWritesStillDenied` — 4
      methods × `/openapi/v3/api/v1` asserting writes stay
      unclassifiable (the carve-out is read-only).
    - `TestEvaluateRequest_RealResourceCallStillFlowsThroughProfile` —
      2 cases confirming GET on a real resource is NOT
      meta-discovery, and POST on a real resource is still denied
      by safe-default with `source=profile` (the fix didn't
      regress write protection).
    - `TestEvaluateRequest_UnclassifiableYieldsDeny` updated to
      use `/swagger.json` instead of `/healthz` (the latter is
      now a meta-read).

End-to-end verification: kbounce built and run as
`run --profile safe-default --mode transparent --default-policy deny`
pointed at a kind cluster; direct `curl` probes against all 12
canonical meta paths (`/openapi/v3`, `/openapi/v3/api/v1`,
`/openapi/v3/apis/apps/v1`, `/api`, `/apis`, `/api/v1`,
`/apis/apps/v1`, `/version`, `/readyz`, `/livez`, `/metrics`,
plus the bouncer-owned `/healthz` which is short-circuited by
the audit-UI handler) returned `x-kbouncer-verdict: allow` +
`x-kbouncer-decision-source: meta-discovery`. The audit log
tail confirmed `meta-discovery / allow` for each. POST on the
same paths returned `verdict=deny source=unclassifiable`; POST
on `/api/v1/namespaces/default/pods` returned
`verdict=deny source=profile`. Per
`[[deliberate-feature-completion]]` the fix ships as one unit
with tests + CHANGELOG + KNOWN-CAVEATS update in lockstep. Per
`[[push-policy-public-repo]]` diff scanned for sensitive data
before push.

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
