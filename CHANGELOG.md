# kbounce changelog

All notable changes to `kbounce` (formerly `kbouncer`) get recorded
here. Versioning follows semver from v1.0.0 onward.

## Unreleased

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
