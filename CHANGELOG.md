# kbounce changelog

All notable changes to `kbounce` (formerly `kbouncer`) get recorded
here. Versioning follows semver from v1.0.0 onward.

## Unreleased

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
