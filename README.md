# kbounce

**Local Kubernetes API-call gating proxy.** Sits between your kubectl /
Helm / coding agent and the real kube-apiserver, parses every request,
records the decision in a SQLite audit log, and (in transparent mode)
can deny calls that don't match its rule set.

`kbounce` is one product in the Bounce suite — the K8s-shaped sibling
of `bounce` (the AWS-SDK-shaped local proxy in the `iam-jit` /
`iam-roles` repo). Both products use the same vocabulary: profiles,
modes, rules, tasks, prompts, pauses. An operator who learned one
understands the other.

The binary was renamed from `kbouncer` to `kbounce` in the 2026-05-17
Bounce-suite rename. The old `kbouncer` binary keeps working for v1.0
with a one-line deprecation warning + is removed in v1.1.

---

## Quickstart

```sh
# Build (single static binary).
go build ./cmd/kbounce

# Default run: cooperative mode, no profile (passthrough), audit-only.
# Banner reminds you about --profile safe-default for the deny layer.
./kbounce run

# Opt into the safe-default safety net:
./kbounce run --profile safe-default
# Or, persistent for your shell:
export KBOUNCER_PROFILE=safe-default
./kbounce run
```

Default port: `8766` (distinct from `bounce`'s `8767` so the two
products can coexist on the same laptop). Default audit DB: `~/.kbouncer/state.db`.

---

## Operating modes

| Mode | Behavior | Use case |
| --- | --- | --- |
| `cooperative` (default) | Parse + log every call; always forward. Verdicts are advisory. | Solo dev iterating fast; previewing what transparent mode would block. |
| `transparent` | DENY verdicts return HTTP 403 to the client. ALLOW forwards unchanged. | Locked-down environments; lower-trust agents; compliance deploys. |

Switch with `--mode cooperative` or `--mode transparent`.

---

## Profiles (the default-profile reshape)

A **profile** is an environment-aware deny layer that fires BEFORE
per-task scopes + global rules. A profile deny is a **hard floor** —
a permissive task scope cannot override it.

Built-in defaults (only two, intentionally):

| Profile | What it does |
| --- | --- |
| `full-user` | Passthrough; no rules. Calls forwarded as-is + audit-logged. **Default** when `--profile` / `KBOUNCER_PROFILE` is unset. |
| `safe-default` | Cross-product safe-by-default. Blocks operations whose blast radius is high enough that the average operator wants them gated: mutating verbs (`delete`/`patch`/`create`/`update`/`deletecollection`), destructive non-writes (`exec`/`portforward`/`attach`/`eviction`), state-changers (`status`/`scale`/`finalize`), privilege primitives (`proxy`/`token`/`binding`/`ephemeralcontainers` + impersonation headers), and CRD-defined mutating subresources (long-tail safety net). Carves out SSAR/SAR/TokenReview previews and `?dryRun=All` requests. NOT a confidentiality boundary — reads of sensitive data still pass. |

Activate with `--profile NAME` or `KBOUNCER_PROFILE=NAME`. When neither
is set, `kbounce run` prints a one-line banner reminding you you're in
passthrough mode + the two ways to opt into `safe-default`.

### Backward-compat aliases

Legacy profile names resolve to their canonical replacements with a
one-line deprecation notice. v1.1 removes the aliases.

| Legacy | Canonical |
| --- | --- |
| `none` | `full-user` |
| `prod-readonly` | `safe-default` |
| `readonly` | `safe-default` |

### Community profiles

Environment-specific profiles (`staging-work`, `dev-only`,
`incident-response`) ship under `community-profiles/` in this repo
rather than as built-in defaults. Install one with:

```sh
kbounce profile install --from https://raw.githubusercontent.com/trsreagan3/kbouncer/main/community-profiles/staging-work.yaml
```

Org-curated profiles install the same way. The fetched URL becomes the
profile's `source`; org-distributed profiles (non-local `source`) are
READ-ONLY at the CLI surface — engineers cannot edit them to bypass
SecOps guardrails.

---

## Subcommand reference

### `kbounce run`

Start the HTTP proxy. The most-used flags:

- `--port 8766` — listen port (loopback only).
- `--host 127.0.0.1` — interface. Binding to anything else requires
  `--i-know-this-binds-externally` to acknowledge the credential-
  handling threat surface.
- `--mode cooperative|transparent` — see above.
- `--default-policy allow|deny` — what transparent mode does when no
  rule matches.
- `--profile NAME` — environment profile. Defaults to `full-user`
  (passthrough). See "Profiles" above.
- `--upstream URL` / `--kubeconfig PATH` — apiserver to forward to.
  When unset, the proxy returns observation-only JSON instead of
  proxying.
- `--tls-cert PATH` / `--tls-key PATH` / `--require-client-cert PATH` —
  inbound TLS / mTLS. Generate the material with `kbounce init-tls`.
- `--prompt-on-deny` — async deny-prompt UX. Every transparent-mode
  DENY queues a prompt the operator can answer later via
  `kbounce prompts answer`.

### `kbounce init-tls`

One-time setup. Writes `ca.crt` / `ca.key` / `server.crt` / `server.key`
into `~/.kbouncer/tls/`. Add `ca.crt` to your kubectl context's
`certificate-authority` field + start the proxy with `--tls-cert ...
--tls-key ...`.

### `kbounce profile {list, show, install}`

- `kbounce profile list` — show available profiles + which one is
  currently active (per `--profile` / `KBOUNCER_PROFILE`).
- `kbounce profile show NAME` — full record for one profile (deny
  keywords, deny verbs, only-clusters, exceptions, allow rules).
- `kbounce profile install --from URL [--sha256 HEX] [--force]` —
  fetch + install profiles from an HTTPS URL. `http://` refused.
  Installed profiles' `source` is the URL; they are read-only at the
  CLI.

### `kbounce audit tail [--limit N]`

Show the most recent N decisions, newest first. `--limit` must be
1-1000 (rejected at parse time; closes UAT-K2 HIGH-K2-03).

### `kbounce rules {add, list, remove}`

Global rule table consulted between the profile-deny hard floor and the
default-policy fallthrough.

- `kbounce rules add --pattern P --effect E [--namespace-scope NS] [--resource-scope RS]` —
  insert a rule. Pattern shape `resource:verb_glob` (e.g. `pods:*`,
  `*:delete*`).
- `kbounce rules list [--json]` — show all rules in evaluation order.
- `kbounce rules remove ID` — delete by numeric id.

### `kbounce tasks {start, active, end, review, list}`

Per-task scopes. An agent (or you) declares a task scope at start;
kbounce enforces it for the duration; the audit log captures the
lifecycle.

- `kbounce tasks start --description "..." [--allow CSV] [--deny CSV] [--ttl 30m]` —
  open a task. Shorthand: `pattern[@namespace][#resource_name]` (e.g.
  `pods:*@prod-billing`, `*:delete*`). Malformed shorthand like
  `@ns=value` is rejected with a clear pointer (UAT-K2 HIGH-K2-01).
- `kbounce tasks active` — show current task if any.
- `kbounce tasks end [--reason "..."]` — close the current task.
- `kbounce tasks review TASK_ID` — post-task summary: decisions,
  allow/deny breakdown, denied calls.
- `kbounce tasks list` — newest-first task history.

### `kbounce prompts {list, show, answer}`

When the proxy runs with `--prompt-on-deny`, every transparent-mode
DENY queues a row here.

- `kbounce prompts list [--status pending|answered|ignored]` — show
  the queue.
- `kbounce prompts show ID` — full prompt detail.
- `kbounce prompts answer ID --kind always|profile|ignore [--target NAME]` —
  answer + apply side effect. The agent has already been denied;
  answers take effect on the NEXT call of the same shape.

### `kbounce pause {start, stop, status, history}`

Timed escape hatch — temporarily demote the proxy to advisory mode for
a window. The proxy keeps observing + logging every call (decisions
audit row links to the pause id), but DENY verdicts no longer return
403. Auto-reverts at expiry; resume early with `pause stop`.

- `kbounce pause start --for 30m [--reason "..."]` — open a window.
- `kbounce pause stop` — end the active window early.
- `kbounce pause status` — show the active window if any.
- `kbounce pause history [--limit N]` — recent windows for audit
  review.

### `kbounce rules recommend`

Synthesize draft rules from observed audit-log traffic (cross-product
parity with `ibounce recommend`):

```
kbounce rules recommend [--since 24h] [--min-support 3] [--limit N]
                        [--apply] [--apply-only CSV]
                        [--include-task-scoped]
                        [--save-as-profile [NAME]]
                        [--profile-description "..."]
                        [--db PATH] [--json]
```

Deterministic — no LLM. Groups ALLOW decisions by (resource, verb),
thresholds on `--min-support`, applies longest-common-prefix detection
for namespace + resource-name scopes. `--apply` persists the rules;
`--save-as-profile [NAME]` writes a NEW local profile. NAME is OPTIONAL
per `[[profile-auto-naming]]`: with a TTY kbounce prompts with a
suggested default (`auto-2026-05-17-pods-readonly`); without a TTY it
auto-generates the name + prints it to stderr.

### `kbounce presets {list, show, apply}`

Curated K8s rule packs — operators (and agents) get starting points
for common shapes instead of authoring from scratch. Five starter
presets ship in v1.0:

- `cluster-admin-minus-destructive` — broadly permissive, blocks the
  highest-blast-radius primitives (deletecollection, pods/exec,
  pods/portforward, pods/attach, pods/eviction, token-mint, binding)
- `eks-cluster-survey` — read-only investigation (get/list/watch
  allow; mutating verbs deny)
- `argocd-app-controller` — GitOps starter (Argo CD verbs +
  cross-resource reads)
- `gke-developer` — dev-environment investigation (reads on workloads
  + log streaming; deny writes)
- `incident-response-readonly` — stricter than `eks-cluster-survey`;
  blocks pod-log + secret reads on `prod-*` namespaces for
  confidentiality during non-prod investigations

Presets are SEPARATE from the `safe-default` profile (the profile is
a hard floor; presets are global-rule starters). They compose.

### `kbounce mcp`

Run the MCP-over-stdio server an agent (Claude Code, Cursor, Codex,
Devin) connects to. Tool family: `kbounce_active_mode`,
`kbounce_active_profile`, `kbounce_active_task`,
`kbounce_recommend_mode_for_task`, `kbounce_scope_self_for_task`,
`kbounce_end_task`, `kbounce_task_review`, `kbounce_list_rules`,
`kbounce_add_rule`, `kbounce_remove_rule`, `kbounce_decide`,
`kbounce_tail_decisions`, `kbounce_recommend_rules`,
`kbounce_list_presets`, `kbounce_apply_preset`.

The MCP server reads the SAME on-disk state the running proxy uses
(`--db` + `--profiles-path`). It does NOT start a proxy listener of
its own — run `kbounce run` separately for the gating + forwarding
layer.

stdin/stdout reserved for the JSON-RPC stream; logs + banner go to
stderr.

### `kbounce version-check`

One-shot, opt-in check against the GitHub Releases API. Prints
`kbounce vX.Y.Z is up to date.` or `kbounce vX.Y.Z is OUT OF DATE.
Latest: vA.B.C. Upgrade: brew upgrade kbounce  or  https://github.com/trsreagan3/kbouncer/releases/latest`.
Exits 0 in every success path AND on network / parse failure
(informational, not a CI gate). Disable entirely with
`export KBOUNCE_NO_VERSION_CHECK=1` — the env-var path performs no
HTTP call. No telemetry: a single `GET` to GitHub's public releases
endpoint with `User-Agent: kbounce/<version>` (no instance id, no
machine fingerprint). Mirrors the `ibounce version-check` Python
sibling.

### `kbounce --version`

Prints `kbounce <version> (commit X, built Y)`. Set at build time via
`-ldflags "-X github.com/trsreagan3/kbouncer/internal/cli.version=v1.0.0
-X github.com/trsreagan3/kbouncer/internal/cli.commit=$(git rev-parse HEAD)
-X github.com/trsreagan3/kbouncer/internal/cli.buildTime=$(date -u +%FT%TZ)"`.

---

## Liveness probe

`GET /healthz` returns 200 with a small JSON status payload (`status`,
`mode`, `default_policy`, `active_profile`, `decisions_count`,
`lookup_errors_counter`, `pause`). Never writes to the audit log;
safe to poll from monit / k8s liveness probes / systemd watchdogs.

The `lookup_errors_counter` field mirrors `bounce`'s healthz shape and
surfaces SQLite-class lookup failures (pause-lookup, active-task
lookup, ruleset load, prompt enqueue, audit write) so monitors can
flag degraded persistence without parsing logs.

---

## Test

```sh
cd kbouncer
go build ./... && go vet ./... && go test ./...
```

All tests are pure-Go and use a temp-directory SQLite DB per test — no
external cluster, no Docker, no fixtures to manage.

---

## Layout

```
kbouncer/
├── cmd/kbounce/                  # canonical binary (5 lines; delegates to internal/cli)
├── cmd/kbouncer/                 # v1.0 deprecation shim — warns + delegates
├── community-profiles/           # opt-in profiles installed via `kbounce profile install`
├── internal/cli/                 # all cobra command wiring; shared by both binaries
├── internal/parser/              # kube-apiserver URL → ParsedRequest
├── internal/profile/             # environment profiles (full-user, safe-default, + custom)
├── internal/proxy/               # Mode + Config + Server + EvaluateRequest
├── internal/rules/               # global rule table
├── internal/store/               # SQLite-backed audit + rules + tasks + prompts + pauses
├── internal/tasks/               # per-task scope shorthand parser + builder
├── internal/tlsmat/              # local CA + server cert generator (`kbounce init-tls`)
├── internal/upstream/            # kubeconfig parser + upstream resolution
├── internal/mcp/                 # MCP-over-stdio server (kbounce_* tools)
├── go.mod                        # module path stays github.com/trsreagan3/kbouncer for v1.0
└── README.md
```

The Go module path stays `github.com/trsreagan3/kbouncer` for v1.0 to
minimize downstream import-path breakage. A future v1.x may move the
module path with a `go.mod replace` directive for one release.

`internal/...` packages are intentionally not exported — `kbounce` is a
shipped binary, not a library other Go programs link against.

---

## Position in the Bounce suite

The LLC ships five products under one umbrella, all built on the same
JIT + audit + ground-truth-scorer DNA:

1. **iam-risk-score.com** — free hosted stateless AWS-IAM-policy scorer.
2. **bounce** — local AWS-SDK-call gating proxy (Python; lives in
   `iam-jit` repo).
3. **kbounce** (this repo) — local K8s-API-call gating proxy (Go;
   single static binary).
4. **iam-jit CLI / SaaS** — JIT IAM credential issuer.
5. **iam-jit Enterprise** — self-hosted, license + support + advanced
   plugins.

Same brand, same scorer DNA, same "creates / never mutates" invariant.
Different audiences, different friction profiles, different
distribution channels — separate products so each can find its own
PMF.
