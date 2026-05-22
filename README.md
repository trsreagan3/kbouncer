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

## Install

```sh
# Canonical install — builds the binary fresh from source into $GOPATH/bin
# (or $HOME/go/bin if GOPATH is unset). Make sure that directory is on
# your PATH.
go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest
```

Then:

### First 60 seconds with kbounce (discovery mode default)

Per `[[discovery-first-default]]` (2026-05-22) + iam-roles KNOWN-CAVEATS
§A21 the canonical shape is **discovery mode** — observe + audit +
pass-through. Closes the K1/K3 NEGATIVE-VALUE failures from the
role-effectiveness eval where the pre-pivot safe-default-as-default
blocked legit DevOps (`rollout restart`, `apply Deployment`) alongside
adversarial actions.

```sh
# Default run: discovery mode (no profile applied; calls forwarded + audit-logged).
# Headline banner reports default_mode=discovery; full OCSF event stream operates as usual.
kbounce run --upstream https://<your-cluster-api>:6443

# Opt into the safe-default safety net (the pre-pivot behavior):
kbounce run --profile safe-default --upstream ...
# Or, persistent for your shell:
export KBOUNCER_PROFILE=safe-default
kbounce run --upstream ...
```

### After upgrade: `kbounce profile doctor` (one-time)

kbounce never overwrites `~/.kbouncer/profiles.yaml` (your edits
survive upgrades), so a new safety floor added to embedded defaults
won't land until you opt in. After upgrading the binary, run:

```sh
kbounce profile doctor          # report missing fields (no write)
kbounce profile doctor --apply  # additively merge + back up prior file
```

See [docs/PROFILE-UPGRADE.md](../iam-roles/docs/PROFILE-UPGRADE.md)
for the full runbook (task #321 / KNOWN-CAVEATS §A19).

### Local development build

If you're iterating on the source tree:

```sh
# Drops the binary into ./bin/kbounce (gitignored).
make build

# Or invoke go directly:
go build -o bin/kbounce ./cmd/kbounce
./bin/kbounce run
```

`bin/` is gitignored — never commit a pre-built binary. Users pick up
fresh source via `go install ...@latest` and get an up-to-date build
every time. Closes #306 / #307 + KNOWN-CAVEATS §A8.

Default port: `8766` (distinct from `bounce`'s `8767` so the two
products can coexist on the same laptop). Default audit DB: `~/.kbouncer/state.db`.

### Docker

Prebuilt multi-arch images (`linux/amd64` + `linux/arm64`) are published
to GHCR on every push to `main` and on every `v*` tag:

```sh
# Cooperative-mode passthrough, kubeconfig + audit DB mounted from host.
docker run --rm \
  -p 8766:8766 \
  -v ~/.kube:/home/nonroot/.kube:ro \
  -v ~/.kbouncer:/home/nonroot/.kbouncer \
  ghcr.io/trsreagan3/kbounce:latest \
  run --host 0.0.0.0 --port 8766 \
      --kubeconfig /home/nonroot/.kube/config \
      --upstream https://kubernetes.default.svc

# Print version (Distroless: no shell, ENTRYPOINT runs the binary directly)
docker run --rm ghcr.io/trsreagan3/kbounce:latest --version
```

Notes:

- The image is a **packaging convenience** — same binary as
  `go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest`, no
  extra features, no telemetry, opt-in `version-check` honored.
- Built on `gcr.io/distroless/static-debian12:nonroot` — non-root by
  default, no shell, no package manager.
- `--host 0.0.0.0` requires the operator to also pass
  `--i-know-this-binds-externally` (see threat-model note on the `run`
  subcommand); the default loopback bind only works when the client is
  inside the same container/pod.
- A Helm chart for in-cluster deployment is planned at
  `trsreagan3/helm-charts` (not yet published; the repo reference is
  forward-looking).

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
- `--preset security-observe` — single-flag shortcut for the
  canonical security-team observation deployment shape (transparent
  mode + JSONL audit + alert rules + 30s heartbeat). See
  `docs/DEPLOYMENT-PRESETS.md` for the framework + override
  semantics; same preset NAME ships across all four Bounce products.

For the full "where do my audit logs go in production" decision tree
(JSONL / webhook + presets / Security Lake / Lambda → S3 / GCP / Azure
/ CI runners / Enterprise fan-out) see the cross-product runbook in the
iam-roles repo:
[docs/PRODUCTION-LOG-STORAGE.md](https://github.com/trsreagan3/iam-roles/blob/main/docs/PRODUCTION-LOG-STORAGE.md).

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

### `kbounce audit tail [--limit N] [--follow] [--filter EXPR ...] [--summary] [--export FORMAT --out PATH]`

Show recent decisions; optionally follow live, filter, summarize, or
export. Per [[cross-product-agent-parity]] the flag set matches
`ibounce audit tail` + `dbounce audit tail` so an operator who knows
one knows them all.

- `--limit N` — cap row count (1-1000, default 50; rejected at parse
  time per UAT-K2 HIGH-K2-03).
- `--follow` — tail the audit DB live (500ms poll; Ctrl-C to exit).
  Mutually exclusive with `--summary` and `--export`.
- `--filter EXPR` — repeatable; AND-combined. Forms: `field=value`,
  `field~regex`, `field>=N`, `field<=N`. Supported fields include the
  cross-product catalog (`severity_id`, `activity_id`, `status_id`,
  `actor.user.name`, `api.operation`, `unmapped.iam_jit.agent.{name,
  session_id}`, `unmapped.iam_jit.event_type`) plus kbounce-specific
  extensions (`resource.namespace`, `resource.name`, `resource.type`,
  `unmapped.iam_jit.{verdict,mode,profile,enforced}`).
- `--summary` — print count groupings (by event_type, severity,
  actor, operation) instead of rows.
- `--export {jsonl,csv,ocsf-bundle} --out PATH` — bulk-export the
  filtered set. CSV defaults omit PII columns; opt in via
  `--csv-columns LIST`.

Full filter / export catalog + worked examples + cross-product parity
table live in [docs/QUERYING-AUDIT-LOGS.md](docs/QUERYING-AUDIT-LOGS.md#live-tail--filtering--summary--export-kbounce-audit-tail).

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

### `kbounce diagnostics bundle` (alias: `kbounce diag bundle`)

One-shot ZIP capturing the operator's redacted config + audit-log
tail + `/healthz` snapshot + system info, suitable for sharing with
support OR pasting to a Claude agent for analysis. Strictly
read-only (no store / profile / audit-log mutations); the only
network call is a single LOCAL `/healthz` GET on the loopback port.
Default output: `./kbounce-diagnostics-{ISO8601-UTC}.zip` (`0o600`).
Override with `--out PATH`. Audit-webhook tokens, license bytes,
webhook URLs, user identifiers, hostnames, and env-var VALUES are
all redacted or hashed before the bundle is written.

See [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md) for the full
contents, redaction policy, and the `--no-audit` flag's purpose.

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
