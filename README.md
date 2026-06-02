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

No Go toolchain required for the paths below — they install a
prebuilt, signed-by-release binary. `kbounce --version` should print a
version after any of them. (Building from source is the last option,
not the first — see [From source](#from-source-go-toolchain-required).)

### Homebrew (macOS / Linux)

```sh
brew install trsreagan3/tap/kbounce
```

### Prebuilt binary (any OS)

Each [GitHub Release](https://github.com/trsreagan3/kbouncer/releases)
attaches `kbounce_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) for
`linux`/`darwin`/`windows` × `amd64`/`arm64`. Download, extract, and
put `kbounce` on your `PATH`:

```sh
# Example: macOS arm64. Swap in the os/arch + version for your machine.
curl -fsSL -o kbounce.tar.gz \
  https://github.com/trsreagan3/kbouncer/releases/latest/download/kbounce_<version>_Darwin_arm64.tar.gz
tar -xzf kbounce.tar.gz kbounce
sudo install kbounce /usr/local/bin/kbounce
```

### Scoop (Windows)

```powershell
scoop bucket add trsreagan3 https://github.com/trsreagan3/scoop-bucket
scoop install kbounce
```

### APT / RPM (Debian/Ubuntu, RHEL/Fedora)

Releases attach `.deb` + `.rpm` packages (installs the binary to
`/usr/local/bin`). They are **not** published to a public APT/RPM
registry yet — download the package from the release and install it
directly:

```sh
# Debian / Ubuntu
curl -fsSL -o kbounce.deb \
  https://github.com/trsreagan3/kbouncer/releases/latest/download/kbounce_<version>_linux_amd64.deb
sudo dpkg -i kbounce.deb

# RHEL / Fedora / Amazon Linux
curl -fsSL -o kbounce.rpm \
  https://github.com/trsreagan3/kbouncer/releases/latest/download/kbounce_<version>_linux_amd64.rpm
sudo rpm -i kbounce.rpm
```

### Docker

See [Docker](#docker) below for the published
`ghcr.io/trsreagan3/kbounce` image (Claude-in-container friendly).

### From source (Go toolchain required)

This path builds the binary fresh from source — needs **Go ≥ 1.26**.
Prefer one of the no-toolchain paths above unless you're iterating on
the source.

```sh
go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest
kbounce --version

# If you get "command not found": $(go env GOPATH)/bin is not on PATH.
# Stock Ubuntu (and most Linux distros) do NOT put ~/go/bin on PATH by
# default. Fix once per shell, then persist in your shell rc:
export PATH="$PATH:$(go env GOPATH)/bin"
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc   # bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc    # zsh
```

> The `go install` PATH note closes #549 (UAT L1 2026-05-24): the
> unmodified `go install` succeeds silently with the binary at
> `~/go/bin/kbounce` while the shell reports "command not found", which
> reads as "install broken" on a fresh machine.

## Add to your agent

kbounce wires into any MCP-compatible coding agent two ways. Pick
whichever fits your setup; they compose.

### MCP mode — the agent introspects + self-scopes via `kbounce_*` tools

One command per client merges a `kbounce` entry into the agent's MCP
config (idempotent; other MCP servers are preserved):

```sh
kbounce mcp install-claude-code   # Claude Code / Claude Desktop
kbounce mcp install-cursor        # Cursor
kbounce mcp install-codex         # Codex (prints a TOML snippet to paste)
kbounce mcp install-devin         # Devin (cloud-agent recipe; see below)
```

The agent then spawns `kbounce mcp serve` and can call `kbounce_decide`
(dry-run a request's verdict), `kbounce_active_mode`,
`kbounce_list_rules`, `kbounce_scope_self_for_task`, etc. Verify with
`kbounce mcp list-tools` (the same list the agent sees). For any other
MCP client, `kbounce mcp show-config` prints a vendor-neutral JSON/YAML
snippet.

The MCP server reads the **same** on-disk state the running proxy uses
(`--db` + `--profiles-path`); it does **not** start a proxy listener of
its own — run `kbounce run` separately for the gating + forwarding
layer.

### Transparent mode — point kubectl through kbounce

Generate the local CA + server cert once, run the proxy with TLS, then
point your agent's `kubectl` / `KUBECONFIG` at kbounce instead of the
real apiserver:

```sh
# 1. One-time: generate ~/.kbouncer/tls/{ca,server}.{crt,key}.
kbounce init-tls

# 2. Run the proxy with TLS, forwarding to the real apiserver.
kbounce run \
  --tls-cert ~/.kbouncer/tls/server.crt \
  --tls-key  ~/.kbouncer/tls/server.key \
  --upstream https://<your-cluster-api>:6443 \
  --mode transparent --profile safe-default
```

```yaml
# 3. In the agent's kubeconfig, point the cluster's server at kbounce
#    and trust the generated CA:
clusters:
  - cluster:
      server: https://127.0.0.1:8766
      certificate-authority: ~/.kbouncer/tls/ca.crt
```

Every API call the agent makes now traverses kbounce: parsed,
audit-logged, ALLOWs forwarded to the real apiserver, and (transparent
mode) out-of-profile requests denied with HTTP 403 before they reach
the cluster.

### Cloud agents (Devin) + Claude-in-container

`kbounce mcp install-devin` prints a recipe rather than editing a local
config: Devin runs in a cloud sandbox that cannot see your local
`127.0.0.1`, so kbounce must run on a host the sandbox can reach
(`--host 0.0.0.0 --i-know-this-binds-externally`) and the agent's
`KUBECONFIG` points at `https://<kbounce-host>:8766`. This is an honest
limitation, not a bug — kbounce never requires root or a transparent
OS-level proxy.

For running an agent (e.g. Claude Code) inside Docker alongside the
bouncer, see the cross-product
[Claude-in-Docker integration guide](../iam-roles/docs/DOCKER-CLAUDE-INTEGRATION.md).

## Quickstart

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
products can coexist on the same laptop).

Default audit DB path resolves in this order (an explicit `--db PATH`
overrides everything):

1. `$KBOUNCER_DB`
2. `$XDG_STATE_HOME/kbounce/state.db`
3. `~/.kbouncer/state.db` (when `$HOME` is set — the historical default)
4. `/var/lib/kbounce/state.db` (rootless containers with no `$HOME`)

Parent directories are created `0700`.

#### Environment variables (`KBOUNCER_` is canonical; `KBOUNCE_` also works)

Every kbounce env var is documented with the canonical `KBOUNCER_`
prefix (`KBOUNCER_PROFILE`, `KBOUNCER_DB`, `KBOUNCER_MODE`,
`KBOUNCER_PROFILES_PATH`, `KBOUNCER_TLS_DIR`, `KBOUNCER_PORT`,
`KBOUNCER_LOG_LEVEL`, `KBOUNCER_UPSTREAM_CA_BUNDLE`,
`KBOUNCER_AUDIT_EVENTS_TOKEN`, `KBOUNCER_AUDIT_LOG_PATH`,
`KBOUNCE_NO_VERSION_CHECK`). Because the binary is named `kbounce`, the
shorter `KBOUNCE_` prefix is **also accepted** for every one of them
(e.g. `KBOUNCE_PROFILE` resolves the same as `KBOUNCER_PROFILE`) — so
dropping the trailing `R` to match the binary name is no longer a
silent no-op. When both prefixes are set, the canonical `KBOUNCER_`
form wins.

#### Verifying a private kube CA

If your kube-apiserver uses a private / self-signed CA that isn't in
your kubeconfig, point kbounce at the PEM bundle so it can verify the
upstream TLS cert:

```sh
kbounce run --upstream https://apiserver.internal:6443 \
  --upstream-ca-bundle /etc/kube/ca.pem
# or, to keep the path out of `ps`:
KBOUNCER_UPSTREAM_CA_BUNDLE=/etc/kube/ca.pem kbounce run --upstream https://apiserver.internal:6443
```

The flag wins over the env var. A missing / unreadable / non-PEM bundle
is a hard startup failure — kbounce never silently falls back to system
roots.

#### Keeping the audit-events token out of `ps`

When binding off-loopback you must set a bearer token for
`GET /audit/events`. Prefer the env var so the secret never appears in
process listings:

```sh
KBOUNCER_AUDIT_EVENTS_TOKEN=<secret> kbounce run --host 0.0.0.0 --i-know-this-binds-externally
```

`--audit-events-token` still works and wins over the env var when both
are set.

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

#### Bind-mounting volumes (UID 65532)

The distroless `:nonroot` base runs as **UID 65532** (no shell, no
package manager, non-root for security). When you bind-mount a host
directory into the container, that directory must be writable by UID
65532 — otherwise kbounce's first attempt to open the SQLite audit
DB or write profiles to the mount will fail with a cryptic error
like:

```
open store: unable to open database file
```

Two ways to fix this:

```sh
# Option A — chown the host directory once (preferred for daemons).
mkdir -p ~/.kbouncer
sudo chown -R 65532:65532 ~/.kbouncer
docker run --rm \
  -p 8766:8766 \
  -v ~/.kbouncer:/home/nonroot/.kbouncer \
  ghcr.io/trsreagan3/kbounce:latest \
  run --upstream https://kubernetes.default.svc

# Option B — run as your host UID (preferred for short-lived dev runs
# where you don't want to leave a host directory owned by 65532).
mkdir -p ~/.kbouncer
docker run --rm \
  --user $(id -u):$(id -g) \
  -p 8766:8766 \
  -v ~/.kbouncer:/home/nonroot/.kbouncer \
  ghcr.io/trsreagan3/kbounce:latest \
  run --upstream https://kubernetes.default.svc
```

**macOS / colima caveat**: colima only bind-mounts `/Users/*` paths
reliably. Mounts under `/tmp`, `/var`, or `/private` silently diverge
between the host and the colima VM — files written by the container
may not appear on the host, and vice versa. Always mount paths under
`/Users/<you>/` on Mac.

#### docker-compose example

```yaml
# compose.yaml — kbounce with host-owned audit dir + cooperative mode.
services:
  kbounce:
    image: ghcr.io/trsreagan3/kbounce:latest
    user: "65532:65532"             # match the distroless :nonroot UID
    command:
      - run
      - --upstream
      - https://kubernetes.default.svc
      - --host
      - 0.0.0.0
      - --port
      - "8766"
      - --kubeconfig
      - /home/nonroot/.kube/config
    ports:
      - "127.0.0.1:8766:8766"       # loopback-only on the host
    volumes:
      - ./kube:/home/nonroot/.kube:ro
      - ./kbouncer-data:/home/nonroot/.kbouncer
    # Before `docker compose up`, run once:
    #   mkdir -p ./kbouncer-data && sudo chown 65532:65532 ./kbouncer-data
```

#### Common errors

| Symptom | Cause | Fix |
| --- | --- | --- |
| `open store: unable to open database file` | Bind-mounted dir not writable by UID 65532 | See **Bind-mounting volumes** above |
| `permission denied` on `/home/nonroot/.kbouncer/...` | Same UID-65532 ownership issue | `chown -R 65532:65532 <hostdir>` or `--user $(id -u):$(id -g)` |
| Files written in container don't appear on host (macOS) | Mount path under `/tmp` or `/var` on colima | Move mount under `/Users/<you>/` |
| `bind: address already in use` on `:8766` | Another kbounce / process already on the port | `lsof -i :8766` then stop the conflicting process or `-p 8767:8766` |

---

## Operating modes

| Mode | Behavior | Use case |
| --- | --- | --- |
| `cooperative` (default) | Parse + log every call; always forward. Verdicts are advisory. | Solo dev iterating fast; previewing what transparent mode would block. |
| `transparent` | DENY verdicts return HTTP 403 to the client. ALLOW forwards unchanged. | Locked-down environments; lower-trust agents; compliance deploys. |

Switch with `--mode cooperative` or `--mode transparent`.

---

## Dynamic deny rules (#324b — cross-product hot-reload)

Profiles are great for stable operator-set rules. For **incident-time
deny ergonomics** ("Claude, make sure nothing touches the prod
namespace for 3h"), kbounce also consumes
`~/.iam-jit/dynamic-denies.yaml` — a cross-product file shared with
ibounce, dbounce, and gbounce. Rules in the file are hot-reloaded on
disk change (fsevents on macOS, inotify on Linux); rules whose
`applied_to` list does NOT include `kbouncer` are silently skipped, so
ONE file fans out across the Bounce suite without operators picking
which proxy to call.

```sh
# Optional override; default is ~/.iam-jit/dynamic-denies.yaml.
kbounce run --upstream https://<api>:6443 \
            --dynamic-denies-path ~/.iam-jit/dynamic-denies.yaml
```

Startup banner reports the loaded count:

```
dynamic-denies: 2 rules loaded from ~/.iam-jit/dynamic-denies.yaml (2 applied to kbouncer; watching for changes)
```

Three kbouncer-shaped pattern kinds are recognized in each rule's
`targets` list:

| Pattern | Matches |
| --- | --- |
| `namespace:prod` / `namespace:prod-*` / `namespace:*.svc` | Parsed K8s namespace |
| `cluster:prod-east` / `cluster:prod-*` | The kubeconfig cluster name kbouncer was launched with |
| `apps/v1/deployments` / `core/v1/secrets` | Exact K8s `group/version/resource` triple (use `core` for the K8s core API; matches the empty-group parser shape) |

On match: the verdict OCSF event carries
`unmapped.iam_jit.ext.deny_source="dynamic"` +
`unmapped.iam_jit.ext.dynamic_deny_rule_id="dd_..."` so a SIEM
distinguishes the source flavor + names the originating rule. Dynamic
denies beat profile-allow + task-allow + global-allow per the
cross-product design doc's "deny always wins over allow" rule.

`POST /admin/dynamic-denies/reload` on the proxy port triggers an
immediate reload from disk — useful for the cross-bouncer fan-out CLI
(#324e), which writes the YAML then POSTs each Bounce product's mgmt
port to confirm the rules are live.

The canonical cross-product design lives at
[`iam-roles/docs/DYNAMIC-DENY-RULES.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/DYNAMIC-DENY-RULES.md);
the on-disk schema at
[`iam-roles/docs/schemas/dynamic-denies-v1.json`](https://github.com/trsreagan3/iam-jit/blob/main/docs/schemas/dynamic-denies-v1.json).
The headline operator-facing CLI (`iam-jit deny add | list | remove |
show`) lands in #324e; this slice (#324b) ships the kbouncer
consumer + manual / agent-driven YAML editing works today.

Honest caveats:

- **The proxy is bypassable.** Per `[[ibounce-honest-positioning]]`:
  an operator who controls the agent's network can route around
  kbounce. The dynamic-deny rules add ergonomics + audit-trail
  visibility; the defense-in-depth half (recommender embedding the
  same denies as explicit `Deny` statements on JIT-issued roles)
  ships in #324f for the AWS surface.
- **Fail-CLOSED on parse error.** A YAML typo retains the previous
  in-memory snapshot — kbounce does NOT silently fall back to "0
  rules applied" when an operator's file fails to validate. The
  failure surfaces in `/healthz` (`total_dynamic_deny_parse_errors`)
  + as a `dynamic_deny.parse_error` admin-action OCSF event.

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

## API credits required?

**No** when an AI agent is in the loop. `kbouncer` is pure
deterministic rules + audit + MCP server. Your agent (Claude Code
/ Cursor / Codex / Devin / any MCP-compatible client) uses its own
LLM credentials (Max / Plus / Pro / API key / Ollama / etc.). The
bouncer never makes an LLM call in this mode — `kbouncer` ships with
zero LLM credentials required for local-dev.

**Yes** for standalone deployments (CI/CD / cron / daemon mode with
no agent in the loop). Opt in via `--llm-backend
anthropic|openai|bedrock|ollama` + supply credentials. This is the
minority case.

See [[bouncer-zero-llm-when-agent-in-loop]] in the iam-roles memory
for the full architecture.

---

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 trsreagan3.

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
