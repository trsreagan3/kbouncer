# kbouncer

**Local Kubernetes API-call gating proxy.** Sits between your kubectl /
Helm / coding agent and the real kube-apiserver, parses every request,
records the decision in an audit log, and (in transparent mode) can
deny calls that don't match its rule set.

`kbouncer` is one of the products in the LLC's suite — the K8s-shaped
sibling of `iam-jit-bouncer` (the AWS-IAM-shaped local proxy that lives
in `src/iam_jit/bouncer/` in the same repository). It is **separate**
from `iam-jit-bouncer`:

- Different target audience: K8s platform admins (cloud-agnostic — GKE,
  AKS, EKS, on-prem) vs the AWS-IAM admins `iam-jit-bouncer` targets.
- Different threat model: K8s RBAC + OPA already exist as the
  cluster-side defense. `kbouncer` is local-side defense-in-depth that
  catches "the cluster boundary is correct, but the call target is
  wrong" — the prompt-injection + agent-typo failure modes.
- Different runtime: `kbouncer` is written in Go (the K8s ecosystem's
  native language) and ships as a single static binary;
  `iam-jit-bouncer` is Python because it sits inside the larger
  `iam-jit` Python codebase.

Same architectural pattern as `iam-jit-bouncer`, intentionally — same
two-mode model, same audit-store shape, same MCP-tool plans (later
slice). Cross-product audit-log review will join across both products'
SQLite databases without translation.

## Two-mode model

`kbouncer` runs in one of two modes, picked at startup via `--mode`:

| Mode | Behavior | Use case |
| --- | --- | --- |
| `cooperative` (default) | Parses + logs every call; always forwards (when forwarding lands in K-Slice 2). Verdicts are **advisory**. | Solo dev iterating fast; previewing what transparent mode WOULD block; running with high-trust agents you want auditing on. |
| `transparent` | `deny` verdicts return **HTTP 403** to the client without forwarding. `allow` verdicts forward unchanged. | Locked-down environments where any K8s call must be gated; running with lower-trust agents; compliance-sensitive deploys. |

Same two-mode taxonomy as `iam-jit-bouncer`, on purpose: operators who
already understand one product understand the other.

## Stage shipping plan

`kbouncer` ships in stages so each slice can land + be reviewed
independently:

- **K-Slice 1.** Foundation: HTTP server, kube-apiserver URL parser,
  SQLite audit store, `kbouncer run` CLI. No upstream forwarding yet —
  the proxy returns the parsed observation as JSON. Useful as a pure
  observability tool.
- **K-Slice 2.** Upstream forwarding to a real kube-apiserver
  (kubeconfig-aware; TLS to the apiserver; SAR-style preflight optional).
- **K-Slice 3.** Rule engine + per-task scopes + MCP tools for
  active-mode declaration.
- **K-Slice 7 (this build).** Environment profiles — a switchable deny
  layer that fires BEFORE per-task scopes and global rules. See
  "Environment profiles" below.
- **K-Slice 4.** Client-cert handling on the proxy listener (mTLS for
  kubectl that prefers cert auth).
- **K-Slice 5.** Streaming subresources: watch / exec / port-forward /
  attach properly proxied.
- **K-Slice 6.** Additional MCP tools (recommend-mode, end-task,
  review) + the agent-friendly intake flow.
- **Post-v1.0.** Admission-webhook deployment shape for in-cluster
  installs.

## Build + run

```sh
# Build the single static binary.
cd kbouncer
go build ./cmd/kbouncer

# Run the proxy in observation-only mode (default flags).
./kbouncer run

# Or with explicit flags:
./kbouncer run \
  --port 8766 \
  --host 127.0.0.1 \
  --mode cooperative \
  --default-policy deny \
  --db ~/.kbouncer/state.db
```

Default port is **`8766`** (distinct from `iam-jit-bouncer`'s `8767`
so the two products can coexist on the same machine without colliding).

The audit DB lives at `~/.kbouncer/state.db` by default; override with
`--db` or the `KBOUNCER_DB` env var.

### Inspect the audit log

After the proxy has been running, see what just happened:

```sh
kbouncer audit tail            # 50 newest decisions
kbouncer audit tail --limit 10 # 10 newest
```

Each row shows timestamp, mode, verdict, decision-source (profile /
global / default / unclassifiable) and the parsed request. Useful
for "what is my agent actually asking the cluster to do?" debugging.

### Liveness probe

`GET /healthz` returns 200 + a small JSON status payload
(`{status, mode, default_policy, active_profile, decisions_count}`)
without writing to the audit log — safe to poll from monit, k8s
liveness probes, or systemd watchdogs.

## Test

```sh
cd kbouncer
go test ./...
```

All tests are pure-Go and use a temp-directory SQLite DB per test — no
external cluster, no Docker, no fixtures to manage.

## Environment profiles

A **profile** is a named, switchable rule layer that adds environment-
aware keyword denies on top of `kbouncer`'s existing per-task scopes
and global rules. When a profile is active, its denies are a **hard
floor** — they fire even if a task scope or global rule would have
allowed the call. This is the property SecOps teams need to approve
the install: "if I say `staging-work`, the agent CAN NOT touch prod
regardless of which other rules are loaded."

Activate a profile with `--profile NAME` or the `KBOUNCER_PROFILE`
env var:

```sh
kbouncer run --profile staging-work
# or:
KBOUNCER_PROFILE=staging-work kbouncer run
```

`kbouncer profile list` shows the available profiles and marks the
active one. The first time `kbouncer run` starts it writes the five
default profiles to `~/.kbouncer/profiles.yaml`; existing files are
**never** overwritten so operator edits survive upgrades.

### The five default profiles

| Profile | What it does |
| --- | --- |
| `staging-work` | Blocks anything that looks like prod (keyword match on `prod`, `production`, `uat`, `live`, `customer` against namespace + resource name). Word-boundary by default so `productivity` is not caught. |
| `prod-readonly` | Even in prod, no writes. Denies `delete`, `patch`, `create`, `update`, `deletecollection`, `exec`, `portforward`, `attach`. |
| `sandbox` | Restricts the proxy to a specific cluster via `only_clusters`. Default config: `sandbox-cluster`. |
| `incident-response` | Read-everything, write-nothing safety net for high-pressure debugging. Same deny_verbs as `prod-readonly`. |
| `none` | No profile rules fire; existing per-task + global rule system unchanged. Useful when you want kbouncer's audit log without the profile floor. |

Composition order (LOAD-BEARING):

1. Profile rules — keyword, `only_clusters`, `deny_verbs`
2. Per-task scope (K-Slice 3)
3. Global rule engine (K-Slice 3)
4. Default policy fall-through

Every gated response carries an `x-kbouncer-decision-source` header
naming the rule layer (`profile`, `task`, `global`, `default`,
`unclassifiable`) so a curl-driven smoke test or audit-log review can
confirm which layer produced the verdict without parsing the JSON
body.

Profile auto-detection from the active `kubectl` context is
**out-of-scope** for K-Slice 7 — ships in K-Slice 8.

## Layout

```
kbouncer/
├── cmd/kbouncer/                 # the CLI entry point (cobra)
├── internal/parser/              # kube-apiserver URL → ParsedRequest
├── internal/profile/             # environment profiles (K-Slice 7)
├── internal/proxy/               # Mode + Config + Server + EvaluateRequest
├── internal/store/               # SQLite-backed audit store
├── go.mod
└── README.md
```

`internal/...` packages are intentionally not exported — `kbouncer` is
a shipped binary, not a library other Go programs link against. If a
library need emerges (e.g. for the admission-webhook shape), promote
the relevant package to a top-level `pkg/...` directory at that time.

## Position in the suite

The LLC ships five products under one brand:

1. **iam-risk-score.com** — free hosted stateless AWS-IAM-policy scorer.
2. **iam-jit-bouncer** — local AWS-SDK-call gating proxy (Python,
   `src/iam_jit/bouncer/`).
3. **kbouncer** — local K8s-API-call gating proxy (Go; this directory).
4. **iam-jit CLI / SaaS** — the JIT IAM credential issuer (`src/iam_jit/`).
5. **iam-jit Enterprise** — self-hosted, license + support + advanced
   plugins.

Same brand, same scorer DNA, same "creates / never mutates" invariant.
Different audiences, different friction profiles, different
distribution channels — separate products so each can find its own
PMF.
