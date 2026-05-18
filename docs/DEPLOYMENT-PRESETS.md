# Deployment Presets

A **deployment preset** is a named bundle of `kbounce run`-command
flag values that activates a common deployment shape with one flag
instead of seven. Presets are SHORTCUTS — every preset value can be
set explicitly; the preset just makes the canonical combinations
discoverable + one-flag for the operator.

Per `[[cross-product-agent-parity]]` the same preset NAMES + same
HARD-vs-SOFT override semantics ship across **ibounce / kbounce /
dbounce / gbounce**. A product MAY skip a preset setting it doesn't
have a subsystem for (e.g. gbounce in G-Slice 1 has no alert-rules
engine), but it will not ERROR on that setting — the banner
annotates `not applicable to this product`.

## The mechanism

A preset is a `(name, description, values)` record where `values`
is a map keyed by run-command parameter with an explicit override
policy per entry:

- **HARD** — operator passing the flag with a DIFFERENT value
  errors. The preset's whole point depends on this setting;
  overriding it silently would yield a deployment shape that does
  not match what the operator asked for.
- **SOFT** — operator's value wins; the preset value is the default
  the operator gets when they leave the flag unset.

The preset resolution runs BEFORE downstream validation gates so
the license / SSRF / loopback-bind checks see the preset-resolved
values, not the raw input.

The startup banner names the active preset + lists every derived
setting (with hard/soft annotation) so the operator sees exactly
what changed. Format is identical across all four Bounce products.

## Available presets (v1.0)

### `security-observe`

```sh
kbounce run --preset security-observe
```

is equivalent to the explicit bundle:

```sh
kbounce run \
  --mode transparent \
  --default-policy allow \
  --audit-log-path ~/.kbouncer/audit/kbounce.jsonl \
  --alert-rules defaults \
  --heartbeat-interval 30s
```

| Setting | Why |
|---|---|
| `--mode transparent` | Observe + audit; do not enforce rules the team has not yet authored. |
| `--default-policy allow` | Transparent observation; do not surprise the operator with denies. |
| `--audit-log-path <default>` | Per-product JSONL stream the security team can ship to a SIEM. |
| `--alert-rules defaults` | Surfaces the six built-in deterministic alerts (admin_fallback_burst, pause_long, non_org_profile_install, unusual_high_risk_action, heartbeat_gap, audit_export_degraded). |
| `--heartbeat-interval 30s` | Liveness signal so the SIEM detects when the proxy is killed/silenced. |

**Override semantics**:

- HARD: `--mode` (the entire point is transparent — overriding it
  reshapes the deployment in a way the preset name does not
  describe).
- SOFT: `--audit-log-path`, `--alert-rules`, `--heartbeat-interval`,
  `--default-policy`.

**v1.0 skip**: kbounce's `--alert-rules` surface is currently a hard
ENTERPRISE license gate (returns the license-required error before
any rule loads; tracked in #235). Until #235 lands the license-file
plumbing, the preset SKIPS `--alert-rules` in kbounce + the startup
banner annotates `--alert-rules: not applicable to this product
(preset value skipped)`. When #235 lands the skip goes away + the
preset wires defaults through automatically. The other four settings
flow through normally.

**What the preset does NOT set** (operator wires explicitly):

- `--audit-webhook-url` + `--audit-webhook-token` — different SIEM
  endpoint per deployment; set via flag, env var, or `kbounce
  config import`.

**Startup banner** announces the preset + every derived setting so
the operator sees exactly what changed:

```
kbounce proxy starting on http://127.0.0.1:8766 (mode=transparent, default-policy=allow, profile=full-user)
deployment preset: security-observe
  --mode = "transparent" (from preset; hard)
  --default-policy = "allow" (from preset; soft)
  --audit-log-path = "/Users/<you>/.kbouncer/audit/kbounce.jsonl" (from preset; soft)
  --alert-rules = "defaults" (from preset; soft)
  --heartbeat-interval = "30s" (from preset; soft)
```

## Roadmap (post-v1.0)

The framework is built to add more presets without schema migrations.
Queued presets (NOT shipped in v1.0):

| Preset | Planned shape | Use case |
|---|---|---|
| `dev-loop` | cooperative + safe-default profile + `--prompt-on-deny` | Solo-dev iteration where the operator wants advisory denies |
| `production-strict` | transparent + strict profile + no overrides + JSONL only | Locked-down production deployments |
| `compliance-audit` | transparent + all-alerts + per-session recording | Compliance evidence-gathering shape |

Per `[[deliberate-feature-completion]]` we ship the framework with
one preset; the next presets ship when a concrete operator asks for
them.

## Cross-product alignment

A single command runs the SAME preset across every Bounce product:

```sh
ibounce  run --preset security-observe
kbounce  run --preset security-observe
dbounce  run --preset security-observe
gbounce  run --preset security-observe   # skips alert-rules; banner annotates
```

This is intentional per `[[cross-product-agent-parity]]`: an SRE
runbook that says "spin up the Bounce suite in observation mode"
maps to one flag name regardless of which proxy is in scope.
