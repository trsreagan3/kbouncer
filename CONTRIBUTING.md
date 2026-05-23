# Contributing to kbouncer

`kbouncer` is the Kubernetes API gating bouncer in the iam-jit
Bounce suite. Same agent-friendly UX surface as `ibounce` per
`[[cross-product-agent-parity]]`, with K8s-flavored verbs +
resources underneath.

## Development setup

```bash
go install ./...
go test ./...
```

Local-test infrastructure (kind + audit DB) lives in
`compose.test.yaml` and is driven by the `Makefile` targets. See
`docs/LOCAL-TEST-INFRA.md` (when present) for the canonical run.

## Adding a rule

Profile rules use the cross-product YAML shape (per
`[[cross-product-agent-parity]]`). Submit profile contributions to
the shared profile repo at
[`trsreagan3/bounce-profiles`](https://github.com/trsreagan3/bounce-profiles).

For K8s-specific verb + resource conventions, see
[`community-profiles/`](./community-profiles) and
[`presets/`](./presets) for shipped examples.

## Adding a preset

Curated preset packs live in `presets/`. Each preset is a YAML
file matching the profile schema with a single role narrative
(e.g. `cluster-admin-minus-destructive`, `argocd-app-controller`).
Add a test in `internal/...` exercising the preset against a
representative request stream.

## Calibration corpus contributions

`kbouncer` composes with the iam-jit calibration corpus when used
alongside iam-jit-issued IRSA roles. See
[`iam-roles/docs/CONTRIBUTING.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/CONTRIBUTING.md)
for the calibration discipline + corpus contribution path.

## Code style

```bash
gofmt -s -w .
go vet ./...
```

Before committing.

## Cross-product parity

Per `[[cross-product-agent-parity]]`, the kbouncer MCP surface
mirrors ibounce's (only the tool prefix changes). When adding a
new MCP tool, add the equivalent surface to the other bouncers
(or file an issue noting the gap). Symmetry is the cross-product
wedge.
