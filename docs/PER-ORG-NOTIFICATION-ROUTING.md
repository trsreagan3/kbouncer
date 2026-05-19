# kbounce per-org notification routing (#280)

**Status:** Shipped 2026-05-19. Enterprise-tier; license-gated
(placeholder error until #235 license-file plumbing lands).

For the full design rationale, YAML schema, match operators,
destination types, secret handling, dry-run usage, and constraints
see the canonical cross-product reference at:

  - **iam-roles repo:** `docs/PER-ORG-NOTIFICATION-ROUTING.md`

The cross-product specification (flag names, YAML format, match
operators, destination types) is shared across ibounce / kbounce /
dbounce per `[[cross-product-agent-parity]]`.

## kbounce-specific notes

- The flag is `kbounce run --alert-routes ROUTES.yaml`. Identical
  shape to `ibounce run --alert-routes` and `dbounce run --alert-routes`.
- The dry-run subcommand is `kbounce config preview-routes --routes
  ROUTES.yaml --event sample.json`. No HTTP traffic is sent; secrets
  render masked.
- License gate is currently a placeholder (`audit.ErrRoutesLicenseRequired`)
  that surfaces a clear error pointing the operator at issue #235.
  Once #235 lands, the placeholder is swapped for the real verifier;
  no other code changes.
- When `--alert-routes` is set, the legacy `--audit-webhook-url`
  path is ignored (with a startup warning). The JSONL log file +
  Security Lake adapter stay independent.

## Quick start

```bash
$ export SOC_SPLUNK_HEC_TOKEN=...
$ export PD_INTEGRATION_KEY=...
$ export SLACK_ONCALL_WEBHOOK=https://hooks.slack.com/services/T1/B2/secret
$ kbounce config preview-routes \
      --routes ~/.iam-jit/kbounce-routes.yaml \
      --event sample-event.json
$ kbounce run --alert-routes ~/.iam-jit/kbounce-routes.yaml
```

## Composition

- The `webhook` destination supports the per-vendor presets from
  #257 (Datadog / Splunk HEC / Sentinel) via the
  `webhook.preset` field, identical to the kbounce
  `--audit-webhook-preset` shape.
- AWS Security Lake (#258) writes parquet to S3 alongside the
  routes engine; you can also point a `webhook` destination at a
  Lambda that ingests into Security Lake for per-route Security
  Lake fan-out.
- Routes can match on agent-identity fields (e.g.
  `unmapped.iam_jit.agent.name`) for per-agent routing — useful when
  one team's automated agent should route to a different collector
  than a human kubectl session.

## Constraints (preserved verbatim from the cross-product memo)

- Don't expose tokens in routes YAML — always use `${ENV_VAR}`.
- Don't make `on_match: continue` the default; first-match-wins is
  what most customers expect.
- Don't add Kafka / SMTP / ServiceNow destinations pre-launch.
  Webhook + PagerDuty + Slack covers the v1.0 demand surface.
- Don't make the routes engine LLM-augmented. Deterministic
  match-engine only.
