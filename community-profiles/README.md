# kbounce community profiles

Profiles in this directory are **community-shipped**, not built into the
`kbounce` binary. Install one with:

```sh
kbounce profile install --from https://raw.githubusercontent.com/trsreagan3/kbouncer/main/community-profiles/staging-work.yaml
```

Or for local installs / air-gapped boxes, copy the contents into your
`~/.kbounce/profiles.yaml`.

## What ships here vs. embedded

The `kbounce` binary embeds only two general-purpose profiles:

| Profile | Purpose |
| --- | --- |
| `full-user` | Passthrough — no rules. The default when no `--profile` / `KBOUNCER_PROFILE` is set. |
| `safe-default` | Cross-product safe-by-default deny layer. Blocks mutating verbs + destructive non-writes + privilege primitives + impersonation + CRD-defined mutating subresources. Carves out SSAR/SAR/TokenReview previews and `?dryRun=All` requests. NOT a confidentiality boundary — reads of sensitive data still pass. |

The profiles below are environment-specific or scenario-specific and live
here so the embedded defaults stay tiny + opinionated:

| Profile | What it does |
| --- | --- |
| `staging-work` | Block anything that looks like prod (keyword match on `prod` / `production` / `uat` / `live` / `customer`). |
| `dev-only` | Restrict the proxy to a single dev / sandbox cluster via `only_clusters`. |
| `incident-response` | Read-everything, write-nothing safety net for high-pressure debugging. |

## Contributing

Drop a YAML file under this directory + open a PR. Keep the schema
minimal — one profile per file, with the same `description` /
`deny_keywords` / `deny_verbs` / `only_clusters` shape the embedded
defaults use.
