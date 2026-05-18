# kbounce config export + import

`kbounce config export` and `kbounce config import` provide a portable
JSON bundle of the operator's full kbounce configuration so an operator
can back up before an upgrade, mirror config across CI runners, migrate
to a new machine, or check the config into a change-management repo.

This document covers the wire shape, the CLI flags, the cross-product
parity contract, and the backwards-compatibility window for pre-#288
exports.

## Quick start

```bash
# Export the current config to a JSON file. Default: redacts secrets,
# writes 0600 perms.
kbounce config export --out ~/backups/kbounce-2026-05-18.json

# Import on a new machine.
kbounce config import --in ~/backups/kbounce-2026-05-18.json
```

## Wire shape

The export is a single JSON document with the following top-level
fields. Schema lives in `schemas/kbounce-config.schema.json` (in-tree).

```json
{
  "schema_version": "1.0",
  "product": "kbounce",
  "exported_at": "2026-05-18T12:34:56Z",
  "binary_version": "v1.0.0",
  "profiles": [...],
  "rules": [...],
  "tasks": [...],
  "presets": [...],
  "audit_export": {...},
  "license_pointer": "...",
  "runtime_config": {...}
}
```

Notes on the load-bearing fields:

- **`schema_version`** — string semver, currently `"1.0"`. Bumped to
  `"1.1"` on additive changes (new sections; old importers ignore them)
  or to `"2.0"` on breaking changes (renamed / removed fields; old
  importers refuse with a clear message).
- **`product`** — always `"kbounce"`. The importer REFUSES any other
  value — you cannot import a dbounce / ibounce / gbounce export into
  kbounce (different rule semantics). This is the same shape sibling
  products use; cross-product detection is one field check, not a
  parser-format guess.

Per-section blocks (`profiles`, `rules`, `tasks`, `presets`,
`audit_export`, `license_pointer`, `runtime_config`) are documented in
the in-tree schema.

## CLI flags

### `kbounce config export`

```
kbounce config export [--out PATH] [--with-secrets | --redact-secrets]
                      [--db PATH] [--profiles PATH]
```

- `--out PATH` — write the JSON to this file. Without it, writes to
  stdout. The output file is created `0600` so a multi-user machine
  cannot expose another operator's export.
- `--with-secrets` — emit audit-webhook tokens and license bytes
  verbatim. Prints a stderr WARNING banner so an operator running
  `config export | tee` inside a recorded terminal sees the leak risk.
- `--redact-secrets` — explicit form of the default (mask secrets with
  `***REDACTED***`). Use in scripts that want to surface the intent.
- `--db PATH` / `--profiles PATH` — override the default file locations.

### `kbounce config import`

```
kbounce config import --in PATH [--dry-run] [--merge | --replace]
                      [--yes] [--db PATH] [--profiles PATH]
```

- `--in PATH` — the export JSON to import. Required. **Primary flag
  per #288 cross-product reconciliation** — ibounce, gbounce, and
  dbounce all use the same flag so one cross-product backup script
  reads identically across the suite.
- `--from PATH` — DEPRECATED alias for `--in PATH`. Still works but
  prints a stderr deprecation warning. Will be removed in a future
  major version. Existing scripts written against `--from` keep working;
  update them at your convenience.
- `--merge` (default) — overlay the imported config onto existing
  state. Existing rules / tasks preserved; profiles with the same name
  are overwritten; imported rules are appended as new rows (preserving
  the audit trail).
- `--replace` — discard existing rules + tasks and import from scratch.
  `profiles.yaml` is rewritten with ONLY the imported set. Requires
  `--yes` to confirm.
- `--dry-run` — show what WOULD change without mutating state.

## Backwards compatibility (pre-#288 exports)

The wire shape converged across the Bounce suite on 2026-05-18 as part
of issue #288. Before that, kbounce exported `schema_version: 1` (int);
after, kbounce exports `schema_version: "1.0"` (string semver).

The reconciled importer accepts BOTH shapes. Reading a pre-#288
export:

1. The legacy `schema_version: 1` (int) field is rewritten in-place to
   the canonical `"1.0"` (string) before schema validation runs.
2. A stderr deprecation warning is printed:

   ```
   kbounce: deprecation: import uses legacy `schema_version: 1` (int)
   shape; this kbounce understands it but future major versions will
   refuse it. Re-export with this binary to upgrade to
   `schema_version: "1.0"` (string).
   ```

3. The import proceeds normally.

This compat window stays open across the full v1.x line. Old exports
on disk are guaranteed to keep importing across binary upgrades —
re-export with a current binary at your convenience to get the
canonical shape.

The pre-#288 `--from PATH` flag is preserved as a deprecated alias for
`--in PATH` on the same compat schedule (works through v1.x; future
major bumps may drop it).

## Cross-product wire-shape parity

kbounce, ibounce, gbounce, and dbounce all emit the same top-level
wire shape (per #288):

- `schema_version: "1.0"` (string semver) on every product
- `product: "<product-name>"` (one of `kbounce`, `ibounce`, `gbounce`,
  `dbounce`) — the importer REFUSES any cross-product import
- `--in PATH` on every product's import command
- `--out PATH` on every product's export command

A single cross-product backup script can target all four:

```bash
for product in kbounce ibounce gbounce dbounce; do
    $product config export --out ~/backups/$product-$(date +%F).json
done
```

The product-field-keyed refuse-cross-product semantic means a
mistyped product name in the script (e.g., piping a dbounce export
into kbounce) surfaces immediately with a clear error rather than
silently corrupting state.

For the wire-shape decisions behind #288 (string semver vs int,
`--in` over `--from`/`--input`, dropping dbounce's `format` field),
see the `project_config_export_wire_divergence` memo in the
iam-jit-portable repo.

## Audit trail

Both `kbounce config export` and `kbounce config import` emit OCSF
admin-action events when `--audit-log-path` (or `KBOUNCER_AUDIT_LOG_PATH`)
is set:

- `config.export` (ActivityOther) — destination path lands in
  `entity_name`; with-secrets flag + byte count land in `ext`.
- `config.import` (ActivityCreate) — source path lands in
  `entity_name`; mode + per-section counts land in `ext`.

Dry-run imports do NOT emit the event (no state changed).

## Related

- `docs/BACKUP-RESTORE.md` — `kbounce backup` / `kbounce restore` for
  SQLite-level snapshots (different feature; backs up the full
  state.db rather than the human-reviewable config bundle).
- `docs/DIAGNOSTICS.md` — `kbounce diagnostics bundle` embeds a
  byte-identical copy of `config export --redact-secrets` as
  `02-config-redacted.json`.
- ibounce + gbounce + dbounce docs for the cross-product equivalents.
