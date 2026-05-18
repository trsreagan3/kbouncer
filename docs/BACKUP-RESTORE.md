# kbounce backup + restore

`kbounce backup` and `kbounce restore` provide single-file SQLite
backup + restore for the kbounce store (#279). They exist so an
operator can:

1. **Migrate** to a new machine without losing their config + rules.
2. **Recover from disaster** by restoring the most recent snapshot
   on a fresh deployment.
3. **Preserve the audit trail** before a risky config change (take a
   backup, make the change, restore if it goes wrong).

Until #279 the only path was "stop the daemon, `cp state.db`,
restart" — error-prone if anyone forgets the shutdown step + the
on-disk file is being written to during the copy. The new
subcommands do the right thing by default.

## Quick start

```bash
# Take a backup of the running kbounce (no shutdown required).
kbounce backup --out /backups/kbounce-2026-05-18.db

# Move the backup to the new machine, then on the destination:
kbounce restore --in /backups/kbounce-2026-05-18.db
# The destination DB path defaults to ~/.kbouncer/state.db; pass
# --dest PATH to override.
```

## `kbounce backup`

```
kbounce backup [--out PATH] [--include-audit] [--include-prompts]
```

- Online backup via SQLite's `VACUUM INTO` — the running proxy
  continues to serve traffic during the snapshot. No shutdown
  required.
- Output is a single SQLite file containing every kbounce table
  EXCEPT the audit firehose by default. The output also carries a
  `kbounce_backup_metadata` table with the version + creation
  timestamp + schema version + which tables were included.
- Output path defaults to `./kbounce-backup-{ISO8601-UTC}.db`; pass
  `--out PATH` to override. The command refuses to clobber an
  existing file at the target path — `rm` first or pick a new name.

### Default contents (what's IN the backup)

- `rules`, `tasks`, `schema_version`, `profile_reload_signal`
- The `kbounce_backup_metadata` table (always present)

### Default exclusions (what's NOT in the backup)

- `decisions` — every audited request. Bulky; usually rotated.
- `pause_events`, `burst_events` — audit-firehose adjacent.
- `pending_prompts` — runtime state; a prompt with no live waiter
  is effectively dead.

### Opting back in

- `--include-audit` keeps `decisions`, `pause_events`,
  `burst_events`.
- `--include-prompts` keeps `pending_prompts`.

Use both when migrating to a new machine and you want the audit
history to survive the move.

### Metadata table

Every backup file embeds a `kbounce_backup_metadata(key, value)`
table with:

| key | example |
|-----|---------|
| `kbounce_version` | `v1.0.0` |
| `created_at` | `2026-05-18T14:32:01Z` |
| `source_hostname_hash` | `a3f7b2c8d4e1` (first 12 hex of sha256 of hostname) |
| `schema_version` | `7` |
| `included_audit` | `false` |
| `included_prompts` | `false` |

The `source_hostname_hash` is a stable identifier without exposing
the hostname itself — useful for "is this the backup from machine
A or machine B?" without leaking either name.

## `kbounce restore`

```
kbounce restore --in PATH [--dest PATH] [--force]
```

- Replaces the destination DB file wholesale with the contents of
  the backup.
- Validates the backup's `kbounce_backup_metadata` table FIRST.
- Refuses to run if a kbounce proxy appears to be running against
  the default loopback port. Stop kbounce first.

### Validation order (first match wins)

1. `--in PATH` must exist + open as a SQLite DB.
2. The backup must carry a `kbounce_backup_metadata` table
   (refuses a random SQLite file).
3. `schema_version` in the metadata MUST equal the running kbounce
   binary's expected schema version. Refused with `--force` too —
   cross-schema restore is a migration, not a restore.
4. `kbounce_version` in the metadata SHOULD equal the running
   binary's version. Mismatch refused unless `--force` is passed
   (and a warning is printed on stderr).
5. If the destination DB already has rows in `rules` or `tasks`,
   the restore is refused unless `--force` is passed.

### Operational pre-flight

The command probes `http://127.0.0.1:8766/healthz` (loopback only)
and refuses if a kbounce listener answers. Override with:

- `--probe-url URL` — point at a non-default loopback port.
- `--skip-running-probe` — bypass the check entirely. Use only when
  you're certain the destination DB is not in use.

### Output

On success the command prints:

```
kbounce: restored 12 rule(s), 0 task(s), 0 profile(s), 0 audit row(s) (decisions=0, prompts=0, pauses=0)
  destination=/home/op/.kbouncer/state.db size=49152 bytes sha256=a1b2c3...
```

The sha256 lets you compare the restored DB across two machines to
confirm a successful migration.

### `--force` semantics

`--force` overrides:

- A `kbounce_version` mismatch warning.
- The destination-non-empty check (existing rules + tasks rows are
  REPLACED by the backup's contents).

`--force` does NOT override:

- A `schema_version` mismatch. Migrating across kbounce schema
  versions is a separate feature (a future `kbounce migrate`
  subcommand); restore is for same-version moves.

## Sample session

Migrating from machine A to machine B:

```bash
# On machine A (running kbounce):
kbounce backup --out /tmp/kbounce-2026-05-18.db \
  --include-audit --include-prompts
# kbounce: backup written to /tmp/kbounce-2026-05-18.db (53248 bytes, sha256 d8f9...)
#   schema_version=7 kbounce_version=v1.0.0 included_audit=true included_prompts=true

# Copy the file to machine B (scp, rsync, whatever).
scp /tmp/kbounce-2026-05-18.db opB@machine-b:/tmp/

# On machine B (kbounce NOT running):
kbounce restore --in /tmp/kbounce-2026-05-18.db
# kbounce: restored 12 rule(s), 0 task(s), 0 profile(s), 50 audit row(s) ...
#   destination=/home/opB/.kbouncer/state.db size=53248 bytes sha256=d8f9...

# Start kbounce on machine B; it reads the restored DB.
kbounce run
```

## Cross-product alignment

`dbounce backup` and `dbounce restore` ship the same CLI shape +
metadata-table format. Flag names (`--out`, `--in`, `--force`,
`--include-audit`, `--include-prompts`), refuse-without-force
semantics, and the embedded metadata-table schema are identical
across the suite per the cross-product-agent-parity contract.

## What's deliberately out of scope

- **Cross-version migration.** Use the appropriate `kbounce
  migrate` step (future) before restoring across schema versions.
- **Continuous backup / WAL shipping.** This is a snapshot tool;
  point-in-time recovery is not on the v1.0 roadmap.
- **Network-attached backup storage.** kbounce is local-only by
  design ([[self-host-zero-billing-dependency]]); shipping the
  backup file to S3 / GCS / Azure is the operator's job (any
  standard backup pipeline works against the output file).
- **Profiles file backup.** Profiles live in `~/.kbouncer/profiles.yaml`,
  not in SQLite. Back that file up separately if you want it
  preserved.

## Audit-trail visibility

Both `kbounce backup` and `kbounce restore` emit OCSF admin-action
events when `--audit-log-path` (or `KBOUNCER_AUDIT_LOG_PATH`) is
configured:

- `store.backup` (Informational severity) — backup file path lands
  in `entity_name`; the file's sha256 + size land in `ext`.
- `store.restore` (High severity) — restore is wholesale-replacing
  the destination DB; security teams should review every restore.

The events ride the same JSONL log + HTTPS webhook transport as
proxy decisions, so a SIEM analyst sees the backup / restore audit
trail alongside the live decision firehose without extra wiring.
