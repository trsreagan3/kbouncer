# Querying kbounce audit logs

kbounce never stores customer audit logs. Every event lands in YOUR
collector (JSONL file, SQLite, or HTTPS webhook → your SIEM); retention
is controlled there, not by kbounce.

This doc shows the SIEM queries security teams ask most often, ordered
by frequency, with the wire-shape fields they key off.

## Wire shape (OCSF v1.1.0, class 6003 API Activity)

Every kbounce audit event is OCSF API Activity. Key fields:

| OCSF field | What it carries | Example |
|---|---|---|
| `metadata.product.name` | always `kbounce` | `"kbounce"` |
| `metadata.product.vendor_name` | always `iam-jit` | `"iam-jit"` |
| `time` | unix milliseconds | `1716163200000` |
| `activity_id` | OCSF verb (1=Create, 2=Read, 3=Update, 4=Delete, 99=Other) | `2` |
| `activity_name` | `<verb>_<resource>` | `"list_pods"` |
| `api.operation` | K8s verb | `"list"` |
| `resources[]` | K8s resource the call targeted | `[{name:"prod/db-0", type:"kubernetes pod"}]` |
| `status_id` | 1=Success, 2=Failure, 99=Other | `2` |
| `actor.user.{name,uid}` | best-effort principal | `{name: "alice@example.com"}` |
| `actor.session.uid` | active per-task scope id | `"task-2026-05-18T14:02:00Z"` |
| `unmapped.iam_jit.verdict` | `ALLOW` / `DENY` / `BYPASS` | `"DENY"` |
| `unmapped.iam_jit.enforced` | `true` when transparent-mode block actually fired | `true` |
| `unmapped.iam_jit.decision_id` | SQLite decisions row id | `1234` |
| `unmapped.iam_jit.mode` | `cooperative` / `transparent` at decision time | `"transparent"` |
| `unmapped.iam_jit.profile` | active environment profile name | `"staging-work"` |
| `unmapped.iam_jit.agent.name` | agent identity (see Agent identity below) | `"claude-code"` |
| `unmapped.iam_jit.agent.session_id` | per-MCP-connection UUID v7 | `"01HK4Q..."` |
| `unmapped.iam_jit.agent.detected_from` | source of the fingerprint | `"mcp_clientinfo"` |
| `unmapped.iam_jit.ext.k8s_subresource` | exec / log / portforward / etc. | `"exec"` |
| `unmapped.iam_jit.ext.namespace` | target namespace | `"prod"` |

## Agent identity

Per [the agent-identity-in-audit feature](../README.md), every event
carries a populated `unmapped.iam_jit.agent` block. The block always
has `name` + `detected_from` set so SIEM queries never trip over
missing fields.

`detected_from` priorities (best-effort, in order):

1. `mcp_clientinfo` — Claude Code / Cursor / Devin / Codex announced
   themselves via the MCP `initialize` handshake. Highest fidelity.
2. `user_agent` — kubectl / client-go / helm / k9s / argocd-cli / flux
   / kustomize parsed from the User-Agent header. Medium fidelity.
3. `process_tree` — parent-process exe path (Linux only;
   `--mcp-process-tree-fingerprint` flag opts in; SENSITIVE — stripped
   from webhook bodies by default per the safety-not-surveillance
   posture).
4. `unknown` — no source fired. The raw User-Agent (if any) is
   preserved under `unmapped.iam_jit.agent.user_agent_raw` so you can
   build a custom filter for tools we don't yet have a rule for.

`session_id` is a UUID v7 minted at MCP-connect, bound across every
audit event in that connection. When the MCP connection closes, a
synthetic `SESSION_ENDED` event lands (activity_id=99,
`unmapped.iam_jit.event_type="SESSION_ENDED"`) so you can close your
"all events from session X" query with both bookends.

## Worked examples per SIEM

### Splunk (SPL)

```spl
# All events from a specific agent session
index=iam_jit_bouncer source=kbounce
  "unmapped.iam_jit.agent.session_id"="01HK4QABCDEF"
| stats count by activity_name, status, unmapped.iam_jit.agent.name

# All DENY events for delete operations in the last 24h
index=iam_jit_bouncer source=kbounce
  "unmapped.iam_jit.verdict"="DENY"
  "api.operation"="delete"
  earliest=-24h
| stats count by actor.user.name, unmapped.iam_jit.agent.name,
         resources{}.name

# Cross-bouncer: every kbounce + ibounce + dbounce event from
# claude-code in May 2026
index=iam_jit_bouncer
  "unmapped.iam_jit.agent.name"="claude-code"
  _time >= "2026-05-01" _time < "2026-06-01"
| stats count by metadata.product.name, activity_name, status
```

### Datadog Logs

```
service:kbounce
@unmapped.iam_jit.agent.name:"claude-code"
@unmapped.iam_jit.agent.session_id:"01HK4QABCDEF"

# All enforced denies (transparent-mode blocks that actually fired)
service:kbounce
@unmapped.iam_jit.verdict:"DENY"
@unmapped.iam_jit.enforced:true

# Exec sessions opened across all bouncers
service:(kbounce OR ibounce OR dbounce)
@unmapped.iam_jit.ext.k8s_subresource:"exec"
```

### Microsoft Sentinel (KQL)

```kql
// All events from claude-code in May 2026
IamJitBouncer_CL
| where TimeGenerated >= datetime(2026-05-01) and TimeGenerated < datetime(2026-06-01)
| where unmapped_iam_jit_s.agent.name == "claude-code"
| summarize count() by activity_name_s, status_s

// Bursts of DENY events from one agent session
IamJitBouncer_CL
| where unmapped_iam_jit_s.verdict == "DENY"
| summarize denies = count() by SessionId = tostring(unmapped_iam_jit_s.agent.session_id),
            Agent = tostring(unmapped_iam_jit_s.agent.name)
| where denies > 10
```

### AWS Security Lake (Athena over OCSF parquet)

```sql
-- All events from claude-code in May 2026
SELECT activity_name, status, COUNT(*) AS cnt
FROM ocsf_api_activity
WHERE eventday BETWEEN '20260501' AND '20260531'
  AND metadata.product.name = 'kbounce'
  AND unmapped['iam_jit']['agent']['name'] = 'claude-code'
GROUP BY activity_name, status
ORDER BY cnt DESC;

-- Find which agent issued an exec into prod
SELECT time, unmapped['iam_jit']['agent']['name']     AS agent,
              unmapped['iam_jit']['agent']['session_id'] AS session,
              actor.user.name                           AS principal,
              resources[1].name                         AS resource
FROM ocsf_api_activity
WHERE metadata.product.name = 'kbounce'
  AND unmapped['iam_jit']['ext']['k8s_subresource'] = 'exec'
  AND unmapped['iam_jit']['ext']['namespace'] = 'prod'
ORDER BY time DESC
LIMIT 100;
```

### Local DuckDB (no SIEM; raw JSONL audit file)

```bash
# All claude-code DENY events in the last 7 days, grouped by activity
duckdb -c "
SELECT activity_name, COUNT(*) AS cnt
FROM read_json_auto('~/.kbouncer/audit.jsonl')
WHERE json_extract_string(unmapped, '\$.iam_jit.agent.name') = 'claude-code'
  AND json_extract_string(unmapped, '\$.iam_jit.verdict') = 'DENY'
  AND time >= (epoch_ms(now()) - 7*24*3600*1000)
GROUP BY activity_name
ORDER BY cnt DESC;"

# Bookend a single agent session — open + close events
duckdb -c "
SELECT to_timestamp(time/1000) AS at,
       activity_name,
       json_extract_string(unmapped, '\$.iam_jit.event_type') AS marker,
       json_extract_string(unmapped, '\$.iam_jit.agent.name') AS agent
FROM read_json_auto('~/.kbouncer/audit.jsonl')
WHERE json_extract_string(unmapped, '\$.iam_jit.agent.session_id') = '01HK4QABCDEF'
ORDER BY time;"
```

### Cross-bouncer filtering (`metadata.product.name`)

If you collect events from multiple bouncers into one SIEM index, the
`metadata.product.name` field disambiguates:

| Product | `metadata.product.name` |
|---|---|
| ibounce (AWS IAM) | `ibounce` |
| kbounce (Kubernetes) | `kbounce` |
| dbounce (DB wire protocols) | `dbounce` |

```spl
# Cross-bouncer: every event from claude-code across the entire suite
index=iam_jit_bouncer
  "unmapped.iam_jit.agent.name"="claude-code"
| stats count by metadata.product.name, activity_name, status
| sort -count
```

## Common patterns

### "Which agent did this?" — single-query answer

Pre-launch this question required joining kbounce audit rows with your
IDE / agent-platform logs by timestamp + user identity. Now:

```spl
index=iam_jit_bouncer
  decision_id=42
| table actor.user.name, unmapped.iam_jit.agent.name,
        unmapped.iam_jit.agent.version,
        unmapped.iam_jit.agent.session_id
```

### "All calls from this agent session"

```spl
index=iam_jit_bouncer
  "unmapped.iam_jit.agent.session_id"="01HK4QABCDEF"
| sort _time
```

The session opens at the first event with this `session_id`; closes at
the `SESSION_ENDED` event with the same `session_id`. Calls between
those bookends are the agent's entire activity.

### "Find bypass" — a CloudTrail / kube-audit event from a user without
matching kbounce activity

If your kube-audit-log shows a delete from `alice@example.com` at
14:02 but there's no kbounce event with `actor.user.name="alice@..."`
within ±2s of that timestamp, alice's call bypassed the proxy. The
agent block is part of the bypass-detection story per
[[script-bypass-threat-model]].

## Retention

kbounce does NOT set retention. Defaults of common collectors:

| Collector | Default retention |
|---|---|
| Splunk | 90 days hot, 1 year warm typical |
| Datadog Logs | 15 days |
| Sentinel | 90 days |
| AWS Security Lake | indefinite (S3 lifecycle controls) |
| Local JSONL | indefinite (logrotate is yours) |
| Local SQLite | indefinite (operator wipes when they want) |

Configure retention in your collector, not in kbounce.

## SENSITIVE fields stripped from webhook by default

Per the safety-not-surveillance posture,
`unmapped.iam_jit.agent.process_exe` and
`unmapped.iam_jit.agent.parent_exe` reveal the operator's local
tooling. The local JSONL log + SQLite always carry them (operator owns
those); the HTTPS webhook strips them unless you opt in via
`--audit-webhook-include-process-tree`.

## Live tail + filtering + summary + export (`kbounce audit tail`)

`kbounce audit tail` is the local-operator view of the same OCSF
events the SIEM-side queries above key off. The flag set matches the
cross-product spec — `ibounce audit tail` + `dbounce audit tail`
ship the same flags, same supported-field catalog, same summary
groupings, same export formats. An operator who knows one knows them
all.

```
kbounce audit tail [--limit N] [--follow]
                   [--filter EXPR ...]
                   [--summary]
                   [--export {jsonl,csv,ocsf-bundle} --out PATH
                    [--csv-columns col1,col2,...]]
                   [--db PATH]
```

### `--follow`

Live tail. Polls the SQLite audit DB every 500ms and prints new
decisions as they land. Exit with Ctrl-C / SIGINT.

```
$ kbounce audit tail --follow
(following kbounce audit DB; Ctrl-C to exit)
AT (UTC)              MODE         VERDICT  SOURCE     REQUEST
2026-05-18 14:20:54   transparent  allow    profile    GET /api/v1/namespaces/prod/pods
2026-05-18 14:20:55   transparent  deny     profile    DELETE /api/v1/namespaces/prod/pods/db-0
                                                ↳  matched deny rule
^C
(follow stopped)
```

### `--filter EXPR` (repeatable; AND-combined)

Three operators:

| Form | Semantics |
|---|---|
| `field=value` | exact string equality |
| `field~regex` | Go regexp (RE2) match |
| `field>=N` / `field<=N` | numeric comparison (integer fields only) |

Supported fields (cross-product vocabulary; same in ibounce + dbounce):

- `severity_id` — OCSF severity enum (1=Informational ... 5=Critical)
- `activity_id` — OCSF activity enum (1=Create, 2=Read, 3=Update, 4=Delete, 99=Other)
- `status_id` — OCSF status enum (1=Success, 2=Failure, 99=Other)
- `actor.user.name` — best-effort principal name
- `api.operation` — K8s verb (e.g. `delete`, `list`)
- `unmapped.iam_jit.agent.name` — agent identity (see Agent identity caveat below)
- `unmapped.iam_jit.agent.session_id` — per-MCP-connection UUID v7
- `unmapped.iam_jit.event_type` — `DECISION` / `SESSION_ENDED` / `HEARTBEAT` / ...

kbounce-specific extensions:

- `resource.namespace` — K8s namespace
- `resource.name` — `namespace/name` or `name` (cluster-scope)
- `resource.type` — `kubernetes pod` / `kubernetes secret` / ...
- `unmapped.iam_jit.verdict` — `ALLOW` / `DENY` / `BYPASS`
- `unmapped.iam_jit.mode` — `cooperative` / `transparent`
- `unmapped.iam_jit.profile` — active profile name
- `unmapped.iam_jit.enforced` — `true` / `false`

Examples:

```
# DELETE-shaped calls only
kbounce audit tail --filter 'api.operation=delete'

# DELETEs against prod, regex form
kbounce audit tail --filter 'api.operation~^delete$' \
                   --filter 'resource.namespace=prod'

# Anything Medium-severity or worse
kbounce audit tail --filter 'severity_id>=3'
```

### `--summary`

Count-summary instead of rows. Four groupings:

```
$ kbounce audit tail --summary
audit-tail summary (3 row(s) considered)

BY EVENT_TYPE
       3  DECISION

BY SEVERITY
       3  Informational

BY ACTOR
       3  (unknown)

BY API.OPERATION
       1  create
       1  delete
       1  list
```

Mutually exclusive with `--follow` (summary is a terminal aggregation;
follow is open-ended).

### `--export {jsonl,csv,ocsf-bundle} --out PATH`

Bulk-export the filtered row set for downstream tools.

- `--export jsonl` — one OCSF API Activity event per line. Round-trips
  through `jq`. Mirrors the wire shape your SIEM ingests.
- `--export csv` — tabular view. Default columns:
  `timestamp,severity,event_type,actor,operation,verdict,agent.name,agent.session_id`.
  PII columns (`actor.user.name`, `actor.user.uid`,
  `agent.process_exe`, `agent.parent_exe`, `agent.user_agent_raw`)
  are OUT of the default set; opt in by naming them in `--csv-columns`.
- `--export ocsf-bundle` — single OCSF Detection Finding (class 2004)
  wrapping the events under `.events[]`. Lets a security team upload
  a forensic snapshot in one shot via a SIEM batch-import endpoint.

```
$ kbounce audit tail --filter 'unmapped.iam_jit.verdict=DENY' \
                     --export jsonl --out denies.jsonl
wrote 7 row(s) to denies.jsonl (format=jsonl)

$ jq -c 'select(.api.operation=="delete")' denies.jsonl
```

`--export` composes with `--filter` (filter applies first; export
writes the survivors).

### Agent identity caveat for SQLite-sourced rows

`kbounce audit tail` reads from the SQLite audit DB, which does NOT
persist the agent-identity block (agent name + session id are bound
in memory for the lifetime of the proxy process; only the JSONL log +
HTTPS webhook persist them). SQLite-sourced rows render
`unmapped.iam_jit.agent.name = "unknown"`. For agent-scoped queries,
`jq` over `~/.kbouncer/audit.jsonl` (or your SIEM) is the canonical
path — the SQLite store is for "what just happened on the proxy"
local-operator workflows.

### Cross-product parity

| Surface | ibounce | kbounce | dbounce |
|---|---|---|---|
| `audit tail --follow` | ships | ships | ships |
| `audit tail --filter EXPR` | ships | ships | ships |
| `audit tail --summary` | ships | ships | ships |
| `audit tail --export {jsonl,csv,ocsf-bundle}` | ships | ships | ships |
| Supported filter fields | shared catalog above | shared + `resource.namespace`/`.name`/`.type` | shared + dbounce SQL ext |

Per [[cross-product-agent-parity]]: the flag set + supported field
vocabulary + summary groupings + export formats are identical across
the suite. Product-specific extension fields (kbounce's
`resource.namespace`, dbounce's SQL-statement fields) are additive —
they never replace the shared catalog.

## HTTP `GET /audit/events` endpoint (`#271`)

kbounce exposes the same query surface as a headless HTTP endpoint on
its existing port (`8766`):

```
GET /audit/events?since=ISO8601&until=ISO8601&filter=field=value&filter=...&limit=N&format=jsonl|ocsf-bundle
```

Same filter language as `kbounce audit tail --filter`, same supported
field catalog. Defaults: `limit=100` (max `1000`), `format=jsonl` (one
OCSF event per line). Pass `format=ocsf-bundle` for a single
OCSF v1.1.0 class 2004 Detection Finding wrapping the matched events.

### Sample invocations

```bash
# Loopback bind (default): no auth required.
curl 'http://127.0.0.1:8766/audit/events?limit=10'

# Filter to one namespace + last hour, NDJSON.
curl 'http://127.0.0.1:8766/audit/events?filter=resource.namespace=prod&since=2026-05-18T00:00:00Z'

# OCSF Detection Finding bundle for SIEM batch import.
curl 'http://127.0.0.1:8766/audit/events?format=ocsf-bundle&limit=100'
```

### Auth model

- **Loopback bind (default)**: no `Authorization` header required.
  kbounce refuses to bind off-loopback without
  `--i-know-this-binds-externally`.
- **External bind**: `kbounce run --i-know-this-binds-externally
  --host 0.0.0.0 --audit-events-token <TOKEN>` is required. Requests
  must carry `Authorization: Bearer <TOKEN>`. Missing header → 401;
  wrong token → 403. kbounce refuses to start in external-bind mode
  without `--audit-events-token`.

### Cross-bouncer query

The `iam-jit audit query` CLI calls this endpoint on every reachable
bouncer in parallel and merges the results. See
[`iam-roles/docs/IAM-JIT-AUDIT-QUERY.md`](https://github.com/trsreagan3/iam-roles/blob/main/docs/IAM-JIT-AUDIT-QUERY.md)
for the cross-product correlation workflow.
