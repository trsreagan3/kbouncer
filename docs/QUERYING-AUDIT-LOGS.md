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
