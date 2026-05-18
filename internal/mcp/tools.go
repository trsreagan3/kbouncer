// MCP tool descriptors. Kept in a separate file from server.go so the
// schema definitions don't crowd the dispatcher.
//
// Each tool entry mirrors the Python iam-jit-bouncer `bouncer_*` shape:
//
//   name         the kbounce_* tool name agents will see
//   description  agent-readable summary (one paragraph max — the agent
//                must be able to decide whether to use this tool from
//                the description alone)
//   inputSchema  JSON-Schema for the arguments. Defensive: every
//                optional arg has a default; every required arg is
//                explicitly listed in `required`.
//
// Schema convention follows the Python side: type/properties/required.
// We do not use $ref or composition — the schemas are flat for
// readability + tooling compat.

package mcp

// ToolDescriptors returns the full tool list surfaced via `tools/list`.
// Returned as a slice (not a map) so the order is deterministic across
// runs — important for agent caching + diff-friendly logs.
func ToolDescriptors() []map[string]any {
	return []map[string]any{
		{
			"name": "kbounce_active_mode",
			"description": "Return kbouncer's current operating mode " +
				"(cooperative | transparent) plus the default-policy " +
				"(allow | deny). Read-only: agents introspect; they cannot " +
				"flip the mode (that requires a proxy restart per " +
				"[[agent-friendly-not-bypassable]]).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "kbounce_active_profile",
			"description": "Return which environment profile is currently " +
				"active (the value of --profile / KBOUNCER_PROFILE at " +
				"proxy-start time, or 'none' if no profile was selected). " +
				"Per [[agent-friendly-not-bypassable]]: agents can READ this " +
				"but CANNOT change it — profile switching is a human/admin " +
				"action requiring a proxy restart. Use this to introspect " +
				"whether a hard-floor deny layer is active before " +
				"recommending actions to the operator. Mirrors the Python " +
				"bouncer_active_profile shape.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "kbounce_recommend_mode_for_task",
			"description": "DETERMINISTIC (not LLM) recommendation: given " +
				"a task shape (verbs + target environment + audit-only " +
				"flag), return 'cooperative' or 'transparent' per the " +
				"[[bouncer-mode-selection-for-agents]] decision matrix. " +
				"Use this BEFORE starting a task to pick the right mode " +
				"flag for `kbouncer run`. The agent's own LLM should " +
				"NOT second-guess this — the answer is deterministic by " +
				"design so the decision is auditable.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"verbs": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "K8s verbs the task will use (get, list, watch, create, ...).",
					},
					"targets_prod": map[string]any{
						"type":        "boolean",
						"description": "True if the task will touch prod-classified namespaces / clusters.",
					},
					"wants_audit_only": map[string]any{
						"type":        "boolean",
						"description": "True if the task is observation-only (no enforcement needed).",
					},
				},
				"required": []string{"verbs"},
			},
		},
		{
			"name": "kbounce_scope_self_for_task",
			"description": "Declare an agent task scope. The agent passes a " +
				"description + the verbs + the resources + (optionally) " +
				"the namespaces it will need; kbouncer opens a task that " +
				"narrows decisions to that declaration. Composes with the " +
				"task-allow flow in the proxy's decision composition order. " +
				"Returns the task_id so the agent can end the task later via " +
				"kbounce_end_task. Per [[creates-never-mutates]]: kbouncer " +
				"creates NEW task scopes; it never modifies pre-existing " +
				"agent identities. Per [[agent-friendly-not-bypassable]]: " +
				"the task scope is enforced for its duration; the agent " +
				"cannot bypass it via an alternative client.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"description": map[string]any{
						"type":        "string",
						"description": "Human-readable task description (recorded in audit log).",
					},
					"verbs": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"resources": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"namespaces": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"deny_verbs": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Verbs the agent KNOWS it should never use during this task (e.g. ['delete']).",
					},
					"duration_minutes": map[string]any{
						"type":    "integer",
						"default": 30,
					},
				},
				"required": []string{"description", "verbs", "resources"},
			},
		},
		{
			"name": "kbounce_active_task",
			"description": "Show the currently-active task scope (if any) " +
				"for kbouncer's owner slot. Returns {active: false} when " +
				"no task is open. Mirrors `kbouncer tasks active` CLI.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "kbounce_end_task",
			"description": "End the currently-active task. Records `reason` " +
				"in the audit log. Mirrors `kbouncer tasks end` CLI.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"reason": map[string]any{
						"type":    "string",
						"default": "ended via mcp",
					},
				},
			},
		},
		{
			"name": "kbounce_task_review",
			"description": "Post-task review summary: total decisions, " +
				"allow/deny breakdown, denied-calls list. Mirrors " +
				"`kbouncer tasks review TASK_ID` CLI.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task_id": map[string]any{"type": "string"},
				},
				"required": []string{"task_id"},
			},
		},
		{
			"name": "kbounce_list_rules",
			"description": "List all global rules in evaluation order " +
				"(deny-beats-allow, first-match). Returns each rule's " +
				"id, pattern, effect, scopes, note, origin.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "kbounce_add_rule",
			"description": "Add a global rule. Pattern shape: " +
				"'resource:verb_glob' (e.g. 'pods:create', 'secrets:get', " +
				"'*:delete*'). Effect: 'allow' | 'deny'. Optional " +
				"namespace_scope / resource_scope / verb_scope are " +
				"AWS-IAM-style globs (only `*` and `?` are meta). Mutating " +
				"tool — recorded in the audit log under origin=user.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":         map[string]any{"type": "string"},
					"effect":          map[string]any{"type": "string", "enum": []string{"allow", "deny"}, "default": "allow"},
					"namespace_scope": map[string]any{"type": "string"},
					"resource_scope":  map[string]any{"type": "string"},
					"verb_scope":      map[string]any{"type": "string"},
					"note":            map[string]any{"type": "string"},
				},
				"required": []string{"pattern"},
			},
		},
		{
			"name": "kbounce_remove_rule",
			"description": "Remove a global rule by numeric id (from " +
				"kbounce_list_rules). Mutating tool — audit-logged.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "integer"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name": "kbounce_decide",
			"description": "Dry-run a request shape through kbouncer's " +
				"rule engine; return the verdict WITHOUT writing to the " +
				"audit log or forwarding upstream. Useful for an agent to " +
				"preview 'would this call be allowed?' before issuing it. " +
				"Returns {verdict, decision_source, reason}.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"method": map[string]any{"type": "string", "default": "GET"},
					"path":   map[string]any{"type": "string", "description": "K8s URL path (e.g. /api/v1/namespaces/default/pods)."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name": "kbounce_recommend_rules",
			"description": "Synthesize draft rules from observed audit-log " +
				"traffic. Returns the rules an operator would get from " +
				"`kbounce rules recommend --since {since}` WITHOUT applying " +
				"them. Read-only tool — useful for an agent at the end of " +
				"a session to suggest 'here are the rules that would " +
				"narrow your future calls.' Per [[cross-product-agent-" +
				"parity]]: mirrors bouncer_recommend_rules on the AWS " +
				"side. Per [[scorer-is-ground-truth]] + [[no-nl-" +
				"synthesis]]: deterministic algorithm; no LLM in the " +
				"synthesis path.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since": map[string]any{
						"type": "string",
						"description": "Window start. Relative ('1h', '24h', '7d') " +
							"or absolute ISO-8601 ('2026-05-17T00:00:00Z'). Default: whole log.",
					},
					"min_support": map[string]any{
						"type":    "integer",
						"default": 3,
						"minimum": 1,
					},
					"include_task_scoped": map[string]any{
						"type":    "boolean",
						"default": false,
						"description": "Include task-scoped decisions in the analysis. Off " +
							"by default: task-scoped decisions are one-off declared " +
							"sessions and shouldn't auto-promote to permanent rules.",
					},
				},
			},
		},
		{
			"name": "kbounce_apply_preset",
			"description": "Apply a curated preset rule pack to the global " +
				"rules table. Use `kbounce_list_presets` first to see " +
				"available names. The preset's rules are ADDED (not " +
				"overwritten) so reapplying produces duplicates — let the " +
				"operator confirm via `kbounce_list_rules`. Per [[cross-" +
				"product-agent-parity]]: mirrors bouncer_apply_preset on " +
				"the AWS side.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "Preset name from `kbounce_list_presets`.",
					},
				},
				"required": []string{"name"},
			},
		},
		{
			"name": "kbounce_list_presets",
			"description": "List the built-in preset names + descriptions. " +
				"Read-only. Use to discover what `kbounce_apply_preset` " +
				"can target.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "kbounce_tail_decisions",
			"description": "Inspect the recent decision audit log " +
				"(every call kbouncer gated). Newest first. Useful for " +
				"agents that want to confirm 'my last call was actually " +
				"allowed' or surface a recent deny to the user.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":    "integer",
						"default": 50,
						"minimum": 1,
						"maximum": 1000,
					},
				},
			},
		},
		{
			"name": "kbounce_audit_export_status",
			"description": "Report the security-team audit-export " +
				"channels' runtime state (#252, Slices 1 + 2). Returns " +
				"which of the two transports are configured (JSONL " +
				"log file + HTTPS webhook), cumulative event totals, " +
				"drop counts, in-flight webhook deliveries, and the " +
				"last-error message for each. Slice 2 (alert rule " +
				"engine) adds alerts_enabled, alerts_fired_count, and " +
				"last_alert_pattern so an operator can confirm the five " +
				"built-in rules (admin_fallback_burst, pause_long, " +
				"non_org_profile_install, unusual_high_risk_action, " +
				"heartbeat_gap) are running + see when the most recent " +
				"one fired. Heartbeat fields (heartbeat_enabled, " +
				"heartbeat_interval_seconds, heartbeat_total_emitted, " +
				"heartbeat_last_emit_unix_milli, heartbeat_healthy) " +
				"surface the liveness watchdog per [[prompt-injection-" +
				"disable-bouncer-threat]] + [[audit-export-failure-" +
				"visibility]] — when heartbeat_healthy is false the " +
				"local heartbeatGapRule has fired + /healthz returns " +
				"503 + a stderr notice was written. Read-only. " +
				"The webhook URL is returned with userinfo + query " +
				"stripped; the Bearer token is NEVER returned (and is " +
				"masked out of any error messages). Use this to confirm " +
				"the running proxy is shipping events to your aggregator " +
				"+ to spot a stuck queue (webhook_in_flight rising). " +
				"Per [[security-team-audit-export]] + [[no-hosted-saas]].",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "list_audit_webhook_presets",
			"description": "#259 — return the cross-product list of audit-" +
				"webhook preset shapes the bouncer speaks, each preset's " +
				"auth header convention + body shape + which CLI flags it " +
				"requires / accepts as optional. Per [[audit-webhook-presets]] " +
				"+ [[cross-product-agent-parity]]: identical JSON shape across " +
				"ibounce / kbounce / dbounce so an agent that wants to ask " +
				"'which webhook shape should I configure for this operator's " +
				"Datadog org?' gets a structured answer regardless of which " +
				"Bounce product it's talking to. READ-ONLY; no side effects; " +
				"safe for agents to poll. Returns the SAME descriptor list " +
				"`kbounce audit-webhook presets list --json` emits.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "kbounce_prompts_bulk_pending",
			"description": "Read-only burst introspection per the [[bulk-" +
				"prompt-answer-ux]] memo. Returns the most-recent unresolved " +
				"BURST_DETECTED event (or burst_id=0 if none), the count of " +
				"currently-pending prompts, the deduplicated (verb, resource) " +
				"tuples those prompts cover, and the list of available bulk-" +
				"answer dispositions. Always available. Use this to surface " +
				"'you have N pending prompts since HH:MM' to the operator " +
				"before recommending the right disposition. Pairs with " +
				"kbounce_prompts_bulk_answer (which is operator-gated by " +
				"design).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "kbounce_prompts_bulk_answer",
			"description": "Resolve a burst of pending DENY prompts with one " +
				"disposition. GATED behind an operator-set shared secret per " +
				"the [[bulk-prompt-answer-ux]] memo's 'Don't' list: an " +
				"adversarial agent that could call this without authorization " +
				"could bulk-allow itself + defeat the operator-in-loop intent. " +
				"Operator wires the gate by passing --bulk-answer-mcp-token " +
				"<secret> to `kbounce mcp serve` AND configuring the agent " +
				"UI to send that secret in args.operator_token. " +
				"Dispositions: session = 24h TTL bulk-allow rules; 3h = 3-hour " +
				"TTL; 10min = 10-minute TTL; profile = hot-swap to args.profile " +
				"name; none = mark answered with no rule change. Default OFF " +
				"(no token configured → tool always refuses).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"decision": map[string]any{
						"type": "string",
						"enum": []string{"session", "3h", "10min", "profile", "none"},
					},
					"profile": map[string]any{
						"type":        "string",
						"description": "Required when decision=profile. The profile name to hot-swap to.",
					},
					"operator_token": map[string]any{
						"type": "string",
						"description": "Operator's shared secret from --bulk-answer-mcp-token. " +
							"Required when the gate is enabled (always required at runtime; " +
							"the tool refuses when the operator hasn't enabled the gate).",
					},
				},
				"required": []string{"decision", "operator_token"},
			},
		},
		{
			"name": "kbounce_pending_sync_prompts",
			"description": "List the pending_prompts rows that the " +
				"running proxy is CURRENTLY blocked on waiting for an " +
				"operator answer (the #203 --sync-prompt-on-deny UX). " +
				"DETERMINISTIC: SQL query against pending_prompts.sync_" +
				"wait_id IS NOT NULL AND status='pending', filtered to " +
				"rows whose in-process waiter is still registered " +
				"(rows from a crashed proxy are NOT returned — the " +
				"request goroutine is dead and cannot resume). Newest " +
				"first. Use this to surface 'there is a blocked request " +
				"waiting on your answer' to an operator's agent client. " +
				"Read-only. Default limit 50.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":    "integer",
						"default": 50,
						"minimum": 1,
						"maximum": 1000,
					},
				},
			},
		},
	}
}
