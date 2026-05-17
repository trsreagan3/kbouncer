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
	}
}
