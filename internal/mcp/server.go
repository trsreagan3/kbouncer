// Package mcp implements kbouncer's MCP (Model Context Protocol) server.
//
// K-Slice 6 — the MCP-over-stdio shape that Claude Code, Cursor, Codex,
// and Devin all consume. An agent client connects to `kbouncer mcp`,
// discovers the tools via JSON-RPC 2.0 `tools/list`, and invokes them
// with `tools/call`. Mirrors the Python iam-jit-bouncer MCP tool family
// (`bouncer_*`) so an operator who already learned one tool surface
// understands the other.
//
// Implementation notes:
//
//   - Hand-rolled JSON-RPC 2.0 loop over stdin/stdout. No external MCP
//     library dependency — the stdio framing is line-delimited JSON,
//     which is small enough that a 200-line dispatcher is cleaner than
//     vendoring a 5000-line MCP SDK. Same approach the Python side
//     took (mcp_server.py's `main` is also a hand-rolled stdin reader).
//   - Tools are dispatched via a string -> handler map; adding a tool
//     means appending to one slice + one switch case. Tool schemas
//     are inputSchema JSON-Schema objects matching the conventions of
//     the Python MCP server.
//   - Tools that need the store (rules CRUD, decide, tail, task
//     lifecycle) take a *store.Store. Tools that need the profile
//     (active_profile) take *profile.Profile.
//   - Tools that READ state read it FRESH on every call (no caching);
//     same invariant the Python side enforces so an agent that
//     hot-reloads sees the live truth.
//
// Audit-cadence notes (per [[audit-cadence-discipline]]):
//
//   - MCP tools that MUTATE (kbounce_add_rule, kbounce_scope_self_for_task,
//     kbounce_end_task) flow through the SAME store API + same input
//     validation as the CLI. An agent that calls add_rule with a
//     malformed pattern gets the same ErrInvalidRule shape the CLI
//     does — there is no MCP-specific bypass surface.
//   - kbounce_recommend_mode_for_task is DETERMINISTIC, per
//     [[bouncer-mode-selection-for-agents]]. No LLM call. The decision
//     matrix is a tiny Go switch the agent can also reason about
//     locally if it wants to.
//   - Agent-impersonation surface: the MCP server runs as the operator
//     who started `kbouncer mcp`. The agent that connects can do
//     EXACTLY what kbouncer-the-process can do — no more. There is no
//     elevation path. Mutations are audited via the store's normal
//     audit-write path so a malicious agent's actions show up in the
//     operator's tail.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/trsreagan3/kbouncer/internal/parser"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/proxy"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
	"github.com/trsreagan3/kbouncer/internal/tasks"
)

// ProtocolVersion is the MCP protocol version we advertise. Tracks the
// 2024-11-05 spec; the Python side advertises the same.
const ProtocolVersion = "2024-11-05"

// ServerName / ServerVersion identify the server to MCP clients.
// ServerName tracks the renamed canonical binary (`kbounce`) per
// [[bounce-suite-rename]]; agents that learned the old name still
// work because the protocol-level handshake doesn't pin on this value.
const (
	ServerName    = "kbounce"
	ServerVersion = "1.0.0"
)

// Config wires the MCP server to the live kbouncer state on disk.
// All fields are optional — a tool that needs something it doesn't
// have surfaces a clear error to the caller.
type Config struct {
	// Store is the SQLite handle the rules / tasks / audit tools
	// consult. Nil disables those tools (they return a structured
	// error to the caller).
	Store *store.Store

	// ActiveProfile names the profile currently bound to the running
	// proxy. May be nil ("none" profile equivalent). Read-only at the
	// MCP surface — agents introspect; they cannot switch the profile.
	ActiveProfile *profile.Profile

	// ProfilesPath is the path to the profiles.yaml currently in use.
	// Surfaced by kbounce_active_profile so an agent can echo "active
	// profile loaded from ~/.kbouncer/profiles.yaml" without guessing.
	ProfilesPath string

	// Mode is the cooperative/transparent mode the running proxy was
	// started with. Surfaced by kbounce_active_mode.
	Mode proxy.Mode

	// DefaultPolicy mirrors the proxy's default-policy flag.
	DefaultPolicy proxy.DefaultPolicy

	// TaskOwner is the owner slot the running proxy is bound to.
	// Surfaced by kbounce_active_task so an agent on a multi-owner
	// laptop talks to the right slot.
	TaskOwner string

	// Actor is the string recorded in audit rows when MCP-initiated
	// mutations land. Defaults to "kbounce-mcp" when empty.
	Actor string
}

// Server is the MCP-over-stdio server. Construct one via NewServer,
// then call Serve(stdin, stdout) — Serve blocks until stdin closes.
type Server struct {
	cfg Config
	mu  sync.Mutex // serializes audit writes that share a sql.DB conn
}

// NewServer constructs an MCP server from the given config.
func NewServer(cfg Config) *Server {
	if cfg.Actor == "" {
		cfg.Actor = "kbounce-mcp"
	}
	return &Server{cfg: cfg}
}

// Serve runs the JSON-RPC loop. One request per line on `in`; one
// response per line on `out`. Blocks until `in` returns io.EOF.
//
// The MCP stdio transport is line-delimited JSON per the spec; no
// Content-Length framing. Parse errors yield a JSON-RPC parse-error
// response with id=null per JSON-RPC 2.0 §5.1.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Bump the buffer cap to handle large `tools/list` responses + the
	// occasional big rule patch. Default is 64KB; we go to 4MB to be
	// safe.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rawRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(errResponse(nil, -32700, fmt.Sprintf("parse error: %v", err)))
			continue
		}
		resp := s.dispatch(req)
		if resp == nil {
			// Notification — no response per JSON-RPC §4.1.
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("mcp: encode response: %w", err)
		}
	}
	return scanner.Err()
}

// rawRequest is the on-the-wire JSON-RPC 2.0 request shape.
type rawRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// dispatch handles one JSON-RPC request. Returns nil for notifications.
func (s *Server) dispatch(req rawRequest) any {
	switch req.Method {
	case "initialize":
		return okResponse(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{
				"name":    ServerName,
				"version": ServerVersion,
			},
		})
	case "tools/list":
		return okResponse(req.ID, map[string]any{"tools": ToolDescriptors()})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResponse(req.ID, -32602, fmt.Sprintf("invalid params: %v", err))
		}
		result, err := s.callTool(p.Name, p.Arguments)
		if err != nil {
			// Convention: tool errors are returned as structured JSON in
			// the content text, not JSON-RPC errors. This mirrors the
			// Python side + lets agents surface the message to the user
			// without parsing the JSON-RPC error envelope.
			result = map[string]any{
				"error": err.Error(),
			}
		}
		text, _ := json.MarshalIndent(result, "", "  ")
		return okResponse(req.ID, map[string]any{
			"content":           []map[string]any{{"type": "text", "text": string(text)}},
			"structuredContent": result,
		})
	case "notifications/initialized", "notifications/cancelled":
		return nil
	}
	return errResponse(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
}

// callTool dispatches the named tool against the given args.
func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	switch name {
	case "kbounce_active_mode":
		return s.toolActiveMode(args)
	case "kbounce_active_profile":
		return s.toolActiveProfile(args)
	case "kbounce_recommend_mode_for_task":
		return toolRecommendModeForTask(args)
	case "kbounce_scope_self_for_task":
		return s.toolScopeSelfForTask(args)
	case "kbounce_active_task":
		return s.toolActiveTask(args)
	case "kbounce_end_task":
		return s.toolEndTask(args)
	case "kbounce_task_review":
		return s.toolTaskReview(args)
	case "kbounce_list_rules":
		return s.toolListRules(args)
	case "kbounce_add_rule":
		return s.toolAddRule(args)
	case "kbounce_remove_rule":
		return s.toolRemoveRule(args)
	case "kbounce_decide":
		return s.toolDecide(args)
	case "kbounce_tail_decisions":
		return s.toolTailDecisions(args)
	}
	return nil, fmt.Errorf("unknown tool: %s", name)
}

// requireStore is the shared precondition check for tools that need
// SQLite. Returns a structured error caller can return directly.
func (s *Server) requireStore() error {
	if s.cfg.Store == nil {
		return errors.New("kbounce mcp: store not configured; pass --db to `kbounce mcp`")
	}
	return nil
}

// ---------------------------------------------------------------------
// Tools that READ live config
// ---------------------------------------------------------------------

func (s *Server) toolActiveMode(_ map[string]any) (map[string]any, error) {
	return map[string]any{
		"mode":           string(s.cfg.Mode),
		"default_policy": string(s.cfg.DefaultPolicy),
	}, nil
}

func (s *Server) toolActiveProfile(_ map[string]any) (map[string]any, error) {
	if s.cfg.ActiveProfile == nil || s.cfg.ActiveProfile.Name == "" ||
		s.cfg.ActiveProfile.Name == profile.FullUserProfileName {
		return map[string]any{
			"name":             profile.FullUserProfileName,
			"description":      "No profile active; calls forwarded as-is + audit-logged. Default.",
			"deny_keyword_n":   0,
			"deny_verb_n":      0,
			"only_cluster_n":   0,
			"allow_rule_n":     0,
			"source":           "local",
			"profiles_path":    s.cfg.ProfilesPath,
		}, nil
	}
	p := s.cfg.ActiveProfile
	source := p.Source
	if source == "" {
		source = "local"
	}
	return map[string]any{
		"name":           p.Name,
		"description":    p.Description,
		"deny_keyword_n": len(p.DenyKeywords),
		"deny_verb_n":    len(p.DenyVerbs),
		"only_cluster_n": len(p.OnlyClusters),
		"allow_rule_n":   len(p.AllowRules),
		"source":         source,
		"profiles_path":  s.cfg.ProfilesPath,
	}, nil
}

// ---------------------------------------------------------------------
// kbounce_recommend_mode_for_task — DETERMINISTIC decision matrix.
// Per [[bouncer-mode-selection-for-agents]]: NOT an LLM call.
// ---------------------------------------------------------------------

func toolRecommendModeForTask(args map[string]any) (map[string]any, error) {
	verbs := stringSliceArg(args, "verbs")
	hasWrites := containsWriteVerb(verbs)
	prodNS := boolArg(args, "targets_prod")
	wantsAudit := boolArg(args, "wants_audit_only", false)

	// Decision matrix (mirrors the Python iam-jit-bouncer
	// recommend_mode_for_task; cooperative is the lean-permissive
	// default unless the task EXPLICITLY needs transparent's
	// enforcement):
	//
	//   wants_audit_only=true                  -> cooperative
	//   targets_prod=true AND has writes       -> transparent
	//   has writes only                        -> cooperative
	//                                             (lean-permissive;
	//                                              admin can pause)
	//   reads-only on any env                  -> cooperative
	mode := proxy.ModeCooperative
	reason := "cooperative mode: lean-permissive default per safety-mode-lean-permissive"
	switch {
	case wantsAudit:
		mode = proxy.ModeCooperative
		reason = "cooperative mode: audit-only declared (wants_audit_only=true)"
	case prodNS && hasWrites:
		mode = proxy.ModeTransparent
		reason = "transparent mode: prod-targeting write task (targets_prod=true AND verbs include write)"
	case hasWrites:
		reason = "cooperative mode: non-prod writes; lean-permissive with audit + admin pause available"
	default:
		reason = "cooperative mode: reads-only; no enforcement needed"
	}
	return map[string]any{
		"mode":   string(mode),
		"reason": reason,
		"deterministic": true, // load-bearing flag: tells caller this is NOT an LLM call
	}, nil
}

// ---------------------------------------------------------------------
// kbounce_scope_self_for_task — agent declares intent + we open a task.
// ---------------------------------------------------------------------

func (s *Server) toolScopeSelfForTask(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	desc, _ := args["description"].(string)
	verbs := stringSliceArg(args, "verbs")
	namespaces := stringSliceArg(args, "namespaces")
	resources := stringSliceArg(args, "resources")
	denyVerbs := stringSliceArg(args, "deny_verbs")
	durationMin := intArg(args, "duration_minutes", 30)
	if len(verbs) == 0 || len(resources) == 0 {
		return nil, errors.New(
			"kbounce_scope_self_for_task: at least one verb + one resource required " +
				"(use `*` for any verb / any resource within the task)")
	}
	allowRules := make([]rules.ProxyRule, 0, len(verbs)*len(resources))
	for _, v := range verbs {
		for _, r := range resources {
			rule := rules.ProxyRule{
				Pattern: fmt.Sprintf("%s:%s", r, v),
				Effect:  rules.EffectAllow,
				Origin:  rules.OriginTask,
			}
			if len(namespaces) == 1 {
				rule.NamespaceScope = namespaces[0]
			}
			allowRules = append(allowRules, rule)
		}
	}
	denyRules := make([]rules.ProxyRule, 0, len(denyVerbs))
	for _, dv := range denyVerbs {
		denyRules = append(denyRules, rules.ProxyRule{
			Pattern: fmt.Sprintf("*:%s", dv),
			Effect:  rules.EffectDeny,
			Origin:  rules.OriginTask,
		})
	}
	scope, err := tasks.BuildScope(desc, allowRules, denyRules, durationMin, s.cfg.Actor, s.cfg.TaskOwner)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cfg.Store.AddTask(scope); err != nil {
		return nil, err
	}
	return map[string]any{
		"task_id":      scope.TaskID,
		"description":  scope.Description,
		"expires_at":   scope.ExpiresAt,
		"allow_rule_n": len(scope.AllowRules),
		"deny_rule_n":  len(scope.DenyRules),
	}, nil
}

func (s *Server) toolActiveTask(_ map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	t, err := s.cfg.Store.GetActiveTask(s.cfg.TaskOwner)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return map[string]any{"active": false}, nil
	}
	return map[string]any{
		"active":       true,
		"task_id":      t.TaskID,
		"description":  t.Description,
		"started_at":   t.StartedAt,
		"expires_at":   t.ExpiresAt,
		"allow_rule_n": len(t.AllowRules),
		"deny_rule_n":  len(t.DenyRules),
	}, nil
}

func (s *Server) toolEndTask(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	reason := stringArg(args, "reason", "ended via mcp")
	t, err := s.cfg.Store.GetActiveTask(s.cfg.TaskOwner)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return map[string]any{"ended": false, "message": "no active task"}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, err := s.cfg.Store.EndTask(t.TaskID, s.cfg.Actor, reason, tasks.StatusCompleted)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ended": ok, "task_id": t.TaskID}, nil
}

func (s *Server) toolTaskReview(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	taskID := stringArg(args, "task_id", "")
	if taskID == "" {
		return nil, errors.New("kbounce_task_review: task_id required")
	}
	rev, err := s.cfg.Store.TaskReviewSummary(taskID)
	if err != nil {
		return nil, err
	}
	if rev == nil {
		return nil, fmt.Errorf("no task with id %q", taskID)
	}
	return map[string]any{
		"task_id":        rev.TaskID,
		"status":         rev.Status,
		"description":    rev.Description,
		"started_at":     rev.StartedAt,
		"ended_at":       rev.EndedAt,
		"decision_count": rev.DecisionCount,
		"allow_count":    rev.AllowCount,
		"deny_count":     rev.DenyCount,
		"denied_calls_n": len(rev.DeniedCalls),
	}, nil
}

// ---------------------------------------------------------------------
// kbounce_list_rules / add_rule / remove_rule — rule CRUD
// ---------------------------------------------------------------------

func (s *Server) toolListRules(_ map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	stored, err := s.cfg.Store.ListRules()
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(stored))
	for _, sr := range stored {
		m := sr.Rule.ToMap()
		m["id"] = int64(sr.ID)
		rows = append(rows, m)
	}
	return map[string]any{
		"rules": rows,
		"count": len(rows),
	}, nil
}

func (s *Server) toolAddRule(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	pattern := stringArg(args, "pattern", "")
	effect := stringArg(args, "effect", "allow")
	r := rules.ProxyRule{
		Pattern:        pattern,
		Effect:         rules.Effect(effect),
		NamespaceScope: stringArg(args, "namespace_scope", ""),
		ResourceScope:  stringArg(args, "resource_scope", ""),
		VerbScope:      stringArg(args, "verb_scope", ""),
		Note:           stringArg(args, "note", ""),
		Origin:         rules.OriginUser,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := s.cfg.Store.AddRule(r)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":      int64(id),
		"pattern": r.Pattern,
		"effect":  string(r.Effect),
	}, nil
}

func (s *Server) toolRemoveRule(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	id := int64(intArg(args, "id", 0))
	if id <= 0 {
		return nil, errors.New("kbounce_remove_rule: id required (positive integer)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, err := s.cfg.Store.RemoveRule(rules.ID(id))
	if err != nil {
		return nil, err
	}
	return map[string]any{"removed": ok, "id": id}, nil
}

// ---------------------------------------------------------------------
// kbounce_decide — dry-run a request shape; returns verdict without
// writing an audit row or forwarding upstream.
// ---------------------------------------------------------------------

func (s *Server) toolDecide(args map[string]any) (map[string]any, error) {
	method := stringArg(args, "method", "GET")
	path := stringArg(args, "path", "")
	if path == "" {
		return nil, errors.New("kbounce_decide: `path` required (e.g. /api/v1/namespaces/default/pods)")
	}
	// Build a synthetic *http.Request the parser package accepts. We
	// use MustParseTestURL's shape (a bare URL + method + empty
	// Header) — same code path the parser test suite exercises so
	// kbounce_decide returns the same verdict the live proxy would.
	req := parser.MustParseTestURL(method, "http://placeholder"+ensureLeadingSlash(path))
	parsed, perr := parser.Parse(req)
	if perr != nil || parsed == nil {
		return map[string]any{
			"verdict":         "deny",
			"decision_source": "unclassifiable",
			"reason":          fmt.Sprintf("unclassifiable path %q", path),
		}, nil
	}
	// Profile evaluation (read-only; same engine the proxy uses).
	if s.cfg.ActiveProfile != nil {
		pv := s.cfg.ActiveProfile.Evaluate(&profile.ParsedRequest{
			Verb:         parsed.Verb,
			Namespace:    parsed.Namespace,
			ResourceName: parsed.Name,
		})
		if pv.Denied {
			return map[string]any{
				"verdict":         "deny",
				"decision_source": "profile",
				"reason":          pv.Reason,
			}, nil
		}
	}
	if s.cfg.Store == nil {
		// No store → can't consult rules. Return default policy as the
		// best-effort verdict so an agent can still preview against the
		// profile.
		return map[string]any{
			"verdict":         string(s.cfg.DefaultPolicy),
			"decision_source": "default",
			"reason":          "no store configured; default policy applied",
		}, nil
	}
	ruleSet, err := s.cfg.Store.LoadRuleSet()
	if err != nil {
		return nil, err
	}
	ruleReq := &rules.ParsedRequest{
		Verb: parsed.Verb, Resource: parsed.Resource,
		Namespace: parsed.Namespace, Name: parsed.Name,
		Group: parsed.Group, Subresource: parsed.Subresource,
	}
	res := ruleSet.Evaluate(ruleReq)
	if res != nil {
		verdict := "allow"
		if res.Effect == rules.EffectDeny {
			verdict = "deny"
		}
		return map[string]any{
			"verdict":         verdict,
			"decision_source": "global",
			"reason":          fmt.Sprintf("matched rule pattern %q", res.Rule.Pattern),
		}, nil
	}
	return map[string]any{
		"verdict":         string(s.cfg.DefaultPolicy),
		"decision_source": "default",
		"reason":          fmt.Sprintf("no rule matched; default policy %q applied", s.cfg.DefaultPolicy),
	}, nil
}

// ---------------------------------------------------------------------
// kbounce_tail_decisions — recent audit rows.
// ---------------------------------------------------------------------

func (s *Server) toolTailDecisions(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	limit := intArg(args, "limit", 50)
	rows, err := s.cfg.Store.RecentDecisions(limit)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		row := map[string]any{
			"at":              r.At.UTC().Format("2006-01-02T15:04:05Z"),
			"method":          r.Method,
			"path":            r.Path,
			"verb":            r.ParsedVerb,
			"resource":        r.ParsedResource,
			"namespace":       r.ParsedNamespace,
			"verdict":         r.DecisionVerdict,
			"reason":          r.DecisionReason,
			"decision_source": r.DecisionSource,
			"enforced":        r.Enforced,
			"is_stream":       r.IsStream,
			"stream_kind":     r.StreamKind,
		}
		if r.TaskID != "" {
			row["task_id"] = r.TaskID
		}
		out = append(out, row)
	}
	return map[string]any{
		"decisions": out,
		"count":     len(out),
	}, nil
}

// ---------------------------------------------------------------------
// arg-coercion helpers
// ---------------------------------------------------------------------

func stringArg(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return def
}

func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return def
}

func boolArg(args map[string]any, key string, def ...bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	if len(def) > 0 {
		return def[0]
	}
	return false
}

func stringSliceArg(args map[string]any, key string) []string {
	raw, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containsWriteVerb(verbs []string) bool {
	writeVerbs := map[string]bool{
		"create":           true,
		"update":           true,
		"patch":            true,
		"delete":           true,
		"deletecollection": true,
		"exec":             true,
		"portforward":      true,
		"attach":           true,
	}
	for _, v := range verbs {
		if writeVerbs[strings.ToLower(v)] {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------
// JSON-RPC envelope helpers
// ---------------------------------------------------------------------

func okResponse(id json.RawMessage, result any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      jsonRawOrNull(id),
		"result":  result,
	}
}

func errResponse(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      jsonRawOrNull(id),
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
}

// jsonRawOrNull returns the raw JSON value if non-nil, else nil so the
// encoder emits `"id": null` per JSON-RPC §5.1 for parse errors.
func jsonRawOrNull(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// ensureLeadingSlash makes sure paths used in synthetic *http.Request
// builders start with `/` so url.Parse treats them as paths, not
// schemes.
func ensureLeadingSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}
