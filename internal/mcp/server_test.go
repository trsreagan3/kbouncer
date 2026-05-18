package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/proxy"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// freshStore returns an open in-memory store backed by a tempdir DB.
// Mirrors the proxy package's test helper so tests read the same way.
func freshStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/state.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// rpcRoundTrip serializes a request to the server's Serve loop and
// returns the parsed response. Single-request convenience; for
// multi-request sessions tests build their own buffered driver.
func rpcRoundTrip(t *testing.T, srv *Server, method string, params any, id int) map[string]any {
	t.Helper()
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	in := bytes.NewBuffer(nil)
	if err := json.NewEncoder(in).Encode(req); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if err := srv.Serve(in, out); err != nil && err != io.EOF {
		t.Fatalf("Serve: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", out.String(), err)
	}
	return resp
}

// callTool is a convenience wrapper around tools/call that returns the
// `structuredContent` payload directly.
func callTool(t *testing.T, srv *Server, name string, args map[string]any) map[string]any {
	t.Helper()
	resp := rpcRoundTrip(t, srv, "tools/call", map[string]any{
		"name":      name,
		"arguments": args,
	}, 42)
	require.NotNil(t, resp["result"], "tools/call must return a result envelope; got %v", resp)
	result := resp["result"].(map[string]any)
	sc, ok := result["structuredContent"].(map[string]any)
	require.True(t, ok, "tools/call result must include structuredContent; got %v", result)
	return sc
}

// ---------------------------------------------------------------------
// initialize + tools/list
// ---------------------------------------------------------------------

func TestServer_InitializeReturnsProtocolVersion(t *testing.T) {
	srv := NewServer(Config{})
	resp := rpcRoundTrip(t, srv, "initialize", map[string]any{}, 1)
	require.NotNil(t, resp["result"])
	result := resp["result"].(map[string]any)
	assert.Equal(t, ProtocolVersion, result["protocolVersion"])
	si := result["serverInfo"].(map[string]any)
	assert.Equal(t, ServerName, si["name"])
}

func TestServer_ToolsListReturnsAllTools(t *testing.T) {
	srv := NewServer(Config{})
	resp := rpcRoundTrip(t, srv, "tools/list", nil, 2)
	result := resp["result"].(map[string]any)
	rawTools := result["tools"].([]any)
	gotNames := make(map[string]bool)
	for _, x := range rawTools {
		m := x.(map[string]any)
		gotNames[m["name"].(string)] = true
	}
	// Sanity: every name we dispatch in callTool MUST show up here so
	// agents can discover them.
	wantNames := []string{
		"kbounce_active_mode",
		"kbounce_active_profile",
		"kbounce_recommend_mode_for_task",
		"kbounce_scope_self_for_task",
		"kbounce_active_task",
		"kbounce_end_task",
		"kbounce_task_review",
		"kbounce_list_rules",
		"kbounce_add_rule",
		"kbounce_remove_rule",
		"kbounce_decide",
		"kbounce_tail_decisions",
		"kbounce_pending_sync_prompts",
	}
	for _, n := range wantNames {
		assert.True(t, gotNames[n], "tools/list missing %q", n)
	}
}

// ---------------------------------------------------------------------
// kbounce_active_mode + kbounce_active_profile
// ---------------------------------------------------------------------

func TestActiveMode_ReflectsConfig(t *testing.T) {
	srv := NewServer(Config{
		Mode:          proxy.ModeTransparent,
		DefaultPolicy: proxy.DefaultPolicyDeny,
	})
	got := callTool(t, srv, "kbounce_active_mode", nil)
	assert.Equal(t, "transparent", got["mode"])
	assert.Equal(t, "deny", got["default_policy"])
}

func TestActiveProfile_FullUserWhenUnset(t *testing.T) {
	srv := NewServer(Config{})
	got := callTool(t, srv, "kbounce_active_profile", nil)
	assert.Equal(t, profile.FullUserProfileName, got["name"])
}

func TestActiveProfile_ReturnsLiveProfile(t *testing.T) {
	p := &profile.Profile{
		Name:         "staging-work",
		Description:  "test profile",
		DenyKeywords: []string{"prod", "production"},
		DenyVerbs:    []string{"delete"},
		Source:       "local",
	}
	srv := NewServer(Config{
		ActiveProfile: p,
		ProfilesPath:  "/tmp/profiles.yaml",
	})
	got := callTool(t, srv, "kbounce_active_profile", nil)
	assert.Equal(t, "staging-work", got["name"])
	assert.EqualValues(t, 2, got["deny_keyword_n"])
	assert.EqualValues(t, 1, got["deny_verb_n"])
	assert.Equal(t, "local", got["source"])
}

// ---------------------------------------------------------------------
// kbounce_recommend_mode_for_task — DETERMINISTIC decision matrix
// ---------------------------------------------------------------------

func TestRecommendModeForTask_ReadsOnlyReturnsCooperative(t *testing.T) {
	srv := NewServer(Config{})
	got := callTool(t, srv, "kbounce_recommend_mode_for_task", map[string]any{
		"verbs":        []any{"get", "list", "watch"},
		"targets_prod": false,
	})
	assert.Equal(t, "cooperative", got["mode"])
	assert.True(t, got["deterministic"].(bool),
		"deterministic flag MUST be true — load-bearing signal that this is NOT an LLM call")
}

func TestRecommendModeForTask_ProdWritesReturnsTransparent(t *testing.T) {
	srv := NewServer(Config{})
	got := callTool(t, srv, "kbounce_recommend_mode_for_task", map[string]any{
		"verbs":        []any{"create", "delete"},
		"targets_prod": true,
	})
	assert.Equal(t, "transparent", got["mode"])
}

func TestRecommendModeForTask_AuditOnlyAlwaysCooperative(t *testing.T) {
	srv := NewServer(Config{})
	got := callTool(t, srv, "kbounce_recommend_mode_for_task", map[string]any{
		"verbs":            []any{"create", "delete"},
		"targets_prod":     true,
		"wants_audit_only": true,
	})
	// wants_audit_only overrides prod-writes — audit mode wants the
	// cooperative path so nothing is blocked.
	assert.Equal(t, "cooperative", got["mode"])
}

// ---------------------------------------------------------------------
// rules CRUD
// ---------------------------------------------------------------------

func TestListRules_EmptyByDefault(t *testing.T) {
	srv := NewServer(Config{Store: freshStore(t)})
	got := callTool(t, srv, "kbounce_list_rules", nil)
	assert.EqualValues(t, 0, got["count"])
}

func TestAddRule_PersistsAndListReturnsIt(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{Store: st})
	added := callTool(t, srv, "kbounce_add_rule", map[string]any{
		"pattern": "pods:get",
		"effect":  "allow",
		"note":    "test",
	})
	assert.NotZero(t, added["id"])

	listed := callTool(t, srv, "kbounce_list_rules", nil)
	assert.EqualValues(t, 1, listed["count"])
	rows := listed["rules"].([]any)
	row := rows[0].(map[string]any)
	assert.Equal(t, "pods:get", row["pattern"])
	assert.Equal(t, "allow", row["effect"])
}

func TestRemoveRule_Works(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{Store: st})
	added := callTool(t, srv, "kbounce_add_rule", map[string]any{
		"pattern": "pods:get",
	})
	id := added["id"]
	removed := callTool(t, srv, "kbounce_remove_rule", map[string]any{"id": id})
	assert.True(t, removed["removed"].(bool))
	// List should be empty again.
	listed := callTool(t, srv, "kbounce_list_rules", nil)
	assert.EqualValues(t, 0, listed["count"])
}

func TestAddRule_RejectsMalformedPattern(t *testing.T) {
	srv := NewServer(Config{Store: freshStore(t)})
	got := callTool(t, srv, "kbounce_add_rule", map[string]any{
		"pattern": "not-a-valid-pattern",
	})
	// Tool surfaces the error string in structuredContent so the agent
	// can show it to the user without parsing the JSON-RPC envelope.
	assert.Contains(t, fmt.Sprint(got["error"]), "invalid rule")
}

// ---------------------------------------------------------------------
// kbounce_scope_self_for_task — mutating + persists a task
// ---------------------------------------------------------------------

func TestScopeSelfForTask_PersistsAndActiveReturnsIt(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{Store: st})
	got := callTool(t, srv, "kbounce_scope_self_for_task", map[string]any{
		"description": "investigate prod alert",
		"verbs":       []any{"get", "list"},
		"resources":   []any{"pods", "deployments"},
		"deny_verbs":  []any{"delete"},
	})
	require.NotEmpty(t, got["task_id"], "task_id must be returned to the agent so it can end the task later")
	assert.EqualValues(t, 4, got["allow_rule_n"], "2 verbs × 2 resources = 4 allow rules")
	assert.EqualValues(t, 1, got["deny_rule_n"])

	active := callTool(t, srv, "kbounce_active_task", nil)
	assert.True(t, active["active"].(bool))
	assert.Equal(t, got["task_id"], active["task_id"])
}

func TestEndTask_ClosesActiveTask(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{Store: st})
	_ = callTool(t, srv, "kbounce_scope_self_for_task", map[string]any{
		"description": "test",
		"verbs":       []any{"get"},
		"resources":   []any{"pods"},
	})
	ended := callTool(t, srv, "kbounce_end_task", map[string]any{"reason": "done"})
	assert.True(t, ended["ended"].(bool))
	active := callTool(t, srv, "kbounce_active_task", nil)
	assert.False(t, active["active"].(bool))
}

// ---------------------------------------------------------------------
// kbounce_decide — dry-run preview without persisting an audit row
// ---------------------------------------------------------------------

func TestDecide_DoesNotWriteAuditRow(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{
		Store:         st,
		DefaultPolicy: proxy.DefaultPolicyAllow,
	})
	// Run a dry-run decide.
	got := callTool(t, srv, "kbounce_decide", map[string]any{
		"method": "GET",
		"path":   "/api/v1/namespaces/default/pods",
	})
	assert.Equal(t, "allow", got["verdict"])
	// No audit row should have been written — the audit log is for
	// LIVE calls the proxy gated, not preview queries.
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	assert.Empty(t, rows, "kbounce_decide MUST NOT write audit rows; it is a dry-run preview")
}

func TestDecide_HonorsActiveProfile(t *testing.T) {
	// Profile that denies anything with "prod" in the namespace.
	p := &profile.Profile{
		Name:         "test-staging",
		DenyKeywords: []string{"prod"},
	}
	srv := NewServer(Config{
		ActiveProfile: p,
		Store:         freshStore(t),
		DefaultPolicy: proxy.DefaultPolicyAllow,
	})
	got := callTool(t, srv, "kbounce_decide", map[string]any{
		"path": "/api/v1/namespaces/prod-app/pods",
	})
	assert.Equal(t, "deny", got["verdict"],
		"decide must consult the active profile so an agent's preview matches what the proxy would do")
	assert.Equal(t, "profile", got["decision_source"])
}

// ---------------------------------------------------------------------
// kbounce_tail_decisions — reads the audit store
// ---------------------------------------------------------------------

func TestTailDecisions_ReturnsRows(t *testing.T) {
	st := freshStore(t)
	// Seed the store with a decision row directly so we don't depend
	// on the proxy.
	_, err := st.RecordDecision(store.DecisionRow{
		Method:          "GET",
		Path:            "/api/v1/namespaces/default/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "allow",
		DecisionReason:  "test",
		ModeAtDecision:  "cooperative",
		DecisionSource:  "global",
	})
	require.NoError(t, err)

	srv := NewServer(Config{Store: st})
	got := callTool(t, srv, "kbounce_tail_decisions", map[string]any{"limit": 10})
	assert.EqualValues(t, 1, got["count"])
	rows := got["decisions"].([]any)
	row := rows[0].(map[string]any)
	assert.Equal(t, "GET", row["method"])
	assert.Equal(t, "allow", row["verdict"])
}

// ---------------------------------------------------------------------
// Unknown method + parse error JSON-RPC paths
// ---------------------------------------------------------------------

func TestUnknownMethod_ReturnsError32601(t *testing.T) {
	srv := NewServer(Config{})
	resp := rpcRoundTrip(t, srv, "definitely/not/a/real/method", nil, 99)
	require.NotNil(t, resp["error"])
	errObj := resp["error"].(map[string]any)
	assert.EqualValues(t, -32601, errObj["code"])
}

func TestUnknownTool_SurfacesErrorInResult(t *testing.T) {
	srv := NewServer(Config{})
	resp := rpcRoundTrip(t, srv, "tools/call", map[string]any{
		"name":      "no_such_tool",
		"arguments": map[string]any{},
	}, 100)
	result := resp["result"].(map[string]any)
	sc := result["structuredContent"].(map[string]any)
	assert.Contains(t, fmt.Sprint(sc["error"]), "unknown tool")
}

func TestParseError_ReturnsParseErrorResponse(t *testing.T) {
	srv := NewServer(Config{})
	out := &bytes.Buffer{}
	err := srv.Serve(strings.NewReader("not json at all\n"), out)
	require.NoError(t, err)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp))
	errObj := resp["error"].(map[string]any)
	assert.EqualValues(t, -32700, errObj["code"])
}

// ---------------------------------------------------------------------
// requireStore: tools that need the store return a clean error when it
// is missing — the agent should never get a stacktrace.
// ---------------------------------------------------------------------

func TestStorelessConfig_TailDecisionsReturnsClearError(t *testing.T) {
	srv := NewServer(Config{}) // no store
	got := callTool(t, srv, "kbounce_tail_decisions", nil)
	assert.Contains(t, fmt.Sprint(got["error"]), "store not configured")
}

// Suppress unused-warning for rules import which is needed by other test
// helpers if added later.
var _ = rules.EffectAllow

// ---------------------------------------------------------------------
// [[agent-identity-in-audit]] — clientInfo capture + session-id mint +
// SESSION_ENDED emission
// ---------------------------------------------------------------------

// captureEmitter is a minimal audit.Emitter that records every event
// in-memory so tests can assert on what the MCP server published.
// Lives in this test file (rather than shared) so the package import
// graph doesn't leak test helpers.
type captureEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureEmitter) Emit(_ context.Context, ev audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *captureEmitter) Status() audit.Status { return audit.Status{} }

func (c *captureEmitter) snapshot() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

// TestNewServer_MintsSessionIDWhenRegistryConfigured covers Feature 2
// of [[agent-identity-in-audit]]: every MCP connection with an
// AgentRegistry configured gets a persistent UUID v7 minted at
// construction so the proxy hot-path can correlate.
func TestNewServer_MintsSessionIDWhenRegistryConfigured(t *testing.T) {
	reg := audit.NewRegistry()
	srv := NewServer(Config{AgentRegistry: reg})
	sid := srv.SessionID()
	assert.NotEmpty(t, sid, "session ID must be minted when registry is configured")
	// Placeholder AgentInfo is registered so a pre-init proxy lookup
	// still resolves (just to {unknown, unknown}).
	info := reg.Lookup(sid)
	assert.Equal(t, audit.AgentNameUnknown, info.Name)
	assert.Equal(t, sid, info.SessionID)
	assert.EqualValues(t, 1, reg.ActiveCount())
}

// TestNewServer_NoRegistryNoSessionID covers the no-registry path —
// the MCP server still works (the audit pipeline just falls back to
// User-Agent fingerprinting on the proxy side).
func TestNewServer_NoRegistryNoSessionID(t *testing.T) {
	srv := NewServer(Config{})
	assert.Empty(t, srv.SessionID(),
		"no registry → no session id minted (back-compat)")
}

// TestInitialize_CapturesClientInfo_BindsToRegistry pins Feature 1:
// the MCP `initialize` request's clientInfo populates the bound
// AgentInfo + re-registers it under the session id so a proxied SDK
// call inherits the identity. The Server's AgentInfo() snapshot is
// the test surface (the registry is forgotten on Serve teardown so
// we read the in-memory bind on the server itself).
func TestInitialize_CapturesClientInfo_BindsToRegistry(t *testing.T) {
	reg := audit.NewRegistry()
	srv := NewServer(Config{AgentRegistry: reg})
	sid := srv.SessionID()

	// Drive initialize via the dispatch path directly (rpcRoundTrip
	// invokes Serve which would Forget on EOF; we want to observe
	// the live-session state).
	srv.dispatch(rawRequest{Method: "initialize", Params: rawMessage(t, map[string]any{
		"clientInfo": map[string]any{"name": "claude-code", "version": "1.2.3"},
	})})

	got := srv.AgentInfo()
	assert.Equal(t, "claude-code", got.Name,
		"clientInfo must overwrite the placeholder")
	assert.Equal(t, "1.2.3", got.Version)
	assert.Equal(t, audit.DetectionSourceMCPClientInfo, got.DetectedFrom)
	assert.Equal(t, sid, got.SessionID)

	// Registry mirrors the bind — proxy hot-path lookup sees the
	// SAME identity (this is the load-bearing cross-component glue).
	regInfo := reg.Lookup(sid)
	assert.Equal(t, "claude-code", regInfo.Name)
}

// rawMessage marshals v to json.RawMessage; test helper for driving
// dispatch directly with structured params.
func rawMessage(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// TestInitialize_AliasNormalization confirms alternate clientInfo
// spellings (Claude-Code / claude_code / @anthropic/claude-code) all
// canonicalize to the SAME bound name so customer SIEM queries on
// agent.name = "claude-code" return all traffic, not just one alias.
func TestInitialize_AliasNormalization(t *testing.T) {
	cases := []string{"Claude-Code", "claude_code", "@anthropic/claude-code"}
	for _, alias := range cases {
		t.Run(alias, func(t *testing.T) {
			reg := audit.NewRegistry()
			srv := NewServer(Config{AgentRegistry: reg})
			srv.dispatch(rawRequest{Method: "initialize", Params: rawMessage(t, map[string]any{
				"clientInfo": map[string]any{"name": alias},
			})})
			got := srv.AgentInfo()
			assert.Equal(t, "claude-code", got.Name,
				"alias %q must canonicalize to claude-code", alias)
		})
	}
}

// TestInitialize_BareInitNoClientInfoKeepsPlaceholder covers the
// spec-compliant-but-sparse case — a client that sends initialize
// with no clientInfo block. The session stays bound to the
// placeholder {unknown, unknown} record so SESSION_ENDED still
// carries a session_id.
func TestInitialize_BareInitNoClientInfoKeepsPlaceholder(t *testing.T) {
	reg := audit.NewRegistry()
	srv := NewServer(Config{AgentRegistry: reg})
	srv.dispatch(rawRequest{Method: "initialize", Params: rawMessage(t, map[string]any{
		"protocolVersion": "2024-11-05",
	})})
	got := srv.AgentInfo()
	assert.Equal(t, audit.AgentNameUnknown, got.Name)
	assert.Equal(t, audit.DetectionSourceUnknown, got.DetectedFrom)
}

// TestServe_EmitsSessionEndedOnClose pins Feature 2's bookend: when
// the MCP stdin closes (Serve returns), the bound session is
// forgotten + a SESSION_ENDED audit event lands on the configured
// AuditEmitter so analysts see both ends of the agent session.
func TestServe_EmitsSessionEndedOnClose(t *testing.T) {
	reg := audit.NewRegistry()
	cap := &captureEmitter{}
	srv := NewServer(Config{
		AgentRegistry: reg,
		AuditEmitter:  cap,
	})
	sid := srv.SessionID()

	// Drive an initialize + close the stdin (empty buffer = immediate
	// EOF after one request).
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"clientInfo": map[string]any{"name": "cursor", "version": "0.45"},
		},
	}
	in := bytes.NewBuffer(nil)
	require.NoError(t, json.NewEncoder(in).Encode(req))
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(in, out))

	// Registry forgot the session.
	assert.EqualValues(t, 0, reg.ActiveCount(),
		"Serve teardown must Forget the session")

	// And SESSION_ENDED was emitted with the bound agent fingerprint.
	events := cap.snapshot()
	require.Len(t, events, 1, "exactly one SESSION_ENDED event must be emitted")
	ev := events[0]
	assert.Equal(t, audit.EventTypeSessionEnded, ev.EventType)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	assert.Equal(t, "cursor", ev.Unmapped.IAMJIT.Agent.Name,
		"SESSION_ENDED must carry the bound agent fingerprint, not just unknown")
	assert.Equal(t, sid, ev.Unmapped.IAMJIT.Agent.SessionID)
}

// TestServe_NoRegistryNoSessionEndedEvent covers the back-compat
// path — a Server constructed without a registry must NOT emit
// spurious SESSION_ENDED events (the feature is opt-in).
func TestServe_NoRegistryNoSessionEndedEvent(t *testing.T) {
	cap := &captureEmitter{}
	srv := NewServer(Config{AuditEmitter: cap})
	require.NoError(t, srv.Serve(strings.NewReader(""), &bytes.Buffer{}))
	assert.Empty(t, cap.snapshot(),
		"no AgentRegistry → no SESSION_ENDED bookend (feature is opt-in)")
}
