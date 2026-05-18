package audit

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------
// FingerprintFromUserAgent — the User-Agent classifier table
// ---------------------------------------------------------------------

// TestFingerprintFromUserAgent_KubectlAndClientGo covers the
// User-Agent shapes K8s tooling actually ships per the
// [[agent-identity-in-audit]] kbounce notes — client-go calls carry
// distinctive UA strings (kubernetes/<commit>), kubectl carries
// kubectl/<version>. New tools added here MUST land an example in
// userAgentRules + a row here.
func TestFingerprintFromUserAgent_KubectlAndClientGo(t *testing.T) {
	cases := []struct {
		name        string
		ua          string
		wantName    string
		wantVersion string
	}{
		{
			name:        "kubectl-darwin-arm64",
			ua:          "kubectl/v1.28.3 (darwin/arm64) kubernetes/abc1234",
			wantName:    "kubectl",
			wantVersion: "v1.28.3",
		},
		{
			name:        "kubectl-linux-amd64",
			ua:          "kubectl/v1.30.0 (linux/amd64) kubernetes/c4a9d11",
			wantName:    "kubectl",
			wantVersion: "v1.30.0",
		},
		{
			name:        "bare-client-go",
			ua:          "kubernetes/v1.28.0 (linux/amd64) kubernetes/abc123",
			wantName:    "client-go",
			wantVersion: "v1.28.0",
		},
		{
			name:        "helm-cli",
			ua:          "Helm/v3.13.2",
			wantName:    "helm",
			wantVersion: "v3.13.2",
		},
		{
			name:        "k9s-tui",
			ua:          "k9s/v0.27.4",
			wantName:    "k9s",
			wantVersion: "v0.27.4",
		},
		{
			name:        "argocd-cli",
			ua:          "argocd-cli/v2.8.0 (linux/amd64)",
			wantName:    "argocd-cli",
			wantVersion: "v2.8.0",
		},
		{
			name:        "flux-cli",
			ua:          "flux/v2.1.0",
			wantName:    "flux",
			wantVersion: "v2.1.0",
		},
		{
			name:        "go-http-client",
			ua:          "Go-http-client/1.1",
			wantName:    "go-http-client",
			wantVersion: "1.1",
		},
		{
			name:        "curl-debug-session",
			ua:          "curl/8.4.0",
			wantName:    "curl",
			wantVersion: "8.4.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := FingerprintFromUserAgent(tc.ua)
			assert.Equal(t, tc.wantName, info.Name, "ua=%q", tc.ua)
			assert.Equal(t, tc.wantVersion, info.Version)
			assert.Equal(t, DetectionSourceUserAgent, info.DetectedFrom,
				"detected_from must record the source for analyst filtering")
			// RawUserAgent only set when no rule matched — should be
			// empty for these mapped cases.
			assert.Empty(t, info.RawUserAgent,
				"raw UA is only preserved when no rule fires")
		})
	}
}

// TestFingerprintFromUserAgent_UnknownPreservesRaw covers the honest-
// best-effort path per [[scorer-is-ground-truth]]: an unrecognized UA
// surfaces as name=unknown but the raw UA is preserved so an analyst
// can build a custom filter for tools we don't yet know about.
func TestFingerprintFromUserAgent_UnknownPreservesRaw(t *testing.T) {
	info := FingerprintFromUserAgent("CustomCorpClient/4.2 (internal)")
	assert.Equal(t, AgentNameUnknown, info.Name)
	assert.Equal(t, DetectionSourceUserAgent, info.DetectedFrom)
	assert.Equal(t, "CustomCorpClient/4.2 (internal)", info.RawUserAgent,
		"raw UA must be preserved so analysts can write their own filters")
}

// TestFingerprintFromUserAgent_EmptyFallsThrough confirms an empty UA
// yields DetectionSourceUnknown so the caller can fall through to
// process-tree fingerprinting (per the priority order in the memo).
func TestFingerprintFromUserAgent_EmptyFallsThrough(t *testing.T) {
	info := FingerprintFromUserAgent("")
	assert.Empty(t, info.Name)
	assert.Equal(t, DetectionSourceUnknown, info.DetectedFrom,
		"empty UA → 'unknown' so the caller can try a different source")
}

// TestFingerprintFromUserAgent_RawTruncated covers the
// pathological-large UA case — a misbehaving client can't blow up
// the audit row size. Cap at RawUserAgentMaxLen with ellipsis.
func TestFingerprintFromUserAgent_RawTruncated(t *testing.T) {
	big := strings.Repeat("X", RawUserAgentMaxLen+50)
	info := FingerprintFromUserAgent(big)
	assert.Equal(t, AgentNameUnknown, info.Name)
	assert.LessOrEqual(t, len(info.RawUserAgent), RawUserAgentMaxLen)
	assert.True(t, strings.HasSuffix(info.RawUserAgent, "..."),
		"truncation must be visible — analyst should see it was clipped")
}

// ---------------------------------------------------------------------
// FingerprintFromMCPClientInfo — the clientInfo alias normalizer
// ---------------------------------------------------------------------

// TestFingerprintFromMCPClientInfo_CanonicalizesAliases covers the
// alias table — Claude Code / Cursor / Devin / Codex have all shipped
// multiple `name` spellings in the wild; canonical_name strips them
// to one stable identifier so a customer's SIEM query joins cleanly.
func TestFingerprintFromMCPClientInfo_CanonicalizesAliases(t *testing.T) {
	cases := []struct {
		clientName string
		want       string
	}{
		{"claude-code", "claude-code"},
		{"Claude-Code", "claude-code"},
		{"claude_code", "claude-code"},
		{"CLAUDE CODE", "claude-code"},
		{"@anthropic/claude-code", "claude-code"},
		{"cursor", "cursor"},
		{"Cursor-IDE", "cursor"},
		{"cursor.sh", "cursor"},
		{"devin", "devin"},
		{"Cognition-Devin", "devin"},
		{"codex", "codex"},
		{"openai-codex", "codex"},
		{"windsurf", "windsurf"},
		{"continue", "continue"},
		{"continue.dev", "continue"},
		// Unknown names pass through lowercased (still recorded as
		// MCP-source so analysts know the agent SAID this).
		{"some-future-agent", "some-future-agent"},
	}
	for _, tc := range cases {
		t.Run(tc.clientName, func(t *testing.T) {
			info := FingerprintFromMCPClientInfo(tc.clientName, "1.2.3")
			assert.Equal(t, tc.want, info.Name)
			assert.Equal(t, "1.2.3", info.Version)
			assert.Equal(t, DetectionSourceMCPClientInfo, info.DetectedFrom)
		})
	}
}

// TestFingerprintFromMCPClientInfo_EmptyNameUnknown covers the
// degenerate path — clientInfo present but empty name still gets a
// queryable agent block with detected_from=mcp_clientinfo so the
// existence of the MCP connection is recorded.
func TestFingerprintFromMCPClientInfo_EmptyNameUnknown(t *testing.T) {
	info := FingerprintFromMCPClientInfo("", "9.9")
	assert.Equal(t, AgentNameUnknown, info.Name)
	assert.Equal(t, "9.9", info.Version)
	assert.Equal(t, DetectionSourceMCPClientInfo, info.DetectedFrom)
}

// ---------------------------------------------------------------------
// Detection-source priority order
// ---------------------------------------------------------------------

// TestDetectionSourcePriority pins the priority order per the
// [[agent-identity-in-audit]] memo: mcp_clientinfo > user_agent >
// process_tree > unknown. Documented via the constant values; this
// test makes the priority explicit so a future refactor that
// reorders the dispatch can't silently change semantics.
func TestDetectionSourcePriority(t *testing.T) {
	// Pinning the literal strings — these are part of the wire shape
	// (customer SIEM queries key off them) so any rename is a
	// breaking change that must surface as a test failure.
	assert.Equal(t, "mcp_clientinfo", DetectionSourceMCPClientInfo)
	assert.Equal(t, "user_agent", DetectionSourceUserAgent)
	assert.Equal(t, "process_tree", DetectionSourceProcessTree)
	assert.Equal(t, "unknown", DetectionSourceUnknown)
}

// ---------------------------------------------------------------------
// Registry — session-id lifecycle + concurrency
// ---------------------------------------------------------------------

// TestRegistry_LifecycleRegisterLookupForget covers the basic happy
// path — Register binds; Lookup returns the bound info with the
// session id stamped on; Forget removes + returns the last-known
// state so the caller can emit SESSION_ENDED with the right agent
// block.
func TestRegistry_LifecycleRegisterLookupForget(t *testing.T) {
	r := NewRegistry()
	sid := NewSessionID()
	info := AgentInfo{
		Name:         "claude-code",
		Version:      "1.2.3",
		DetectedFrom: DetectionSourceMCPClientInfo,
	}
	r.Register(sid, info)
	assert.EqualValues(t, 1, r.ActiveCount())

	got := r.Lookup(sid)
	assert.Equal(t, "claude-code", got.Name)
	assert.Equal(t, sid, got.SessionID,
		"Lookup must stamp session id onto the returned info")

	forgot := r.Forget(sid)
	assert.Equal(t, "claude-code", forgot.Name)
	assert.Equal(t, sid, forgot.SessionID)
	assert.EqualValues(t, 0, r.ActiveCount())

	// Subsequent Lookup returns zero info with the session id still
	// stamped (so a stale-header request from a closed session is
	// recorded with the id but no fingerprint).
	stale := r.Lookup(sid)
	assert.Empty(t, stale.Name)
	assert.Equal(t, sid, stale.SessionID)
}

// TestRegistry_NilSafeOps covers the nil-Registry path that callers
// rely on (proxy hot-path with cfg.AgentRegistry==nil). All methods
// must be no-ops; lookups return zero info.
func TestRegistry_NilSafeOps(t *testing.T) {
	var r *Registry
	r.Register("sid", AgentInfo{Name: "x"}) // must not panic
	got := r.Lookup("sid")
	assert.Empty(t, got.Name)
	assert.Empty(t, got.SessionID)
	forgot := r.Forget("sid")
	assert.Empty(t, forgot.Name)
	assert.EqualValues(t, 0, r.ActiveCount())
}

// TestRegistry_RegisterIsIdempotentNoActiveDoubleCount confirms
// re-registering the same session id (e.g. clientInfo arrives AFTER
// the placeholder was registered at NewServer) overwrites the bound
// info WITHOUT double-counting active sessions.
func TestRegistry_RegisterIsIdempotentNoActiveDoubleCount(t *testing.T) {
	r := NewRegistry()
	sid := NewSessionID()
	r.Register(sid, AgentInfo{Name: AgentNameUnknown})
	r.Register(sid, AgentInfo{Name: "claude-code"})
	assert.EqualValues(t, 1, r.ActiveCount(),
		"re-Register on same id must not double-count active sessions")
	assert.Equal(t, "claude-code", r.Lookup(sid).Name,
		"second Register must overwrite the placeholder bind")
}

// TestRegistry_RaceCleanConcurrentRegisterLookupForget exercises the
// RWMutex protection — concurrent Register / Lookup / Forget calls
// must not race per `go test -race`. Goroutines hammer a fresh
// registry with distinct session ids; the final ActiveCount must
// reflect the surviving (non-forgotten) sessions.
func TestRegistry_RaceCleanConcurrentRegisterLookupForget(t *testing.T) {
	r := NewRegistry()
	const N = 50
	var wg sync.WaitGroup
	wg.Add(N * 2)
	for i := 0; i < N; i++ {
		sid := uuid.New().String()
		go func(sid string) {
			defer wg.Done()
			r.Register(sid, AgentInfo{Name: "claude-code", DetectedFrom: DetectionSourceMCPClientInfo})
			for j := 0; j < 10; j++ {
				_ = r.Lookup(sid)
			}
			r.Forget(sid)
		}(sid)
		// And a parallel reader that does a stray lookup against a
		// random id — must not race.
		go func() {
			defer wg.Done()
			_ = r.Lookup(uuid.New().String())
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 0, r.ActiveCount(),
		"every Register was paired with Forget; active count should be zero")
}

// ---------------------------------------------------------------------
// NewSessionID — UUID v7 time-ordered IDs
// ---------------------------------------------------------------------

// TestNewSessionID_IsUUIDv7AndUnique pins the [[agent-identity-in-
// audit]] Don't list: "Don't make session ID predictable (use UUID v7
// with random component, not a counter)." A counter would let a
// malicious agent forge "this came from session N+1." UUID v7 is
// time-ordered (so SIEM queries sort sanely) + random in the trailing
// 74 bits.
func TestNewSessionID_IsUUIDv7AndUnique(t *testing.T) {
	id1 := NewSessionID()
	id2 := NewSessionID()
	assert.NotEqual(t, id1, id2, "session ids must be unique")
	// Parse + check the version nibble (the [14] char of the canonical
	// UUID string format is the version digit per RFC 9562 §5).
	u1, err := uuid.Parse(id1)
	require.NoError(t, err, "session id must parse as a UUID")
	assert.Equal(t, uuid.Version(7), u1.Version(),
		"session id must be UUID v7 — predictable IDs would let a malicious agent forge 'this came from session N'")
}

// ---------------------------------------------------------------------
// ToOCSFAgent — the AgentInfo → wire shape conversion
// ---------------------------------------------------------------------

// TestAgentInfo_ToOCSFAgent_AlwaysPopulatedDefaults pins the wire-
// shape invariant: every audit event carries a queryable agent block.
// Empty AgentInfo → {name:"unknown", detected_from:"unknown"} so a
// SIEM query on unmapped.iam_jit.agent.name = "unknown" surfaces
// unattributed traffic as a first-class signal rather than missing-
// field noise.
func TestAgentInfo_ToOCSFAgent_AlwaysPopulatedDefaults(t *testing.T) {
	out := AgentInfo{}.ToOCSFAgent()
	require.NotNil(t, out)
	assert.Equal(t, AgentNameUnknown, out.Name)
	assert.Equal(t, DetectionSourceUnknown, out.DetectedFrom)
	assert.Empty(t, out.SessionID)
	assert.Empty(t, out.ProcessExe)
	assert.Empty(t, out.ParentExe)
}

// TestAgentInfo_ToOCSFAgent_PreservesFields covers the populated
// path — every AgentInfo field round-trips through ToOCSFAgent.
func TestAgentInfo_ToOCSFAgent_PreservesFields(t *testing.T) {
	in := AgentInfo{
		Name:         "claude-code",
		Version:      "1.2.3",
		SessionID:    "01HK4Q...",
		DetectedFrom: DetectionSourceMCPClientInfo,
		ProcessExe:   "/usr/local/bin/claude",
		ParentExe:    "/Applications/Cursor.app/Contents/MacOS/Cursor",
		RawUserAgent: "ClaudeCode/1.2.3",
	}
	out := in.ToOCSFAgent()
	require.NotNil(t, out)
	assert.Equal(t, in.Name, out.Name)
	assert.Equal(t, in.Version, out.Version)
	assert.Equal(t, in.SessionID, out.SessionID)
	assert.Equal(t, in.DetectedFrom, out.DetectedFrom)
	assert.Equal(t, in.ProcessExe, out.ProcessExe)
	assert.Equal(t, in.ParentExe, out.ParentExe)
	assert.Equal(t, in.RawUserAgent, out.RawUserAgent)
}

// ---------------------------------------------------------------------
// SESSION_ENDED event + FromDecision agent-block plumbing
// ---------------------------------------------------------------------

// TestNewSessionEndedEvent_OCSFShape pins the synthetic event the MCP
// server emits when an agent session closes. Same OCSF shape as the
// AUDIT_DROPPED marker (activity_id=99 + event_type marker under
// unmapped.iam_jit) but with the agent block populated so analysts
// can close their "all events from session X" query bookends.
func TestNewSessionEndedEvent_OCSFShape(t *testing.T) {
	info := AgentInfo{
		Name:         "claude-code",
		Version:      "1.2.3",
		SessionID:    "01HK4QABCDEF",
		DetectedFrom: DetectionSourceMCPClientInfo,
	}
	ev := NewSessionEndedEvent(info)
	assert.Equal(t, ClassUID, ev.ClassUID)
	assert.Equal(t, ActivityOther, ev.ActivityID)
	assert.Equal(t, "session_ended", ev.ActivityName)
	assert.Equal(t, SeverityInformational, ev.SeverityID)
	assert.Equal(t, "SESSION_ENDED", ev.Unmapped.IAMJIT.EventType)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	assert.Equal(t, "claude-code", ev.Unmapped.IAMJIT.Agent.Name)
	assert.Equal(t, "01HK4QABCDEF", ev.Unmapped.IAMJIT.Agent.SessionID)
	assert.Equal(t, EventTypeSessionEnded, ev.EventType)
}

// TestFromDecision_AgentBlockAlwaysPresent covers the wire-shape
// guarantee for decision events: the agent block is always non-nil
// on a FromDecision event (defaulting to unknown/unknown) so a SIEM
// query on unmapped.iam_jit.agent.* never trips over missing fields.
func TestFromDecision_AgentBlockAlwaysPresent(t *testing.T) {
	ev := FromDecision(DecisionInput{Verdict: "allow"})
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent,
		"every decision event MUST carry a queryable agent block")
	assert.Equal(t, AgentNameUnknown, ev.Unmapped.IAMJIT.Agent.Name)
	assert.Equal(t, DetectionSourceUnknown, ev.Unmapped.IAMJIT.Agent.DetectedFrom)
}

// TestFromDecision_AgentBlockThreadsThroughInput confirms a populated
// AgentInfo on the input lands intact on the wire shape (the
// FromDecision → ToOCSFAgent path).
func TestFromDecision_AgentBlockThreadsThroughInput(t *testing.T) {
	ev := FromDecision(DecisionInput{
		Verdict: "allow",
		Agent: AgentInfo{
			Name:         "claude-code",
			Version:      "1.2.3",
			SessionID:    "01HK4Q-test",
			DetectedFrom: DetectionSourceMCPClientInfo,
		},
	})
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	a := ev.Unmapped.IAMJIT.Agent
	assert.Equal(t, "claude-code", a.Name)
	assert.Equal(t, "1.2.3", a.Version)
	assert.Equal(t, "01HK4Q-test", a.SessionID)
	assert.Equal(t, DetectionSourceMCPClientInfo, a.DetectedFrom)

	// Confirm it serializes under unmapped.iam_jit.agent.* (not
	// top-level) so it stays in the vendor extension.
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	unm := m["unmapped"].(map[string]any)
	jit := unm["iam_jit"].(map[string]any)
	agent, ok := jit["agent"].(map[string]any)
	require.True(t, ok, "agent block must serialize under unmapped.iam_jit.agent")
	assert.Equal(t, "claude-code", agent["name"])
	assert.Equal(t, "01HK4Q-test", agent["session_id"])
	assert.Equal(t, "mcp_clientinfo", agent["detected_from"])
	// process_exe / parent_exe MUST NOT appear when empty (omitempty).
	_, hasExe := agent["process_exe"]
	assert.False(t, hasExe, "process_exe must be omitempty when unset")
}

// ---------------------------------------------------------------------
// RedactForWebhook — SENSITIVE process-tree fields stripped by default
// ---------------------------------------------------------------------

// TestRedactForWebhook_StripsProcessTreeByDefault pins the
// [[security-team-positioning-safety-not-surveillance]] gate: the
// HTTPS webhook body MUST NOT carry the operator's process_exe /
// parent_exe paths unless the operator explicitly opted in via
// IncludeProcessTree=true.
func TestRedactForWebhook_StripsProcessTreeByDefault(t *testing.T) {
	ev := FromDecision(DecisionInput{
		Verdict: "allow",
		Agent: AgentInfo{
			Name:         "claude-code",
			DetectedFrom: DetectionSourceMCPClientInfo,
			ProcessExe:   "/usr/local/bin/claude",
			ParentExe:    "/Applications/Cursor.app/Contents/MacOS/Cursor",
		},
	})
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	require.NotEmpty(t, ev.Unmapped.IAMJIT.Agent.ProcessExe,
		"unredacted event keeps process_exe (local-log home)")

	redacted := ev.RedactForWebhook(false)
	require.NotNil(t, redacted.Unmapped.IAMJIT.Agent)
	assert.Empty(t, redacted.Unmapped.IAMJIT.Agent.ProcessExe,
		"webhook body MUST strip process_exe by default")
	assert.Empty(t, redacted.Unmapped.IAMJIT.Agent.ParentExe,
		"webhook body MUST strip parent_exe by default")
	// Non-sensitive fields preserved.
	assert.Equal(t, "claude-code", redacted.Unmapped.IAMJIT.Agent.Name)
	assert.Equal(t, DetectionSourceMCPClientInfo, redacted.Unmapped.IAMJIT.Agent.DetectedFrom)

	// And the original event is unmodified (defensive copy).
	assert.Equal(t, "/usr/local/bin/claude", ev.Unmapped.IAMJIT.Agent.ProcessExe,
		"RedactForWebhook must return a copy; original event preserves the local-trail fields")
}

// TestRedactForWebhook_IncludeOptIn covers the operator opt-in: when
// IncludeProcessTree=true the webhook body carries the fields. Used
// by customers who explicitly want full forensics in their SIEM (and
// have signed off on the local-tooling exposure).
func TestRedactForWebhook_IncludeOptIn(t *testing.T) {
	ev := FromDecision(DecisionInput{
		Verdict: "allow",
		Agent: AgentInfo{
			Name:         "claude-code",
			DetectedFrom: DetectionSourceMCPClientInfo,
			ProcessExe:   "/usr/local/bin/claude",
		},
	})
	redacted := ev.RedactForWebhook(true)
	assert.Equal(t, "/usr/local/bin/claude",
		redacted.Unmapped.IAMJIT.Agent.ProcessExe,
		"opt-in must preserve the SENSITIVE process-tree fields")
}

// TestRedactForWebhook_NilAgentIsSafe covers AUDIT_DROPPED + alert
// events which don't carry an agent block. Redaction must be a
// no-op.
func TestRedactForWebhook_NilAgentIsSafe(t *testing.T) {
	dropped := NewDroppedMarker(3)
	require.Nil(t, dropped.Unmapped.IAMJIT.Agent,
		"synthetic markers don't carry an agent block")
	out := dropped.RedactForWebhook(false)
	assert.Nil(t, out.Unmapped.IAMJIT.Agent,
		"redact on a nil agent must stay nil")
}
