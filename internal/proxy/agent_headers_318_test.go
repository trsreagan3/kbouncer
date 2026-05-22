// agent_headers_318_test.go — #318 / §A16 cross-bouncer X-Agent-*
// header parity for kbouncer.
//
// These tests assert that kbouncer reads the canonical
// `X-Agent-Name` + `X-Agent-Session-Id` headers on inbound requests
// and populates `unmapped.iam_jit.agent.{name, session_id,
// detected_from}` on every OCSF audit event so that
// `iam-jit audit query --filter agent.session_id=X` returns kbouncer
// events alongside gbounce / ibounce / dbounce ones.
//
// Mirrors gbounce's #308 test pattern + the ibounce slice's canonical
// test names. Per [[cross-product-agent-parity]] the four product test
// suites assert the same shape so cross-product behaviour can be
// verified at a glance.

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
)

// canonicalAgentName + canonicalSessionID are reusable test fixtures
// shaped like the values a real agent runtime would supply.
const (
	canonicalAgentName   = "parity-test"
	canonicalSessionID   = "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
	canonicalSessionIDv4 = "01968d6a-9c12-4a4b-b6f8-3b8e4c0d1aef"
)

// TestAgentHeaders_HappyPath — both headers present + valid → the
// resulting OCSF event carries the agent.name + agent.session_id +
// detected_from=http_header. Canonical cross-product test name.
func TestAgentHeaders_HappyPath(t *testing.T) {
	st := freshStore(t)
	cap := &proxyCaptureEmitter{}
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		AuditEmitter:  cap,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	req.Header.Set("X-Agent-Name", canonicalAgentName)
	req.Header.Set("X-Agent-Session-Id", canonicalSessionID)
	req.Header.Set("User-Agent", "kubectl/v1.30.0 (darwin/arm64) kubernetes/abc1234")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	ev := cap.lastDecision(t)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent,
		"every decision event MUST carry an agent block")
	a := ev.Unmapped.IAMJIT.Agent
	// X-Agent-* wins over kubectl UA — explicit declaration always
	// beats heuristic detection per [[cross-product-agent-parity]].
	assert.Equal(t, canonicalAgentName, a.Name)
	assert.Equal(t, canonicalSessionID, a.SessionID)
	assert.Equal(t, audit.DetectionSourceHTTPHeader, a.DetectedFrom)
	// No rejections counted on the happy path.
	assert.Equal(t, int64(0), s.totalAgentHeadersRejected.Load())
}

// TestAgentHeaders_NoHeaders_FallbackToUserAgent — when neither
// X-Agent-* header is present, the existing User-Agent fingerprint
// path fires unchanged. Cross-product invariant: header is ADDITIVE;
// the pre-#318 detection chain stays intact.
func TestAgentHeaders_NoHeaders_FallbackToUserAgent(t *testing.T) {
	st := freshStore(t)
	cap := &proxyCaptureEmitter{}
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		AuditEmitter:  cap,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "kubectl/v1.30.0 (darwin/arm64) kubernetes/abc1234")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	ev := cap.lastDecision(t)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	a := ev.Unmapped.IAMJIT.Agent
	assert.Equal(t, "kubectl", a.Name)
	assert.Equal(t, audit.DetectionSourceUserAgent, a.DetectedFrom)
	assert.Equal(t, "", a.SessionID, "no header session id → no session id surfaced")
}

// TestAgentHeaders_InvalidName_Rejected — an X-Agent-Name with shell
// metacharacters is dropped (the event surfaces as fingerprint-only)
// + the rejection counter on /healthz bumps so an operator debugging
// "why is my session id missing?" sees the issue.
func TestAgentHeaders_InvalidName_Rejected(t *testing.T) {
	st := freshStore(t)
	cap := &proxyCaptureEmitter{}
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		AuditEmitter:  cap,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	// Shell injection shape — must be rejected per gbounce regex.
	req.Header.Set("X-Agent-Name", "bad agent; rm -rf /")
	req.Header.Set("X-Agent-Session-Id", canonicalSessionID)
	req.Header.Set("User-Agent", "kubectl/v1.30.0")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	ev := cap.lastDecision(t)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	a := ev.Unmapped.IAMJIT.Agent
	// Invalid name → fell through to UA. The malicious value is NEVER
	// written into the audit event.
	assert.Equal(t, "kubectl", a.Name)
	assert.NotContains(t, a.Name, "rm -rf")
	// Valid session_id still overlays so cross-bouncer correlation works.
	assert.Equal(t, canonicalSessionID, a.SessionID)
	// Counter bumped exactly once.
	assert.Equal(t, int64(1), s.totalAgentHeadersRejected.Load())
}

// TestAgentHeaders_NameOnly_PartialDetection — when only X-Agent-Name
// validates (session_id absent), the resulting block carries
// `detected_from=http_header_name_only` so SIEM filters can
// distinguish full from partial header attribution.
func TestAgentHeaders_NameOnly_PartialDetection(t *testing.T) {
	st := freshStore(t)
	cap := &proxyCaptureEmitter{}
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		AuditEmitter:  cap,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	req.Header.Set("X-Agent-Name", canonicalAgentName)
	// No X-Agent-Session-Id supplied — partial detection.
	req.Header.Set("User-Agent", "kubectl/v1.30.0")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	ev := cap.lastDecision(t)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	a := ev.Unmapped.IAMJIT.Agent
	assert.Equal(t, canonicalAgentName, a.Name)
	assert.Equal(t, "", a.SessionID)
	assert.Equal(t, audit.DetectionSourceHTTPHeaderNameOnly, a.DetectedFrom)
}

// TestAgentHeaders_InvalidSessionID_Rejected — an X-Agent-Session-Id
// with spaces / shell metacharacters is dropped + the counter bumps.
// The valid X-Agent-Name still flows through.
func TestAgentHeaders_InvalidSessionID_Rejected(t *testing.T) {
	st := freshStore(t)
	cap := &proxyCaptureEmitter{}
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		AuditEmitter:  cap,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	req.Header.Set("X-Agent-Name", canonicalAgentName)
	req.Header.Set("X-Agent-Session-Id", "not a session id with spaces")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	ev := cap.lastDecision(t)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	a := ev.Unmapped.IAMJIT.Agent
	assert.Equal(t, canonicalAgentName, a.Name)
	// Invalid session id is dropped — detected_from drops to the
	// name-only variant since the session_id never validated.
	assert.Equal(t, "", a.SessionID)
	assert.Equal(t, audit.DetectionSourceHTTPHeaderNameOnly, a.DetectedFrom)
	assert.Equal(t, int64(1), s.totalAgentHeadersRejected.Load())
}

// TestIsValidAgentName_MatchesGbounceRegex asserts kbouncer's
// validator regex matches gbounce's byte-for-byte. Cross-product
// invariant per [[cross-product-agent-parity]]: a name accepted by
// kbouncer must be accepted by every other Bouncer.
func TestIsValidAgentName_MatchesGbounceRegex(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"claude-code", true},
		{"cursor", true},
		{"openai-codex", true},
		{"devin", true},
		{"gpt-4.1", true},
		{"my_agent.v2", true},
		{"a", true},
		{"", false},
		{"has spaces", false},
		{"shell$injection", false},
		{"back`tick", false},
		{"semi;colon", false},
		{"path/sep", false},
		{"with\nnewline", false},
		{"quote'mark", false},
	}
	for _, c := range cases {
		got := audit.IsValidAgentName(c.name)
		assert.Equal(t, c.valid, got, "IsValidAgentName(%q)", c.name)
	}
}

// TestAgentHeaders_UUIDv4_Accepted — operators may use UUID v4 (the
// default in many SDKs) for session ids. We don't enforce v7 strictly
// per the §A16 spec.
func TestAgentHeaders_UUIDv4_Accepted(t *testing.T) {
	st := freshStore(t)
	cap := &proxyCaptureEmitter{}
	s := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		AuditEmitter:  cap,
	}, st)
	ts := httptest.NewServer(http.HandlerFunc(s.handle))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/namespaces/default/pods", nil)
	require.NoError(t, err)
	req.Header.Set("X-Agent-Name", canonicalAgentName)
	req.Header.Set("X-Agent-Session-Id", canonicalSessionIDv4)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	ev := cap.lastDecision(t)
	require.NotNil(t, ev.Unmapped.IAMJIT.Agent)
	assert.Equal(t, canonicalSessionIDv4, ev.Unmapped.IAMJIT.Agent.SessionID)
}
