// dynamic_deny_test.go — #324b proxy-side regression suite.
//
// Covers:
//   - namespace pattern → DENY with deny_source=dynamic +
//     dynamic_deny_rule_id on the observation
//   - cluster pattern → DENY when the proxy's configured cluster matches
//   - resource-triple pattern → DENY on the parser's group/version/resource
//   - dynamic-deny precedence: beats profile-allow + global-allow
//   - the deny audit event carries the dynamic_deny_rule_id on the
//     ext block via the canonical DecisionInput
//   - the POST /admin/dynamic-denies/reload endpoint reloads the file
//     end-to-end + returns the expected JSON shape
//   - /healthz surfaces dynamic_denies_* fields

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/dynamicdeny"
	"github.com/trsreagan3/kbouncer/internal/profile"
)

// ddTestRuleID is a stable rule id used across the dynamic-deny
// regression suite.
const ddTestRuleID = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"

// ddYAML builds a minimal one-rule YAML payload targeting kbouncer.
func ddYAML(t *testing.T, target string) string {
	t.Helper()
	added := time.Now().UTC().Format(time.RFC3339)
	return strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + ddTestRuleID,
		`    targets: ["` + target + `"]`,
		`    reason: "operator: test lockout"`,
		`    duration: "1h"`,
		`    added_by: "u@h"`,
		`    added_at: "` + added + `"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
}

// loadDynamicDenies parses the given YAML body + returns a RuleSet
// ready to thread through EvalOptions.DynamicDenies.
func loadDynamicDenies(t *testing.T, body string) *dynamicdeny.RuleSet {
	t.Helper()
	rs, err := dynamicdeny.LoadBytes([]byte(body), "test.yaml")
	require.NoError(t, err)
	return rs
}

func TestEval_DynamicDenyNamespaceMatch(t *testing.T) {
	st := freshStore(t)
	rs := loadDynamicDenies(t, ddYAML(t, "namespace:prod"))
	// Build a request targeting prod namespace; the evaluator should
	// short-circuit to DENY with deny_source=dynamic.
	req, _ := http.NewRequest("GET", "/api/v1/namespaces/prod/pods", nil)
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow, nil, "",
		EvalOptions{DynamicDenies: rs})
	require.Equal(t, VerdictDeny, obs.DecisionVerdict, "namespace:prod should fire dynamic-deny")
	require.Equal(t, SourceDynamic, obs.DecisionSource)
	require.Equal(t, DenySourceDynamic, obs.DenySource)
	require.Equal(t, ddTestRuleID, obs.DynamicDenyRuleID)
	require.Contains(t, obs.DecisionReason, ddTestRuleID)
	require.Contains(t, obs.DecisionReason, "namespace:prod")
}

func TestEval_DynamicDenyClusterMatch(t *testing.T) {
	st := freshStore(t)
	rs := loadDynamicDenies(t, ddYAML(t, "cluster:prod-east"))
	// A request from the prod-east cluster — kbouncer was launched
	// with --cluster prod-east. Namespace doesn't carry the match;
	// the cluster argument does.
	req, _ := http.NewRequest("GET", "/api/v1/namespaces/default/pods", nil)
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow, nil, "prod-east",
		EvalOptions{DynamicDenies: rs})
	require.Equal(t, VerdictDeny, obs.DecisionVerdict)
	require.Equal(t, DenySourceDynamic, obs.DenySource)
	require.Equal(t, ddTestRuleID, obs.DynamicDenyRuleID)
}

func TestEval_DynamicDenyResourceTripleMatch(t *testing.T) {
	st := freshStore(t)
	rs := loadDynamicDenies(t, ddYAML(t, "core/v1/secrets"))
	// Core API secrets request — parser emits Group="" so the
	// matcher's "core" alias must align.
	req, _ := http.NewRequest("GET", "/api/v1/namespaces/default/secrets", nil)
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow, nil, "",
		EvalOptions{DynamicDenies: rs})
	require.Equal(t, VerdictDeny, obs.DecisionVerdict)
	require.Equal(t, DenySourceDynamic, obs.DenySource)
	require.Equal(t, ddTestRuleID, obs.DynamicDenyRuleID)
}

func TestEval_DynamicDenyResourceTripleNoMatch(t *testing.T) {
	st := freshStore(t)
	rs := loadDynamicDenies(t, ddYAML(t, "core/v1/secrets"))
	// A pods request should NOT match the secrets rule.
	req, _ := http.NewRequest("GET", "/api/v1/namespaces/default/pods", nil)
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow, nil, "",
		EvalOptions{DynamicDenies: rs})
	require.NotEqual(t, SourceDynamic, obs.DecisionSource,
		"non-matching resource should not fire dynamic-deny")
	require.Empty(t, obs.DynamicDenyRuleID)
}

func TestEval_DynamicDenyPrecedenceOverProfileAllow(t *testing.T) {
	st := freshStore(t)
	// Build a permissive profile that would allow the request, then
	// install a dynamic-deny rule. The dynamic-deny must beat the
	// profile-allow per the cross-product design doc's "deny always
	// wins over allow" rule.
	openProfile := &profile.Profile{
		Name: "permissive-test",
	}
	rs := loadDynamicDenies(t, ddYAML(t, "namespace:prod"))
	req, _ := http.NewRequest("GET", "/api/v1/namespaces/prod/pods", nil)
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow,
		openProfile, "",
		EvalOptions{DynamicDenies: rs})
	require.Equal(t, VerdictDeny, obs.DecisionVerdict,
		"dynamic-deny should beat profile-allow")
	require.Equal(t, SourceDynamic, obs.DecisionSource)
	require.Equal(t, ddTestRuleID, obs.DynamicDenyRuleID)
}

func TestEval_DynamicDenyMatchCallbackFires(t *testing.T) {
	st := freshStore(t)
	rs := loadDynamicDenies(t, ddYAML(t, "namespace:prod"))
	req, _ := http.NewRequest("GET", "/api/v1/namespaces/prod/pods", nil)
	var matchCount int
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow, nil, "",
		EvalOptions{
			DynamicDenies:      rs,
			OnDynamicDenyMatch: func(_ *dynamicdeny.Pattern) { matchCount++ },
		})
	require.Equal(t, VerdictDeny, obs.DecisionVerdict)
	require.Equal(t, 1, matchCount, "OnDynamicDenyMatch should fire exactly once")
}

// captureEmitter records the events the proxy emits so a test can
// assert the OCSF wire shape carries the new dynamic-deny ext fields.
type captureEmitter struct {
	events []audit.Event
}

func (e *captureEmitter) Emit(_ context.Context, ev audit.Event) {
	e.events = append(e.events, ev)
}

// Status is required to satisfy the audit.Emitter interface; the
// dynamic-deny tests don't care about the status surface.
func (e *captureEmitter) Status() audit.Status { return audit.Status{} }

func TestEval_DynamicDenyAuditEventCarriesRuleId(t *testing.T) {
	st := freshStore(t)
	rs := loadDynamicDenies(t, ddYAML(t, "namespace:prod"))
	emitter := &captureEmitter{}
	req, _ := http.NewRequest("GET", "/api/v1/namespaces/prod/pods", nil)
	obs := EvaluateRequestFull(req, st, ModeTransparent, DefaultPolicyAllow, nil, "",
		EvalOptions{
			DynamicDenies: rs,
			AuditEmitter:  emitter,
		})
	require.Equal(t, VerdictDeny, obs.DecisionVerdict)
	require.NotEmpty(t, emitter.events, "audit emitter should have been called")
	ev := emitter.events[len(emitter.events)-1]
	require.NotNil(t, ev.Unmapped.IAMJIT.Ext, "ext block should be populated")
	gotSource, _ := ev.Unmapped.IAMJIT.Ext["deny_source"].(string)
	require.Equal(t, DenySourceDynamic, gotSource,
		"ext.deny_source should be 'dynamic'")
	gotRuleID, _ := ev.Unmapped.IAMJIT.Ext["dynamic_deny_rule_id"].(string)
	require.Equal(t, ddTestRuleID, gotRuleID,
		"ext.dynamic_deny_rule_id should be the rule id")
}

func TestReloadEndpoint_E2E(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "dynamic-denies.yaml")
	// Pre-write a file so the watcher has a starting snapshot.
	require.NoError(t, os.WriteFile(yamlPath,
		[]byte(ddYAML(t, "namespace:prod")), 0o600))
	w, err := dynamicdeny.NewWatcher(yamlPath, nil)
	require.NoError(t, err)

	st := freshStore(t)
	cfg := Config{
		Host:               "127.0.0.1",
		Port:               0,
		Mode:               ModeCooperative,
		DefaultPolicy:      DefaultPolicyDeny,
		DynamicDenyWatcher: w,
	}.Normalize()
	srv := NewServer(cfg, st)

	// POST the reload endpoint via the handler directly (avoids
	// binding a real socket).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/dynamic-denies/reload", nil)
	srv.dynamicDenyReloadHandler("")(rec, req)
	require.Equal(t, http.StatusOK, rec.Code,
		"reload should succeed; got body=%q", rec.Body.String())
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	reloaded, _ := body["reloaded"].(bool)
	require.True(t, reloaded, "reloaded should be true")
	// JSON numbers decode as float64.
	if n, ok := body["rules_count"].(float64); !ok || int(n) != 1 {
		t.Errorf("rules_count = %v; want 1", body["rules_count"])
	}
	if n, ok := body["rules_applied_to_kbouncer"].(float64); !ok || int(n) != 1 {
		t.Errorf("rules_applied_to_kbouncer = %v; want 1", body["rules_applied_to_kbouncer"])
	}
}

func TestReloadEndpoint_RejectsNonPOST(t *testing.T) {
	srv := NewServer(Config{}.Normalize(), freshStore(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/dynamic-denies/reload", nil)
	srv.dynamicDenyReloadHandler("")(rec, req)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestReloadEndpoint_503WhenNoWatcher(t *testing.T) {
	// No DynamicDenyWatcher configured — the handler should 503.
	srv := NewServer(Config{}.Normalize(), freshStore(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/dynamic-denies/reload", nil)
	srv.dynamicDenyReloadHandler("")(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestReloadEndpoint_ParseErrorReturns422(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "dynamic-denies.yaml")
	require.NoError(t, os.WriteFile(yamlPath,
		[]byte(ddYAML(t, "namespace:prod")), 0o600))
	w, err := dynamicdeny.NewWatcher(yamlPath, nil)
	require.NoError(t, err)

	// Overwrite with garbage so the reload fails.
	require.NoError(t, os.WriteFile(yamlPath,
		[]byte("schema_version: \"1.0\"\ndenies: not-a-list\n"), 0o600))

	srv := NewServer(Config{DynamicDenyWatcher: w}.Normalize(), freshStore(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/dynamic-denies/reload", nil)
	srv.dynamicDenyReloadHandler("")(rec, req)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code,
		"parse error should 422; body=%q", rec.Body.String())
}

func TestHealthz_SurfacesDynamicDenyFields(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "dynamic-denies.yaml")
	require.NoError(t, os.WriteFile(yamlPath,
		[]byte(ddYAML(t, "namespace:prod")), 0o600))
	w, err := dynamicdeny.NewWatcher(yamlPath, nil)
	require.NoError(t, err)
	srv := NewServer(Config{DynamicDenyWatcher: w}.Normalize(), freshStore(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.Bytes()
	for _, want := range []string{
		`"dynamic_denies_enabled":true`,
		`"dynamic_denies_count":1`,
		`"dynamic_denies_path":"` + yamlPath + `"`,
		`"total_dynamic_deny_matches":0`,
		`"total_dynamic_deny_reloads":0`,
		`"total_dynamic_deny_parse_errors":0`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("/healthz body missing %s\nbody=%s", want, string(body))
		}
	}
}

func TestHealthz_DynamicDenyDisabledWhenNoWatcher(t *testing.T) {
	srv := NewServer(Config{}.Normalize(), freshStore(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"dynamic_denies_enabled":false`)
	require.Contains(t, rec.Body.String(), `"dynamic_denies_count":0`)
}
