package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trsreagan3/kbouncer/internal/structureddeny"
)

// TestStructuredDeny403_IncludesCaughtByBouncer — #459 / §A57b. The
// kbouncer 403 wire body must lead with caught_by_bouncer per
// [[ambient-value-prop-and-friction-framing]] so an agent sees the
// same "your bouncer caught something" framing it sees from ibounce.
func TestStructuredDeny403_IncludesCaughtByBouncer(t *testing.T) {
	body := write403AndDecode(t, sampleObs("delete"))
	if got, ok := body["caught_by_bouncer"].(string); !ok || got != "kbouncer" {
		t.Fatalf("caught_by_bouncer = %v; want \"kbouncer\"", body["caught_by_bouncer"])
	}
}

// TestStructuredDeny403_IncludesClassifierField asserts the
// go-heuristic-only marker rides on the wire per
// [[ibounce-honest-positioning]].
func TestStructuredDeny403_IncludesClassifierField(t *testing.T) {
	body := write403AndDecode(t, sampleObs("delete"))
	if got, ok := body["classifier_hook"].(string); !ok || got != structureddeny.ClassifierHookGoHeuristic {
		t.Fatalf("classifier_hook = %v; want %q",
			body["classifier_hook"], structureddeny.ClassifierHookGoHeuristic)
	}
}

// TestStructuredDeny403_IncludesSuggestedAllowCommand asserts the
// `kbounce profile allow ...` command rides on the wire body when the
// deny is allow-able (not a dynamic-deny rule).
func TestStructuredDeny403_IncludesSuggestedAllowCommand(t *testing.T) {
	body := write403AndDecode(t, sampleObs("delete"))
	got, ok := body["suggested_allow_command"].(string)
	if !ok || got == "" {
		t.Fatalf("suggested_allow_command missing or empty: %v", body["suggested_allow_command"])
	}
	for _, want := range []string{"kbounce profile allow", "--target", "--action", "apps/deployments:delete"} {
		if !strings.Contains(got, want) {
			t.Errorf("suggested_allow_command = %q; missing %q", got, want)
		}
	}
}

// TestStructuredDeny403_IncludesRecommendedAction asserts the enum
// value lands on the wire body. Destructive verb → halt+escalate.
func TestStructuredDeny403_IncludesRecommendedAction(t *testing.T) {
	body := write403AndDecode(t, sampleObs("delete"))
	got, ok := body["recommended_action"].(string)
	if !ok {
		t.Fatalf("recommended_action missing: %v", body["recommended_action"])
	}
	if got != structureddeny.RecommendedActionHaltEscalate {
		t.Fatalf("recommended_action = %q; want %q (destructive verb)",
			got, structureddeny.RecommendedActionHaltEscalate)
	}
}

// TestStructuredDeny403_PreservesLegacyKeys asserts every legacy K8s
// Status field is preserved unchanged per [[creates-never-mutates]].
// The structured-deny fields are ADDITIVE.
func TestStructuredDeny403_PreservesLegacyKeys(t *testing.T) {
	body := write403AndDecode(t, sampleObs("get"))
	for _, k := range []string{"kind", "apiVersion", "metadata", "status", "message", "reason", "details", "code"} {
		if _, ok := body[k]; !ok {
			t.Errorf("legacy K8s Status key %q missing", k)
		}
	}
	if got, _ := body["kind"].(string); got != "Status" {
		t.Errorf("kind = %v; want \"Status\"", body["kind"])
	}
	if got, _ := body["apiVersion"].(string); got != "v1" {
		t.Errorf("apiVersion = %v; want \"v1\"", body["apiVersion"])
	}
}

// TestStructuredDeny403_HeuristicClassifierAdversarialBackstop asserts
// the Go-local heuristic mirrors the Python KNOWN_ADVERSARIAL_PATTERNS
// for the kbouncer action shape <group>/<resource>:<verb>.
func TestStructuredDeny403_HeuristicClassifierAdversarialBackstop(t *testing.T) {
	body := write403AndDecode(t, sampleObs("delete"))
	if got, _ := body["is_likely_injection_classification"].(string); got != structureddeny.InjectionAppearsAdversarial {
		t.Errorf("classification for delete = %v; want %q",
			got, structureddeny.InjectionAppearsAdversarial)
	}
	// Non-destructive verb → ambiguous (the lean-permissive default).
	body2 := write403AndDecode(t, sampleObs("get"))
	if got, _ := body2["is_likely_injection_classification"].(string); got != structureddeny.InjectionAmbiguous {
		t.Errorf("classification for get = %v; want %q",
			got, structureddeny.InjectionAmbiguous)
	}
}

// TestStructuredDeny403_SchemaVersionFieldPresent asserts the wire
// schema version is emitted so consumers can detect future bumps.
func TestStructuredDeny403_SchemaVersionFieldPresent(t *testing.T) {
	body := write403AndDecode(t, sampleObs("get"))
	if got, _ := body["structured_deny_schema_version"].(string); got != structureddeny.SchemaVersion {
		t.Fatalf("structured_deny_schema_version = %v; want %q", body["structured_deny_schema_version"], structureddeny.SchemaVersion)
	}
}

// TestStructuredDeny403_DenyEventIDFieldPresent asserts the stable
// event id is on the wire so an agent can pass it to a future MCP
// iam_jit_handle_deny call.
func TestStructuredDeny403_DenyEventIDFieldPresent(t *testing.T) {
	body := write403AndDecode(t, sampleObs("get"))
	got, _ := body["deny_event_id"].(string)
	if !strings.HasPrefix(got, "evt_kbouncer_") {
		t.Fatalf("deny_event_id = %q; want evt_kbouncer_ prefix", got)
	}
}

// sampleObs builds a minimal RequestObservation that exercises the
// kbouncer action shape <group>/<resource>:<verb>.
func sampleObs(verb string) *RequestObservation {
	return &RequestObservation{
		Method:          "DELETE",
		Path:            "/apis/apps/v1/namespaces/prod/deployments/api",
		ParsedVerb:      verb,
		ParsedGroup:     "apps",
		ParsedResource:  "deployments",
		ParsedNamespace: "prod",
		ParsedName:      "api",
		DecisionVerdict: VerdictDeny,
		DecisionReason:  "kbouncer test deny",
		DecisionSource:  SourceProfile,
		ModeAtDecision:  string(ModeTransparent),
	}
}

// write403AndDecode invokes writeK8sForbidden against an httptest
// recorder and decodes the JSON body.
func write403AndDecode(t *testing.T, obs *RequestObservation) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	writeK8sForbidden(w, obs)
	if w.Result().StatusCode != 403 {
		t.Fatalf("status = %d; want 403", w.Result().StatusCode)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v\nbody=%s", err, w.Body.String())
	}
	return body
}
