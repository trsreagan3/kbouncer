package structureddeny

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStructuredDeny_IncludesCaughtByBouncer asserts the lead-with-
// caught_by_bouncer framing per
// [[ambient-value-prop-and-friction-framing]].
func TestStructuredDeny_IncludesCaughtByBouncer(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "kbouncer"})
	if sd.CaughtByBouncer != "kbouncer" {
		t.Fatalf("CaughtByBouncer = %q; want %q", sd.CaughtByBouncer, "kbouncer")
	}
	if _, ok := sd.AsMap()["caught_by_bouncer"]; !ok {
		t.Fatalf("AsMap missing caught_by_bouncer key")
	}
}

// TestStructuredDeny_IncludesClassifierField verifies the explicit
// go-heuristic-only marker per [[ibounce-honest-positioning]].
func TestStructuredDeny_IncludesClassifierField(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "kbouncer", Action: "apps/deployments:get"})
	if sd.ClassifierHook != ClassifierHookGoHeuristic {
		t.Fatalf("ClassifierHook = %q; want %q", sd.ClassifierHook, ClassifierHookGoHeuristic)
	}
}

// TestStructuredDeny_IncludesSuggestedAllowCommand asserts the field
// rides through unchanged when the caller pre-populates it (kbouncer
// builds the kbounce-shaped command at the call site).
func TestStructuredDeny_IncludesSuggestedAllowCommand(t *testing.T) {
	cmd := "kbounce profile allow --target default/foo --action apps/deployments:get --reason ..."
	sd := Build(BuildOptions{
		Bouncer:               "kbouncer",
		Action:                "apps/deployments:get",
		Resource:              "default/foo",
		SuggestedAllowCommand: cmd,
	})
	if sd.SuggestedAllowCommand != cmd {
		t.Fatalf("SuggestedAllowCommand = %q; want %q", sd.SuggestedAllowCommand, cmd)
	}
}

// TestStructuredDeny_IncludesRecommendedAction asserts the enum value
// is one of the canonical three.
func TestStructuredDeny_IncludesRecommendedAction(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "kbouncer", Action: "apps/deployments:get"})
	switch sd.RecommendedAction {
	case RecommendedActionEasyAllow, RecommendedActionHaltEscalate, RecommendedActionRephraseRetry:
	default:
		t.Fatalf("RecommendedAction = %q; want one of the canonical three", sd.RecommendedAction)
	}
}

// TestStructuredDeny_HeuristicClassifierAdversarialBackstop asserts the
// destructive-verb backstop fires for the kbouncer action shape
// "<group>/<resource>:<verb>" with a verb like "delete".
func TestStructuredDeny_HeuristicClassifierAdversarialBackstop(t *testing.T) {
	cases := []struct {
		action string
		want   string
	}{
		{"namespaces:delete", InjectionAppearsAdversarial},
		{"apps/deployments:delete", InjectionAppearsAdversarial},
		{"core/secrets:get", InjectionAmbiguous},
		{"apps/deployments:list", InjectionAmbiguous},
		{"rbac/clusterrolebindings:remove", InjectionAppearsAdversarial},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			sd := Build(BuildOptions{Bouncer: "kbouncer", Action: c.action})
			if sd.IsLikelyInjectionClassification != c.want {
				t.Fatalf("classification for %q = %q; want %q",
					c.action, sd.IsLikelyInjectionClassification, c.want)
			}
			if c.want == InjectionAppearsAdversarial && sd.RecommendedAction != RecommendedActionHaltEscalate {
				t.Fatalf("adversarial verb %q got recommended=%q; want halt+escalate",
					c.action, sd.RecommendedAction)
			}
		})
	}
}

// TestStructuredDeny_SchemaVersionFieldPresent asserts the wire-level
// schema version is emitted.
func TestStructuredDeny_SchemaVersionFieldPresent(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "kbouncer"})
	if sd.StructuredDenySchemaVersion != SchemaVersion {
		t.Fatalf("StructuredDenySchemaVersion = %q; want %q",
			sd.StructuredDenySchemaVersion, SchemaVersion)
	}
}

// TestStructuredDeny_DenyEventIDDeterministic asserts the synthesized
// event id is stable across re-projection of the same deny fields so
// agents can correlate.
func TestStructuredDeny_DenyEventIDDeterministic(t *testing.T) {
	opts := BuildOptions{
		Bouncer: "kbouncer", Action: "apps/deployments:delete",
		Resource: "default/foo", When: "2026-05-23T12:00:00Z",
	}
	a := Build(opts)
	b := Build(opts)
	if a.DenyEventID != b.DenyEventID {
		t.Fatalf("DenyEventID not deterministic: %q vs %q", a.DenyEventID, b.DenyEventID)
	}
	if !strings.HasPrefix(a.DenyEventID, "evt_kbouncer_") {
		t.Fatalf("DenyEventID = %q; want evt_kbouncer_ prefix", a.DenyEventID)
	}
}

// TestStructuredDeny_DynamicDenyMeansRephraseRetry asserts dynamic-deny
// rules push the recommended action away from easy-allow (the operator
// can't allow a dynamic-deny away — they have to rephrase or pick a
// different resource).
func TestStructuredDeny_DynamicDenyMeansRephraseRetry(t *testing.T) {
	sd := Build(BuildOptions{
		Bouncer:    "kbouncer",
		Action:     "apps/deployments:get",
		DenySource: "dynamic_deny",
	})
	if sd.RecommendedAction != RecommendedActionRephraseRetry {
		t.Fatalf("dynamic_deny recommended=%q; want %q",
			sd.RecommendedAction, RecommendedActionRephraseRetry)
	}
}

// TestStructuredDeny_AsMapMatchesWireSchema asserts the AsMap keys
// EXACTLY match the canonical wire field names that Python ibounce
// emits, so an agent can grep either bouncer's 403 body with the same
// jq query.
func TestStructuredDeny_AsMapMatchesWireSchema(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "kbouncer"})
	m := sd.AsMap()
	wantKeys := []string{
		"caught_by_bouncer",
		"is_likely_injection_classification",
		"suggested_allow_command",
		"recommended_action",
		"deny_event_id",
		"classifier_hook",
		"deny_source_classified",
		"structured_deny_schema_version",
	}
	for _, k := range wantKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("AsMap missing wire-schema key %q", k)
		}
	}
}

// TestStructuredDeny_JSONRoundTripsCanonicalShape asserts the JSON tag
// names on the struct match the wire schema (in case someone renames
// a tag accidentally during a refactor).
func TestStructuredDeny_JSONRoundTripsCanonicalShape(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "kbouncer"})
	b, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	out := string(b)
	for _, want := range []string{
		`"caught_by_bouncer":"kbouncer"`,
		`"structured_deny_schema_version":"1.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %q; got %s", want, out)
		}
	}
}
