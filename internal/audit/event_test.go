package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFromDecision_OCSFSchemaShape pins the OCSF v1.1.0 class 6003
// API Activity event shape per [[ocsf-audit-schema]] for kbounce:
// every required field is populated + correctly typed for a typical
// DELETE-pod decision.
func TestFromDecision_OCSFSchemaShape(t *testing.T) {
	in := DecisionInput{
		At:              time.Date(2026, 5, 18, 12, 34, 56, 789e6, time.UTC),
		DecisionID:      42,
		Mode:            "transparent",
		Profile:         "safe-default",
		Verdict:         "deny",
		Reason:          "matched rule X",
		DecisionSource:  "profile",
		Enforced:        true,
		Host:            "127.0.0.1:8766",
		Upstream:        "kubernetes.default.svc:443",
		Method:          "DELETE",
		Path:            "/api/v1/namespaces/prod/pods/db-0",
		ParsedVerb:      "delete",
		ParsedGroup:     "",
		ParsedVersion:   "v1",
		ParsedResource:  "pods",
		ParsedNamespace: "prod",
		ParsedName:      "db-0",
		TaskID:          "task-123",
	}
	ev := FromDecision(in)

	// metadata
	assert.Equal(t, OCSFSchemaVersion, ev.Metadata.Version)
	assert.Equal(t, "1.1.0", ev.Metadata.Version)
	assert.Equal(t, "kbounce", ev.Metadata.Product.Name)
	assert.Equal(t, "iam-jit", ev.Metadata.Product.VendorName)
	assert.NotEmpty(t, ev.Metadata.Product.Version)

	// class + category constants
	assert.Equal(t, 6003, ev.ClassUID)
	assert.Equal(t, "API Activity", ev.ClassName)
	assert.Equal(t, 6, ev.CategoryUID)
	assert.Equal(t, "Application Activity", ev.CategoryName)

	// activity + type
	assert.Equal(t, ActivityDelete, ev.ActivityID)
	assert.Equal(t, "delete_pods", ev.ActivityName)
	assert.Equal(t, 600300+ActivityDelete, ev.TypeUID)
	assert.Equal(t, "API Activity: Delete", ev.TypeName)

	// severity (Slice 1 default)
	assert.Equal(t, SeverityInformational, ev.SeverityID)
	assert.Equal(t, "Informational", ev.Severity)

	// status: transparent-mode enforced DENY → Failure
	assert.Equal(t, StatusFailure, ev.StatusID)
	assert.Equal(t, "Failure", ev.Status)
	assert.Equal(t, "matched rule X", ev.StatusDetail)

	// time as unix ms
	want := time.Date(2026, 5, 18, 12, 34, 56, 789e6, time.UTC).UnixMilli()
	assert.Equal(t, want, ev.Time)

	// api
	assert.Equal(t, "delete", ev.API.Operation)
	assert.Equal(t, "kubernetes", ev.API.Service.Name)
	assert.Equal(t, "42", ev.API.Request.UID)

	// resources
	require.Len(t, ev.Resources, 1)
	assert.Equal(t, "prod/db-0", ev.Resources[0].Name)
	assert.Equal(t, "namespaces/prod/pods/db-0", ev.Resources[0].UID)
	assert.Equal(t, "kubernetes pod", ev.Resources[0].Type)

	// endpoints
	require.NotNil(t, ev.SrcEndpoint)
	assert.Equal(t, "127.0.0.1", ev.SrcEndpoint.IP)
	assert.Equal(t, 8766, ev.SrcEndpoint.Port)
	require.NotNil(t, ev.DstEndpoint)
	assert.Equal(t, "kubernetes.default.svc", ev.DstEndpoint.Hostname)
	assert.Equal(t, 443, ev.DstEndpoint.Port)

	// actor: no principal → user is nil; task id surfaces as session
	require.NotNil(t, ev.Actor)
	assert.Nil(t, ev.Actor.User, "no principal extracted → user omitted")
	require.NotNil(t, ev.Actor.Session)
	assert.Equal(t, "task-123", ev.Actor.Session.UID)

	// unmapped.iam_jit
	ext := ev.Unmapped.IAMJIT
	assert.Equal(t, "transparent", ext.Mode)
	assert.Equal(t, "safe-default", ext.Profile)
	assert.Equal(t, "DENY", ext.Verdict)
	assert.Equal(t, int64(42), ext.DecisionID)
	assert.True(t, ext.Enforced)
	require.NotNil(t, ext.Ext)
	assert.Equal(t, "delete", ext.Ext["k8s_verb"])
	assert.Equal(t, "prod", ext.Ext["namespace"])
	assert.Equal(t, "task-123", ext.Ext["task_id"])
	assert.Equal(t, "profile", ext.Ext["decision_source"])
	assert.Equal(t, "v1", ext.Ext["k8s_api_version"])
}

// TestFromDecision_K8sVerbToActivityIDMapping exercises the verb
// classifier table per the [[ocsf-audit-schema]] memo. Per
// [[scorer-is-ground-truth]] this is a flat lookup; treat the table
// as ground truth + assert each row.
func TestFromDecision_K8sVerbToActivityIDMapping(t *testing.T) {
	cases := []struct {
		verb       string
		activityID int
	}{
		{"get", ActivityRead},
		{"list", ActivityRead},
		{"watch", ActivityRead},
		{"create", ActivityCreate},
		{"update", ActivityUpdate},
		{"patch", ActivityUpdate},
		{"delete", ActivityDelete},
		{"deletecollection", ActivityDelete},
		{"exec", ActivityOther},
		{"portforward", ActivityOther},
		{"proxy", ActivityOther},
		{"bind", ActivityOther},
		{"escalate", ActivityOther},
		{"impersonate", ActivityOther},
		{"", ActivityUnknown},
		{"some-future-verb", ActivityOther},
	}
	for _, tc := range cases {
		got := k8sVerbToActivityID(tc.verb)
		assert.Equal(t, tc.activityID, got, "verb=%q", tc.verb)
	}
}

// TestFromDecision_StatusMapping covers the verdict → OCSF status
// mapping per the memo. Cooperative-mode advisory DENY is the
// nuanced case: status_id=Success (because the upstream call did
// succeed) but status_detail surfaces the advisory deny reason so a
// reviewer reading the OCSF stream still sees the bouncer flagged it.
func TestFromDecision_StatusMapping(t *testing.T) {
	cases := []struct {
		name         string
		verdict      string
		enforced     bool
		wantStatusID int
		wantDetail   string
	}{
		{"allow", "allow", false, StatusSuccess, "reason"},
		{"deny-enforced", "deny", true, StatusFailure, "reason"},
		{"deny-advisory", "deny", false, StatusSuccess, "advisory deny (cooperative mode): reason"},
		{"bypass", "bypass", false, StatusSuccess, "pause-bypass: reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := FromDecision(DecisionInput{
				Verdict:  tc.verdict,
				Enforced: tc.enforced,
				Reason:   "reason",
			})
			assert.Equal(t, tc.wantStatusID, ev.StatusID)
			assert.Equal(t, tc.wantDetail, ev.StatusDetail)
		})
	}
}

// TestFromDecision_EmptyResources covers events where no resource
// was parsed (e.g. /healthz, /version, /api). OCSF requires
// resources to be present; emit an empty array, not null.
func TestFromDecision_EmptyResources(t *testing.T) {
	ev := FromDecision(DecisionInput{Verdict: "allow"})
	require.NotNil(t, ev.Resources)
	assert.Len(t, ev.Resources, 0)
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"resources":[]`,
		"resources MUST serialize as [] not null per OCSF spec")
}

// TestFromDecision_DefaultsTime confirms missing At → now() in ms.
func TestFromDecision_DefaultsTime(t *testing.T) {
	ev := FromDecision(DecisionInput{Verdict: "allow"})
	nowMs := time.Now().UTC().UnixMilli()
	assert.InDelta(t, nowMs, ev.Time, 5000,
		"time should be within 5s of now (ms granularity)")
}

// TestFromDecision_SerializableJSON confirms the event marshals
// without error + includes the OCSF-required top-level keys.
func TestFromDecision_SerializableJSON(t *testing.T) {
	ev := FromDecision(DecisionInput{
		DecisionID: 7,
		Verdict:    "allow",
		ParsedVerb: "list",
		ParsedResource: "pods",
	})
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	out := string(b)
	for _, k := range []string{
		`"metadata"`, `"time"`, `"class_uid":6003`, `"category_uid":6`,
		`"activity_id"`, `"activity_name"`, `"type_uid"`, `"severity_id":1`,
		`"status_id"`, `"api"`, `"resources"`, `"unmapped"`, `"iam_jit"`,
	} {
		assert.True(t, strings.Contains(out, k),
			"expected substring %s in serialized event: %s", k, out)
	}
	// The internal DecisionID + EventType fields MUST NOT serialize
	// (they are convenience handles, the OCSF home is
	// api.request.uid + activity_id).
	assert.NotContains(t, out, `"DecisionID"`)
	assert.NotContains(t, out, `"EventType"`)
}

// TestNewDroppedMarker_OCSFShape covers the synthetic audit-dropped
// event per the memo: activity_id=99, severity_id=3 (Medium),
// status_id=99 (Other), unmapped.iam_jit.event_type=AUDIT_DROPPED.
func TestNewDroppedMarker_OCSFShape(t *testing.T) {
	m := NewDroppedMarker(5)
	assert.Equal(t, 6003, m.ClassUID)
	assert.Equal(t, ActivityOther, m.ActivityID)
	assert.Equal(t, "audit_dropped", m.ActivityName)
	assert.Equal(t, 600300+ActivityOther, m.TypeUID)
	assert.Equal(t, SeverityMedium, m.SeverityID)
	assert.Equal(t, "Medium", m.Severity)
	assert.Equal(t, StatusOther, m.StatusID)
	assert.Equal(t, "Other", m.Status)
	assert.Contains(t, m.StatusDetail, "audit-export webhook dropped 5 events")
	assert.Equal(t, "AUDIT_DROPPED", m.Unmapped.IAMJIT.EventType)
	assert.Equal(t, int64(5), m.Unmapped.IAMJIT.DroppedCount)
	assert.Equal(t, "kbounce", m.Metadata.Product.Name)
	assert.Equal(t, "iam-jit", m.Metadata.Product.VendorName)
	assert.Equal(t, EventTypeAuditDropped, m.EventType)
	// Resources must serialize as [] not null.
	require.NotNil(t, m.Resources)
}

// TestSetBuildVersion threads the linker-stamped version into the
// event metadata. Save + restore so other tests in this package
// don't see the override.
func TestSetBuildVersion(t *testing.T) {
	orig := buildVersion
	t.Cleanup(func() { buildVersion = orig })
	SetBuildVersion("1.0.0-test")
	ev := FromDecision(DecisionInput{Verdict: "allow"})
	assert.Equal(t, "1.0.0-test", ev.Metadata.Product.Version)
	// Empty input does nothing.
	SetBuildVersion("")
	assert.Equal(t, "1.0.0-test", buildVersion)
}

// TestFromDecision_PrincipalPopulatesActorUser pins the actor.user
// branch — when PrincipalName / PrincipalUID is supplied (Slice 2),
// the OCSF actor object exposes them.
func TestFromDecision_PrincipalPopulatesActorUser(t *testing.T) {
	ev := FromDecision(DecisionInput{
		Verdict:       "allow",
		PrincipalName: "alice@example.com",
		PrincipalUID:  "uid-abc-123",
	})
	require.NotNil(t, ev.Actor)
	require.NotNil(t, ev.Actor.User)
	assert.Equal(t, "alice@example.com", ev.Actor.User.Name)
	assert.Equal(t, "uid-abc-123", ev.Actor.User.UID)
}

// TestFromDecision_HostOnlyEndpointParses covers a hostname-only
// Upstream (no port) — surfaces hostname only, port stays 0
// (omitempty drops it from wire).
func TestFromDecision_HostOnlyEndpointParses(t *testing.T) {
	ev := FromDecision(DecisionInput{
		Verdict:  "allow",
		Upstream: "kubernetes.default.svc",
	})
	require.NotNil(t, ev.DstEndpoint)
	assert.Equal(t, "kubernetes.default.svc", ev.DstEndpoint.Hostname)
	assert.Equal(t, 0, ev.DstEndpoint.Port)
	assert.Empty(t, ev.DstEndpoint.IP)
}

// TestEvent_OCSFSchemaCompliance is the schema-validation gate per
// the [[ocsf-audit-schema]] memo. Hand-rolled validator (no
// third-party deps per task constraints) asserts:
//
//   - every OCSF v1.1.0 class 6003 REQUIRED field is present
//   - every required field has the correct JSON type
//   - nested required sub-objects are present + typed
//
// Fails loud on any missing or mistyped required field — a downstream
// SIEM that expects strict OCSF would reject otherwise.
func TestEvent_OCSFSchemaCompliance(t *testing.T) {
	cases := []struct {
		name string
		in   DecisionInput
	}{
		{
			name: "allow-list-pods",
			in: DecisionInput{
				DecisionID:     1,
				Verdict:        "allow",
				ParsedVerb:     "list",
				ParsedResource: "pods",
				Host:           "127.0.0.1:8766",
				Upstream:       "kubernetes.default.svc:443",
			},
		},
		{
			name: "deny-delete-pod-transparent",
			in: DecisionInput{
				DecisionID:      2,
				Verdict:         "deny",
				Enforced:        true,
				ParsedVerb:      "delete",
				ParsedResource:  "pods",
				ParsedNamespace: "prod",
				ParsedName:      "db-0",
				Host:            "127.0.0.1:8766",
				Upstream:        "kubernetes.default.svc:443",
				Mode:            "transparent",
			},
		},
		{
			name: "exec-pod-subresource",
			in: DecisionInput{
				DecisionID:        3,
				Verdict:           "allow",
				ParsedVerb:        "exec",
				ParsedResource:    "pods",
				ParsedSubresource: "exec",
				Host:              "127.0.0.1:8766",
				Upstream:          "k8s.example.com:6443",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := FromDecision(tc.in)
			b, err := json.Marshal(ev)
			require.NoError(t, err)
			var m map[string]any
			require.NoError(t, json.Unmarshal(b, &m))
			validateOCSFAPIActivity(t, m)
		})
	}

	// Dropped marker must also pass.
	t.Run("audit-dropped-marker", func(t *testing.T) {
		ev := NewDroppedMarker(7)
		b, err := json.Marshal(ev)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		validateOCSFAPIActivity(t, m)
	})
}

// validateOCSFAPIActivity is the hand-rolled OCSF v1.1.0 class 6003
// required-field check. Asserts presence + JSON type for every
// field the OCSF spec marks as required for API Activity events.
//
// Per the [[ocsf-audit-schema]] memo "don't ship without a schema-
// validation test that loads the JSONL output + validates against
// the OCSF JSON Schema" — we satisfy this with a focused validator
// keyed off the published spec, avoiding a new third-party dep.
func validateOCSFAPIActivity(t *testing.T, m map[string]any) {
	t.Helper()

	// metadata.version + product.{name,vendor_name,version}
	meta, ok := m["metadata"].(map[string]any)
	require.True(t, ok, "metadata must be an object")
	assertString(t, meta, "version")
	require.Equal(t, "1.1.0", meta["version"])
	prod, ok := meta["product"].(map[string]any)
	require.True(t, ok, "metadata.product must be an object")
	assertString(t, prod, "name")
	assertString(t, prod, "vendor_name")
	assertString(t, prod, "version")

	// time: integer (unix milliseconds).
	_, ok = m["time"].(float64)
	require.True(t, ok, "time must be a number (got %T)", m["time"])

	// class + category constants.
	assertNumberEquals(t, m, "class_uid", 6003)
	assertString(t, m, "class_name")
	assertNumberEquals(t, m, "category_uid", 6)
	assertString(t, m, "category_name")

	// activity + type.
	assertNumber(t, m, "activity_id")
	assertString(t, m, "activity_name")
	assertNumber(t, m, "type_uid")
	assertString(t, m, "type_name")

	// severity + status.
	assertNumber(t, m, "severity_id")
	assertString(t, m, "severity")
	assertNumber(t, m, "status_id")
	assertString(t, m, "status")

	// type_uid = class_uid * 100 + activity_id (OCSF derivation rule).
	classUID := int(m["class_uid"].(float64))
	activityID := int(m["activity_id"].(float64))
	wantType := classUID*100 + activityID
	gotType := int(m["type_uid"].(float64))
	require.Equal(t, wantType, gotType,
		"type_uid MUST equal class_uid*100 + activity_id per OCSF spec")

	// api object: service.name + request.uid (request can have empty uid).
	api, ok := m["api"].(map[string]any)
	require.True(t, ok, "api must be an object")
	svc, ok := api["service"].(map[string]any)
	require.True(t, ok, "api.service must be an object")
	assertString(t, svc, "name")
	_, ok = api["request"].(map[string]any)
	require.True(t, ok, "api.request must be an object")

	// resources: array (may be empty).
	resources, ok := m["resources"].([]any)
	require.True(t, ok, "resources must be an array (got %T)", m["resources"])
	for i, r := range resources {
		ro, ok := r.(map[string]any)
		require.True(t, ok, "resources[%d] must be an object", i)
		// Each resource SHOULD have at least one of name/uid; type
		// SHOULD be present.
		hasIdent := ro["name"] != nil || ro["uid"] != nil
		require.True(t, hasIdent, "resources[%d] needs name or uid", i)
	}

	// unmapped.iam_jit: vendor extension.
	unm, ok := m["unmapped"].(map[string]any)
	require.True(t, ok, "unmapped must be an object")
	jit, ok := unm["iam_jit"].(map[string]any)
	require.True(t, ok, "unmapped.iam_jit must be an object")
	// At least one of {verdict, event_type} must be set so the
	// extension carries non-trivial signal.
	hasSig := jit["verdict"] != nil || jit["event_type"] != nil
	require.True(t, hasSig, "unmapped.iam_jit needs verdict OR event_type")
}

func assertString(t *testing.T, m map[string]any, key string) {
	t.Helper()
	v, ok := m[key]
	require.True(t, ok, "missing %q", key)
	_, ok = v.(string)
	require.True(t, ok, "%q must be string (got %T)", key, v)
	require.NotEmpty(t, v, "%q must be non-empty", key)
}

func assertNumber(t *testing.T, m map[string]any, key string) {
	t.Helper()
	v, ok := m[key]
	require.True(t, ok, "missing %q", key)
	_, ok = v.(float64)
	require.True(t, ok, "%q must be number (got %T)", key, v)
}

func assertNumberEquals(t *testing.T, m map[string]any, key string, want int) {
	t.Helper()
	assertNumber(t, m, key)
	require.Equal(t, float64(want), m[key], "%q must equal %d", key, want)
}

// TestEvent_CrossProductFixture is the shared-shape assertion from
// the [[ocsf-audit-schema]] memo's cross-product consistency check.
// Sibling agents land an identical-named test in ibounce + dbounce
// asserting the SAME invariants (different products, same shape).
func TestEvent_CrossProductFixture(t *testing.T) {
	in := DecisionInput{
		At:              time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC),
		DecisionID:      99,
		Mode:            "cooperative",
		Profile:         "safe-default",
		Verdict:         "allow",
		Reason:          "default",
		Enforced:        false,
		ParsedVerb:      "get",
		ParsedResource:  "pods",
		ParsedNamespace: "default",
		ParsedName:      "p1",
	}
	ev := FromDecision(in)

	assert.Equal(t, 6003, ev.ClassUID,
		"class_uid is fixed at 6003 across the Bounce suite")
	assert.Equal(t, "1.1.0", ev.Metadata.Version,
		"metadata.version pinned to OCSF v1.1.0 across the suite")
	assert.Equal(t, "iam-jit", ev.Metadata.Product.VendorName,
		"vendor_name is iam-jit across the suite")
	assert.Contains(t, []string{"ibounce", "kbounce", "dbounce"},
		ev.Metadata.Product.Name,
		"product.name must be one of the 3 Bounce products")

	// type_uid derivation rule.
	assert.Equal(t, 600300+ev.ActivityID, ev.TypeUID,
		"type_uid MUST equal 600300 + activity_id")

	// unmapped.iam_jit common-field presence.
	ext := ev.Unmapped.IAMJIT
	assert.NotEmpty(t, ext.Mode)
	assert.NotEmpty(t, ext.Profile)
	assert.NotEmpty(t, ext.Verdict)
	assert.Equal(t, int64(99), ext.DecisionID,
		"unmapped.iam_jit.decision_id MUST match the SQLite row id")
	// api.request.uid mirrors the SQLite row.
	assert.Equal(t, "99", ev.API.Request.UID)
}

// TestEvent_VendorExtensionNeverSwallowsRequiredFields is a paranoia
// check: the iam-jit-native fields stay under unmapped.iam_jit; they
// don't leak into top-level OCSF keys (which would break SIEM ingest).
// Walks the unmarshaled map directly so we don't rely on string
// scanning of the JSON encoding (more robust to key-order changes).
func TestEvent_VendorExtensionNeverSwallowsRequiredFields(t *testing.T) {
	ev := FromDecision(DecisionInput{
		Mode:       "transparent",
		Profile:    "safe-default",
		Verdict:    "deny",
		Enforced:   true,
		DecisionID: 17,
		ParsedVerb: "delete",
	})
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))

	// None of these keys may appear at the top level — they belong
	// under unmapped.iam_jit so a downstream SIEM doesn't mistake
	// them for canonical OCSF fields.
	for _, key := range []string{"verdict", "decision_id", "enforced", "mode", "profile"} {
		_, present := m[key]
		assert.False(t, present,
			"iam-jit-native field %q leaked to top-level OCSF surface", key)
	}
	// And confirm they all DO appear under unmapped.iam_jit (so the
	// test would also catch a regression that dropped them entirely).
	unm, ok := m["unmapped"].(map[string]any)
	require.True(t, ok)
	jit, ok := unm["iam_jit"].(map[string]any)
	require.True(t, ok)
	for _, key := range []string{"verdict", "decision_id", "enforced", "mode", "profile"} {
		_, present := jit[key]
		assert.True(t, present, "unmapped.iam_jit.%s should be set on a deny", key)
	}
}
