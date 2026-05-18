package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromDecision_SchemaCompleteness(t *testing.T) {
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
		Upstream:        "kubernetes.default.svc",
		Method:          "DELETE",
		Path:            "/api/v1/namespaces/prod/pods/db-0",
		ParsedVerb:      "delete",
		ParsedGroup:     "",
		ParsedVersion:   "v1",
		ParsedResource:  "pods",
		ParsedNamespace: "prod",
		ParsedName:      "db-0",
		StreamKind:      "",
		TaskID:          "task-123",
	}
	ev := FromDecision(in)

	// Required top-level fields per the shared spec.
	assert.Equal(t, "kbounce", ev.Product)
	assert.Equal(t, SchemaVersion, ev.Version)
	assert.Equal(t, EventTypeDecision, ev.EventType)
	assert.Equal(t, int64(42), ev.DecisionID)
	assert.Equal(t, "transparent", ev.Mode)
	assert.Equal(t, "safe-default", ev.Profile)
	assert.Equal(t, "deny", ev.Verdict)
	assert.Equal(t, "matched rule X", ev.Reason)
	assert.True(t, ev.Enforced)
	assert.Equal(t, "127.0.0.1:8766", ev.Host)
	assert.Equal(t, "kubernetes.default.svc", ev.Upstream)
	assert.Equal(t, "DELETE /api/v1/namespaces/prod/pods/db-0", ev.Action)
	assert.Equal(t, "prod/pods/db-0", ev.Resource)

	// Timestamp serialized RFC3339Nano UTC.
	assert.Contains(t, ev.Timestamp, "2026-05-18T12:34:56")

	// Ext carries kbounce-specific fields without renaming top-level
	// schema keys.
	require.NotNil(t, ev.Ext)
	assert.Equal(t, "delete", ev.Ext["k8s_verb"])
	assert.Equal(t, "prod", ev.Ext["namespace"])
	assert.Equal(t, "task-123", ev.Ext["task_id"])
	assert.Equal(t, "profile", ev.Ext["decision_source"])
}

func TestFromDecision_OmitsEmptyExt(t *testing.T) {
	in := DecisionInput{
		Verdict: "allow",
		Reason:  "default policy",
	}
	ev := FromDecision(in)
	assert.Nil(t, ev.Ext, "ext should be nil when no extension fields apply")
}

func TestFromDecision_DefaultsTimestamp(t *testing.T) {
	ev := FromDecision(DecisionInput{Verdict: "allow"})
	// Parses as RFC3339Nano + lands within the last few seconds.
	parsed, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), parsed, 5*time.Second)
}

func TestFromDecision_SerializableJSON(t *testing.T) {
	ev := FromDecision(DecisionInput{
		DecisionID: 7,
		Verdict:    "allow",
	})
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	out := string(b)
	// Required JSON keys present per shared schema.
	for _, k := range []string{`"ts"`, `"product"`, `"version"`, `"event_type"`, `"decision_id"`, `"verdict"`} {
		assert.True(t, strings.Contains(out, k), "expected key %s in %s", k, out)
	}
}

func TestNewDroppedMarker_Shape(t *testing.T) {
	m := NewDroppedMarker(5)
	assert.Equal(t, EventTypeAuditDropped, m.EventType)
	assert.Equal(t, int64(5), m.Count)
	assert.Equal(t, "kbounce", m.Product)
	assert.Equal(t, SchemaVersion, m.Version)
	assert.NotEmpty(t, m.Reason)
}
