package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListAuditWebhookPresetsRegisteredInToolsList confirms the new
// MCP tool is wired up in the tools/list surface.
func TestListAuditWebhookPresetsRegisteredInToolsList(t *testing.T) {
	tools := ToolDescriptors()
	names := map[string]bool{}
	for _, t := range tools {
		if n, ok := t["name"].(string); ok {
			names[n] = true
		}
	}
	assert.True(t, names["list_audit_webhook_presets"],
		"list_audit_webhook_presets missing from ToolDescriptors()")
}

// TestListAuditWebhookPresetsToolReturnsFourPresets confirms the
// agent-facing surface returns the same four presets the CLI emits.
func TestListAuditWebhookPresetsToolReturnsFourPresets(t *testing.T) {
	s := &Server{}
	result, err := s.toolListAuditWebhookPresets(nil)
	require.NoError(t, err)
	presets, ok := result["presets"].([]map[string]any)
	require.True(t, ok, "expected presets []map[string]any; got %T", result["presets"])
	require.Len(t, presets, 4)
	want := []string{"generic", "datadog", "splunk-hec", "sentinel"}
	for i, preset := range presets {
		assert.Equal(t, want[i], preset["name"])
		for _, field := range []string{
			"description", "auth_header", "body_shape",
			"required_flags", "optional_flags",
		} {
			_, has := preset[field]
			assert.True(t, has, "preset %q missing field %q", preset["name"], field)
		}
	}
}

// TestListAuditWebhookPresetsToolCarriesNoSecret: per
// [[security-team-audit-export]] + [[self-host-zero-billing-
// dependency]]: descriptor lists ONLY shape metadata. No real
// token, no real URL.
func TestListAuditWebhookPresetsToolCarriesNoSecret(t *testing.T) {
	s := &Server{}
	result, err := s.toolListAuditWebhookPresets(nil)
	require.NoError(t, err)
	payload := strings.ToLower(asString(t, result))
	// Forbidden: actual secret values, not header NAMES (descriptors
	// document the header name `DD-API-KEY: <api_key>` legitimately).
	for _, bad := range []string{
		"bearer abc", "password=", "secret=",
		"dd_api_key=", "splunk_token=", "shared_key=",
	} {
		assert.NotContains(t, payload, bad,
			"unexpected literal %q in MCP tool descriptor", bad)
	}
}

// asString renders the MCP tool result as a string so callers can
// grep for forbidden literals. Uses fmt's %v on a map[string]any
// (the MCP envelope shape).
func asString(t *testing.T, v any) string {
	t.Helper()
	var sb strings.Builder
	render(&sb, v)
	return sb.String()
}

func render(w *strings.Builder, v any) {
	switch n := v.(type) {
	case map[string]any:
		for k, val := range n {
			w.WriteString(k)
			w.WriteString(":")
			render(w, val)
			w.WriteString(",")
		}
	case []map[string]any:
		for _, x := range n {
			render(w, x)
		}
	case []any:
		for _, x := range n {
			render(w, x)
		}
	case string:
		w.WriteString(n)
	default:
		// integers / bools fall through silently — irrelevant to the
		// secret-literal grep.
	}
}
