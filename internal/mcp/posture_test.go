// Posture MCP-tool tests per #383 / §A42.

package mcp

import (
	"testing"
)

// TestMCP_PostureReturnsBlock confirms the kbounce_posture tool dispatches
// successfully + returns a result with the documented top-level keys.
func TestMCP_PostureReturnsBlock(t *testing.T) {
	t.Setenv("KBOUNCER_MODE", "transparent")
	t.Setenv("KBOUNCER_PROFILE", "safe-default")
	srv := &Server{}
	resp, err := srv.toolPosture(nil)
	if err != nil {
		t.Fatalf("toolPosture: %v", err)
	}
	for _, k := range []string{
		"schema_version", "bouncer", "captured_at", "running",
		"port", "default_port", "mode", "active_profile",
	} {
		if _, ok := resp[k]; !ok {
			t.Errorf("missing key %q in posture MCP response", k)
		}
	}
	if resp["bouncer"] != "kbounce" {
		t.Errorf("bouncer=%v want kbounce", resp["bouncer"])
	}
	if resp["mode"] != "transparent" {
		t.Errorf("mode=%v want transparent", resp["mode"])
	}
	if resp["active_profile"] != "safe-default" {
		t.Errorf("active_profile=%v want safe-default", resp["active_profile"])
	}
}

// TestMCP_PostureToolDescriptorPresent confirms kbounce_posture is
// included in the tool descriptor list so MCP clients see it via
// tools/list.
func TestMCP_PostureToolDescriptorPresent(t *testing.T) {
	tools := ToolDescriptors()
	for _, td := range tools {
		if td["name"] == "kbounce_posture" {
			return
		}
	}
	t.Errorf("kbounce_posture missing from ToolDescriptors() output")
}
