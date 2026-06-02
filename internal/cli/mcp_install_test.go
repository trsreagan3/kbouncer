// CLI-level smoke tests for the `kbounce mcp install-*` + `show-config`
// + `list-tools` subcommands. The deep behavior tests live in
// internal/mcpinstall/install_test.go; these tests verify the cobra
// wiring lands the right calls + the back-compat for bare `kbounce
// mcp` is preserved.
//
// Mirrors the test discipline on the ibounce side
// (per [[cross-product-agent-parity]]).

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCP_InstallClaudeCode_WritesFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude_desktop_config.json")

	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"mcp", "install-claude-code", "--path", target})
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	servers := got["mcpServers"].(map[string]any)
	require.Contains(t, servers, "kbounce")
}

func TestMCP_InstallCursor_PreservesExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mcp.json")
	pre := []byte(`{"mcpServers":{"other":{"command":"x"}}}`)
	require.NoError(t, os.WriteFile(target, pre, 0o644))

	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"mcp", "install-cursor", "--path", target})
	require.NoError(t, root.Execute())

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	servers := got["mcpServers"].(map[string]any)
	assert.Contains(t, servers, "other", "other entries must survive merge")
	assert.Contains(t, servers, "kbounce")
}

func TestMCP_InstallCodex_TOMLPrintsSnippetWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")

	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"mcp", "install-codex", "--path", target})
	require.NoError(t, root.Execute())

	// Snippet must be in stdout — the operator pastes it into Codex.
	assert.Contains(t, stdout.String(), "kbounce")
	assert.Contains(t, stdout.String(), "mcp")
	assert.Contains(t, stdout.String(), "serve")

	// Must NOT have written the TOML file.
	_, err := os.Stat(target)
	assert.True(t, os.IsNotExist(err))
}

func TestMCP_InstallDevin_PrintsRecipeWithoutWriting(t *testing.T) {
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"mcp", "install-devin"})
	require.NoError(t, root.Execute())

	s := stdout.String()
	// Devin is a cloud agent — recipe, not a written config.
	assert.Contains(t, s, "no local config to write")
	assert.Contains(t, s, "PATH A")
	assert.Contains(t, s, "PATH B")
	// Load-bearing cloud caveat: bouncer at a HOST address, not loopback.
	assert.Contains(t, s, "127.0.0.1 is NOT")
	assert.Contains(t, s, "<kbounce-host>")
	// Snippet shape lines up with show-config (mcp serve).
	assert.Contains(t, s, "mcp")
	assert.Contains(t, s, "serve")
}

func TestMCP_ShowConfig_JSONShapeMatchesInstallSnippet(t *testing.T) {
	root := newRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"mcp", "show-config"})
	require.NoError(t, root.Execute())

	s := stdout.String()
	// Footer pointing at install-* subcommands keeps show-config
	// discoverable.
	assert.Contains(t, s, "install-claude-code")
	assert.Contains(t, s, "install-cursor")
	assert.Contains(t, s, "install-codex")

	// Strip the footer (lines starting with "#") so we can parse the JSON.
	idx := strings.Index(s, "\n#")
	require.Greater(t, idx, 0)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(s[:idx]), &got))
	servers := got["mcpServers"].(map[string]any)
	entry := servers["kbounce"].(map[string]any)
	assert.Equal(t, "kbounce", entry["command"])
	args := entry["args"].([]any)
	require.Len(t, args, 2)
	assert.Equal(t, "mcp", args[0])
	assert.Equal(t, "serve", args[1])
}

func TestMCP_ListTools_PrintsKnownTools(t *testing.T) {
	root := newRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"mcp", "list-tools"})
	require.NoError(t, root.Execute())

	s := stdout.String()
	// Header line.
	assert.Contains(t, s, "NAME")
	assert.Contains(t, s, "DESCRIPTION")
	// A handful of tools we know exist — locks the list-tools wiring
	// down to the live ToolDescriptors().
	for _, name := range []string{
		"kbounce_active_mode",
		"kbounce_decide",
		"kbounce_list_rules",
		"kbounce_scope_self_for_task",
	} {
		assert.Contains(t, s, name, "list-tools must include %s", name)
	}
}
