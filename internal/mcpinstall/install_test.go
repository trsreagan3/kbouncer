package mcpinstall

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------
// Canonical config-snippet shape.
// ---------------------------------------------------------------------

// TestServerConfigDict_Shape locks the snippet shape down so a careless
// edit to ServerConfigDict / ServerEntry doesn't silently change what
// install-* commands write. The exact shape is load-bearing for cross-
// product parity with ibounce.
func TestServerConfigDict_Shape(t *testing.T) {
	cfg := ServerConfigDict()
	require.Contains(t, cfg, "mcpServers", "top-level mcpServers key is the MCP schema requirement")

	servers, ok := cfg["mcpServers"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, servers, ServerName)

	entry, ok := servers[ServerName].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, ServerCommand, entry["command"])

	args, ok := entry["args"].([]string)
	require.True(t, ok, "args is []string in the in-memory shape (JSON-serialized as a string array on the wire)")
	assert.Equal(t, ServerArgs, args)

	// The install snippet MUST point at `mcp serve` (canonical), not
	// bare `mcp`. Configs written to operator laptops must not pin on
	// the bare-default back-compat shape.
	assert.Equal(t, []string{"mcp", "serve"}, args,
		"generated MCP configs must invoke `kbounce mcp serve` so they don't depend on the back-compat bare default")

	// env is present but empty so clients that require the field don't
	// blow up.
	_, hasEnv := entry["env"]
	assert.True(t, hasEnv)
}

// ---------------------------------------------------------------------
// install-claude-code: path detection + fresh install
// ---------------------------------------------------------------------

func TestInstallClaudeCode_FreshInstall_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude_desktop_config.json")

	out := &bytes.Buffer{}
	res, err := InstallClaudeCode(Options{
		Path: target,
		Out:  out,
	})
	require.NoError(t, err)
	assert.True(t, res.Created)
	assert.False(t, res.Updated)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))

	servers := got["mcpServers"].(map[string]any)
	entry := servers[ServerName].(map[string]any)
	assert.Equal(t, ServerCommand, entry["command"])
}

// TestInstallClaudeCode_PreservesOtherMCPServers is the audit-cadence
// (a) closure: the install must NEVER overwrite OTHER agents' MCP
// server entries when merging. Triggered by the per-task self-check
// requirement.
func TestInstallClaudeCode_PreservesOtherMCPServers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")

	// Pre-seed an existing config with another server entry + a
	// non-mcpServers key the install must NOT touch.
	pre := map[string]any{
		"theme": "dark",
		"mcpServers": map[string]any{
			"some-other-tool": map[string]any{
				"command": "other",
				"args":    []any{"--stdio"},
			},
		},
	}
	preData, _ := json.MarshalIndent(pre, "", "  ")
	require.NoError(t, os.WriteFile(target, preData, 0o644))

	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))

	assert.Equal(t, "dark", got["theme"], "non-mcpServers keys must survive merge")
	servers := got["mcpServers"].(map[string]any)
	_, hadOther := servers["some-other-tool"]
	assert.True(t, hadOther, "pre-existing mcpServers entries must survive merge")
	_, hadKbounce := servers[ServerName]
	assert.True(t, hadKbounce, "kbounce entry must be added by merge")
}

// TestInstallClaudeCode_NeverDoubleAdds is the second half of audit-
// cadence (a): re-running the install REPLACES the kbounce entry in
// place rather than appending a duplicate (mcpServers is a map, but
// the test asserts the key+entry shape after a second install).
func TestInstallClaudeCode_NeverDoubleAdds(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")

	// First install creates the file.
	res1, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.True(t, res1.Created)
	assert.False(t, res1.Updated)

	// Second install updates in place (Updated=true, Created=false).
	res2, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.False(t, res2.Created)
	assert.True(t, res2.Updated)

	// File still only has ONE kbounce entry — the map structure
	// prevents duplicates by design, but assert here to lock the
	// behavior down so a future refactor can't break it.
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	servers := got["mcpServers"].(map[string]any)
	assert.Len(t, servers, 1, "exactly one mcpServers entry expected after double install")
}

// TestInstallClaudeCode_AtomicWrite_NoPartialOnError is the audit-
// cadence (b) closure: a failed atomic write must NEVER leave the
// target half-overwritten. We can't easily inject a write failure
// mid-stream, but we CAN assert that a successful run leaves no
// .kbounce-mcp-install-*.tmp siblings in the target directory.
func TestInstallClaudeCode_AtomicWrite_LeavesNoTempfileSiblings(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")

	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		// audit-cadence (b): tempfiles MUST be cleaned up; the only
		// surviving file should be the target.
		if strings.HasPrefix(e.Name(), ".kbounce-mcp-install-") {
			t.Errorf("tempfile %q survived install — atomic-write cleanup is broken", e.Name())
		}
	}
}

// TestInstallClaudeCode_RefusesBadPath_NoForce locks the malformed-
// existing-config refusal. Operator must explicitly --force a clobber.
func TestInstallClaudeCode_RefusesMalformedJSON_NoForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(target, []byte("this is not json"), 0o644))

	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid JSON")
}

func TestInstallClaudeCode_ForceOverridesMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(target, []byte("this is not json"), 0o644))

	_, err := InstallClaudeCode(Options{Path: target, Force: true, Out: &bytes.Buffer{}})
	require.NoError(t, err)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	servers := got["mcpServers"].(map[string]any)
	_, ok := servers[ServerName]
	assert.True(t, ok, "--force must produce a valid config with the kbounce entry")
}

// ---------------------------------------------------------------------
// install-cursor: same shape as Claude Code.
// ---------------------------------------------------------------------

func TestInstallCursor_PreservesOtherMCPServers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mcp.json")

	pre := map[string]any{
		"mcpServers": map[string]any{
			"existing-tool": map[string]any{"command": "other"},
		},
	}
	preData, _ := json.MarshalIndent(pre, "", "  ")
	require.NoError(t, os.WriteFile(target, preData, 0o644))

	res, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.False(t, res.Created)
	assert.False(t, res.Updated)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))

	servers := got["mcpServers"].(map[string]any)
	_, hadExisting := servers["existing-tool"]
	assert.True(t, hadExisting)
	_, hadKbounce := servers[ServerName]
	assert.True(t, hadKbounce)
}

func TestInstallCursor_FreshInstall_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	// Target inside a non-existent subdir — install must MkdirAll.
	target := filepath.Join(dir, "nested", "subdir", "mcp.json")

	_, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.False(t, info.IsDir())
}

// ---------------------------------------------------------------------
// install-codex: TOML path -> manual snippet; JSON path -> installs.
// ---------------------------------------------------------------------

func TestInstallCodex_TOMLPath_PrintsManualSnippet(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")

	out := &bytes.Buffer{}
	res, err := InstallCodex(Options{Path: target, Out: out})
	require.NoError(t, err)
	assert.True(t, res.Manual, "TOML target must trigger manual-snippet path")
	assert.NotEmpty(t, res.Snippet)

	// The snippet must contain the canonical command + args.
	assert.Contains(t, res.Snippet, ServerCommand)
	assert.Contains(t, res.Snippet, "\"mcp\"")
	assert.Contains(t, res.Snippet, "\"serve\"")

	// CRITICAL: install-codex must NOT create or modify the TOML file
	// (we promised the operator we'd leave their TOML alone).
	_, err = os.Stat(target)
	assert.True(t, os.IsNotExist(err), "TOML target must NOT be touched; got err=%v", err)

	// Output must include the snippet so the operator sees what to paste.
	assert.Contains(t, out.String(), ServerCommand)
}

func TestInstallCodex_JSONPath_InstallsLikeClaudeCode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "codex-mcp.json")

	res, err := InstallCodex(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.False(t, res.Manual)
	assert.True(t, res.Created)

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	servers := got["mcpServers"].(map[string]any)
	_, ok := servers[ServerName]
	assert.True(t, ok)
}

// ---------------------------------------------------------------------
// show-config: JSON + YAML shapes.
// ---------------------------------------------------------------------

func TestShowConfig_JSONShape(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeJSON))

	// Strip the trailing comment block (starts with "\n# ...") so we can
	// parse the JSON cleanly.
	s := out.String()
	idx := strings.Index(s, "\n#")
	require.Greater(t, idx, 0, "show-config must end with a `# Or for the common MCP clients` footer")
	jsonPart := s[:idx]

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonPart), &got))
	servers := got["mcpServers"].(map[string]any)
	entry := servers[ServerName].(map[string]any)
	assert.Equal(t, ServerCommand, entry["command"])
	args := entry["args"].([]any)
	require.Len(t, args, 2)
	assert.Equal(t, "mcp", args[0])
	assert.Equal(t, "serve", args[1])

	// Footer must point operators at the install-* commands.
	assert.Contains(t, s, "kbounce mcp install-claude-code")
	assert.Contains(t, s, "kbounce mcp install-cursor")
	assert.Contains(t, s, "kbounce mcp install-codex")
}

func TestShowConfig_YAMLShape(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeYAML))
	s := out.String()
	assert.Contains(t, s, "mcpServers:")
	assert.Contains(t, s, "  "+ServerName+":")
	assert.Contains(t, s, "    command: "+ServerCommand)
	assert.Contains(t, s, "      - mcp")
	assert.Contains(t, s, "      - serve")
}

func TestShowConfig_UnknownShapeErrors(t *testing.T) {
	out := &bytes.Buffer{}
	err := ShowConfig(out, Shape("xml"))
	require.Error(t, err)
}

// ---------------------------------------------------------------------
// list-tools formatting.
// ---------------------------------------------------------------------

func TestFormatToolList_RendersTwoColumnTable(t *testing.T) {
	out := &bytes.Buffer{}
	entries := []ToolListEntry{
		{Name: "kbounce_active_mode", Description: "Return the current mode. Extra detail after period."},
		{Name: "kbounce_decide", Description: "Dry-run a request shape; return verdict."},
		{Name: "kbounce_add_rule", Description: "Add a global rule."},
	}
	require.NoError(t, FormatToolList(out, entries))
	s := out.String()

	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 1+len(entries), "header + one row per entry")

	// Header.
	assert.Contains(t, lines[0], "NAME")
	assert.Contains(t, lines[0], "DESCRIPTION")

	// Rows are alphabetized by name.
	assert.Contains(t, lines[1], "kbounce_active_mode")
	assert.Contains(t, lines[2], "kbounce_add_rule")
	assert.Contains(t, lines[3], "kbounce_decide")

	// First-sentence truncation: the active_mode row must NOT include
	// the "Extra detail after period" trailer.
	assert.NotContains(t, lines[1], "Extra detail")
}

// ---------------------------------------------------------------------
// audit-cadence (c): install never requires shell elevation.
// ---------------------------------------------------------------------

// TestInstall_NoElevationDefaultPath verifies every default candidate
// path is inside the operator's $HOME (or %APPDATA% on Windows). No
// /etc paths, no system-wide install targets — install must work for
// a non-root user out of the box.
func TestInstall_DefaultCandidatesAreInsideHome(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	checkInsideHome := func(t *testing.T, name string, paths []string) {
		t.Helper()
		for _, p := range paths {
			// On Windows the APPDATA candidate may live under
			// %APPDATA% which is inside the user profile but not
			// necessarily $HOME — accept any path that starts with
			// the user profile root.
			if !strings.HasPrefix(p, home) {
				// Allow APPDATA-rooted paths.
				if appdata := os.Getenv("APPDATA"); appdata != "" && strings.HasPrefix(p, appdata) {
					continue
				}
				t.Errorf("%s candidate %q is outside operator home (%q) — would require shell elevation",
					name, p, home)
			}
		}
	}

	checkInsideHome(t, "claude-code", ClaudeCodeConfigCandidates())
	checkInsideHome(t, "cursor", CursorConfigCandidates())
	checkInsideHome(t, "codex", CodexConfigCandidates())
}

// TestInstall_AtomicWrite_FileModeIsUserReadable locks the file mode
// down: written configs must be operator-readable + not world-writable.
// 0o644 is the default; assert that's what we land on.
func TestInstall_WrittenFileModeIsSensible(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)

	info, err := os.Stat(target)
	require.NoError(t, err)
	mode := info.Mode().Perm()
	// World-writable would let any local process tamper with the MCP
	// command line + escalate. Refuse if the install lands there.
	assert.Equal(t, fs.FileMode(0), mode&0o002,
		"written config must not be world-writable; got mode %o", mode)
}
