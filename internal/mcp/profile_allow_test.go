// profile_allow_test.go — #386 / §A25 Phase 2 MCP tool tests.

package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/profile"
)

func writeMCPProfile(t *testing.T, dir, name, source string) string {
	t.Helper()
	body := "profiles:\n  " + name + ":\n    description: test\n"
	if source != "" {
		body += "    source: " + source + "\n"
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMcpTool_ProfileAllow_PendingByDefault(t *testing.T) {
	dir := t.TempDir()
	qp := filepath.Join(dir, "pending.jsonl")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", qp)
	path := writeMCPProfile(t, dir, "full-user", "")
	ps, _ := profile.LoadProfiles(path)
	active, _ := ps.Active("full-user")

	srv := NewServer(Config{
		ActiveProfile: active,
		ProfilesPath:  path,
	})

	out := callTool(t, srv, "kbounce_profile_allow", map[string]any{
		"target": "namespaces/staging",
		"action": []any{"apps/deployments:get"},
		"reason": "agent reads staging",
	})
	require.Equal(t, true, out["ok"], "ok must be true; got %v", out)
	require.Equal(t, "pending_approval", out["status"],
		"default-off self-grant must queue; got %v", out)
	require.NotNil(t, out["pending_entry"])
}

func TestMcpTool_ProfileAllow_RefusesWildcardTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", filepath.Join(dir, "pending.jsonl"))
	path := writeMCPProfile(t, dir, "full-user", "")
	ps, _ := profile.LoadProfiles(path)
	active, _ := ps.Active("full-user")
	srv := NewServer(Config{ActiveProfile: active, ProfilesPath: path})

	out := callTool(t, srv, "kbounce_profile_allow", map[string]any{
		"target": "*",
		"action": []any{"apps/deployments:get"},
		"reason": "broad",
	})
	require.Equal(t, false, out["ok"])
	require.Equal(t, "target_too_broad", out["code"])
}

func TestMcpTool_DeniesRecent_ReturnsList(t *testing.T) {
	st := freshStore(t)
	srv := NewServer(Config{Store: st})

	out := callTool(t, srv, "kbounce_denies_recent", map[string]any{
		"since": "1h",
	})
	require.Equal(t, true, out["ok"])
	require.Equal(t, "kbounce", out["bouncer"])
	rows, _ := out["rows"].([]any)
	require.NotNil(t, rows)
}

func TestMcpTool_DeniesRecent_NoStoreReturnsError(t *testing.T) {
	srv := NewServer(Config{})
	out := callTool(t, srv, "kbounce_denies_recent", map[string]any{})
	require.Equal(t, false, out["ok"])
	require.Equal(t, "store_not_configured", out["error"])
}
