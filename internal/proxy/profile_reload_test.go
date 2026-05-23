// profile_reload_test.go — #386 / §A25 Phase 2 admin endpoint tests.

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/profile"
)

// writeReloadProfilesYAML writes a minimal profiles.yaml with the
// named profile in local source so the reload endpoint has a target
// to hot-swap.
func writeReloadProfilesYAML(t *testing.T, dir, profileName string, rules int) string {
	t.Helper()
	body := "profiles:\n  " + profileName + ":\n    description: test\n"
	if rules > 0 {
		body += "    allow_rules:\n"
		for i := 0; i < rules; i++ {
			body += "    - pattern: apps/deployments:get\n      arn_scope: namespaces/staging\n"
		}
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdminProfileReload_HotSwapsActiveProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBOUNCER_PROFILES_PATH", filepath.Join(dir, "profiles.yaml"))
	path := writeReloadProfilesYAML(t, dir, "full-user", 0)

	ps, err := profile.LoadProfiles(path)
	require.NoError(t, err)
	active, _ := ps.Active("full-user")

	cfg := Config{
		ActiveProfile: active,
	}.Normalize()
	srv := NewServer(cfg, freshStore(t))

	// First reload: no rules.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", path)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%q", rec.Body.String())
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body["reloaded"].(bool))
	require.Equal(t, float64(0), body["rules_in_active_profile"])

	// Mutate the file (simulate `kbounce profile allow`).
	_ = writeReloadProfilesYAML(t, dir, "full-user", 2)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", path)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%q", rec.Body.String())
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body["reloaded"].(bool))
	require.Equal(t, float64(2), body["rules_in_active_profile"])

	// The hot-swap must be visible via ActiveProfile().
	got := srv.ActiveProfile()
	require.NotNil(t, got)
	require.Equal(t, 2, len(got.AllowRules))
}

func TestAdminProfileReload_RejectsNonPOST(t *testing.T) {
	srv := NewServer(Config{}.Normalize(), freshStore(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", "")(rec, req)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminProfileReload_NoActiveProfileNoOp(t *testing.T) {
	srv := NewServer(Config{}.Normalize(), freshStore(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", "")(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body["reloaded"].(bool))
	require.True(t, body["no_active_profile"].(bool))
}

func TestAdminProfileReload_BearerTokenGate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBOUNCER_PROFILES_PATH", filepath.Join(dir, "profiles.yaml"))
	path := writeReloadProfilesYAML(t, dir, "full-user", 0)
	ps, _ := profile.LoadProfiles(path)
	active, _ := ps.Active("full-user")
	srv := NewServer(Config{ActiveProfile: active}.Normalize(), freshStore(t))

	// No Authorization header → 401.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("the-token", path)(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Wrong token → 403.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/admin/profile/reload", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	srv.profileReloadHandler("the-token", path)(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)

	// Right token → 200.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/admin/profile/reload", nil)
	req.Header.Set("Authorization", "Bearer the-token")
	srv.profileReloadHandler("the-token", path)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}
