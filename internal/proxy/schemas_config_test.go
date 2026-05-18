package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemasConfigEndpointServesEmbeddedSchema confirms
// `GET /schemas/config` returns the same bytes that ship in
// schemas/kbounce-config.schema.json.
func TestSchemasConfigEndpointServesEmbeddedSchema(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/schemas/config", nil)
	rec := httptest.NewRecorder()
	schemasConfigHandler(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t,
		strings.HasPrefix(resp.Header.Get("Content-Type"), "application/schema+json"),
		"unexpected content type: %q", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Byte-identical to the published schema in the repo. The
	// internal/proxy/schemas_config.json is a build-time copy of
	// schemas/kbounce-config.schema.json; this test catches the
	// case where they drift.
	wantPath := repoSchemaPath(t)
	want, err := os.ReadFile(wantPath)
	require.NoError(t, err)
	assert.Equal(t, want, body,
		"served schema diverged from %s — re-copy the published "+
			"schema into internal/proxy/schemas_config.json",
		wantPath)
}

// TestSchemasConfigEndpointReturnsValidJSONSchema confirms the
// served bytes parse as JSON + carry the post-#288 wire-shape
// (string semver schema_version).
func TestSchemasConfigEndpointReturnsValidJSONSchema(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/schemas/config", nil)
	rec := httptest.NewRecorder()
	schemasConfigHandler(rec, req)

	body, err := io.ReadAll(rec.Result().Body)
	require.NoError(t, err)

	var schema map[string]any
	require.NoError(t, json.Unmarshal(body, &schema))
	props, _ := schema["properties"].(map[string]any)
	require.NotNil(t, props)
	sv, _ := props["schema_version"].(map[string]any)
	require.NotNil(t, sv)
	assert.Equal(t, "string", sv["type"])
	// enum is a JSON array; encoding/json decodes to []any.
	enumVals, ok := sv["enum"].([]any)
	require.True(t, ok)
	require.Len(t, enumVals, 1)
	assert.Equal(t, "1.0", enumVals[0])

	prod, _ := props["product"].(map[string]any)
	require.NotNil(t, prod)
	prodEnum, _ := prod["enum"].([]any)
	require.Len(t, prodEnum, 1)
	assert.Equal(t, "kbounce", prodEnum[0])
}

// TestSchemasConfigEndpointRejectsNonGet confirms PUT / POST / DELETE
// return 405 — the schema is READ-only metadata.
func TestSchemasConfigEndpointRejectsNonGet(t *testing.T) {
	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
	} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/schemas/config", nil)
			rec := httptest.NewRecorder()
			schemasConfigHandler(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()
			assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			assert.Equal(t, "GET, HEAD", resp.Header.Get("Allow"))
		})
	}
}

// repoSchemaPath returns the absolute path to the published
// kbounce-config schema file (the in-repo source of truth).
func repoSchemaPath(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// schemas_config_test.go -> internal/proxy/ -> internal/ -> <root>
	root := filepath.Dir(filepath.Dir(filepath.Dir(here)))
	return filepath.Join(root, "schemas", "kbounce-config.schema.json")
}
