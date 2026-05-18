// Tests for `kbounce diagnostics bundle` per [[basic-app-hygiene-
// features]] TIER 1 + the #277 spec. The suite covers:
//
//   - Bundle command exits 0 + writes a valid ZIP on disk.
//   - Manifest contains every other entry's sha256 (matches the
//     on-disk bytes).
//   - No webhook URL / no token shape appears ANYWHERE in the
//     bundle (grepped across all entries).
//   - User identifiers in audit-event excerpts are replaced with
//     stable hashes; the same input ID hashes to the same token
//     across two events (cross-event correlation preserved).
//   - Bundle still produces a usable output when /healthz is
//     unreachable (degrades gracefully — health section records
//     "unreachable", bundle still exits 0).
//   - Bundle handles 0-byte audit log + 0-byte panic log without
//     panicking.
//   - --out PATH respected; default falls back to
//     ./kbounce-diagnostics-{timestamp}.zip.
//   - --no-audit suppresses the audit-tail content entirely.
//
// Tests follow the sibling pattern in config_test.go: one-shot
// newRootCmd() invocations on a hermetic tempdir, reading the
// resulting ZIP back from disk.
package cli

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runDiagnosticsCLI is the test wrapper specialised for the
// diagnostics subcommand surface. Sets KBOUNCER_PROFILES_PATH +
// KBOUNCER_AUDIT_LOG_PATH so the tempdir is what the bundle reads.
func runDiagnosticsCLI(t *testing.T, dbPath, profilesPath, logPath string, args ...string) (string, string, error) {
	t.Helper()
	t.Setenv("KBOUNCER_PROFILES_PATH", profilesPath)
	if logPath != "" {
		t.Setenv("KBOUNCER_AUDIT_LOG_PATH", logPath)
	}
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	full := append([]string{}, args...)
	full = append(full, "--db", dbPath)
	root.SetArgs(full)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// readBundleEntries opens a ZIP at path and returns a name → body
// map. Keeps tests focused on the bundle's semantic shape (file
// names + body contents) rather than the ZIP container.
func readBundleEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	zr, err := zip.OpenReader(path)
	require.NoError(t, err, "open ZIP")
	defer zr.Close()
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		require.NoError(t, err, "open ZIP entry %q", f.Name)
		body, err := io.ReadAll(rc)
		require.NoError(t, err, "read ZIP entry %q", f.Name)
		_ = rc.Close()
		out[f.Name] = body
	}
	return out
}

func TestDiagnosticsBundle_WritesValidZip(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz", // intentionally dead
	)
	require.NoError(t, err)

	st, err := os.Stat(outPath)
	require.NoError(t, err, "bundle ZIP must exist on disk")
	require.Greater(t, st.Size(), int64(0), "bundle must be non-empty")
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "bundle file must be 0o600")

	entries := readBundleEntries(t, outPath)
	// Required sections per the package-doc list.
	for _, want := range []string{
		"00-README.txt",
		"01-version.txt",
		"02-config-redacted.json",
		"03-active-profile.json",
		"04-audit-tail.jsonl",
		"05-healthz.json",
		"06-system.txt",
		"07-listener.json",
		"08-panics.txt",
		"09-manifest.json",
	} {
		_, present := entries[want]
		assert.True(t, present,
			"bundle MUST include %q (got entries: %v)", want, keysOf(entries))
	}
}

func TestDiagnosticsBundle_ManifestSha256sMatch(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	entries := readBundleEntries(t, outPath)
	manifestRaw, ok := entries["09-manifest.json"]
	require.True(t, ok, "manifest entry must be present")

	var manifest struct {
		BundleVersion int `json:"bundle_version"`
		Entries       []struct {
			Name   string `json:"name"`
			Size   int    `json:"size"`
			Sha256 string `json:"sha256"`
		} `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(manifestRaw, &manifest))
	assert.Equal(t, 1, manifest.BundleVersion)
	require.NotEmpty(t, manifest.Entries, "manifest must list every entry")

	for _, e := range manifest.Entries {
		body, present := entries[e.Name]
		require.True(t, present,
			"manifest references %q but entry not in bundle", e.Name)
		assert.Equal(t, len(body), e.Size, "size mismatch for %s", e.Name)
		gotSum := sha256Hex(body)
		assert.Equal(t, e.Sha256, gotSum,
			"sha256 mismatch for %s (manifest=%s, actual=%s)",
			e.Name, e.Sha256, gotSum)
	}
}

func TestDiagnosticsBundle_NoTokenOrWebhookURLAnywhere(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	// Seed an audit log line that LOOKS LIKE a token + a webhook URL.
	// The token-shape we plant must survive the redactor as either
	// the placeholder or a hashed user-id, NEVER as the original
	// literal.
	const knownToken = "super-secret-hec-token-abcdef0123456789ABCDEF"
	const knownWebhook = "https://secret-siem.example.com/ingest?key=x"
	const knownUserID = "alice@operator.example.com"

	auditLine := fmt.Sprintf(
		`{"actor":{"user":{"name":%q,"uid":%q}},`+
			`"api":{"request":{"uid":"abc"}},`+
			`"unmapped":{"kbounce":{"audit_export":{"webhook_url":%q,"token":%q}}}}`,
		knownUserID, knownUserID, knownWebhook, knownToken)
	require.NoError(t, os.WriteFile(logPath, []byte(auditLine+"\n"), 0o600))

	// Also seed a panic log containing a token shape + URL so we
	// exercise the plain-text redactor.
	panicPath := filepath.Join(dir, "panic.log")
	require.NoError(t, os.WriteFile(panicPath, []byte(
		"panic: bearer "+knownToken+" called "+knownWebhook+"\n"), 0o600))

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--panic-log", panicPath,
		"--include-audit-tail", "10",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	entries := readBundleEntries(t, outPath)
	for name, body := range entries {
		assert.NotContains(t, string(body), knownToken,
			"token %q leaked into bundle entry %q", knownToken, name)
		assert.NotContains(t, string(body), knownWebhook,
			"webhook URL %q leaked into bundle entry %q",
			knownWebhook, name)
		assert.NotContains(t, string(body), knownUserID,
			"user identifier %q leaked into bundle entry %q",
			knownUserID, name)
	}
}

func TestDiagnosticsBundle_UserIDsHashedStably(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	// Two events for the same actor + one for a different actor.
	const idA = "alice@example.org"
	const idB = "bob@example.org"
	lines := []string{
		fmt.Sprintf(`{"actor":{"user":{"name":%q}},"seq":1}`, idA),
		fmt.Sprintf(`{"actor":{"user":{"name":%q}},"seq":2}`, idA),
		fmt.Sprintf(`{"actor":{"user":{"name":%q}},"seq":3}`, idB),
	}
	require.NoError(t, os.WriteFile(logPath,
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600))

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--include-audit-tail", "10",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	entries := readBundleEntries(t, outPath)
	tail := string(entries["04-audit-tail.jsonl"])
	// Compute expected hashes (matches hashUserID()).
	expectA := hashUserID(idA)
	expectB := hashUserID(idB)
	assert.Equal(t, 2, strings.Count(tail, expectA),
		"alice's stable hash must appear twice (cross-event correlation)")
	assert.Equal(t, 1, strings.Count(tail, expectB),
		"bob's stable hash must appear once")
	assert.NotContains(t, tail, idA)
	assert.NotContains(t, tail, idB)
}

func TestDiagnosticsBundle_HealthzUnreachableGraceful(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		// Port 1 + reserved-low likely refuses; this is the "is-not-
		// running" scenario.
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err,
		"bundle MUST exit 0 even when /healthz is unreachable")

	entries := readBundleEntries(t, outPath)
	healthRaw := string(entries["05-healthz.json"])
	assert.Contains(t, healthRaw, "unreachable",
		"health section must record 'unreachable' when probe fails")
}

func TestDiagnosticsBundle_HandlesZeroByteFilesGracefully(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	panicPath := filepath.Join(dir, "panic.log")
	outPath := filepath.Join(dir, "bundle.zip")

	// Create both files as 0 bytes.
	require.NoError(t, os.WriteFile(logPath, []byte{}, 0o600))
	require.NoError(t, os.WriteFile(panicPath, []byte{}, 0o600))

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--panic-log", panicPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err, "bundle must handle 0-byte logs without panicking")

	entries := readBundleEntries(t, outPath)
	tail := string(entries["04-audit-tail.jsonl"])
	assert.Contains(t, tail, "empty",
		"empty audit log section should annotate the empty state")
	panicSec := string(entries["08-panics.txt"])
	assert.Contains(t, panicSec, "empty",
		"empty panic log section should annotate the empty state")
}

func TestDiagnosticsBundle_RespectsOutFlag(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	customOut := filepath.Join(dir, "subdir", "named.zip")

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", customOut,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)
	_, err = os.Stat(customOut)
	assert.NoError(t, err, "bundle MUST honor --out's exact path (including non-existent parent)")
}

func TestDiagnosticsBundle_NoAuditSuppressesTail(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	// Seed a real audit line that WOULD show up if --no-audit were
	// ignored.
	const tellTale = "this-line-must-not-appear-when-no-audit-is-set"
	require.NoError(t, os.WriteFile(logPath,
		[]byte(fmt.Sprintf(`{"event":%q}`+"\n", tellTale)), 0o600))

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--no-audit",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	entries := readBundleEntries(t, outPath)
	tail := string(entries["04-audit-tail.jsonl"])
	assert.NotContains(t, tail, tellTale,
		"--no-audit must suppress audit-tail content")
	assert.Contains(t, tail, "intentionally omitted",
		"--no-audit must explain the empty section")
}

func TestDiagnosticsBundle_RedactsConfigSecrets(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)
	entries := readBundleEntries(t, outPath)
	cfgRaw := string(entries["02-config-redacted.json"])
	// Parse it as a ConfigExport — the diagnostics body must be
	// structurally identical to `config export --redact-secrets`.
	var exp ConfigExport
	require.NoError(t, json.Unmarshal([]byte(cfgRaw), &exp),
		"02-config-redacted.json must be a valid ConfigExport")
	assert.Equal(t, "kbounce", exp.Product)
	assert.Equal(t, "1.0", exp.SchemaVersion,
		"diagnostics bundle config must use the post-#288 string semver")
}

func TestDiagnosticsBundle_EnvKeysOnlyNoValues(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	// A KBOUNCER_* env var with a sensitive-looking value. Only the
	// KEY should appear in the system section; the VALUE never.
	t.Setenv("KBOUNCER_FAKE_TOKEN_FOR_TEST", "do-not-leak-this-value-please")

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)
	entries := readBundleEntries(t, outPath)
	for name, body := range entries {
		assert.NotContains(t, string(body), "do-not-leak-this-value-please",
			"env-var VALUE leaked into bundle entry %q", name)
	}
	// The KEY should appear in the system section.
	assert.Contains(t, string(entries["06-system.txt"]), "KBOUNCER_FAKE_TOKEN_FOR_TEST",
		"system section must list env KEY")
}

func TestDiagnosticsBundle_DefaultOutPathPattern(t *testing.T) {
	// When --out is omitted the default writes to the current
	// working directory using a timestamped filename. We chdir to a
	// hermetic tempdir so we don't pollute the repo + don't
	// surprise other tests.
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")

	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	_, _, err = runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	// Expect at least one matching file.
	matches, err := filepath.Glob("kbounce-diagnostics-*.zip")
	require.NoError(t, err)
	assert.NotEmpty(t, matches,
		"default --out must write kbounce-diagnostics-*.zip in CWD")
}

func TestDiagnosticsBundle_EmitsAdminAction(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diagnostics", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	// The admin-action OCSF event should have been appended to the
	// audit log via the env-var fallback.
	body, err := os.ReadFile(logPath)
	require.NoError(t, err)
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "diagnostics.bundle",
		"admin-action event for diagnostics.bundle must be appended to the audit log")
}

func TestDiagnosticsBundle_DiagAliasResolves(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	logPath := filepath.Join(dir, "audit.jsonl")
	outPath := filepath.Join(dir, "bundle.zip")

	// Operators are told they can type `kbounce diag bundle ...`.
	// Cobra command aliases handle the synonym; this test guards
	// against an accidental removal of the alias.
	_, _, err := runDiagnosticsCLI(t, db, profilesPath, logPath,
		"diag", "bundle",
		"--out", outPath,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err, "`kbounce diag bundle` alias must work")
	_, err = os.Stat(outPath)
	assert.NoError(t, err)
}

func TestRedactAuditLine_HandlesMalformedJSON(t *testing.T) {
	// Non-JSON line MUST still get the plain-text scrubber pass
	// (so an accidental log-rotation marker carrying a URL or
	// token still gets redacted).
	in := "not-json bearer abc123def456ghi789jkl012mno345pqr678stu and https://siem.example/x"
	out := redactAuditLine(in)
	assert.NotContains(t, out, "abc123def456ghi789jkl012mno345pqr678stu")
	assert.NotContains(t, out, "https://siem.example/x")
}

// keysOf returns the sorted keys of a map for diagnostic output.
func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sha256Hex matches the manifest's encoding (hex of sha256).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
