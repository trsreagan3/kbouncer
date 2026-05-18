package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/audit"
)

// startTLSPayloadServer returns an httptest.NewTLSServer that responds
// to every GET with the given bytes. Returned URL points at the
// server; the corresponding HTTP client (set up to skip cert verify
// for the test cert) is constructed by the test via
// InsecureTLSClientForTests.
func startTLSPayloadServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tmpProfilesPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "profiles.yaml")
}

// TestInstall_HappyPath_HTTPS — happy path: HTTPS URL → profiles
// installed with source = URL.
func TestInstall_HappyPath_HTTPS(t *testing.T) {
	payload := []byte(`
profiles:
  acme-staging:
    description: "Acme's staging guardrail"
    deny_keywords: ["prod"]
  acme-readonly:
    description: "no writes"
    deny_verbs: ["delete", "patch"]
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	res, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, srv.URL, res.SourceURL)
	assert.Equal(t, target, res.ProfilesPath)
	assert.ElementsMatch(t, []string{"acme-staging", "acme-readonly"}, res.InstalledNames)
	assert.False(t, res.SHA256Verified) // no pin passed

	// Verify file contents end-to-end via the loader.
	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	staging, err := ps.Active("acme-staging")
	require.NoError(t, err)
	assert.Equal(t, srv.URL, staging.Source, "source must be the fetch URL")
	assert.Equal(t, []string{"prod"}, staging.DenyKeywords)
	ro, err := ps.Active("acme-readonly")
	require.NoError(t, err)
	assert.Equal(t, srv.URL, ro.Source)
}

// TestInstall_HTTPSchemeRefused — http:// URL is rejected before any
// network access.
func TestInstall_HTTPSchemeRefused(t *testing.T) {
	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{
		From:         "http://example.invalid/p.yaml",
		HTTPClient:   InsecureTLSClientForTests(), // never used
		ProfilesPath: target,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "https://")
	// No file written.
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr), "no profiles file should have been created")
}

// TestInstall_SHA256Mismatch — pin mismatch → exit 2.
func TestInstall_SHA256Mismatch(t *testing.T) {
	payload := []byte("profiles:\n  x:\n    description: ok\n")
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	_, err := Install(context.Background(), InstallOptions{
		From:           srv.URL,
		HTTPClient:     InsecureTLSClientForTests(),
		ProfilesPath:   target,
		ExpectedSHA256: strings.Repeat("0", 64),
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "sha256 mismatch")
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr), "no profiles file should have been created on mismatch")
}

// TestInstall_SHA256Match — correct pin → success, verified flag true.
func TestInstall_SHA256Match(t *testing.T) {
	payload := []byte("profiles:\n  x:\n    description: ok\n")
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	sum := sha256.Sum256(payload)
	pin := hex.EncodeToString(sum[:])

	res, err := Install(context.Background(), InstallOptions{
		From:           srv.URL,
		HTTPClient:     InsecureTLSClientForTests(),
		ProfilesPath:   target,
		ExpectedSHA256: pin,
	})
	require.NoError(t, err)
	assert.True(t, res.SHA256Verified)
	assert.Equal(t, pin, res.SHA256)
}

// TestInstall_SHA256Match_ColonSeparated — colon-separated + upper
// case pin is normalized (mirrors Python).
func TestInstall_SHA256Match_ColonSeparated(t *testing.T) {
	payload := []byte("profiles:\n  x:\n    description: ok\n")
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	sum := sha256.Sum256(payload)
	pin := hex.EncodeToString(sum[:])
	// Inject colons + uppercase to exercise normalization.
	var b strings.Builder
	for i, r := range strings.ToUpper(pin) {
		if i > 0 && i%2 == 0 {
			b.WriteRune(':')
		}
		b.WriteRune(r)
	}

	_, err := Install(context.Background(), InstallOptions{
		From:           srv.URL,
		HTTPClient:     InsecureTLSClientForTests(),
		ProfilesPath:   target,
		ExpectedSHA256: b.String(),
	})
	require.NoError(t, err)
}

// TestInstall_MalformedYAML — invalid YAML → exit 1, no file.
func TestInstall_MalformedYAML(t *testing.T) {
	payload := []byte("not: [valid: yaml: at all : :")
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitPayload, ie.ExitCode)
	assert.Contains(t, strings.ToLower(ie.Message), "yaml")
}

// TestInstall_PayloadWithoutProfilesObject — missing top-level
// `profiles` key → refused.
func TestInstall_PayloadWithoutProfilesObject(t *testing.T) {
	payload := []byte("not_profiles: []\n")
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitPayload, ie.ExitCode)
	assert.Contains(t, ie.Message, "profiles")
}

// TestInstall_ValidationFailureAbortsBeforeWriting — if any single
// profile fails validation, NONE are written (all-or-nothing).
func TestInstall_ValidationFailureAbortsBeforeWriting(t *testing.T) {
	payload := []byte(`
profiles:
  good:
    description: "ok"
  bad:
    keyword_match: "regex"
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitPayload, ie.ExitCode)

	// No partial install — file must not exist.
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr),
		"profiles file must not exist after validation failure")
}

// TestInstall_ConflictWithoutForceRefused — same-name conflict → exit 2.
func TestInstall_ConflictWithoutForceRefused(t *testing.T) {
	target := tmpProfilesPath(t)
	// Pre-existing local profile.
	require.NoError(t, os.WriteFile(target, []byte(`
profiles:
  acme-staging:
    description: "user's local copy"
`), 0o600))

	payload := []byte(`
profiles:
  acme-staging:
    description: "org version"
`)
	srv := startTLSPayloadServer(t, payload)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "--force")

	// Local version preserved.
	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("acme-staging")
	require.NoError(t, err)
	assert.Equal(t, "user's local copy", p.Description)
}

// TestInstall_ConflictWithForceOverwrites — --force replaces.
func TestInstall_ConflictWithForceOverwrites(t *testing.T) {
	target := tmpProfilesPath(t)
	require.NoError(t, os.WriteFile(target, []byte(`
profiles:
  acme-staging:
    description: "user's local copy"
`), 0o600))

	payload := []byte(`
profiles:
  acme-staging:
    description: "org version"
`)
	srv := startTLSPayloadServer(t, payload)

	res, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
		Force:        true,
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("acme-staging")
	require.NoError(t, err)
	assert.Equal(t, "org version", p.Description)
	assert.Equal(t, srv.URL, p.Source)
}

// TestInstall_SourceFieldInPayloadIsOverridden — a malicious payload
// claiming `source: local` cannot escape the read-only invariant;
// install forces source to the URL.
func TestInstall_SourceFieldInPayloadIsOverridden(t *testing.T) {
	payload := []byte(`
profiles:
  sneaky:
    description: "claims to be local"
    source: "local"
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("sneaky")
	require.NoError(t, err)
	assert.Equal(t, srv.URL, p.Source,
		"install must force source to the fetch URL; payload's source:local must be ignored")
}

// TestInstall_RecordsSourceField — installed profile keeps the URL on
// disk + survives a load round-trip.
func TestInstall_RecordsSourceField(t *testing.T) {
	payload := []byte(`
profiles:
  x:
    description: "ok"
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)

	// Raw file contents should contain `source: <URL>` (the URL is
	// what the read-only check + provenance reporting key off).
	raw, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "source: "+srv.URL,
		"on-disk profile must record source = fetch URL")
}

// TestUpsertProfile_RefusesOverwriteOfInstalledProfile — installed
// profiles are read-only via the canonical write entry point. This is
// the invariant that the Python test exercises via the recommender's
// save-as-profile path; we exercise it directly against UpsertProfile.
func TestUpsertProfile_RefusesOverwriteOfInstalledProfile(t *testing.T) {
	payload := []byte(`
profiles:
  acme-locked:
    description: "org"
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)

	// Now attempt to upsert a local profile with the same name. Must
	// be refused with a message that mentions "read-only".
	err = UpsertProfile(&Profile{
		Name:        "acme-locked",
		Description: "engineer's local override attempt",
	}, target)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read-only",
		"UpsertProfile must refuse to clobber an installed profile")

	// And the original content must still be on disk.
	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("acme-locked")
	require.NoError(t, err)
	assert.Equal(t, "org", p.Description)
	assert.Equal(t, srv.URL, p.Source)
}

// TestUpsertProfile_AllowsOverwriteOfLocalProfile — local profiles
// can be overwritten freely (mirrors the recommender's expected
// behavior on save-as-profile of a name the user already owns).
func TestUpsertProfile_AllowsOverwriteOfLocalProfile(t *testing.T) {
	target := tmpProfilesPath(t)
	require.NoError(t, os.WriteFile(target, []byte(`
profiles:
  my-local:
    description: "v1"
`), 0o600))

	err := UpsertProfile(&Profile{
		Name:        "my-local",
		Description: "v2",
	}, target)
	require.NoError(t, err)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("my-local")
	require.NoError(t, err)
	assert.Equal(t, "v2", p.Description)
}

// TestInstall_PreservesUnrelatedExistingProfiles — installing one
// org profile must not delete unrelated local profiles in the same
// file.
func TestInstall_PreservesUnrelatedExistingProfiles(t *testing.T) {
	target := tmpProfilesPath(t)
	require.NoError(t, os.WriteFile(target, []byte(`
profiles:
  my-personal:
    description: "engineer's personal profile"
    deny_keywords: ["temp"]
`), 0o600))

	payload := []byte(`
profiles:
  org-profile:
    description: "from IT"
`)
	srv := startTLSPayloadServer(t, payload)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	personal, err := ps.Active("my-personal")
	require.NoError(t, err)
	assert.Equal(t, "engineer's personal profile", personal.Description,
		"install must not clobber unrelated local profiles")
	org, err := ps.Active("org-profile")
	require.NoError(t, err)
	assert.Equal(t, srv.URL, org.Source)
}

// captureInstallEmitter is a test-only audit.Emitter implementation
// (sat next to the test it serves so we don't grow an exported test
// helper out of the audit package just for one consumer).
type captureInstallEmitter struct {
	events []audit.Event
}

func (c *captureInstallEmitter) Emit(_ context.Context, ev audit.Event) {
	c.events = append(c.events, ev)
}

func (c *captureInstallEmitter) Status() audit.Status { return audit.Status{} }

// TestInstall_EmitsSyntheticProfileInstallEvent confirms a successful
// install fires the EventTypeProfileInstall synthetic event through
// the wired emitter — the install-time alerting wire per
// [[security-team-audit-export]] + #270. Per
// [[deliberate-feature-completion]] the wiring is verified end-to-end
// (real HTTPS fetch + real on-disk write + emit) rather than via a
// unit on the builder alone (which is covered separately in
// internal/audit/synthetic_events_test.go).
func TestInstall_EmitsSyntheticProfileInstallEvent(t *testing.T) {
	payload := []byte(`
profiles:
  org-readonly:
    description: "org-distributed read-only profile"
    deny_verbs: ["delete", "patch"]
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	emitter := &captureInstallEmitter{}

	res, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
		AuditEmitter: emitter,
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Len(t, emitter.events, 1,
		"successful install must emit exactly one synthetic install event")
	ev := emitter.events[0]
	assert.Equal(t, audit.EventTypeProfileInstall, ev.EventType,
		"synthetic event must use the install-specific event type")
	assert.Equal(t, "org-readonly", ev.Unmapped.IAMJIT.Profile)
	require.NotNil(t, ev.Unmapped.IAMJIT.Ext)
	assert.Equal(t, srv.URL, ev.Unmapped.IAMJIT.Ext["profile_source"],
		"event must carry the fetch URL so the non_org rule's allowlist gate works")
	assert.Equal(t, []string{"org-readonly"}, ev.Unmapped.IAMJIT.Ext["installed_profiles"])
}

// TestInstall_NilEmitterStillSucceeds confirms the AuditEmitter field
// is optional — operators who haven't wired audit export still get a
// working install. Mirrors the default CLI path.
func TestInstall_NilEmitterStillSucceeds(t *testing.T) {
	payload := []byte(`
profiles:
  org-readonly:
    description: "no emitter wired"
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	res, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
		// AuditEmitter intentionally unset
	})
	require.NoError(t, err)
	require.NotNil(t, res)
}

// TestInstall_FailedInstallDoesNotEmit guards the "emit only on
// success" invariant — a sha256 mismatch must NOT produce a synthetic
// event (the audit trail would lie about an install that didn't
// happen).
func TestInstall_FailedInstallDoesNotEmit(t *testing.T) {
	payload := []byte("profiles:\n  x:\n    description: ok\n")
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)
	emitter := &captureInstallEmitter{}

	_, err := Install(context.Background(), InstallOptions{
		From:           srv.URL,
		ExpectedSHA256: "deadbeef" + strings.Repeat("0", 56), // 64 hex chars; wrong
		HTTPClient:     InsecureTLSClientForTests(),
		ProfilesPath:   target,
		AuditEmitter:   emitter,
	})
	require.Error(t, err)
	assert.Empty(t, emitter.events,
		"failed install must not emit a synthetic event")
}

// TestInstall_AllowRulesRoundTrip — allow_rules in the payload survive
// load + serialize (the field exists for cross-product YAML symmetry).
func TestInstall_AllowRulesRoundTrip(t *testing.T) {
	payload := []byte(`
profiles:
  acme-engineer:
    description: "with allow rules"
    allow_rules:
      - pattern: "get pods"
        note: "read pods anywhere"
      - pattern: "list namespaces"
        arn_scope: "*"
`)
	srv := startTLSPayloadServer(t, payload)
	target := tmpProfilesPath(t)

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: target,
	})
	require.NoError(t, err)

	ps, err := LoadProfiles(target)
	require.NoError(t, err)
	p, err := ps.Active("acme-engineer")
	require.NoError(t, err)
	require.Len(t, p.AllowRules, 2)
	assert.Equal(t, "get pods", p.AllowRules[0].Pattern)
	assert.Equal(t, "read pods anywhere", p.AllowRules[0].Note)
	assert.Equal(t, "list namespaces", p.AllowRules[1].Pattern)
	assert.Equal(t, "*", p.AllowRules[1].ArnScope)
}
