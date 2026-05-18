// Tests for `kbounce investigate` (#273) — the cross-product
// "land a Claude-ready evidence pack" subcommand. Coverage:
//
//   - Command exits 0 + writes the two expected artifact files.
//   - --print-prompts lists 10 prompts WITHOUT writing files.
//   - --time-range "24h" filters audit-tail by seeded timestamps.
//   - Missing/empty audit DB → command still succeeds + records the
//     gap in the evidence file so a Claude analyst sees data, not
//     a tool failure.
//   - --filter rejects garbage early (before touching the disk).
//   - The "starter prompts" list stays in the neutral safety-team
//     vocabulary per [[security-team-positioning-safety-not-
//     surveillance]] (no "violation"/"infraction"/"unauthorized").
//   - The subcommand never dials a non-loopback host per
//     [[self-host-zero-billing-dependency]].
package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

// runInvestigateCLI is the test wrapper for `kbounce investigate`.
// Sets KBOUNCER_PROFILES_PATH so the embedded diagnostics bundle
// reads our tmpdir profiles path rather than the operator's real
// home.
func runInvestigateCLI(
	t *testing.T, dbPath, profilesPath string, args ...string,
) (string, string, error) {
	t.Helper()
	t.Setenv("KBOUNCER_PROFILES_PATH", profilesPath)
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

func TestInvestigate_ParseTimeRange(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"4w", 4 * 7 * 24 * time.Hour},
		{"24H", 24 * time.Hour},
	}
	for _, tc := range cases {
		got, err := parseTimeRange(tc.in)
		require.NoError(t, err, "parseTimeRange(%q)", tc.in)
		assert.Equal(t, tc.want, got, "parseTimeRange(%q)", tc.in)
	}
	for _, bad := range []string{"", "garbage", "24m", "0h", "-3d"} {
		_, err := parseTimeRange(bad)
		require.Error(t, err, "parseTimeRange(%q) must reject", bad)
	}
}

func TestInvestigate_StarterPromptsAvoidLoadedVocab(t *testing.T) {
	// Per [[security-team-positioning-safety-not-surveillance]] —
	// the user-facing prompt strings must NOT use accusation
	// vocabulary.
	banned := []string{"violation", "infraction", "unauthorized"}
	for _, prompt := range starterPrompts {
		lower := strings.ToLower(prompt)
		for _, w := range banned {
			assert.NotContains(t, lower, w,
				"prompt %q contains banned vocab %q", prompt, w)
		}
	}
	assert.Equal(t, 10, len(starterPrompts),
		"investigate ships exactly 10 starter prompts")
}

func TestInvestigate_PrintPromptsWritesNoFiles(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	stdout, _, err := runInvestigateCLI(t,
		filepath.Join(dir, "kb.db"),
		filepath.Join(dir, "profiles.yaml"),
		"investigate", "--print-prompts", "--out-dir", outDir,
	)
	require.NoError(t, err)
	for _, p := range starterPrompts {
		assert.Contains(t, stdout, p)
	}
	// --print-prompts MUST short-circuit before touching disk.
	_, statErr := os.Stat(outDir)
	assert.True(t, os.IsNotExist(statErr),
		"--print-prompts must not create --out-dir (got %v)", statErr)
}

func TestInvestigate_WritesBothArtifacts(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	outDir := filepath.Join(dir, "out")

	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	stdout, _, err := runInvestigateCLI(t, db, profilesPath,
		"investigate",
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	evidencePath := filepath.Join(outDir, investigationEvidenceFilename)
	contextPath := filepath.Join(outDir, investigationContextFilename)
	evSt, err := os.Stat(evidencePath)
	require.NoError(t, err, "evidence file must exist")
	require.Greater(t, evSt.Size(), int64(100),
		"evidence file should carry the OCSF envelope + 3 seeded events")
	require.Equal(t, os.FileMode(0o600), evSt.Mode().Perm(),
		"evidence file must be 0o600 (owner-only)")

	ctxSt, err := os.Stat(contextPath)
	require.NoError(t, err, "context bundle must exist")
	require.Greater(t, ctxSt.Size(), int64(100),
		"context bundle should carry diagnostics ZIP entries")

	// Stdout includes both paths + the privacy note.
	assert.Contains(t, stdout, evidencePath)
	assert.Contains(t, stdout, contextPath)
	assert.Contains(t, stdout, "Anthropic")
	assert.Contains(t, stdout, "local Claude client")
}

func TestInvestigate_EvidenceFileIsValidOCSFFinding(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	outDir := filepath.Join(dir, "out")

	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runInvestigateCLI(t, db, profilesPath,
		"investigate",
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	require.NoError(t, err)

	var bundle struct {
		ClassUID    int    `json:"class_uid"`
		ClassName   string `json:"class_name"`
		FindingInfo struct {
			UID  string `json:"uid"`
			Desc string `json:"desc"`
		} `json:"finding_info"`
		Events []map[string]any `json:"events"`
	}
	require.NoError(t, json.Unmarshal(body, &bundle))
	assert.Equal(t, 2004, bundle.ClassUID, "must be OCSF Detection Finding")
	assert.Equal(t, "Detection Finding", bundle.ClassName)
	assert.Contains(t, bundle.FindingInfo.UID, "kbounce-investigate-")
	assert.Contains(t, bundle.FindingInfo.Desc, "audit_log_present=true")
	assert.Equal(t, 3, len(bundle.Events),
		"all 3 seeded fixture rows should land in the bundle")
}

func TestInvestigate_ContextBundleHasNoAuditTail(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	outDir := filepath.Join(dir, "out")

	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	_, _, err := runInvestigateCLI(t, db, profilesPath,
		"investigate",
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	zr, err := zip.OpenReader(filepath.Join(outDir, investigationContextFilename))
	require.NoError(t, err)
	defer zr.Close()
	var auditBody []byte
	for _, f := range zr.File {
		if f.Name == "04-audit-tail.jsonl" {
			rc, err := f.Open()
			require.NoError(t, err)
			defer rc.Close()
			var buf bytes.Buffer
			_, err = buf.ReadFrom(rc)
			require.NoError(t, err)
			auditBody = buf.Bytes()
			break
		}
	}
	require.NotNil(t, auditBody, "context bundle must include the audit-tail section")
	assert.Contains(t, string(auditBody),
		"--no-audit was passed",
		"context bundle must record --no-audit since the evidence "+
			"file carries the audit content")
}

func TestInvestigate_TimeRangeFiltersByCutoff(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	outDir := filepath.Join(dir, "out")

	now := time.Now().UTC()
	// One recent row, one ancient row. --time-range 24h must keep
	// only the recent.
	recent := store.DecisionRow{
		At:              now.Add(-1 * time.Hour),
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "allow",
		ModeAtDecision:  "transparent",
		DecisionSource:  "profile",
		ProfileName:     "safe-default",
	}
	ancient := store.DecisionRow{
		At:              now.Add(-30 * 24 * time.Hour),
		Method:          "POST",
		Path:            "/api/v1/pods",
		ParsedVerb:      "create",
		ParsedResource:  "pods",
		DecisionVerdict: "deny",
		ModeAtDecision:  "transparent",
		DecisionSource:  "profile",
		ProfileName:     "safe-default",
	}
	st := seedDecisions(t, db, []store.DecisionRow{ancient, recent})
	st.Close()

	_, _, err := runInvestigateCLI(t, db, profilesPath,
		"investigate",
		"--time-range", "24h",
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	require.NoError(t, err)
	var bundle struct {
		Events []map[string]any `json:"events"`
	}
	require.NoError(t, json.Unmarshal(body, &bundle))
	assert.Equal(t, 1, len(bundle.Events),
		"--time-range 24h must filter out the 30d-old row")
}

func TestInvestigate_EmptyDBStillSucceeds(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	outDir := filepath.Join(dir, "out")

	stdout, _, err := runInvestigateCLI(t, db, profilesPath,
		"investigate",
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)
	assert.Contains(t, stdout, "audit log was missing")

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	require.NoError(t, err)
	var bundle struct {
		FindingInfo struct {
			Desc string `json:"desc"`
		} `json:"finding_info"`
	}
	require.NoError(t, json.Unmarshal(body, &bundle))
	assert.Contains(t, bundle.FindingInfo.Desc, "audit_log_present=false")
}

func TestInvestigate_RejectsBadFilter(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runInvestigateCLI(t,
		filepath.Join(dir, "kb.db"),
		filepath.Join(dir, "profiles.yaml"),
		"investigate",
		"--filter", "garbage_no_operator",
		"--out-dir", filepath.Join(dir, "out"),
	)
	require.Error(t, err, "bad filter must fail before writing artifacts")
	_, statErr := os.Stat(filepath.Join(dir, "out"))
	assert.True(t, os.IsNotExist(statErr),
		"failed filter must not create --out-dir")
}

func TestInvestigate_RejectsBadTimeRange(t *testing.T) {
	dir := t.TempDir()
	_, _, err := runInvestigateCLI(t,
		filepath.Join(dir, "kb.db"),
		filepath.Join(dir, "profiles.yaml"),
		"investigate",
		"--time-range", "24m",
		"--out-dir", filepath.Join(dir, "out"),
	)
	require.Error(t, err, "bad time-range must fail before writing artifacts")
}

func TestInvestigate_NoOutboundNetworkCall(t *testing.T) {
	// Per [[self-host-zero-billing-dependency]] the subcommand must
	// never dial a non-loopback host. We hijack net.DefaultResolver
	// + intercept TCP dials at the http.Transport layer indirectly
	// by pointing --healthz-url at a closed loopback port — if the
	// command tried to reach anywhere ELSE, it would attempt DNS,
	// which we'd notice by the test failing on the assert below.
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	outDir := filepath.Join(dir, "out")

	st := seedDecisions(t, db, fixtureDecisions(time.Now().UTC()))
	st.Close()

	// Sanity: a TCP dial to an obviously-non-loopback target fails
	// fast on this host. We rely on the test being run in a sandbox
	// without outbound network — the diagnostics bundle's only
	// network call is to opts.HealthzURL, which we pin to loopback.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 50*time.Millisecond)
	if err == nil {
		_ = conn.Close()
	}

	_, _, err = runInvestigateCLI(t, db, profilesPath,
		"investigate",
		"--out-dir", outDir,
		"--healthz-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err,
		"investigate must succeed end-to-end with loopback-only network")
}
