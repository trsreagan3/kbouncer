// profile_allow_cli_test.go — Fix 1 tests for the profile allow
// default-profile trap (issue: `kbounce profile allow` without --profile
// silently writes to "full-user" even when the running proxy uses a
// different profile, e.g. "safe-default"). The fix (option b) emits a
// loud WARNING naming the exact profile written to and advising the
// operator to re-run with --profile when ambiguous.
//
// These tests lock the new mismatch-warning behaviour so a future
// refactor cannot silently re-introduce the footgun.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeMinimalProfilesYAML writes a minimal profiles.yaml containing one
// local profile with the given name. Returns the file path.
func writeMinimalProfilesYAML(t *testing.T, dir, profileName string) string {
	t.Helper()
	path := filepath.Join(dir, "profiles.yaml")
	body := map[string]any{
		"profiles": map[string]any{
			profileName: map[string]any{
				"description": "test profile for " + profileName,
			},
		},
	}
	raw, err := yaml.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestProfileAllow_NoProfileFlag_NoEnv_WarnsMismatch locks the core Fix 1
// behaviour: when --profile is omitted AND KBOUNCER_PROFILE is unset, the
// allow lands on "full-user" (the library default) and the command MUST
// print a WARNING naming which profile was written to so the operator can
// verify it matches the running proxy.
func TestProfileAllow_NoProfileFlag_NoEnv_WarnsMismatch(t *testing.T) {
	dir := t.TempDir()
	profilesPath := writeMinimalProfilesYAML(t, dir, "full-user")

	// Ensure neither KBOUNCER_PROFILE nor KBOUNCE_PROFILE is set.
	t.Setenv("KBOUNCER_PROFILE", "")
	t.Setenv("KBOUNCE_PROFILE", "")
	// Isolate the pending-approval queue.
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH",
		filepath.Join(dir, "pending.jsonl"))

	root := newRootCmd()
	root.SetArgs([]string{
		"profile", "allow",
		"--target", "namespaces/staging",
		"--action", "apps/deployments:get",
		"--reason", "test allow",
		"--profiles-path", profilesPath,
	})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("profile allow must succeed even without --profile; err=%v stdout=%q stderr=%q",
			err, stdout.String(), stderr.String())
	}

	// The mismatch warning MUST appear on stderr.
	errOut := stderr.String()
	if !strings.Contains(errOut, "WARNING") {
		t.Errorf("expected WARNING on stderr when --profile is omitted and KBOUNCER_PROFILE is unset;\n"+
			"  stderr=%q\n  stdout=%q", errOut, stdout.String())
	}
	// The warning MUST name which profile was written to.
	if !strings.Contains(errOut, "full-user") {
		t.Errorf("WARNING must name the profile written to ('full-user'); stderr=%q", errOut)
	}
	// The rule MUST have been applied (command succeeded).
	if !strings.Contains(stdout.String(), "applied") {
		t.Errorf("expected 'applied' in stdout; got=%q", stdout.String())
	}
}

// TestProfileAllow_NoProfileFlag_EnvMatchesDefault_NoWarning verifies that
// when --profile is omitted but KBOUNCER_PROFILE matches the profile the
// allow was written to (both resolve to "full-user"), NO warning is emitted
// — this is the "operator has set the env var correctly" clean path.
func TestProfileAllow_NoProfileFlag_EnvMatchesDefault_NoWarning(t *testing.T) {
	dir := t.TempDir()
	profilesPath := writeMinimalProfilesYAML(t, dir, "full-user")

	t.Setenv("KBOUNCER_PROFILE", "full-user")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH",
		filepath.Join(dir, "pending.jsonl"))

	root := newRootCmd()
	root.SetArgs([]string{
		"profile", "allow",
		"--target", "namespaces/staging",
		"--action", "apps/deployments:get",
		"--reason", "test allow",
		"--profiles-path", profilesPath,
	})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("profile allow must succeed; err=%v stdout=%q stderr=%q",
			err, stdout.String(), stderr.String())
	}

	// No WARNING on stderr when env matches the written profile.
	if strings.Contains(stderr.String(), "WARNING") {
		t.Errorf("must NOT emit a WARNING when KBOUNCER_PROFILE matches the written profile;\n"+
			"  stderr=%q", stderr.String())
	}
}

// TestProfileAllow_NoProfileFlag_EnvDiffersFromWritten_WarnsMismatch is
// the critical fix-1 scenario: KBOUNCER_PROFILE=staging-work (the running
// proxy's profile) but --profile is omitted AND staging-work is not in the
// profiles.yaml (so the library falls back to full-user). The allow lands on
// "full-user", which is different from what the running proxy uses. The
// command MUST warn that the allow landed on a DIFFERENT profile from the
// running proxy.
func TestProfileAllow_NoProfileFlag_EnvDiffersFromWritten_WarnsMismatch(t *testing.T) {
	dir := t.TempDir()
	// profiles.yaml only has "full-user" — NOT "staging-work" (the env-var
	// profile). The library will fall back to full-user when staging-work
	// is not found, so the allow lands on full-user != staging-work.
	profilesPath := writeMinimalProfilesYAML(t, dir, "full-user")

	// Simulate: running proxy started with --profile staging-work.
	t.Setenv("KBOUNCER_PROFILE", "staging-work")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH",
		filepath.Join(dir, "pending.jsonl"))

	root := newRootCmd()
	root.SetArgs([]string{
		"profile", "allow",
		"--target", "namespaces/staging",
		"--action", "apps/deployments:get",
		"--reason", "forgot --profile flag",
		"--profiles-path", profilesPath,
	})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	// The command will fail (staging-work not found in profiles.yaml)
	// OR succeed by falling back to full-user. Either way, if it
	// succeeded, the mismatch warning must be present.
	_ = root.Execute()

	errOut := stderr.String()
	outStr := stdout.String()

	if strings.Contains(outStr, "applied") {
		// Allow landed on a profile. It can't be staging-work (not in
		// profiles.yaml), so it must be full-user — a mismatch with the env.
		if !strings.Contains(errOut, "WARNING") {
			t.Errorf("when allow lands on a profile != KBOUNCER_PROFILE (staging-work), "+
				"a WARNING must appear on stderr;\n  stderr=%q\n  stdout=%q",
				errOut, outStr)
		}
		if !strings.Contains(errOut, "staging-work") {
			t.Errorf("WARNING must mention the running proxy's profile 'staging-work';\n"+
				"  stderr=%q", errOut)
		}
	}
	// If the command failed (profile_not_found for staging-work), that's
	// also honest behaviour: the library reports the profile was not found
	// rather than silently falling back. Both outcomes are acceptable;
	// the silent-fallback case must emit the warning.
}

// TestProfileAllow_ExplicitProfile_NoWarning confirms that when the
// operator passes an explicit --profile the warning is suppressed
// unconditionally — an explicit flag means the operator made an
// intentional choice.
func TestProfileAllow_ExplicitProfile_NoWarning(t *testing.T) {
	dir := t.TempDir()
	profilesPath := writeMinimalProfilesYAML(t, dir, "full-user")

	// Even with a mismatching env var, explicit --profile must suppress
	// the warning.
	t.Setenv("KBOUNCER_PROFILE", "safe-default")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH",
		filepath.Join(dir, "pending.jsonl"))

	root := newRootCmd()
	root.SetArgs([]string{
		"profile", "allow",
		"--target", "namespaces/staging",
		"--action", "apps/deployments:get",
		"--reason", "explicit profile",
		"--profile", "full-user",
		"--profiles-path", profilesPath,
	})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("profile allow with explicit --profile must succeed; err=%v", err)
	}
	if strings.Contains(stderr.String(), "WARNING") {
		t.Errorf("must NOT emit a mismatch WARNING when --profile is explicitly set;\n"+
			"  stderr=%q", stderr.String())
	}
}
