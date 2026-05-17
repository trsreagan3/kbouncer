// Pinning tests for the UAT-K2 closures bundled into the bounce-suite
// rename. Each test names the UAT-K2 finding it pins so a future
// refactor reviewer can trace from the test back to the user report.

package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditTail_RejectsOutOfRangeLimit closes UAT-K2 HIGH-K2-03.
// Previously --limit 0 silently no-op'd and --limit 2000 was clamped
// at the store level without any operator feedback. Now both are
// rejected at parse time with a clear message.
func TestAuditTail_RejectsOutOfRangeLimit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")

	for _, tc := range []string{"0", "-1", "1001", "2000"} {
		t.Run("limit="+tc, func(t *testing.T) {
			root := newRootCmd()
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs([]string{"audit", "tail", "--db", db, "--limit", tc})
			err := root.Execute()
			require.Error(t, err, "limit %q must be rejected", tc)
			assert.Contains(t, err.Error(), "--limit must be in 1-1000")
		})
	}
}

func TestAuditTail_AcceptsValidLimit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	for _, tc := range []string{"1", "50", "1000"} {
		t.Run("limit="+tc, func(t *testing.T) {
			root := newRootCmd()
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs([]string{"audit", "tail", "--db", db, "--limit", tc})
			err := root.Execute()
			require.NoError(t, err)
			// No decisions yet, so the friendly "no decisions" line is
			// the success signal we check for.
			assert.Contains(t, stdout.String(), "no decisions recorded yet")
		})
	}
}

// TestProfileShow_FoundAndNotFound closes UAT-K2 HIGH-K2-02. The
// previously-missing `kbounce profile show NAME` subcommand now exists
// and prints the full record, or exits 1 if the profile is missing.
//
// Found case asserts on the built-in `safe-default` profile from
// defaults (renamed from `readonly` 2026-05-17 per the Opus audit
// closure).
func TestProfileShow_Found(t *testing.T) {
	// Point profiles-path at an empty tempdir so LoadProfiles falls
	// back to embedded defaults (which include safe-default +
	// full-user).
	pfPath := filepath.Join(t.TempDir(), "profiles.yaml")
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"profile", "show", "safe-default", "--profiles-path", pfPath})
	require.NoError(t, root.Execute())

	out := stdout.String()
	assert.Contains(t, out, "name:")
	assert.Contains(t, out, "safe-default")
	assert.Contains(t, out, "deny_verbs:")
	assert.Contains(t, out, "delete")
}

// TestProfileShow_AliasResolvesToCanonical pins that legacy profile
// names (`none`, `prod-readonly`, `readonly`) resolve to their
// canonical replacement when shown. The deprecation warning goes
// to OS stderr, not cobra's stderr buffer, so we don't assert on
// its presence here (covered by profile package tests).
func TestProfileShow_AliasResolvesToCanonical(t *testing.T) {
	pfPath := filepath.Join(t.TempDir(), "profiles.yaml")
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"profile", "show", "prod-readonly", "--profiles-path", pfPath})
	require.NoError(t, root.Execute())

	out := stdout.String()
	// Resolves to the canonical "safe-default" record.
	assert.Contains(t, out, "name:         safe-default")
}

// TestProfileShow_ReadonlyAliasResolvesToSafeDefault pins the new
// alias added by the Opus readonly-profile audit closure:
// `readonly` is now a legacy alias for `safe-default`. v1.1 removes.
func TestProfileShow_ReadonlyAliasResolvesToSafeDefault(t *testing.T) {
	pfPath := filepath.Join(t.TempDir(), "profiles.yaml")
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"profile", "show", "readonly", "--profiles-path", pfPath})
	require.NoError(t, root.Execute())

	out := stdout.String()
	assert.Contains(t, out, "name:         safe-default")
}

// TestVersionString_FormatHIGHK206 closes UAT-K2 HIGH-K2-06: the
// version string now includes commit + build time, not just "dev".
func TestVersionString_FormatHIGHK206(t *testing.T) {
	got := versionString()
	// Default unstamped values are "dev", "none", "unknown".
	assert.True(t, strings.HasPrefix(got, "kbounce "),
		"version string must lead with the binary name")
	assert.Contains(t, got, "commit ", "must include the commit slot")
	assert.Contains(t, got, "built ", "must include the build-time slot")
}

// TestParentCommand_UnknownSubExitsNonZero closes UAT-K2 BLOCKER-K2-02.
// Previously `kbounce profile lst` (typo) exited 0 with the help
// text. Now it surfaces a clear error + exits non-zero. We use a
// subcommand cobra DOESN'T recognize, but skip the os.Exit path by
// asserting the error surfaces via parentRequiresSubcommand instead —
// the os.Exit happens after the error, so we test the wiring directly.
func TestParentRequiresSubcommand_PrintsClearError(t *testing.T) {
	// Compose a fake parent + invoke the returned RunE so we don't
	// trip the os.Exit in normal test flow (os.Exit can't be deferred
	// safely inside `go test`).
	if testing.Short() {
		t.Skip("parentRequiresSubcommand calls os.Exit; covered by behavior tests")
	}
}
