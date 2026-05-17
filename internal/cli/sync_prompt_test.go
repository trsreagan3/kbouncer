// CLI surface tests for #203 synchronous deny-prompt v1.1 flags.
//
// Covers:
//
//   - --prompt-on-deny + --sync-prompt-on-deny on the same invocation
//     → CLI rejects with a clear error message
//   - --sync-prompt-timeout outside [5s, 300s] → rejected
//   - --sync-prompt-default bogus → rejected
//   - --sync-prompt-on-deny without --mode transparent → succeeds but
//     prints the silent-ignored warning to stderr (NOT an error)

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runRunArgs invokes `kbounce run ...` with a short context so the
// proxy doesn't actually start serving — we just want the CLI's
// parse-and-validate phase to fire. The proxy startup ends when ctx
// cancels (via signal.NotifyContext); the test cancels immediately
// after Execute() so a successful parse returns quickly.
func runRunArgs(t *testing.T, db string, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	full := append([]string{"run", "--db", db, "--port", "0"}, args...)
	root.SetArgs(full)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := root.ExecuteContext(ctx)
	return stdout.String(), stderr.String(), err
}

func TestSyncPromptCLI_MutexWithAsyncFlag(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	_, _, err := runRunArgs(t, db, "--prompt-on-deny", "--sync-prompt-on-deny")
	require.Error(t, err, "both flags on one invocation must fail")
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestSyncPromptCLI_TimeoutTooShort(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	_, _, err := runRunArgs(t, db,
		"--sync-prompt-on-deny", "--sync-prompt-timeout", "1s")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--sync-prompt-timeout")
}

func TestSyncPromptCLI_TimeoutTooLong(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	_, _, err := runRunArgs(t, db,
		"--sync-prompt-on-deny", "--sync-prompt-timeout", "10m")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--sync-prompt-timeout")
}

func TestSyncPromptCLI_BogusDefault(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	_, _, err := runRunArgs(t, db,
		"--sync-prompt-on-deny", "--sync-prompt-default", "maybe")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--sync-prompt-default")
}

func TestSyncPromptCLI_CooperativeAccepted(t *testing.T) {
	// Cooperative + --sync-prompt-on-deny → parse succeeds (NOT an
	// error). The run command prints a banner-level warning to
	// os.Stderr that the flag is silently ignored; we don't intercept
	// os.Stderr here (the run command writes there directly for
	// banner output), but the test confirms the flag combination is
	// accepted by cobra's parse + validate phase, with no error
	// surfaced.
	db := filepath.Join(t.TempDir(), "kb.db")
	_, _, err := runRunArgs(t, db,
		"--mode", "cooperative", "--sync-prompt-on-deny")
	// Either nil (clean shutdown via ctx cancel) or a port-bind error
	// is acceptable — what we want to confirm is no mutex / range
	// validation error.
	if err != nil {
		assert.NotContains(t, err.Error(), "mutually exclusive")
		assert.NotContains(t, err.Error(), "--sync-prompt-")
	}
}

// keep unused import alive in case of follow-up assertions.
var _ = strings.Contains
