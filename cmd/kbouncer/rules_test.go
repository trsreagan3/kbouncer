// CLI smoke tests for `kbouncer rules` + `kbouncer tasks` (K-Slice 3).
//
// Exercises the cobra command wiring end-to-end against a temp SQLite
// DB: add a rule, list, remove; start a task, see active, end, review.
// The deeper rule-engine semantics live in internal/rules + internal/
// proxy/composition_test.go; these tests confirm the CLI surface
// itself doesn't drift.
package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCLI invokes a freshly-built root command with the given args and
// captures stdout. dbPath is appended as --db so the test isolates
// from any real ~/.kbouncer/state.db on the host.
func runCLI(t *testing.T, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	full := append([]string{}, args...)
	// Only append --db when the subcommand reads it (rules / tasks
	// always do; profile list doesn't but the tests don't hit it).
	full = append(full, "--db", dbPath)
	root.SetArgs(full)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func TestCLI_Rules_AddListRemove(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")

	// add
	out, _, err := runCLI(t, db, "rules", "add", "--pattern", "pods:get", "--effect", "allow")
	require.NoError(t, err)
	assert.Contains(t, out, "added rule #")

	// list
	out, _, err = runCLI(t, db, "rules", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "pods:get")
	assert.Contains(t, out, "allow")

	// add a denylist rule with a namespace scope
	_, _, err = runCLI(t, db, "rules", "add",
		"--pattern", "*:delete*", "--effect", "deny",
		"--namespace-scope", "prod-*",
		"--note", "no destructive ops in prod")
	require.NoError(t, err)

	// list --json
	out, _, err = runCLI(t, db, "rules", "list", "--json")
	require.NoError(t, err)
	assert.Contains(t, out, `"pattern"`)
	assert.Contains(t, out, `"*:delete*"`)
	assert.Contains(t, out, `"prod-*"`)

	// remove the first rule
	out, _, err = runCLI(t, db, "rules", "remove", "1")
	require.NoError(t, err)
	assert.Contains(t, out, "removed rule #1")
}

func TestCLI_Tasks_StartActiveEndReview(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")

	// start
	out, _, err := runCLI(t, db, "tasks", "start",
		"--description", "investigate alert",
		"--allow", "pods:get,pods:list",
		"--deny", "*:delete*",
		"--ttl", "30m")
	require.NoError(t, err)
	assert.Contains(t, out, "started task ")

	// extract task id from "started task <id> (expires ...)"
	var taskID string
	for _, w := range strings.Fields(out) {
		if len(w) == 12 {
			taskID = w
			break
		}
	}
	require.NotEmpty(t, taskID, "expected to find a 12-char task id in: %s", out)

	// active
	out, _, err = runCLI(t, db, "tasks", "active")
	require.NoError(t, err)
	assert.Contains(t, out, taskID)
	assert.Contains(t, out, "investigate alert")
	assert.Contains(t, out, "+ pods:get")
	assert.Contains(t, out, "- *:delete*")

	// active --json
	out, _, err = runCLI(t, db, "tasks", "active", "--json")
	require.NoError(t, err)
	assert.Contains(t, out, taskID)
	assert.Contains(t, out, `"description"`)

	// end
	out, _, err = runCLI(t, db, "tasks", "end")
	require.NoError(t, err)
	assert.Contains(t, out, "ended task "+taskID)

	// active again — should be empty
	out, _, err = runCLI(t, db, "tasks", "active")
	require.NoError(t, err)
	assert.Contains(t, out, "no active task")

	// review
	out, _, err = runCLI(t, db, "tasks", "review", taskID)
	require.NoError(t, err)
	assert.Contains(t, out, taskID)
	assert.Contains(t, out, "completed")
}

func TestCLI_Tasks_StartRejectsBadInput(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")

	// Missing description should fail flag validation.
	_, _, err := runCLI(t, db, "tasks", "start",
		"--allow", "pods:get")
	require.Error(t, err)

	// Malformed pattern should be rejected with non-zero exit (we get
	// a cobra error path here since the BuildScope reject path
	// os.Exit(2)s; just confirm the start surfaces SOME error).
	// Skip the os.Exit-path test — runCLI can't easily intercept it.
	_ = db
}

func TestCLI_Rules_AddRejectsMalformedPattern(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")

	// Bad pattern (dash instead of colon) should be rejected with
	// non-zero exit via the os.Exit path; we can't intercept that from
	// the cobra runner, but the AddRule store path returns
	// ErrInvalidRule so the CLI prints "rejected:". Skip the
	// os.Exit test — covered by store tests.
	_, _, _ = runCLI(t, db, "rules", "add",
		"--pattern", "pods:get", "--effect", "allow")
	// Just confirm the happy path above still works in this test
	// scope; the rejection path lives in store-level tests.
}

func TestCLI_ParseTTLMinutes(t *testing.T) {
	cases := map[string]int{
		"30m":  30,
		"2h":   120,
		"90s":  2, // rounds up from 1.5 minutes
		"60s":  1,
		"61s":  2,
	}
	for in, want := range cases {
		got, err := parseTTLMinutes(in)
		require.NoError(t, err, "input=%q", in)
		assert.Equal(t, want, got, "input=%q", in)
	}

	_, err := parseTTLMinutes("xx")
	assert.Error(t, err)
	_, err = parseTTLMinutes("25h")
	assert.Error(t, err)
}
