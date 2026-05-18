// End-to-end coverage for the admin-action OCSF event wiring in
// kbounce's mutating subcommands (pause, rules, presets, profile
// install). Each subcommand opens a one-shot LogWriter when
// --audit-log-path is set, emits the admin-action event, and closes
// the writer; the test reads the resulting JSONL file to confirm the
// event landed with the right activity_name + actor + before/after
// hashes.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCLIWithAudit invokes a freshly-built root command with the given
// args, appending --db <dbPath> + --audit-log-path <logPath>. Captures
// stdout / stderr the same way runCLI does.
func runCLIWithAudit(t *testing.T, dbPath, logPath string, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	full := append([]string{}, args...)
	full = append(full, "--db", dbPath, "--audit-log-path", logPath)
	root.SetArgs(full)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// readAuditEvents reads the JSONL audit log at path and returns each
// row as a parsed map.
func readAuditEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "reading audit log %s", path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	out := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m),
			"unmarshal line %q", line)
		out = append(out, m)
	}
	return out
}

// findAdminActionEvent picks the first ADMIN_ACTION row with the
// given activity_name; useful when other event types (DECISION /
// alert / etc.) might also be in the file.
func findAdminActionEvent(t *testing.T, events []map[string]any, activityName string) map[string]any {
	t.Helper()
	for _, ev := range events {
		if ev["activity_name"] == activityName {
			return ev
		}
	}
	t.Fatalf("admin-action %q not found in %d events", activityName, len(events))
	return nil
}

// adminActionConfigChange extracts the unmapped.iam_jit.ext.config_change
// block (the load-bearing wire-shape carrier for admin-action events).
func adminActionConfigChange(t *testing.T, ev map[string]any) map[string]any {
	t.Helper()
	unmapped, _ := ev["unmapped"].(map[string]any)
	require.NotNil(t, unmapped, "event missing unmapped block")
	iamJit, _ := unmapped["iam_jit"].(map[string]any)
	require.NotNil(t, iamJit, "event missing unmapped.iam_jit")
	ext, _ := iamJit["ext"].(map[string]any)
	require.NotNil(t, ext, "event missing unmapped.iam_jit.ext")
	cfg, _ := ext["config_change"].(map[string]any)
	require.NotNil(t, cfg, "event missing config_change block")
	return cfg
}

func TestCLI_AdminAction_RulesAdd_EmitsEvent(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	logPath := filepath.Join(dir, "audit.jsonl")

	out, _, err := runCLIWithAudit(t, db, logPath,
		"rules", "add", "--pattern", "pods:get", "--effect", "allow")
	require.NoError(t, err)
	assert.Contains(t, out, "added rule #")

	events := readAuditEvents(t, logPath)
	require.Len(t, events, 1, "expected exactly one admin-action event")
	ev := events[0]
	assert.Equal(t, "rule.add", ev["activity_name"])
	assert.EqualValues(t, 6003, ev["class_uid"])
	assert.EqualValues(t, 1, ev["activity_id"], "rule.add must map to Create")
	assert.EqualValues(t, 1, ev["severity_id"], "rule.add must be Informational")

	cfg := adminActionConfigChange(t, ev)
	assert.Equal(t, "rule.add", cfg["type"])
	assert.Equal(t, "cli", cfg["source"])
	assert.Equal(t, "rule", cfg["entity_kind"])
	assert.Equal(t, "pods:get", cfg["entity"])

	beforeHash, _ := cfg["before_hash"].(string)
	afterHash, _ := cfg["after_hash"].(string)
	require.Len(t, beforeHash, 64)
	require.Len(t, afterHash, 64)
	assert.NotEqual(t, beforeHash, afterHash,
		"before/after rule-table state must hash differently")
}

func TestCLI_AdminAction_RulesRemove_EmitsEvent(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	logPath := filepath.Join(dir, "audit.jsonl")

	// Seed a rule first.
	_, _, err := runCLIWithAudit(t, db, logPath,
		"rules", "add", "--pattern", "pods:get", "--effect", "allow")
	require.NoError(t, err)

	_, _, err = runCLIWithAudit(t, db, logPath, "rules", "remove", "1")
	require.NoError(t, err)

	events := readAuditEvents(t, logPath)
	require.Len(t, events, 2, "rule.add + rule.remove = 2 events")
	removed := findAdminActionEvent(t, events, "rule.remove")
	assert.EqualValues(t, 4, removed["activity_id"], "rule.remove must map to Delete")
	cfg := adminActionConfigChange(t, removed)
	assert.Equal(t, "rule.remove", cfg["type"])
	assert.Equal(t, "pods:get", cfg["entity"])
}

func TestCLI_AdminAction_PauseStart_EmitsEvent(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	logPath := filepath.Join(dir, "audit.jsonl")

	out, _, err := runCLIWithAudit(t, db, logPath,
		"pause", "start", "--for", "5m", "--reason", "incident response")
	require.NoError(t, err)
	assert.Contains(t, out, "active")

	events := readAuditEvents(t, logPath)
	require.GreaterOrEqual(t, len(events), 1)
	ev := findAdminActionEvent(t, events, "pause.start")
	cfg := adminActionConfigChange(t, ev)
	assert.Equal(t, "pause.start", cfg["type"])
	assert.Equal(t, "pause_window", cfg["entity_kind"])
	// Pause start has nil before-state → before_hash MUST be absent.
	_, hasBefore := cfg["before_hash"]
	assert.False(t, hasBefore,
		"pause.start before-state is nil; before_hash must be omitted")
	_, hasAfter := cfg["after_hash"].(string)
	assert.True(t, hasAfter, "pause.start after_hash must be present")
}

func TestCLI_AdminAction_PauseStop_EmitsEvent(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	logPath := filepath.Join(dir, "audit.jsonl")

	_, _, err := runCLIWithAudit(t, db, logPath,
		"pause", "start", "--for", "5m")
	require.NoError(t, err)

	out, _, err := runCLIWithAudit(t, db, logPath, "pause", "stop")
	require.NoError(t, err)
	assert.Contains(t, out, "ended early")

	events := readAuditEvents(t, logPath)
	stop := findAdminActionEvent(t, events, "pause.stop")
	assert.EqualValues(t, 3, stop["activity_id"], "pause.stop maps to Update")
	cfg := adminActionConfigChange(t, stop)
	assert.Equal(t, "pause.stop", cfg["type"])
}

func TestCLI_AdminAction_PresetsApply_EmitsEvent(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	logPath := filepath.Join(dir, "audit.jsonl")

	// Pick the first available preset name dynamically so the test
	// doesn't drift if the preset catalog changes. `presets list` does
	// NOT accept --db so we call it without the audit-log wrapper.
	root := newRootCmd()
	var listOut bytes.Buffer
	root.SetOut(&listOut)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"presets", "list", "--json"})
	require.NoError(t, root.Execute())
	var catalog []map[string]any
	require.NoError(t, json.Unmarshal(listOut.Bytes(), &catalog))
	require.NotEmpty(t, catalog, "preset catalog must be non-empty for this test")
	presetName, _ := catalog[0]["name"].(string)
	require.NotEmpty(t, presetName)

	_, _, err := runCLIWithAudit(t, db, logPath, "presets", "apply", presetName)
	require.NoError(t, err)

	events := readAuditEvents(t, logPath)
	apply := findAdminActionEvent(t, events, "preset.apply")
	assert.EqualValues(t, 1, apply["activity_id"], "preset.apply maps to Create")
	cfg := adminActionConfigChange(t, apply)
	assert.Equal(t, presetName, cfg["entity"])
	assert.Equal(t, "preset", cfg["entity_kind"])
	// Before / after rule-table hashes both present (the apply added
	// rules so the hashes must differ).
	beforeHash, _ := cfg["before_hash"].(string)
	afterHash, _ := cfg["after_hash"].(string)
	require.Len(t, beforeHash, 64)
	require.Len(t, afterHash, 64)
	assert.NotEqual(t, beforeHash, afterHash)
}

func TestCLI_AdminAction_NoAuditPath_NoEmit(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	logPath := filepath.Join(dir, "audit.jsonl")

	// No --audit-log-path → admin action succeeds, no file is written.
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"rules", "add",
		"--pattern", "pods:get", "--effect", "allow", "--db", db})
	require.NoError(t, root.Execute())

	_, err := os.Stat(logPath)
	assert.True(t, os.IsNotExist(err),
		"no --audit-log-path → audit log file must not be created")
}

func TestCLI_AdminAction_EnvFallback(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "kb.db")
	logPath := filepath.Join(dir, "audit.jsonl")

	t.Setenv("KBOUNCER_AUDIT_LOG_PATH", logPath)
	// Pass no --audit-log-path; the env var should drive the wiring.
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"rules", "add",
		"--pattern", "pods:get", "--effect", "allow", "--db", db})
	require.NoError(t, root.Execute())

	events := readAuditEvents(t, logPath)
	require.Len(t, events, 1,
		"env-var fallback must drive the same admin-action emit path")
	assert.Equal(t, "rule.add", events[0]["activity_name"])
}
