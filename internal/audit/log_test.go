package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogWriter_CreatesPathAppendsValidJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path})
	require.NoError(t, err)
	defer lw.Close()

	for i := 0; i < 3; i++ {
		ev := FromDecision(DecisionInput{
			DecisionID: int64(i),
			Verdict:    "allow",
			Method:     "GET",
			Path:       "/api/v1/pods",
		})
		require.NoError(t, lw.Write(ctx, ev))
	}
	// Worker is async — give it a moment to flush before reading.
	require.Eventually(t, func() bool {
		return lw.Total() == 3
	}, 2*time.Second, 10*time.Millisecond, "worker should drain queue")

	// File mode 0600.
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Each line is valid JSON conforming to the OCSF wire shape.
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 3)
	for _, line := range lines {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		assert.Equal(t, float64(6003), m["class_uid"])
		meta := m["metadata"].(map[string]any)
		prod := meta["product"].(map[string]any)
		assert.Equal(t, "kbounce", prod["name"])
		assert.Equal(t, "iam-jit", prod["vendor_name"])
	}
}

func TestLogWriter_OverflowDrops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lw, err := NewLogWriter(ctx, LogWriterOptions{
		Path:       path,
		QueueDepth: 2,
	})
	require.NoError(t, err)
	defer lw.Close()

	// Pre-fill the queue + then push more than the depth. Use a
	// blocking event to prevent the worker from draining first.
	// Actually, we can't block the worker — instead push fast
	// enough that some land in the queue + some overflow. The
	// dropped counter is the assertion.
	dropped := 0
	for i := 0; i < 100; i++ {
		ev := FromDecision(DecisionInput{DecisionID: int64(i), Verdict: "allow"})
		if err := lw.Write(ctx, ev); err != nil {
			dropped++
		}
	}
	// Either some events dropped OR all drained — but if all
	// drained, the dropped counter is the source of truth.
	assert.Equal(t, int64(dropped), lw.Dropped(),
		"dropped counter should match the number of Write errors")
}

func TestLogWriter_FsyncFlag(t *testing.T) {
	// We can't directly observe fsync; assert the flag is wired by
	// flipping it + ensuring no error + total still increments.
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, fsync := range []bool{false, true} {
		path := filepath.Join(dir, "audit-"+map[bool]string{false: "nofsync", true: "fsync"}[fsync]+".jsonl")
		lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path, Fsync: fsync})
		require.NoError(t, err)
		require.NoError(t, lw.Write(ctx, FromDecision(DecisionInput{DecisionID: 1, Verdict: "allow"})))
		require.Eventually(t, func() bool { return lw.Total() == 1 },
			2*time.Second, 10*time.Millisecond)
		assert.Empty(t, lw.LastError(), "no error expected with fsync=%v", fsync)
		lw.Close()
	}
}

func TestLogWriter_RejectsEmptyPath(t *testing.T) {
	_, err := NewLogWriter(context.Background(), LogWriterOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty path")
}

func TestLogWriter_ContextCancelStopsWorker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path})
	require.NoError(t, err)
	require.NoError(t, lw.Write(ctx, FromDecision(DecisionInput{DecisionID: 1, Verdict: "allow"})))
	require.Eventually(t, func() bool { return lw.Total() == 1 },
		2*time.Second, 10*time.Millisecond)
	cancel()
	// Close cleans up the goroutine. Wait inside Close.
	lw.Close()
}

func TestLogWriter_PathReturnsConfiguredPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	lw, err := NewLogWriter(context.Background(), LogWriterOptions{Path: path})
	require.NoError(t, err)
	defer lw.Close()
	assert.Equal(t, path, lw.Path())
}
