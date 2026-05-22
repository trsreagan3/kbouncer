// watcher_test.go — #324b watcher regression suite.
//
// Covers:
//   - file-creation event triggers reload + emits ReasonFileCreated /
//     ReasonFileModified (either is valid depending on fsevents timing)
//   - file-modification event triggers reload
//   - rapid sequential writes are debounced (only one reload per
//     debounce quiet-period)
//   - parse error retains the previous snapshot + emits
//     ReasonParseError (fail-CLOSED)
//   - ReloadNow manual reload semantics
//   - empty-path no-op shape

package dynamicdeny

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// validYAMLPayload builds a single-rule YAML payload using the given
// rule id + target.
func validYAMLPayload(ruleID, target string) string {
	added := time.Now().UTC().Format(time.RFC3339)
	return strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + ruleID,
		`    targets: ["` + target + `"]`,
		`    reason: "test"`,
		`    duration: "1h"`,
		`    added_by: "u@h"`,
		`    added_at: "` + added + `"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
}

// captureEmits records every emit-callback invocation for assertion.
type capturedEmit struct {
	reason ReloadReason
	count  int
	err    string
}

type emitRecorder struct {
	mu       sync.Mutex
	captured []capturedEmit
}

func (er *emitRecorder) Emit(reason ReloadReason, rs *RuleSet, err error) {
	er.mu.Lock()
	defer er.mu.Unlock()
	c := capturedEmit{reason: reason}
	if rs != nil {
		c.count = len(rs.Rules)
	}
	if err != nil {
		c.err = err.Error()
	}
	er.captured = append(er.captured, c)
}

func (er *emitRecorder) Snapshot() []capturedEmit {
	er.mu.Lock()
	defer er.mu.Unlock()
	out := make([]capturedEmit, len(er.captured))
	copy(out, er.captured)
	return out
}

// waitForEmit polls the recorder until at least n events of the given
// reason show up OR the timeout elapses. Returns the matching events
// in arrival order.
func waitForEmit(er *emitRecorder, reason ReloadReason, n int, timeout time.Duration) []capturedEmit {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var match []capturedEmit
		for _, c := range er.Snapshot() {
			if reason == "" || c.reason == reason {
				match = append(match, c)
			}
		}
		if len(match) >= n {
			return match
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func TestWatcher_DetectsFileCreation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	var stderr bytes.Buffer
	w.SetStderr(&stderr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	if got := len(w.Snapshot().Rules); got != 0 {
		t.Errorf("initial snapshot should be empty; got %d", got)
	}

	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "namespace:prod")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	matches := waitForEmit(er, "", 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatalf("no emit captured after file creation; stderr=%q", stderr.String())
	}
	gotReason := matches[len(matches)-1].reason
	if gotReason != ReasonFileCreated && gotReason != ReasonFileModified {
		t.Errorf("emit reason = %q; want file_created or file_modified", gotReason)
	}
	snap := w.Snapshot()
	if len(snap.Rules) != 1 {
		t.Errorf("post-create snapshot = %d rule(s); want 1", len(snap.Rules))
	}
}

func TestWatcher_DetectsFileModification(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "namespace:prod")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	if got := len(w.Snapshot().Rules); got != 1 {
		t.Fatalf("initial snapshot should have 1 rule; got %d", got)
	}

	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID2, "namespace:stage")), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	matches := waitForEmit(er, "", 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatal("no emit captured after modify")
	}
	snap := w.Snapshot()
	if len(snap.Rules) != 1 || snap.Rules[0].ID != validRuleID2 {
		t.Errorf("post-modify snapshot = %v; want one rule with id %q", snap.Rules, validRuleID2)
	}
}

func TestWatcher_Debounces100ms(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "namespace:prod")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	// Long debounce so all the rapid writes coalesce.
	w.SetDebouncePeriod(150 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	// 5 rapid writes, each < 20ms apart. Should coalesce into ONE
	// reload (which fires once the 150ms quiet-period elapses).
	for i := 0; i < 5; i++ {
		body := validYAMLPayload(validRuleID2, "namespace:stage")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(15 * time.Millisecond)
	}

	// Wait for the debounce timer to elapse + an additional grace.
	time.Sleep(250 * time.Millisecond)

	snap := er.Snapshot()
	if len(snap) == 0 {
		t.Fatal("no emit captured; rapid writes should produce at least 1 reload")
	}
	if len(snap) > 2 {
		t.Errorf("rapid 5-write storm produced %d emits; expected <= 2 (debounce working)", len(snap))
	}
}

func TestWatcher_RetainsRulesOnParseError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "namespace:prod")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	if got := len(w.Snapshot().Rules); got != 1 {
		t.Fatalf("initial snapshot should have 1 rule; got %d", got)
	}

	// Overwrite with garbage YAML.
	if err := os.WriteFile(p, []byte("schema_version: \"1.0\"\ndenies: not-a-list\n"), 0o600); err != nil {
		t.Fatalf("rewrite garbage: %v", err)
	}

	matches := waitForEmit(er, ReasonParseError, 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatal("no parse_error emit captured")
	}
	// Previous snapshot retained.
	snap := w.Snapshot()
	if len(snap.Rules) != 1 || snap.Rules[0].ID != validRuleID {
		t.Errorf("post-parse-error snapshot = %v; want previous rule retained", snap.Rules)
	}
	if w.TotalParseErrors() == 0 {
		t.Error("TotalParseErrors should be incremented")
	}
}

func TestWatcher_ReloadNow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "namespace:prod")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var calls atomic.Int64
	emit := func(reason ReloadReason, rs *RuleSet, err error) {
		calls.Add(1)
	}
	w, err := NewWatcher(p, emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	// Manual reload without changing the file.
	rs, err := w.ReloadNow(ReasonReloadRequested)
	if err != nil {
		t.Fatalf("ReloadNow: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Errorf("rules after manual reload = %d; want 1", len(rs.Rules))
	}
	if calls.Load() == 0 {
		t.Error("emit callback should have fired on manual reload")
	}
}

func TestWatcher_NoPathStartIsNoOp(t *testing.T) {
	w, err := NewWatcher("", nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	w.Stop()
	if got := len(w.Snapshot().Rules); got != 0 {
		t.Errorf("empty-path snapshot = %d; want 0", got)
	}
}
