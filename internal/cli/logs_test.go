// Package cli — verify-chain (ADOPT-10/#734) tamper-detection tests.
//
// MED-2 closure: the `kbouncer logs verify-chain` operator subcommand is the
// reachable entrypoint for the tamper-evident hash-chain verifier. These
// tests prove a clean chain reports OK (zero exit) and a tampered chain
// reports the break + a non-zero exit — the property an incident-response
// runbook depends on per [[ibounce-honest-positioning]].

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trsreagan3/kbouncer/internal/audit"
)

// stampChainToFile builds an N-event hash-chain via the audit package's
// StampJSON (the same code path the live writer uses) and writes the
// canonical rows to audit.jsonl in dir. Returns the file path.
func stampChainToFile(t *testing.T, dir string, n int) string {
	t.Helper()
	chain := audit.LoadChainState(dir, 0)
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		ev := map[string]any{
			"class_uid":     6003,
			"activity_name": "Read",
			"time":          1700000000000 + i,
			"unmapped":      map[string]any{"iam_jit": map[string]any{"i": i}},
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		stamped, err := chain.StampJSON(raw)
		if err != nil {
			t.Fatalf("stamp %d: %v", i, err)
		}
		buf.Write(stamped)
		buf.WriteByte('\n')
	}
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLogsVerifyChain_Clean asserts the verify-chain command reports a
// clean chain (zero exit, "chain OK") for an untampered log.
func TestLogsVerifyChain_Clean(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 4)

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("verify-chain on a clean log must succeed; got err=%v out=%q", err, buf.String())
	}
	if !strings.Contains(buf.String(), "chain OK:") {
		t.Errorf("expected 'chain OK:' summary; got: %q", buf.String())
	}
}

// TestLogsVerifyChain_SiblingIgnored locks Fix 2: the chain verifier
// must be FILE-SCOPED to the named audit log. A sibling JSONL file in
// the same directory that has a different prefix must NOT be pulled
// into the chain walk and must NOT cause a false TAMPER report.
//
// Setup: clean "audit.jsonl" chain in dir + an unrelated sibling
// "other-service.jsonl" that is NOT a valid chain JSONL. The verifier
// must report "chain OK" because it only walks audit*.jsonl.gz and
// audit.jsonl, not the unrelated sibling.
func TestLogsVerifyChain_SiblingIgnored(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 3)

	// Write an unrelated JSONL file in the same directory. It is NOT
	// a valid chain event, so if the verifier ever includes it the
	// chain walk would either report a bad-JSON inconsistency or a
	// missing-chain-block inconsistency — causing a false TAMPER.
	sibling := filepath.Join(dir, "other-service.jsonl")
	if err := os.WriteFile(sibling, []byte(`{"not":"a chain event"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Also write a gz sibling with a different stem so we can confirm
	// the archive glob doesn't pull it in.
	gzSibling := filepath.Join(dir, "other-audit-20240101T000000Z.jsonl.gz")
	if err := os.WriteFile(gzSibling, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("verify-chain must succeed (chain OK) even with sibling files in the dir; "+
			"got err=%v out=%q — sibling files must be ignored", err, buf.String())
	}
	if !strings.Contains(buf.String(), "chain OK:") {
		t.Errorf("expected 'chain OK:' but got: %q", buf.String())
	}
}

// TestAuditVerify_Alias locks Fix 3: `kbounce audit verify` must be a
// working alias for `kbounce logs verify-chain` per
// [[cross-product-agent-parity]]. It must report "chain OK" on a clean
// log and return zero exit — verifying the alias is wired correctly.
func TestAuditVerify_Alias(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 3)

	root := newRootCmd()
	root.SetArgs([]string{"audit", "verify", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("audit verify (alias for logs verify-chain) must succeed on a clean log; "+
			"got err=%v out=%q", err, buf.String())
	}
	if !strings.Contains(buf.String(), "chain OK:") {
		t.Errorf("expected 'chain OK:' from audit verify alias; got: %q", buf.String())
	}
}

// TestAuditVerify_TamperDetected locks Fix 3 for the non-zero-exit case:
// the `audit verify` alias must surface tamper findings exactly like
// `logs verify-chain` does.
func TestAuditVerify_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 3)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected 3 rows, got %d", len(lines))
	}
	tampered := strings.Replace(lines[1], `"activity_name":"Read"`, `"activity_name":"Delete"`, 1)
	if tampered == lines[1] {
		t.Fatalf("tamper substitution had no effect; row=%q", lines[1])
	}
	lines[1] = tampered
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"audit", "verify", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err == nil {
		t.Fatalf("audit verify MUST return non-zero on a tampered log; got out=%q", buf.String())
	}
	if !strings.Contains(buf.String(), "TAMPER DETECTED") {
		t.Errorf("expected 'TAMPER DETECTED'; got: %q", buf.String())
	}
}

// TestLogsVerifyChain_TamperDetected is the load-bearing tamper test:
// edit one row's payload in place, then assert the command reports a
// hash-mismatch break AND exits non-zero — the property an
// incident-response runbook depends on per [[ibounce-honest-positioning]].
func TestLogsVerifyChain_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 4)

	// Tamper: flip a value inside the middle row's payload WITHOUT
	// recomputing its chain hash. The stored hash no longer matches the
	// recomputed hash over the edited payload.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected 4 rows, got %d", len(lines))
	}
	// Row index 2 (seq=2): change activity_name Read -> Delete.
	tampered := strings.Replace(lines[2], `"activity_name":"Read"`, `"activity_name":"Delete"`, 1)
	if tampered == lines[2] {
		t.Fatalf("tamper substitution did not change the row; row=%q", lines[2])
	}
	lines[2] = tampered
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	err = root.Execute()
	if err == nil {
		t.Fatalf("verify-chain MUST return a non-zero (error) result on a tampered log; got out=%q", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "TAMPER DETECTED") {
		t.Errorf("expected 'TAMPER DETECTED' in output; got: %q", out)
	}
	if !strings.Contains(out, "hash mismatch") {
		t.Errorf("expected the hash-mismatch reason naming the edited row; got: %q", out)
	}
	if !strings.Contains(out, "seq=2") {
		t.Errorf("expected the break to be reported at seq=2 (the edited row); got: %q", out)
	}
}
