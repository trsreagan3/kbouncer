// chain_behavior_test.go — unit tests for audit chain correctness +
// the Fix 2 file-scoped verification behavior.
package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestChain_CleanVerify(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 5)
	writeLines(t, filepath.Join(dir, "audit.jsonl"), lines)

	res, err := VerifyChain(dir, st.StateFileAbsent())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("expected clean chain, got: %+v", res.Inconsistencies)
	}
	if res.EventsChecked != 5 {
		t.Fatalf("events_checked = %d, want 5", res.EventsChecked)
	}
	if res.HeadSeq == nil || *res.HeadSeq != 4 {
		t.Fatalf("head_seq = %v, want 4", res.HeadSeq)
	}
}

func TestChain_TamperMiddleEventFailsVerify(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 5)

	// Tamper a field in the MIDDLE event (index 2) without recomputing
	// its hash — exactly what a quiet log editor would do.
	var ev map[string]any
	dec := json.NewDecoder(bytes.NewReader(lines[2]))
	dec.UseNumber()
	if err := dec.Decode(&ev); err != nil {
		t.Fatal(err)
	}
	ev["unmapped"].(map[string]any)["iam_jit"].(map[string]any)["verdict"] = "DENY"
	tampered, _ := json.Marshal(ev)
	lines[2] = tampered
	writeLines(t, filepath.Join(dir, "audit.jsonl"), lines)

	res, err := VerifyChain(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("expected tamper to be detected, chain verified clean")
	}
	var sawHashMismatch bool
	for _, inc := range res.Inconsistencies {
		if inc.Reason == ReasonHashMismatch && inc.Seq != nil && *inc.Seq == 2 {
			sawHashMismatch = true
		}
	}
	if !sawHashMismatch {
		t.Fatalf("expected hash-mismatch finding at seq 2, got: %+v", res.Inconsistencies)
	}
}

func TestChain_DeletedRowFailsVerify(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 5)
	// Delete the middle row.
	kept := append(append([][]byte{}, lines[:2]...), lines[3:]...)
	writeLines(t, filepath.Join(dir, "audit.jsonl"), kept)

	res, _ := VerifyChain(dir, false)
	if res.OK() {
		t.Fatal("expected deletion to be detected")
	}
	var sawGap, sawPrev bool
	for _, inc := range res.Inconsistencies {
		switch inc.Reason {
		case ReasonSeqGap:
			sawGap = true
		case ReasonPrevHashMismatch:
			sawPrev = true
		}
	}
	if !sawGap || !sawPrev {
		t.Fatalf("expected seq-gap + prev-hash-mismatch, got: %+v", res.Inconsistencies)
	}
}

func TestChain_StatePersistsAcrossReload(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 3)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	st2 := LoadChainState(dir, 0)
	if st2.StateFileAbsent() {
		t.Fatal("state should not be absent after Save")
	}
	if st2.NextSeq() != 3 {
		t.Fatalf("reloaded next_seq = %d, want 3", st2.NextSeq())
	}
	if st2.HeadHash() != st.HeadHash() {
		t.Fatalf("reloaded head hash mismatch: %s vs %s", st2.HeadHash(), st.HeadHash())
	}
}

func TestChain_StateFilePerms(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 1)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("chain state perms = %o, want 600", fi.Mode().Perm())
	}
}

// --- Fix 2: file-scoped chain verification ---

// TestChainSourceFilesScoped_SiblingIgnored locks the Fix 2 invariant:
// chainSourceFilesScoped must not include files whose prefix differs from
// the named active file. A sibling JSONL archive with a different stem
// must be excluded so it cannot produce a false TAMPER inconsistency.
func TestChainSourceFilesScoped_SiblingIgnored(t *testing.T) {
	dir := t.TempDir()
	// Write the real chain's active log.
	active := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(active, []byte(`{}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Write a rotated archive that belongs to this chain.
	realArchive := filepath.Join(dir, "audit-20240101T000000Z.jsonl.gz")
	if err := os.WriteFile(realArchive, []byte("gz-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Write sibling files with DIFFERENT stems that must NOT be included.
	sibling1 := filepath.Join(dir, "other-service-20240101T000000Z.jsonl.gz")
	if err := os.WriteFile(sibling1, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling2 := filepath.Join(dir, "other.jsonl")
	if err := os.WriteFile(sibling2, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, err := chainSourceFilesScoped(dir, "audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	// Should include realArchive + active.jsonl, NOT the siblings.
	if len(files) != 2 {
		t.Fatalf("expected 2 files (real archive + active); got %d: %v", len(files), files)
	}
	for _, f := range files {
		base := filepath.Base(f)
		if base == "other-service-20240101T000000Z.jsonl.gz" || base == "other.jsonl" {
			t.Errorf("sibling file %q must not be included in the chain walk", base)
		}
	}
}

// TestVerifyChainFile_ScopedToNamedFile locks that VerifyChainFile only
// verifies the named file and its rotated siblings. A sibling JSONL in the
// same dir with a different stem that contains invalid chain data must NOT
// cause a false TAMPER result.
func TestVerifyChainFile_ScopedToNamedFile(t *testing.T) {
	dir := tmpLogDir(t)
	// Build a clean chain and write to audit.jsonl.
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 4)
	activeFile := filepath.Join(dir, "audit.jsonl")
	writeLines(t, activeFile, lines)

	// Write an unrelated JSONL file in the same directory. It is NOT a
	// valid chain event — if the verifier included it, it would report a
	// missing-chain-block inconsistency (false TAMPER).
	sibling := filepath.Join(dir, "unrelated.jsonl")
	if err := os.WriteFile(sibling, []byte(`{"not":"a chain"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// VerifyChainFile must report clean despite the sibling.
	res, err := VerifyChainFile(activeFile, st.StateFileAbsent())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("VerifyChainFile reported TAMPER despite sibling file — file-scoped "+
			"invariant violated; inconsistencies: %+v", res.Inconsistencies)
	}
	if res.EventsChecked != 4 {
		t.Fatalf("expected 4 events checked; got %d", res.EventsChecked)
	}
}

// TestVerifyChainFile_RealTamperStillCaught confirms that VerifyChainFile
// still detects genuine tampering (a modified row's hash no longer matches)
// even though sibling files are excluded. File-scoped != blind.
func TestVerifyChainFile_RealTamperStillCaught(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 4)

	// Tamper: flip a field in the middle row WITHOUT recomputing its hash.
	var ev map[string]any
	dec := json.NewDecoder(bytes.NewReader(lines[2]))
	dec.UseNumber()
	if err := dec.Decode(&ev); err != nil {
		t.Fatal(err)
	}
	ev["activity_name"] = "Tampered"
	tampered, _ := json.Marshal(ev)
	lines[2] = tampered

	activeFile := filepath.Join(dir, "audit.jsonl")
	writeLines(t, activeFile, lines)

	res, err := VerifyChainFile(activeFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("VerifyChainFile must detect tamper in the named file; chain verified clean instead")
	}
	var sawMismatch bool
	for _, inc := range res.Inconsistencies {
		if inc.Reason == ReasonHashMismatch && inc.Seq != nil && *inc.Seq == 2 {
			sawMismatch = true
		}
	}
	if !sawMismatch {
		t.Fatalf("expected hash-mismatch finding at seq=2; got: %+v", res.Inconsistencies)
	}
}
