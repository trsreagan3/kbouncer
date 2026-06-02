package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestManager_ChainStampsAndVerifies — ADOPT-10 / #734 — events emitted
// through the Manager → LogWriter path with a chain configured must
// land chained on disk + verify clean, and Manager.Status() must
// surface honest chain + manifest state.
func TestManager_ChainStampsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	chain := LoadChainState(dir, 0)
	signer, err := NewManifestSigner(dir, "kbouncer", 1, filepath.Join(dir, "keys"), DefaultKeypairName)
	if err != nil {
		t.Fatal(err)
	}
	lw, err := NewLogWriter(context.Background(), LogWriterOptions{
		Path:   logPath,
		Fsync:  true,
		Chain:  chain,
		Signer: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(ManagerOptions{LogWriter: lw})

	for i := 0; i < 3; i++ {
		mgr.Emit(context.Background(), Event{DecisionID: int64(i)})
	}
	// Allow the worker to drain.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && lw.Total() < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	mgr.Close()

	// Each on-disk line carries a chain block.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("audit log empty")
	}

	res, err := VerifyChain(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("chain failed verification: %+v", res.Inconsistencies)
	}
	if res.EventsChecked != 3 {
		t.Fatalf("events_checked = %d, want 3", res.EventsChecked)
	}

	st := mgr.Status()
	if !st.ChainEnabled {
		t.Fatal("Status.ChainEnabled = false; want true")
	}
	if st.ChainHeadSeq != 2 {
		t.Fatalf("Status.ChainHeadSeq = %d, want 2", st.ChainHeadSeq)
	}
	if st.ChainHeadHash == "" {
		t.Fatal("Status.ChainHeadHash empty")
	}
	if !st.ManifestConfigured {
		t.Fatal("Status.ManifestConfigured = false; want true")
	}
	// A manifest should have been emitted (interval=1) + verify clean.
	files := ListManifests(dir)
	if len(files) == 0 {
		t.Fatal("expected at least one manifest emitted")
	}
	m, err := LoadManifestFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := VerifyManifest(m, ""); !ok {
		t.Fatalf("emitted manifest failed verify: %s", reason)
	}
}
