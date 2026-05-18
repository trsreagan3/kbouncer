// CLI-level tests for `kbounce backup` + `kbounce restore` (#279).
//
// The store package owns the heavy lifting tests; this file covers
// the Cobra wiring: flag parsing, default-path generation, the
// "is kbounce running" probe, and the admin-action emission.
package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// runCmd is a tiny helper that invokes a fresh root command with
// the supplied args + captures stdout/stderr. Mirrors the helper
// every other CLI test file uses.
func runCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

func TestBackup_DefaultGeneratesTimestampedPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBOUNCER_DB", filepath.Join(dir, "state.db"))
	t.Setenv("HOME", dir)
	// Chdir so the auto-generated ./kbounce-backup-* lands in tmp.
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir tmp: %v", err)
	}

	_, stderr, err := runCmd(t, "backup")
	if err != nil {
		t.Fatalf("backup: %v (stderr=%s)", err, stderr)
	}
	// Verify the generated file exists and has the kbounce-backup-
	// prefix.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "kbounce-backup-") &&
			strings.HasSuffix(e.Name(), ".db") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no kbounce-backup-*.db file found in %s", dir)
	}
}

func TestBackup_ExplicitOutPathWritesFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KBOUNCER_DB", filepath.Join(dir, "state.db"))

	outPath := filepath.Join(dir, "my-backup.db")
	_, stderr, err := runCmd(t,
		"backup", "--out", outPath, "--db", filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("backup: %v (stderr=%s)", err, stderr)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("expected backup file at %s: %v", outPath, err)
	}
	if !strings.Contains(stderr, "backup written to "+outPath) {
		t.Errorf("stderr should report destination; got %s", stderr)
	}
}

func TestRestore_RequiresIn(t *testing.T) {
	_, _, err := runCmd(t, "restore")
	if err == nil {
		t.Fatalf("expected error when --in is missing")
	}
	if !strings.Contains(err.Error(), "--in PATH is required") {
		t.Errorf("error should mention --in: %v", err)
	}
}

func TestRestore_RoundTripViaCLI(t *testing.T) {
	dir := t.TempDir()
	srcDB := filepath.Join(dir, "src.db")
	t.Setenv("KBOUNCER_DB", srcDB)

	// Seed a row in the source via a direct SQL touch — keeps the
	// test focused on the CLI wiring rather than dragging in the
	// rules-add subcommand.
	if err := seedRule(t, srcDB, "test-rule"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	backupPath := filepath.Join(dir, "b.db")
	if _, stderr, err := runCmd(t,
		"backup", "--out", backupPath, "--db", srcDB); err != nil {
		t.Fatalf("backup: %v (%s)", err, stderr)
	}

	destPath := filepath.Join(dir, "dest.db")
	_, stderr, err := runCmd(t,
		"restore", "--in", backupPath,
		"--dest", destPath,
		"--skip-running-probe")
	if err != nil {
		t.Fatalf("restore: %v (%s)", err, stderr)
	}
	if !strings.Contains(stderr, "restored 1 rule") {
		t.Errorf("stderr should say 'restored 1 rule(s)'; got %s", stderr)
	}
}

func TestRestore_RefusesIfKbounceListenerDetected(t *testing.T) {
	// Stand up a fake healthz listener on loopback so the probe
	// returns "running".
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
	defer srv.Close()

	dir := t.TempDir()
	srcDB := filepath.Join(dir, "src.db")
	t.Setenv("KBOUNCER_DB", srcDB)
	if err := seedRule(t, srcDB, "x"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	backupPath := filepath.Join(dir, "b.db")
	if _, _, err := runCmd(t,
		"backup", "--out", backupPath, "--db", srcDB); err != nil {
		t.Fatalf("backup: %v", err)
	}

	destPath := filepath.Join(dir, "dest.db")
	_, _, err := runCmd(t,
		"restore", "--in", backupPath,
		"--dest", destPath,
		"--probe-url", srv.URL+"/healthz")
	if err == nil {
		t.Fatalf("expected refuse when listener detected")
	}
	if !strings.Contains(err.Error(), "appears to be running") {
		t.Errorf("error should mention 'appears to be running': %v", err)
	}
}

func TestRestore_SkipProbeBypassesRunningCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer srv.Close()
	dir := t.TempDir()
	srcDB := filepath.Join(dir, "src.db")
	t.Setenv("KBOUNCER_DB", srcDB)
	if err := seedRule(t, srcDB, "x"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	backupPath := filepath.Join(dir, "b.db")
	if _, _, err := runCmd(t,
		"backup", "--out", backupPath, "--db", srcDB); err != nil {
		t.Fatalf("backup: %v", err)
	}
	destPath := filepath.Join(dir, "dest.db")
	if _, _, err := runCmd(t,
		"restore", "--in", backupPath,
		"--dest", destPath,
		"--probe-url", srv.URL+"/healthz",
		"--skip-running-probe"); err != nil {
		t.Fatalf("--skip-running-probe should bypass: %v", err)
	}
}

func TestProbeKbounceRunning_RefusesNonLoopback(t *testing.T) {
	running, reason := probeKbounceRunning("http://example.com:8766/healthz")
	if running {
		t.Errorf("non-loopback probe should NOT report running")
	}
	if !strings.Contains(reason, "loopback") {
		t.Errorf("reason should mention loopback: %s", reason)
	}
}

func TestProbeKbounceRunning_NoListenerReturnsFalse(t *testing.T) {
	// Use a port that's vanishingly unlikely to be in use locally.
	running, _ := probeKbounceRunning("http://127.0.0.1:1/healthz")
	if running {
		t.Errorf("probe should be false when no listener is bound")
	}
}

func TestProbeKbounceRunning_DetectsLiveListener(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer srv.Close()
	// httptest.NewServer binds to 127.0.0.1:<rand-port> by default.
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(u.Host, "127.0.0.1") {
		t.Skipf("httptest didn't bind to 127.0.0.1 (got %s); skipping", u.Host)
	}
	running, reason := probeKbounceRunning(srv.URL + "/healthz")
	if !running {
		t.Errorf("expected running=true; reason=%s", reason)
	}
}

// seedRule opens a fresh kbounce store at the given path + inserts
// one rule row via the store-package's full migration path so
// the on-disk schema exactly matches production.
//
// The pattern parameter is taken as a literal resource name; we
// wrap it as "pattern:*" so it satisfies rules.ParsePattern's
// resource:verb_glob requirement.
func seedRule(t *testing.T, dbPath, patternResource string) error {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = st.AddRule(rules.ProxyRule{
		Pattern: patternResource + ":*",
		Effect:  rules.EffectAllow,
	})
	return err
}
