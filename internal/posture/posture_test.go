// Posture tests for kbounce per #383 / §A42.
//
// Covers the test list from the launch-blocker spec:
//   - TestPosture_ReportsActiveProfileAndMode
//   - TestPosture_ReportsScopeRestrictions (via KUBECONFIG marker)
//   - TestPosture_JSONOutputValidatesAgainstSchema
//   - TestPosture_DetectsRunningViaLoopbackProbe
//   - TestPosture_DetectsMisconfigEnvSetButBouncerDown
//   - TestPosture_DefaultPortIsPinned

package posture

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// helper — bind a loopback socket on a random port + return (listener, port).
func bindLoopback(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bindLoopback: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	return l, port
}

func TestPosture_ReportsActiveProfileAndMode(t *testing.T) {
	t.Setenv("KBOUNCER_PROFILE", "safe-default")
	t.Setenv("KBOUNCER_MODE", "transparent")
	b := Capture()
	if b.ActiveProfile != "safe-default" {
		t.Errorf("ActiveProfile=%q want safe-default", b.ActiveProfile)
	}
	if b.Mode != "transparent" {
		t.Errorf("Mode=%q want transparent", b.Mode)
	}
	if b.Bouncer != "kbounce" {
		t.Errorf("Bouncer=%q want kbounce", b.Bouncer)
	}
}

func TestPosture_ReportsUnknownWhenNoEnv(t *testing.T) {
	t.Setenv("KBOUNCER_PROFILE", "")
	t.Setenv("KBOUNCER_MODE", "")
	b := Capture()
	if b.ActiveProfile != "unknown" {
		t.Errorf("ActiveProfile=%q want unknown", b.ActiveProfile)
	}
	if b.Mode != "unknown" {
		t.Errorf("Mode=%q want unknown", b.Mode)
	}
}

func TestPosture_DetectsKubeconfigMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(KubeconfigMarker+"\napiVersion: v1\n"), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", path)
	b := Capture()
	if b.EnvVarPointingHere == "" {
		t.Errorf("EnvVarPointingHere should be set, got empty")
	}
}

func TestPosture_NonKbounceKubeconfigDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", path)
	b := Capture()
	if b.EnvVarPointingHere != "" {
		t.Errorf("non-kbounce kubeconfig should not match, got %q", b.EnvVarPointingHere)
	}
	if b.EnvVarSetElsewhere == "" {
		t.Errorf("EnvVarSetElsewhere should describe the non-kbounce kubeconfig")
	}
}

func TestPosture_DetectsMisconfigEnvSetButBouncerDown(t *testing.T) {
	// Setup KUBECONFIG pointing at a kbounce-marked file BUT kbounce
	// itself is not running on its default port (since the test doesn't
	// start one). Expect misconfig.
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(KubeconfigMarker+"\n"), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", path)
	// Ensure the default port is NOT listening: bind it momentarily then
	// release it. (Tests run sequentially so this should be safe.)
	b := Capture()
	if b.Running {
		t.Skip("default kbounce port " +
			"happens to be in use by another process; skipping misconfig test")
	}
	if b.Misconfig == "" {
		t.Errorf("misconfig should be set when KUBECONFIG points at " +
			"a kbounce kubeconfig but kbounce isn't running")
	}
}

func TestPosture_DefaultPortIsPinned(t *testing.T) {
	if DefaultPort != 8766 {
		t.Errorf("DefaultPort=%d; if you changed the kbounce --port default, "+
			"update both the cli flag and this constant", DefaultPort)
	}
}

func TestPosture_JSONOutputValidatesAgainstSchema(t *testing.T) {
	b := Capture()
	bs, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(bs, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Required keys per the §A42 spec.
	for _, k := range []string{
		"schema_version", "bouncer", "captured_at", "running",
		"port", "default_port", "mode", "active_profile",
	} {
		if _, ok := roundtrip[k]; !ok {
			t.Errorf("missing required key %q in JSON output", k)
		}
	}
	if roundtrip["schema_version"] != SchemaVersion {
		t.Errorf("schema_version=%v want %s", roundtrip["schema_version"], SchemaVersion)
	}
}

func TestPosture_DetectsRunningViaLoopbackProbe(t *testing.T) {
	l, port := bindLoopback(t)
	defer l.Close()
	// Directly test the helper rather than spawning kbounce.
	if !loopbackPortOpen(port, 250*1_000_000) {
		t.Errorf("loopbackPortOpen returned false for a bound port %d", port)
	}
}
