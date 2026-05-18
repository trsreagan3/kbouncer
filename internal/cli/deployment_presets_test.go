// Tests for #254 — `kbounce run --preset security-observe`.
//
// Covers:
//   - all canonical settings activate
//   - HARD override (operator passes --mode cooperative) errors
//   - SOFT override (operator passes --audit-log-path /custom) allowed
//   - banner names the active preset + which settings are derived
//   - preset description uses neutral language (no violation /
//     infraction / unauthorized) per [[security-team-positioning-
//     safety-not-surveillance]]
//   - preset does NOT introduce any audit-webhook-url (per
//     [[self-host-zero-billing-dependency]])
//
// These tests exercise the preset framework in isolation. The
// integration test that the run command actually rebinds the flag
// variables lives alongside the run-command tests (rules_test.go +
// friends).

package cli

import (
	"strings"
	"testing"
)

func TestSecurityObserve_ActivatesCanonicalSettings(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	if preset == nil {
		t.Fatal("expected non-nil preset")
	}
	want := map[string]string{
		"mode":               "transparent",
		"default-policy":     "allow",
		"audit-log-path":     DefaultAuditLogPath("kbounce"),
		"alert-rules":        "defaults",
		"heartbeat-interval": "30s",
	}
	for k, v := range want {
		got, ok := preset.Values[k]
		if !ok {
			t.Errorf("preset missing key %q", k)
			continue
		}
		if got.Value != v {
			t.Errorf("preset[%q] = %q; want %q", k, got.Value, v)
		}
	}
}

func TestSecurityObserve_HardOverridesModeOnly(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	hard := []string{}
	soft := []string{}
	for k, v := range preset.Values {
		if v.Policy == PresetHard {
			hard = append(hard, k)
		}
		if v.Policy == PresetSoft {
			soft = append(soft, k)
		}
	}
	if len(hard) != 1 || hard[0] != "mode" {
		t.Errorf("expected exactly one HARD key (mode); got %v", hard)
	}
	if len(soft) != 4 {
		t.Errorf("expected 4 SOFT keys; got %d (%v)", len(soft), soft)
	}
}

func TestApplyPreset_HardOverrideErrors(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	_, err := ApplyPreset(
		preset,
		map[string]bool{"mode": true},
		map[string]string{
			"mode":               "cooperative",
			"default-policy":     "deny",
			"audit-log-path":     "",
			"alert-rules":        "",
			"heartbeat-interval": "0s",
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected error on HARD mode override")
	}
	var perr *PresetOverrideError
	if !asPresetOverrideError(err, &perr) {
		t.Fatalf("expected PresetOverrideError; got %T (%v)", err, err)
	}
	if perr.Flag != "mode" {
		t.Errorf("wrong flag in error: %q", perr.Flag)
	}
	msg := err.Error()
	for _, want := range []string{"security-observe", "mode", "HARD", "drop the --preset", "drop the explicit"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

func TestApplyPreset_HardWithMatchingValueSucceeds(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	res, err := ApplyPreset(
		preset,
		map[string]bool{"mode": true},
		map[string]string{
			"mode":               "transparent", // matches preset HARD value
			"default-policy":     "deny",
			"audit-log-path":     "",
			"alert-rules":        "",
			"heartbeat-interval": "0s",
		},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// mode lands in OverriddenKeys (operator restated it), NOT in
	// DerivedKeys (operator value wins).
	found := false
	for _, k := range res.OverriddenKeys {
		if k == "mode" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected mode in OverriddenKeys; got %v", res.OverriddenKeys)
	}
}

func TestApplyPreset_SoftOverrideAllowed(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	res, err := ApplyPreset(
		preset,
		map[string]bool{"audit-log-path": true},
		map[string]string{
			"mode":               "cooperative",
			"default-policy":     "deny",
			"audit-log-path":     "/custom/siem.jsonl",
			"alert-rules":        "",
			"heartbeat-interval": "0s",
		},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// audit-log-path is in OverriddenKeys; mode + others are in
	// DerivedKeys.
	wantOverridden := []string{"audit-log-path"}
	if !stringSlicesEqual(res.OverriddenKeys, wantOverridden) {
		t.Errorf("OverriddenKeys = %v; want %v", res.OverriddenKeys, wantOverridden)
	}
	wantDerived := []string{"mode", "default-policy", "alert-rules", "heartbeat-interval"}
	if !stringSlicesEqual(res.DerivedKeys, wantDerived) {
		t.Errorf("DerivedKeys = %v; want %v", res.DerivedKeys, wantDerived)
	}
}

func TestApplyPreset_SkipKeysLandInBanner(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	res, err := ApplyPreset(
		preset,
		nil,
		map[string]string{
			"mode":               "cooperative",
			"default-policy":     "deny",
			"audit-log-path":     "",
			"alert-rules":        "",
			"heartbeat-interval": "0s",
		},
		map[string]bool{"alert-rules": true},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, k := range res.SkippedKeys {
		if k == "alert-rules" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected alert-rules in SkippedKeys; got %v", res.SkippedKeys)
	}
}

func TestFormatBanner_ShowsPresetAndDerivedKeys(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	res, err := ApplyPreset(preset, nil, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := FormatBanner(preset, res)
	if len(lines) == 0 {
		t.Fatal("expected at least one banner line")
	}
	if !strings.Contains(lines[0], "deployment preset: security-observe") {
		t.Errorf("first line should name preset: %q", lines[0])
	}
	// Every derived key shows up in some line with the policy.
	joined := strings.Join(lines, "\n")
	for _, key := range []string{"mode", "audit-log-path", "alert-rules", "heartbeat-interval", "default-policy"} {
		if !strings.Contains(joined, "--"+key) {
			t.Errorf("banner missing --%s: %s", key, joined)
		}
	}
	if !strings.Contains(joined, "from preset; hard") {
		t.Error("banner should annotate mode as hard")
	}
	if !strings.Contains(joined, "from preset; soft") {
		t.Error("banner should annotate at least one key as soft")
	}
}

func TestSecurityObserve_NeutralLanguageNoViolationTerms(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	blob := strings.ToLower(preset.Description)
	for _, forbidden := range []string{"violation", "infraction", "unauthorized"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("preset description leaks %q: %s", forbidden, preset.Description)
		}
	}
}

func TestSecurityObserve_NoPhoneHome(t *testing.T) {
	preset := GetPreset("security-observe", "kbounce")
	if _, ok := preset.Values["audit-webhook-url"]; ok {
		t.Error("preset must NOT set audit-webhook-url (per [[self-host-zero-billing-dependency]])")
	}
	if _, ok := preset.Values["audit-webhook-token"]; ok {
		t.Error("preset must NOT set audit-webhook-token")
	}
}

func TestUnknownPreset_ReturnsNil(t *testing.T) {
	if GetPreset("does-not-exist", "kbounce") != nil {
		t.Error("expected nil for unknown preset")
	}
}

func TestListPresetNames_OnlySecurityObserve(t *testing.T) {
	names := ListPresetNames()
	if len(names) != 1 || names[0] != "security-observe" {
		t.Errorf("v1.0 should ship exactly security-observe; got %v", names)
	}
}

// asPresetOverrideError is a small type-assertion helper that works
// like errors.As but without importing errors here.
func asPresetOverrideError(err error, target **PresetOverrideError) bool {
	pe, ok := err.(*PresetOverrideError)
	if !ok {
		return false
	}
	*target = pe
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Integration test: exercise the actual `kbounce run --preset
// security-observe --mode cooperative` cobra invocation. We pass a
// custom --db pointed at an in-tempdir SQLite file so the run
// command's store-open succeeds; the HARD-override error fires
// BEFORE the store opens (the preset resolution is the first thing
// in RunE), so we never get as far as opening a real port.
func TestRunCmd_HardOverrideErrorsBeforeBind(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{
		"run",
		"--preset", "security-observe",
		"--mode", "cooperative",
		"--db", t.TempDir() + "/kb.db",
		"--port", "0",
	})
	// Cobra prints errors to its configured Err writer; suppress.
	root.SetOut(devNull{})
	root.SetErr(devNull{})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected HARD-override error")
	}
	msg := err.Error()
	for _, want := range []string{"security-observe", "mode", "HARD", "drop the --preset"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }
