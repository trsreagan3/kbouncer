// Tests for `kbounce profile doctor` (task #321 / KNOWN-CAVEATS §A19).
//
// Cross-product symmetric with dbounce/internal/profile/doctor_test.go.

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func freshProfilesPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if _, err := EnsureDefaultProfilesFile(path); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	return path
}

func stripFieldFromProfile(t *testing.T, path, profileName, field string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	profilesObj := tree["profiles"].(map[string]any)
	body := profilesObj[profileName].(map[string]any)
	delete(body, field)
	profilesObj[profileName] = body
	out, err := yaml.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestDoctor_FreshProfile_NoWarnings(t *testing.T) {
	path := freshProfilesPath(t)
	rep, err := Check(path)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(rep.MissingFields) != 0 {
		t.Fatalf("expected zero missing fields on fresh profile; got %d: %+v",
			len(rep.MissingFields), rep.MissingFields)
	}
	if line := StartupBannerLine("kbounce", path); line != "" {
		t.Fatalf("fresh profile should not emit a startup banner; got %q", line)
	}
}

func TestDoctor_MissingSafetyFloor_WarnsLoudly(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_subresource_writes")

	rep, err := Check(path)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	var found *FieldGap
	for i := range rep.MissingFields {
		g := rep.MissingFields[i]
		if g.ProfileName == "safe-default" && g.Field == "deny_subresource_writes" {
			found = &rep.MissingFields[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected deny_subresource_writes in missing list; got %+v",
			rep.MissingFields)
	}
	if found.Category != CategorySafetyFloor {
		t.Fatalf("expected category safety-floor; got %q", found.Category)
	}
	if !rep.HasSafetyFloorGap() {
		t.Fatalf("HasSafetyFloorGap should report true")
	}
	line := StartupBannerLine("kbounce", path)
	if line == "" {
		t.Fatalf("startup banner should fire on safety-floor gap")
	}
	if !strings.Contains(line, "§A19") {
		t.Fatalf("startup banner should reference §A19; got %q", line)
	}
	if !strings.Contains(line, "kbounce profile doctor") {
		t.Fatalf("startup banner should name kbounce profile doctor; got %q", line)
	}
}

func TestDoctor_MissingConvenience_NoStartupWarn_ButShowsInDoctor(t *testing.T) {
	original := shippedDefaultsCatalog
	t.Cleanup(func() { shippedDefaultsCatalog = original })
	shippedDefaultsCatalog = append([]FieldGap{
		{
			ProfileName:  "safe-default",
			Field:        "_test_convenience_field",
			Category:     CategoryConvenience,
			WhyMatters:   "test-only convenience",
			AddedIn:      "test fixture",
			DefaultValue: "test",
		},
	}, original...)

	path := freshProfilesPath(t)
	rep, err := Check(path)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	var sawConvenience, sawSafetyFloor bool
	for _, g := range rep.MissingFields {
		if g.Category == CategoryConvenience {
			sawConvenience = true
		}
		if g.Category == CategorySafetyFloor {
			sawSafetyFloor = true
		}
	}
	if !sawConvenience {
		t.Fatalf("expected convenience gap; got %+v", rep.MissingFields)
	}
	if sawSafetyFloor {
		t.Fatalf("fresh profile should not have safety-floor gap")
	}
	if line := StartupBannerLine("kbounce", path); line != "" {
		t.Fatalf("startup banner must NOT fire on convenience-only gaps; got %q", line)
	}
	rendered := FormatReport("kbounce", rep)
	if !strings.Contains(rendered, "_test_convenience_field") {
		t.Fatalf("doctor output should list convenience field; got %q", rendered)
	}
}

func TestDoctor_Apply_MergesAdditively(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_subresource_writes")
	// Add an operator-customized field that --apply MUST NOT touch.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	body := tree["profiles"].(map[string]any)["safe-default"].(map[string]any)
	body["custom_field_operator_added"] = "preserved-value"
	out, err := yaml.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	result, err := Apply(path, ApplyOptions{Now: now})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(result.AppliedFields) == 0 {
		t.Fatalf("expected at least one applied field")
	}

	mergedRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	var mergedTree map[string]any
	if err := yaml.Unmarshal(mergedRaw, &mergedTree); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}
	mergedBody := mergedTree["profiles"].(map[string]any)["safe-default"].(map[string]any)
	if mergedBody["deny_subresource_writes"] != true {
		t.Fatalf("expected deny_subresource_writes=true after apply; got %v",
			mergedBody["deny_subresource_writes"])
	}
	if mergedBody["custom_field_operator_added"] != "preserved-value" {
		t.Fatalf("operator-customized field was lost; got %v",
			mergedBody["custom_field_operator_added"])
	}
}

func TestDoctor_Apply_BacksUp(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_subresource_writes")

	priorBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	now := time.Date(2026, 5, 22, 12, 34, 56, 0, time.UTC)
	result, err := Apply(path, ApplyOptions{Now: now})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.HasSuffix(result.BackupPath, ".bak-20260522-123456") {
		t.Fatalf("backup path missing UTC timestamp suffix; got %q", result.BackupPath)
	}
	backupBytes, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backupBytes) != string(priorBytes) {
		t.Fatalf("backup contents differ from prior profile state")
	}
}

func TestDoctor_Acknowledge_SilencesUntilNewVersion(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_subresource_writes")
	if StartupBannerLine("kbounce", path) == "" {
		t.Fatalf("pre-ack: banner should fire")
	}
	if _, err := Acknowledge(path); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if line := StartupBannerLine("kbounce", path); line != "" {
		t.Fatalf("post-ack: banner should be silent; got %q", line)
	}
	ack := AcknowledgedVersionPath(path)
	if err := os.WriteFile(ack, []byte("OLDER-VERSION-STAMP\n"), 0o600); err != nil {
		t.Fatalf("write older ack: %v", err)
	}
	if line := StartupBannerLine("kbounce", path); line == "" {
		t.Fatalf("after version-bump simulation, banner should re-arm")
	}
}

func TestDoctor_CatalogCoversEmbeddedDefaults(t *testing.T) {
	var pf profileFile
	if err := yaml.Unmarshal(DefaultProfilesYAML(), &pf); err != nil {
		t.Fatalf("parse embedded defaults: %v", err)
	}
	for _, gap := range shippedDefaultsCatalog {
		if _, ok := pf.Profiles[gap.ProfileName]; !ok {
			t.Fatalf("catalog references profile %q absent from embedded defaults",
				gap.ProfileName)
		}
	}
}
