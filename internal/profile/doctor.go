// Package profile — doctor.go
//
// `kbounce profile doctor` — diff-checks the operator's installed
// profile YAML against the embedded shipped defaults and reports
// missing fields without touching the file.
//
// Context: this exists because kbounce NEVER overwrites
// ~/.kbouncer/profiles.yaml once it's been written (operator edits
// must survive). That's the right default for operator-customized
// state, but it silently turns into UPGRADE-BLINDNESS when a new
// safety floor is added to embedded defaults AFTER the operator's
// local file was written.
//
// Per task #321 / KNOWN-CAVEATS §A19 — the role-effectiveness eval
// 2026-05-22 surfaced the upgrade-blindness pattern in dbounce
// (operators pre-#302 ran without the DCL floor); kbouncer + ibounce
// + gbounce ship the same `profile doctor` surface for cross-product
// parity per [[cross-product-agent-parity]].
//
// Architecture (cross-product symmetric with dbounce + ibounce +
// gbounce):
//
//   - Check() — compare installed profile YAML against embedded
//     defaults; return MissingFields[] + category for each.
//   - Apply() — additively merge missing fields into the on-disk
//     profile; back up the prior file BEFORE write. NEVER overwrites
//     operator-customized field VALUES (only adds absent KEYS).
//   - Acknowledge() — write the per-operator acknowledged-version
//     stamp so the startup banner stays silent until a new
//     ShippedDefaultsVersion ships.
//   - HasSafetyFloorGap() — fast predicate used by the `kbounce run`
//     startup banner to decide whether to emit the one-line caveat.
//
// Field categories (cross-product):
//
//   - "safety-floor" — denies that ENFORCE the safe-default
//     guarantees. Missing one = the safety claim is silently false.
//     EXAMPLES: deny_subresource_writes, deny_on_impersonation. The
//     startup banner fires ONLY for missing safety-floor fields.
//   - "detection" — observation features.
//   - "audit" — telemetry-shape changes.
//   - "convenience" — defaults / naming / TTL. Pure-UX.
//
// Per [[creates-never-mutates]]: Apply() is additive only. Per
// [[security-team-positioning-safety-not-surveillance]]: framed as
// "your profile is behind" not "you are non-compliant."

package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FieldCategory classifies the urgency of a missing default field.
type FieldCategory string

const (
	CategorySafetyFloor FieldCategory = "safety-floor"
	CategoryDetection   FieldCategory = "detection"
	CategoryAudit       FieldCategory = "audit"
	CategoryConvenience FieldCategory = "convenience"
)

// FieldGap describes one missing default field in the operator's
// installed profile relative to the embedded defaults.
type FieldGap struct {
	ProfileName  string
	Field        string
	Category     FieldCategory
	WhyMatters   string
	AddedIn      string
	DefaultValue any
}

// Report is the output of Check().
type Report struct {
	MissingFields          []FieldGap
	InstalledPath          string
	ShippedDefaultsVersion string
}

// HasSafetyFloorGap returns true when at least one MissingFields
// entry is CategorySafetyFloor.
func (r *Report) HasSafetyFloorGap() bool {
	if r == nil {
		return false
	}
	for _, g := range r.MissingFields {
		if g.Category == CategorySafetyFloor {
			return true
		}
	}
	return false
}

// shippedDefaultsCatalog is the source-of-truth list of default
// fields the doctor knows about. Adding a new safety floor to
// embedded defaults.yaml REQUIRES adding a row here; the test
// `TestDoctor_CatalogCoversEmbeddedDefaults` enforces this.
//
// Stable order: by category (safety-floor first), then alphabetical
// by (ProfileName, Field).
var shippedDefaultsCatalog = []FieldGap{
	{
		ProfileName: "safe-default",
		Field:       "deny_subresource_writes",
		Category:    CategorySafetyFloor,
		WhyMatters: "Gap-K-14: long-tail safety net for CRD-defined " +
			"mutating subresources not enumerated in deny_verbs. " +
			"Without this, a write to a CRD-defined subresource " +
			"(create/update/patch) escapes the safe-default deny set.",
		AddedIn:      "kbounce 0.6.0 (#286, 2026-05-21)",
		DefaultValue: true,
	},
	{
		ProfileName: "safe-default",
		Field:       "deny_on_impersonation",
		Category:    CategorySafetyFloor,
		WhyMatters: "Gap-K-9: Impersonate-User / Impersonate-Group " +
			"headers let a caller masquerade as another principal. " +
			"Without this floor, an agent can use --as / --as-group " +
			"to bypass the safe-default's verb deny via a more " +
			"permissive principal.",
		AddedIn:      "kbounce 0.6.0 (#286, 2026-05-21)",
		DefaultValue: true,
	},
}

// ShippedDefaultsVersion is the version stamp baked into the
// embedded defaults. Bump when defaults.yaml changes in a way
// operators should re-acknowledge.
const ShippedDefaultsVersion = "2026-05-22-321"

// Check inspects the installed profile YAML at path against the
// shippedDefaultsCatalog. Returns a Report with zero MissingFields
// when the operator's file is current.
func Check(path string) (*Report, error) {
	r := &Report{
		InstalledPath:          path,
		ShippedDefaultsVersion: ShippedDefaultsVersion,
	}
	if path == "" {
		return r, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return r, nil
		}
		return nil, fmt.Errorf("kbounce: read profiles %q: %w", path, err)
	}
	var rawTree map[string]any
	if err := yaml.Unmarshal(raw, &rawTree); err != nil {
		return nil, fmt.Errorf("kbounce: parse profiles tree: %w", err)
	}
	profilesObj, _ := rawTree["profiles"].(map[string]any)

	for _, want := range shippedDefaultsCatalog {
		profileBody, _ := profilesObj[want.ProfileName].(map[string]any)
		if profileBody == nil {
			continue
		}
		if _, present := profileBody[want.Field]; present {
			continue
		}
		r.MissingFields = append(r.MissingFields, want)
	}
	sort.SliceStable(r.MissingFields, func(i, j int) bool {
		return categoryRank(r.MissingFields[i].Category) <
			categoryRank(r.MissingFields[j].Category)
	})
	return r, nil
}

func categoryRank(c FieldCategory) int {
	switch c {
	case CategorySafetyFloor:
		return 0
	case CategoryDetection:
		return 1
	case CategoryAudit:
		return 2
	case CategoryConvenience:
		return 3
	}
	return 9
}

// ApplyOptions tunes Apply().
type ApplyOptions struct {
	Now time.Time
}

// ApplyResult describes what Apply() did.
type ApplyResult struct {
	BackupPath    string
	AppliedFields []FieldGap
}

// Apply additively merges missing default fields into profiles.yaml.
// NEVER overwrites operator-set values. Backs up the prior file.
//
// Per [[creates-never-mutates]]: ADDITIVE only.
func Apply(path string, opts ApplyOptions) (*ApplyResult, error) {
	if path == "" {
		return nil, errors.New("kbounce: Apply requires a profiles.yaml path")
	}
	rep, err := Check(path)
	if err != nil {
		return nil, err
	}
	if len(rep.MissingFields) == 0 {
		return &ApplyResult{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kbounce: read profiles %q: %w", path, err)
	}
	var rawTree map[string]any
	if err := yaml.Unmarshal(raw, &rawTree); err != nil {
		return nil, fmt.Errorf("kbounce: parse profiles tree: %w", err)
	}
	profilesObj, _ := rawTree["profiles"].(map[string]any)
	if profilesObj == nil {
		profilesObj = map[string]any{}
		rawTree["profiles"] = profilesObj
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	backupPath := backupPathFor(path, now)
	if err := os.WriteFile(backupPath, raw, 0o600); err != nil {
		return nil, fmt.Errorf("kbounce: write backup %q: %w", backupPath, err)
	}

	applied := make([]FieldGap, 0, len(rep.MissingFields))
	for _, gap := range rep.MissingFields {
		profileBody, _ := profilesObj[gap.ProfileName].(map[string]any)
		if profileBody == nil {
			continue
		}
		if _, present := profileBody[gap.Field]; present {
			continue
		}
		profileBody[gap.Field] = gap.DefaultValue
		profilesObj[gap.ProfileName] = profileBody
		applied = append(applied, gap)
	}

	out, err := yaml.Marshal(rawTree)
	if err != nil {
		return nil, fmt.Errorf("kbounce: encode profiles yaml: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".profiles-*.yaml.tmp")
	if err != nil {
		return nil, fmt.Errorf("kbounce: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("kbounce: write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("kbounce: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("kbounce: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("kbounce: rename into place: %w", err)
	}
	return &ApplyResult{BackupPath: backupPath, AppliedFields: applied}, nil
}

func backupPathFor(path string, now time.Time) string {
	stamp := now.UTC().Format("20060102-150405")
	return path + ".bak-" + stamp
}

// AcknowledgedVersionPath returns the per-operator acknowledged-
// version file path. Lives next to profiles.yaml.
func AcknowledgedVersionPath(profilesPath string) string {
	if profilesPath == "" {
		return ""
	}
	dir := filepath.Dir(profilesPath)
	return filepath.Join(dir, ".profiles-acknowledged-version")
}

// Acknowledge writes the current ShippedDefaultsVersion to the
// acknowledged-version file.
func Acknowledge(profilesPath string) (string, error) {
	ack := AcknowledgedVersionPath(profilesPath)
	if ack == "" {
		return "", errors.New("kbounce: Acknowledge requires a profiles.yaml path")
	}
	if dir := filepath.Dir(ack); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("kbounce: mkdir %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(ack, []byte(ShippedDefaultsVersion+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("kbounce: write acknowledgement: %w", err)
	}
	return ack, nil
}

// IsAcknowledged returns true when the on-disk acknowledged-version
// matches the current ShippedDefaultsVersion.
func IsAcknowledged(profilesPath string) bool {
	ack := AcknowledgedVersionPath(profilesPath)
	if ack == "" {
		return false
	}
	raw, err := os.ReadFile(ack)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == ShippedDefaultsVersion
}

// FormatReport renders the multi-line text shown by `kbounce profile
// doctor`.
func FormatReport(product string, r *Report) string {
	if r == nil || len(r.MissingFields) == 0 {
		return fmt.Sprintf(
			"%s: profile doctor — installed profile matches shipped defaults (version %s).\n",
			product, ShippedDefaultsVersion)
	}
	var b strings.Builder
	fmt.Fprintf(&b,
		"%s: profile doctor — your installed profile is missing %d field(s) "+
			"that ship in this version (defaults version %s):\n\n",
		product, len(r.MissingFields), ShippedDefaultsVersion)
	for _, gap := range r.MissingFields {
		fmt.Fprintf(&b, "  - profile=%s field=%s\n", gap.ProfileName, gap.Field)
		fmt.Fprintf(&b, "    category:   %s\n", gap.Category)
		fmt.Fprintf(&b, "    why:        %s\n", gap.WhyMatters)
		fmt.Fprintf(&b, "    added in:   %s\n", gap.AddedIn)
		fmt.Fprintf(&b, "    default:    %v\n\n", gap.DefaultValue)
	}
	fmt.Fprintf(&b, "To accept the new defaults: %s profile doctor --apply\n", product)
	fmt.Fprintf(&b, "To suppress this warning:   %s profile doctor --acknowledge\n", product)
	return b.String()
}

// StartupBannerLine returns the one-line caveat the bouncer's `run`
// command emits at startup when the installed profile is missing a
// safety-floor field AND the operator hasn't acknowledged the
// current shipped-defaults version.
//
// Framing per [[security-team-positioning-safety-not-surveillance]]:
// "your profile is behind" — NOT "you are non-compliant."
func StartupBannerLine(product string, profilesPath string) string {
	if profilesPath == "" {
		return ""
	}
	if IsAcknowledged(profilesPath) {
		return ""
	}
	rep, err := Check(profilesPath)
	if err != nil {
		return ""
	}
	if !rep.HasSafetyFloorGap() {
		return ""
	}
	return fmt.Sprintf(
		"caveat: your safe-default profile is missing fields shipped in "+
			"this version — run `%s profile doctor` for details "+
			"(KNOWN-CAVEATS §A19)",
		product)
}
