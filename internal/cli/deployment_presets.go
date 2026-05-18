// Deployment presets — single-flag shortcuts for common kbounce
// deployment shapes.
//
// A deployment preset is a NAMED BUNDLE of run-command flag values.
// `kbounce run --preset security-observe` is equivalent to typing out
// the canonical 6-7 flags by hand; the preset just makes the common
// deployment one-flag for the operator (+ documents intent).
//
// Per [[cross-product-agent-parity]]: same preset NAMES + same
// HARD-vs-SOFT override semantics across ibounce / kbounce / dbounce /
// gbounce. The HARD flag for `security-observe` is `--mode` (the
// entire point of the preset is transparent); SOFT flags are the
// audit-export sinks + heartbeat cadence (operators have different
// SIEMs).
//
// Per [[security-team-positioning-safety-not-surveillance]]: preset
// descriptions use NEUTRAL language. No "violation" / "infraction" /
// "unauthorized" — these are observability tools.

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PresetOverridePolicy tags each preset value as HARD (operator
// passing the flag with a different value errors) or SOFT (operator's
// value wins; preset value is the default-only).
type PresetOverridePolicy string

const (
	PresetHard PresetOverridePolicy = "hard"
	PresetSoft PresetOverridePolicy = "soft"
)

// PresetValue is one named (flag → value, override-policy) entry in a
// deployment preset. We use string-valued representation for the wire
// format + parse to the typed value in the caller — keeps the preset
// table decoupled from Cobra flag types.
type PresetValue struct {
	Key      string // CLI flag name (e.g. "mode")
	Value    string // preset value as a string
	Policy   PresetOverridePolicy
	Skipped  bool   // banner annotation: product does not support this setting
	Override bool   // operator explicitly overrode (SOFT path)
}

// DeploymentPreset is a named bundle of run-command flag values.
type DeploymentPreset struct {
	Name        string
	Description string
	// Insertion order is preserved for stable banner output, so we
	// carry both a map (for lookups) + a slice (for order).
	Order  []string
	Values map[string]PresetValue
}

// DefaultAuditLogPath returns the per-product default JSONL audit-log
// path the security-observe preset uses when --audit-log-path is
// unset. Honors $XDG_STATE_HOME → $HOME/.kbouncer/audit/<product>.jsonl.
func DefaultAuditLogPath(product string) string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home := os.Getenv("HOME")
		if home == "" {
			home = "."
		}
		base = filepath.Join(home, ".kbouncer")
	}
	return filepath.Join(base, "audit", product+".jsonl")
}

// BuildSecurityObserve returns the canonical security-team observation
// preset. See docs/DEPLOYMENT-PRESETS.md for the framework + use case.
func BuildSecurityObserve(product string) DeploymentPreset {
	return DeploymentPreset{
		Name: "security-observe",
		Description: "security-team observation: transparent mode + JSONL audit + " +
			"alert rules (defaults) + 30s heartbeat. Designed for the 'gather " +
			"data first; author profile second' starting shape per " +
			"[[bouncer-mode-selection-for-agents]]. Use when the security team " +
			"is establishing a baseline of agent behavior before deciding " +
			"which calls to gate.",
		Order: []string{
			"mode",
			"default-policy",
			"audit-log-path",
			"alert-rules",
			"heartbeat-interval",
		},
		Values: map[string]PresetValue{
			// HARD: the whole point of this preset is transparent.
			"mode": {Key: "mode", Value: "transparent", Policy: PresetHard},
			// SOFT: transparent observation; do not surprise the
			// operator with denies on rules they have not yet authored.
			"default-policy": {Key: "default-policy", Value: "allow", Policy: PresetSoft},
			// SOFT: per-product default path. Operator points at their
			// own location.
			"audit-log-path": {
				Key: "audit-log-path", Value: DefaultAuditLogPath(product),
				Policy: PresetSoft,
			},
			// SOFT: built-in default alert rules. Operator may layer
			// their own YAML. Magic value "defaults" maps to the
			// "use all built-ins with default thresholds" path inside
			// buildAuditManager.
			"alert-rules": {Key: "alert-rules", Value: "defaults", Policy: PresetSoft},
			// SOFT: 30s heartbeat per #264 recommendation.
			"heartbeat-interval": {
				Key: "heartbeat-interval", Value: "30s",
				Policy: PresetSoft,
			},
		},
	}
}

// GetPreset returns the preset by name, or nil if unknown.
func GetPreset(name, product string) *DeploymentPreset {
	switch name {
	case "security-observe":
		p := BuildSecurityObserve(product)
		return &p
	}
	return nil
}

// ListPresetNames returns the v1.0 preset names.
func ListPresetNames() []string {
	return []string{"security-observe"}
}

// PresetOverrideError signals an operator passed both --preset NAME
// and an explicit flag whose value the preset marks HARD with a
// different value. Surface this to the operator with a "drop the
// preset OR drop the explicit flag" message.
type PresetOverrideError struct {
	Preset      string
	Flag        string
	PresetValue string
	GivenValue  string
}

func (e *PresetOverrideError) Error() string {
	return fmt.Sprintf(
		"--preset %s sets --%s=%q (HARD); cannot override with operator-supplied --%s=%q. "+
			"Either drop the --preset flag, OR drop the explicit --%s flag.",
		e.Preset, e.Flag, e.PresetValue, e.Flag, e.GivenValue, e.Flag,
	)
}

// PresetResolution is the output of ApplyPreset — the values the run
// command should use (after merging operator overrides) + the banner
// metadata.
type PresetResolution struct {
	// DerivedKeys lists preset values the run command will use as-is
	// (operator did not override). Stable order matches Preset.Order.
	DerivedKeys []string
	// SkippedKeys lists preset values the product does not support
	// (e.g. gbounce G-Slice 1 has no alert-rules engine). The banner
	// annotates these.
	SkippedKeys []string
	// OverriddenKeys lists SOFT-override keys where the operator's
	// value wins. The banner does NOT echo these (they're operator-
	// supplied, the operator knows they passed them).
	OverriddenKeys []string
}

// ApplyPreset resolves a preset against the operator-supplied flag
// set. It returns a PresetResolution describing which values came
// from the preset, which were skipped, and which were overridden. The
// caller is responsible for actually rebinding the flag variables —
// this function only computes the resolution.
//
// operatorChanged maps preset key → true when the operator explicitly
// passed the flag (Cobra's pflag.Flag.Changed). When the value
// matches the preset HARD value exactly, no error is raised (operator
// re-stated the preset's value redundantly; harmless).
//
// skipKeys is the set of preset keys the product does not support;
// they land in SkippedKeys for the banner.
//
// presetValues maps the operator's CURRENT value for each preset key
// (i.e. the operator-supplied value, OR the flag default if not set).
// We need this to compare against the preset's HARD value.
func ApplyPreset(
	preset *DeploymentPreset,
	operatorChanged map[string]bool,
	currentValues map[string]string,
	skipKeys map[string]bool,
) (*PresetResolution, error) {
	res := &PresetResolution{}
	for _, key := range preset.Order {
		pv := preset.Values[key]
		if skipKeys != nil && skipKeys[key] {
			res.SkippedKeys = append(res.SkippedKeys, key)
			continue
		}
		if operatorChanged[key] {
			// Operator explicitly passed the flag.
			given := currentValues[key]
			if pv.Policy == PresetHard && given != pv.Value {
				return nil, &PresetOverrideError{
					Preset:      preset.Name,
					Flag:        key,
					PresetValue: pv.Value,
					GivenValue:  given,
				}
			}
			// SOFT (or HARD with matching value) → operator wins.
			res.OverriddenKeys = append(res.OverriddenKeys, key)
			continue
		}
		// Operator did not set this flag; preset value applies.
		res.DerivedKeys = append(res.DerivedKeys, key)
	}
	return res, nil
}

// FormatBanner returns the stderr lines the run command prints to
// announce the active preset + which settings are derived from it.
// Format is identical across all four Bounce products per
// [[cross-product-agent-parity]].
func FormatBanner(preset *DeploymentPreset, res *PresetResolution) []string {
	lines := []string{fmt.Sprintf("deployment preset: %s", preset.Name)}
	for _, key := range preset.Order {
		// Only echo DERIVED keys (operator did not override). Skip
		// skipped (rendered separately) + overridden (operator knows).
		derived := false
		for _, dk := range res.DerivedKeys {
			if dk == key {
				derived = true
				break
			}
		}
		if !derived {
			continue
		}
		pv := preset.Values[key]
		lines = append(lines, fmt.Sprintf(
			"  --%s = %q (from preset; %s)",
			pv.Key, pv.Value, pv.Policy,
		))
	}
	for _, key := range preset.Order {
		skipped := false
		for _, sk := range res.SkippedKeys {
			if sk == key {
				skipped = true
				break
			}
		}
		if !skipped {
			continue
		}
		pv := preset.Values[key]
		lines = append(lines, fmt.Sprintf(
			"  --%s: not applicable to this product (preset value skipped)",
			pv.Key,
		))
	}
	return lines
}

// MustParseDuration is a helper for the run-command's preset
// resolution path; preset values are author-controlled string
// literals so any parse error is a programming bug.
func MustParseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(fmt.Sprintf("deployment preset: invalid duration literal %q: %v", s, err))
	}
	return d
}
