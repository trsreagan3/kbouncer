// Package presets exposes the curated K8s starter-rule packs that
// ship with kbounce. Cross-product parity with iam-jit-bouncer's
// presets group (see [[cross-product-agent-parity]]): an agent that
// learned `ibounce presets list/show/apply` uses identical shapes on
// kbounce + dbounce.
//
// Per [[safe-default-is-readonly-admin-minus]]: presets are SEPARATE
// from the `safe-default` profile. The profile is a hard-floor deny
// layer that fires before global rules; a preset is a starter rule
// set the operator applies + customizes in the global rule table.
// They compose: profile denies still fire first.
//
// Per [[scorer-is-ground-truth]] + [[ibounce-honest-positioning]]:
// presets are deterministic, not LLM-generated. The pack the
// operator sees today is the pack they get next week — predictable,
// auditable, copy-pasteable into a profile bundle.
//
// Each preset ships as a YAML file under `presets/` at the repo
// root, embedded into the binary via `//go:embed` so a fresh install
// always has access to the full curated set even on an air-gapped
// machine.
package presets

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/kbouncer/internal/rules"
)

// presetsFS embeds the YAML files under `presets/` at the repo root.
// Stays in-binary so the operator doesn't have to ship the YAML
// alongside the kbounce binary. Add a new preset by dropping a YAML
// file in the repo's `presets/` directory + bumping the catalog
// count in the README + writing a test.
//
//go:embed all:files
var presetsFS embed.FS

// presetRule mirrors the on-disk YAML shape. Kept private — callers
// see []rules.ProxyRule which is the canonical engine type.
type presetRule struct {
	Pattern        string `yaml:"pattern"`
	Effect         string `yaml:"effect"`
	NamespaceScope string `yaml:"namespace_scope,omitempty"`
	ResourceScope  string `yaml:"resource_scope,omitempty"`
	VerbScope      string `yaml:"verb_scope,omitempty"`
	Note           string `yaml:"note,omitempty"`
}

// presetFile is the on-disk YAML body for ONE preset file. One preset
// per file (vs ibounce's presets-in-Python-dict) so contributors can
// add a preset via a single PR that touches one YAML — easier
// reviewable surface than a single large registry file.
type presetFile struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Rules       []presetRule `yaml:"rules"`
}

// Preset is one curated rule pack. Returned by Get / List as the
// public type; callers iterate Rules to apply / display.
type Preset struct {
	// Name is the operator-facing identifier passed to `presets show`
	// and `presets apply`. Stable across kbounce versions.
	Name string

	// Description is a one-paragraph human summary of when to use
	// this preset. Surfaced by `presets list` + `presets show`.
	Description string

	// Rules is the ordered rule list applied to the global rule table
	// on `presets apply`. Order matters: deny-beats-allow within a
	// match class, but BOTH classes evaluate first-match, so the
	// preset author's ordering becomes the operator's display order.
	Rules []rules.ProxyRule
}

// ToMap returns a JSON-friendly representation. Used by MCP +
// `presets show --json`.
func (p Preset) ToMap() map[string]any {
	out := make([]map[string]any, 0, len(p.Rules))
	for _, r := range p.Rules {
		out = append(out, r.ToMap())
	}
	return map[string]any{
		"name":        p.Name,
		"description": p.Description,
		"rule_count":  len(p.Rules),
		"rules":       out,
	}
}

var (
	loadOnce sync.Once
	loaded   map[string]Preset
	loadErr  error
)

// load reads every YAML under presets/ once + caches the result.
// Errors at startup surface via Get/List so the CLI prints a clear
// "preset catalog failed to load" instead of crashing.
func load() (map[string]Preset, error) {
	loadOnce.Do(func() {
		loaded = map[string]Preset{}
		entries, err := fs.ReadDir(presetsFS, "files")
		if err != nil {
			loadErr = fmt.Errorf("kbounce: read preset catalog: %w", err)
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			raw, rerr := fs.ReadFile(presetsFS, path.Join("files", e.Name()))
			if rerr != nil {
				loadErr = fmt.Errorf("kbounce: read preset %q: %w", e.Name(), rerr)
				return
			}
			var pf presetFile
			if uerr := yaml.Unmarshal(raw, &pf); uerr != nil {
				loadErr = fmt.Errorf("kbounce: parse preset %q: %w", e.Name(), uerr)
				return
			}
			if pf.Name == "" {
				loadErr = fmt.Errorf(
					"kbounce: preset %q missing required `name` field", e.Name())
				return
			}
			rs := make([]rules.ProxyRule, 0, len(pf.Rules))
			for i, r := range pf.Rules {
				if _, _, perr := rules.ParsePattern(r.Pattern); perr != nil {
					loadErr = fmt.Errorf(
						"kbounce: preset %q rule[%d] pattern %q invalid: %w",
						pf.Name, i, r.Pattern, perr)
					return
				}
				eff := rules.Effect(strings.ToLower(r.Effect))
				if eff == "" {
					eff = rules.EffectAllow
				}
				if !eff.IsValid() {
					loadErr = fmt.Errorf(
						"kbounce: preset %q rule[%d] effect %q must be allow|deny",
						pf.Name, i, r.Effect)
					return
				}
				rs = append(rs, rules.ProxyRule{
					Pattern:        r.Pattern,
					Effect:         eff,
					NamespaceScope: r.NamespaceScope,
					ResourceScope:  r.ResourceScope,
					VerbScope:      r.VerbScope,
					Note:           r.Note,
					Origin:         rules.OriginDefault,
				})
			}
			loaded[pf.Name] = Preset{
				Name:        pf.Name,
				Description: pf.Description,
				Rules:       rs,
			}
		}
	})
	return loaded, loadErr
}

// ErrUnknownPreset is returned by Get when the requested name is not
// in the embedded catalog.
var ErrUnknownPreset = errors.New("kbounce: unknown preset")

// List returns the loaded presets in lexical order. Empty result
// means the catalog failed to load — check the returned error.
func List() ([]Preset, error) {
	cat, err := load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cat))
	for n := range cat {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Preset, 0, len(names))
	for _, n := range names {
		out = append(out, cat[n])
	}
	return out, nil
}

// Get returns the named preset or ErrUnknownPreset.
func Get(name string) (Preset, error) {
	cat, err := load()
	if err != nil {
		return Preset{}, err
	}
	p, ok := cat[name]
	if !ok {
		return Preset{}, fmt.Errorf("%w: %q (available: %s)",
			ErrUnknownPreset, name, strings.Join(namesSorted(cat), ", "))
	}
	return p, nil
}

func namesSorted(cat map[string]Preset) []string {
	out := make([]string, 0, len(cat))
	for n := range cat {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
