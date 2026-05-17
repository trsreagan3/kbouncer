// Package profile implements environment-aware kbounce profiles.
//
// A profile is a named, switchable rule layer that adds environment-aware
// keyword denies on top of the existing per-task scope and global rule
// engine. When active, a profile's denies are a HARD FLOOR — they fire
// even if a task scope or global rule would have allowed the call. This
// is the property SecOps teams need to approve the install: "if I say
// 'readonly', the agent CAN NOT mutate anything regardless of which
// other rules are loaded."
//
// Profiles are symmetric across kbounce (this package) and the Python
// iam-jit-bouncer; the YAML schema is intentionally identical so an
// operator who reads one understands the other.
//
// Composition order (LOAD-BEARING — do not reorder):
//
//  1. Profile deny_keywords match (and not in exceptions) → DENY (source=profile)
//  2. Profile only_clusters mismatch                       → DENY (source=profile)
//  3. Profile deny_verbs match                             → DENY (source=profile)
//  4. Active task-scope deny                               → DENY (source=task)
//  5. Active task-scope allow                              → ALLOW (source=task)
//  6. Global rules                                         → standard match flow
//
// Profile rules fire BEFORE task / global rules. A permissive task scope
// CANNOT override a profile deny. See [[safety-mode-two-modes]] and
// [[safety-mode-lean-permissive]] in the product memory.
//
// Embedded default profiles (only two, intentionally):
//
//   - full-user — passthrough sentinel (zero rules). Default when no
//     --profile / KBOUNCER_PROFILE is selected.
//   - readonly  — blocks write + destructive verbs (delete, patch,
//     create, update, deletecollection, exec, portforward, attach).
//     General-purpose safety net; works in any environment.
//
// Backward-compat aliases (mapped to new names at lookup; deprecation-
// warned in v1.0, removed in v1.1):
//
//   - "none"          → "full-user"
//   - "prod-readonly" → "readonly"
//
// Other environment-specific profiles (staging-work, dev-only,
// incident-response) ship in the kbounce repo's `community-profiles/`
// directory and install via `kbounce profile install --from URL`.
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// KeywordMatchMode controls how deny_keywords are compared to the
// candidate strings (resource name, namespace, cluster, etc.).
type KeywordMatchMode string

const (
	// MatchWordBoundary uses `\bkeyword\b` (case-insensitive). The default.
	// "prod" matches "prod-cluster" and "cluster-prod" but NOT "productivity".
	// Recommended for most teams — fewer false positives.
	MatchWordBoundary KeywordMatchMode = "word_boundary"

	// MatchSubstring uses raw substring containment (case-insensitive).
	// "prod" matches "productivity" too. Easier to bypass; useful for
	// stricter ops teams that accept the false-positive rate.
	MatchSubstring KeywordMatchMode = "substring"
)

// IsValid returns true for known match modes.
func (m KeywordMatchMode) IsValid() bool {
	switch m {
	case MatchWordBoundary, MatchSubstring:
		return true
	}
	return false
}

// KeywordTarget names a field on the parsed request that deny_keywords
// are compared against. Multiple targets compose with OR — a match on
// any one fires the deny.
type KeywordTarget string

const (
	// TargetResourceName compares against the K8s resource name (pod name,
	// deployment name, configmap name, ...).
	TargetResourceName KeywordTarget = "resource_name"

	// TargetNamespace compares against the K8s namespace.
	TargetNamespace KeywordTarget = "namespace"

	// TargetCluster compares against the cluster the proxy is wired to.
	// (Pulled from ParsedRequest.Cluster; the proxy populates this from
	// the active kubeconfig context when one is set.)
	TargetCluster KeywordTarget = "cluster"
)

// IsValid returns true for known keyword targets.
func (t KeywordTarget) IsValid() bool {
	switch t {
	case TargetResourceName, TargetNamespace, TargetCluster:
		return true
	}
	return false
}

// ParsedRequest is the minimal view of a kube-apiserver request that
// profile evaluation needs. The proxy populates it from its own
// parser.ParsedRequest; we keep it local to this package so the profile
// engine can be unit-tested without dragging in the proxy / parser.
//
// Symmetric to the Python iam-jit-bouncer's ParsedRequest fields used
// by profile evaluation — keep this struct in sync if you grow either.
type ParsedRequest struct {
	// Verb is the K8s-canonical verb (get, list, watch, create, update,
	// patch, delete, deletecollection) or the subresource name when the
	// URL targets a subresource (exec, log, ...).
	Verb string

	// Namespace is the namespace from the URL or "" for cluster-scoped.
	Namespace string

	// ResourceName is the named object the URL targets, or "" for
	// collection-level operations.
	ResourceName string

	// Cluster is the active kubeconfig cluster name when the proxy can
	// determine it; "" otherwise. Used for only_clusters matching and
	// for the "cluster" keyword target.
	Cluster string
}

// ProfileAllowRule is one allow rule embedded in a profile. Profile-
// scoped allow rules are merged into the rule engine ALONGSIDE global
// rules when the profile is active; they do NOT short-circuit profile
// deny layers above. Shape mirrors the iam-jit-bouncer Python
// ProfileAllowRule so YAML profiles round-trip across both products.
//
// kbouncer does not yet consume AllowRules in the evaluator (K-Slice 7
// is deny-only); the field is parsed + serialized so YAML written by
// the Python bouncer (or a future kbouncer slice) survives the round
// trip. Adding the field now keeps the on-disk shape stable.
type ProfileAllowRule struct {
	// Pattern is the verb/resource pattern (kbouncer convention TBD;
	// kept opaque for now so symmetric YAML loads cleanly).
	Pattern string `yaml:"pattern"`

	// ArnScope (Python-side) / cluster or namespace scope (K8s-side).
	// Kept named after the AWS shape so profile YAML round-trips; a
	// future K-Slice may rename for K8s semantics with a YAML alias.
	ArnScope string `yaml:"arn_scope,omitempty"`

	// RegionScope is the AWS-side region scope; harmless on the K8s
	// side, preserved for round-trip.
	RegionScope string `yaml:"region_scope,omitempty"`

	// Note is an operator-readable description of why this rule exists.
	Note string `yaml:"note,omitempty"`
}

// Profile is one named environment profile.
type Profile struct {
	// Name is the YAML key, set by LoadProfiles after parsing.
	Name string `yaml:"-"`

	// Description is the human-readable summary shown by `profile list`
	// and surfaced in audit reasons. Optional.
	Description string `yaml:"description,omitempty"`

	// DenyKeywords are case-insensitive tokens that, if matched against
	// any of KeywordTargets on the parsed request and NOT present in
	// Exceptions, cause a deny.
	DenyKeywords []string `yaml:"deny_keywords,omitempty"`

	// KeywordTargets selects which request fields DenyKeywords compare
	// against. Defaults to [resource_name, namespace] when unset.
	KeywordTargets []KeywordTarget `yaml:"keyword_targets,omitempty"`

	// KeywordMatch picks the comparison mode. Defaults to MatchWordBoundary
	// when unset.
	KeywordMatch KeywordMatchMode `yaml:"keyword_match,omitempty"`

	// OnlyClusters, when non-empty, hard-restricts the profile to only
	// fire allows for requests whose Cluster is in this list. Requests
	// against any other cluster are denied with source=profile.
	OnlyClusters []string `yaml:"only_clusters,omitempty"`

	// DenyVerbs are K8s verbs that, if matched (case-insensitive) against
	// the parsed request's Verb, cause a deny. Useful for "read-only"
	// profiles (deny delete/patch/create/update).
	DenyVerbs []string `yaml:"deny_verbs,omitempty"`

	// Exceptions is a false-positive allowlist. If any exception string
	// appears as a substring of any keyword target field, the keyword
	// deny is suppressed (only_clusters / deny_verbs are NOT suppressed).
	Exceptions []string `yaml:"exceptions,omitempty"`

	// AllowRules are profile-scoped allow rules. Parsed + serialized for
	// round-trip with the Python bouncer's profile shape. Not yet
	// consumed by the kbouncer evaluator (K-Slice 7 is deny-only).
	AllowRules []ProfileAllowRule `yaml:"allow_rules,omitempty"`

	// Source records provenance. Empty or "local" → user-edited.
	// A URL (set by `profile install --from URL`) → org-distributed,
	// READ-ONLY at the CLI surface (UpsertProfile refuses to overwrite
	// a non-local source). Mirrors the iam-jit-bouncer Python field
	// of the same name so the enterprise-profile-distribution memo's
	// invariants hold in both products.
	Source string `yaml:"source,omitempty"`

	// compiledKeywords holds pre-compiled regexes for word_boundary mode.
	// Built lazily on first Evaluate via compileOnce; safe for concurrent
	// callers thereafter.
	compiledKeywords []*regexp.Regexp
	compileOnce      sync.Once
	compileErr       error
}

// IsLocalSource reports whether the profile is editable at the CLI
// surface (i.e., it was not installed from an org URL). The empty
// string and "local" both count as local — the embedded defaults
// don't set Source, and the Python implementation defaults to "local"
// when the YAML omits the field.
func (p *Profile) IsLocalSource() bool {
	if p == nil {
		return true
	}
	return p.Source == "" || p.Source == "local"
}

// Profiles is a loaded collection of named profiles plus metadata.
type Profiles struct {
	// Path is the on-disk YAML the profiles were loaded from, or "" when
	// loaded from defaults / in-memory.
	Path string

	// All is the name → Profile map. The reserved name "none" is always
	// present; LoadProfiles ensures this.
	All map[string]*Profile
}

// Verdict is what Evaluate returns. When Denied is true, the proxy
// short-circuits to a 403 with Source / Reason carried into the audit log.
type Verdict struct {
	// Denied is true when the profile blocks the request. False does
	// NOT mean "allow" — it means "profile abstains; defer to the rest
	// of the rule engine".
	Denied bool

	// Reason is a one-line audit-log-ready description, e.g.
	// "profile staging-work: namespace 'prod-app' matched keyword 'prod'".
	Reason string

	// Source is the rule layer that produced the verdict. Always "profile"
	// when this package returns Denied=true. Kept on the verdict so the
	// proxy's decision_source column stays self-describing.
	Source string

	// ProfileName is the name of the profile that fired, useful for
	// metrics + UI surfaces.
	ProfileName string
}

// SourceProfile is the decision_source value the proxy records when a
// profile deny fires. Exported so the proxy package can compare without
// repeating the string literal.
const SourceProfile = "profile"

// FullUserProfileName is the reserved profile name that disables profile
// rules entirely. Always present in Profiles.All. Renamed from "none"
// in the 2026-05-17 default-profile reshape — see [[bounce-suite-rename]]
// and [[bounce-default-profile-pattern]] in the product memory.
const FullUserProfileName = "full-user"

// NoneProfileName is the legacy alias for FullUserProfileName. Kept for
// backward-compat at the lookup surface (resolveProfileAlias). v1.1
// removes the alias.
//
// Deprecated: use FullUserProfileName.
const NoneProfileName = "none"

// ReadonlyProfileName is the reserved profile name for the general-
// purpose read-only safety net. Renamed from "prod-readonly" in the
// 2026-05-17 default-profile reshape (the rule set isn't prod-specific —
// it's "block write + destructive verbs in ANY environment").
const ReadonlyProfileName = "readonly"

// profileAliases maps legacy profile names to their canonical
// replacement. Lookups that hit an alias emit a one-shot deprecation
// warning + transparently resolve to the canonical name. v1.1 removes
// this map.
var profileAliases = map[string]string{
	"none":          FullUserProfileName,
	"prod-readonly": ReadonlyProfileName,
}

// resolveProfileAlias returns the canonical profile name for an alias,
// plus a bool indicating whether the input was an alias. Used by
// Profiles.Active so unknown-name errors print the canonical names but
// legacy invocations still succeed.
func resolveProfileAlias(name string) (string, bool) {
	if canonical, ok := profileAliases[name]; ok {
		return canonical, true
	}
	return name, false
}

// ErrUnknownProfile is returned by Profiles.Active when the requested
// name is not in the loaded set. Kept distinct from a YAML parse error
// so the CLI can give a different message ("did you mean 'readonly'?").
var ErrUnknownProfile = errors.New("kbounce: unknown profile")

// ErrInvalidProfile is returned by LoadProfiles when a profile's fields
// are internally inconsistent (e.g. unknown keyword target).
var ErrInvalidProfile = errors.New("kbounce: invalid profile")

// profileFile is the on-disk YAML shape; private because callers see
// Profiles, not the raw file struct.
type profileFile struct {
	Profiles map[string]*Profile `yaml:"profiles"`
}

// LoadProfiles reads profiles.yaml from path and returns the parsed
// collection. If path is "" or the file doesn't exist, the embedded
// default profiles are returned (with Profiles.Path = "" so the caller
// knows nothing was on disk).
//
// The "none" profile is always synthesized into the result even if the
// YAML omits it, so callers can always look it up.
func LoadProfiles(path string) (*Profiles, error) {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err == nil {
			return parseProfiles(raw, path)
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("kbounce: read profiles %q: %w", path, err)
		}
		// File missing → fall through to defaults. Don't error: kbouncer
		// runs without a profile file just fine (no profile is selected
		// until --profile or KBOUNCER_PROFILE picks one).
	}
	return parseProfiles(DefaultProfilesYAML(), "")
}

// parseProfiles is the shared YAML→Profiles deserializer used by both
// LoadProfiles and the in-memory default loader.
func parseProfiles(raw []byte, path string) (*Profiles, error) {
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("kbounce: parse profiles yaml: %w", err)
	}
	if pf.Profiles == nil {
		pf.Profiles = map[string]*Profile{}
	}
	for name, p := range pf.Profiles {
		if p == nil {
			// Allow `staging-work:` with empty body — synthesize an empty
			// profile so name lookup doesn't NPE downstream.
			p = &Profile{}
			pf.Profiles[name] = p
		}
		p.Name = name
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidProfile, name, err)
		}
	}
	// Always make "full-user" addressable, even if the YAML doesn't define
	// it. "full-user" is a hard-coded sentinel: zero rules of its own,
	// so it always abstains. Codifying it here means callers don't need
	// a special-case branch.
	if _, ok := pf.Profiles[FullUserProfileName]; !ok {
		pf.Profiles[FullUserProfileName] = &Profile{
			Name:        FullUserProfileName,
			Description: "No profile active; calls forwarded as-is + audit-logged. Default.",
		}
	}
	return &Profiles{Path: path, All: pf.Profiles}, nil
}

// validate checks for internal inconsistencies that should be reported at
// load time rather than discovered on the first matching request.
func (p *Profile) validate() error {
	if p.KeywordMatch != "" && !p.KeywordMatch.IsValid() {
		return fmt.Errorf("keyword_match %q is not one of: %s, %s",
			p.KeywordMatch, MatchWordBoundary, MatchSubstring)
	}
	for _, t := range p.KeywordTargets {
		if !t.IsValid() {
			return fmt.Errorf("keyword_targets contains unknown target %q (want resource_name, namespace, cluster)", t)
		}
	}
	return nil
}

// Active returns the named profile or ErrUnknownProfile. The lookup is
// strict: an unknown name surfaces an error rather than silently falling
// back to the default. Silent fallback hides typos and would let the
// operator think they're protected when they're not.
//
// Backward-compat: legacy profile names ("none", "prod-readonly")
// resolve to their canonical replacements ("full-user", "readonly")
// with a one-line deprecation notice printed to stderr. v1.1 removes
// the alias path entirely. End-user invocations are the only consumers
// of aliases; internal callers use the canonical names directly.
func (ps *Profiles) Active(name string) (*Profile, error) {
	if ps == nil {
		return nil, ErrUnknownProfile
	}
	if name == "" {
		// Empty string == no profile selected. The CLI handles this by
		// returning the "full-user" profile so the proxy's evaluate
		// path always has a non-nil profile to call.
		return ps.All[FullUserProfileName], nil
	}
	canonical, wasAlias := resolveProfileAlias(name)
	if wasAlias {
		fmt.Fprintf(os.Stderr,
			"kbounce: profile name %q is deprecated; use %q. "+
				"Aliases remain in v1.0 + are removed in v1.1.\n",
			name, canonical)
	}
	p, ok := ps.All[canonical]
	if !ok {
		return nil, fmt.Errorf("%w: %q (loaded: %s)", ErrUnknownProfile, name, ps.NamesSorted())
	}
	return p, nil
}

// NamesSorted returns the loaded profile names in lexical order. Used
// by the `profile list` CLI subcommand and by error messages.
func (ps *Profiles) NamesSorted() []string {
	if ps == nil {
		return nil
	}
	out := make([]string, 0, len(ps.All))
	for name := range ps.All {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Evaluate runs profile rules in the documented composition order and
// returns the verdict. A nil receiver, the "full-user" profile, or a
// profile with zero rules returns Denied=false (abstain).
//
// The function is pure: no I/O, no audit-store writes. The caller (proxy)
// is responsible for recording the verdict + carrying Source / Reason
// into the audit row.
func (p *Profile) Evaluate(req *ParsedRequest) Verdict {
	if p == nil || p.Name == FullUserProfileName || req == nil {
		return Verdict{}
	}

	// Order 1: deny_keywords (with exceptions allowlist).
	if len(p.DenyKeywords) > 0 {
		mode := p.KeywordMatch
		if mode == "" {
			mode = MatchWordBoundary
		}
		targets := p.KeywordTargets
		if len(targets) == 0 {
			// Sensible default: most useful keyword targets for K8s.
			targets = []KeywordTarget{TargetResourceName, TargetNamespace}
		}
		candidates := collectCandidates(req, targets)
		if p.matchesAnyException(candidates) {
			// Exception suppresses keyword denies but NOT only_clusters
			// or deny_verbs — those represent harder operator intent.
			// Fall through to the next rule class.
		} else if matched, keyword, field := p.matchKeywords(candidates, mode); matched {
			return Verdict{
				Denied:      true,
				Reason:      fmt.Sprintf("profile %q: %s %q matched keyword %q", p.Name, field, candidates[field], keyword),
				Source:      SourceProfile,
				ProfileName: p.Name,
			}
		}
	}

	// Order 2: only_clusters mismatch.
	if len(p.OnlyClusters) > 0 {
		if !containsFold(p.OnlyClusters, req.Cluster) {
			cl := req.Cluster
			if cl == "" {
				cl = "<unset>"
			}
			return Verdict{
				Denied:      true,
				Reason:      fmt.Sprintf("profile %q: cluster %q not in only_clusters %v", p.Name, cl, p.OnlyClusters),
				Source:      SourceProfile,
				ProfileName: p.Name,
			}
		}
	}

	// Order 3: deny_verbs match.
	if len(p.DenyVerbs) > 0 && req.Verb != "" {
		if containsFold(p.DenyVerbs, req.Verb) {
			return Verdict{
				Denied:      true,
				Reason:      fmt.Sprintf("profile %q: verb %q in deny_verbs", p.Name, req.Verb),
				Source:      SourceProfile,
				ProfileName: p.Name,
			}
		}
	}

	// No profile rule fired; defer to the next layer.
	return Verdict{}
}

// collectCandidates pulls the candidate strings for the configured
// targets. Returns a map field-name → value so the audit reason can name
// which field matched.
func collectCandidates(req *ParsedRequest, targets []KeywordTarget) map[KeywordTarget]string {
	out := make(map[KeywordTarget]string, len(targets))
	for _, t := range targets {
		switch t {
		case TargetResourceName:
			out[t] = req.ResourceName
		case TargetNamespace:
			out[t] = req.Namespace
		case TargetCluster:
			out[t] = req.Cluster
		}
	}
	return out
}

// matchesAnyException returns true if any exception is a substring (case-
// insensitive) of any candidate value. Exceptions are intentionally
// substring (not word-boundary) so an operator can paste a partial team
// name like "eng-productivity" and have it cover both
// "eng-productivity-tooling" and "eng-productivity-ci".
func (p *Profile) matchesAnyException(candidates map[KeywordTarget]string) bool {
	if len(p.Exceptions) == 0 {
		return false
	}
	for _, val := range candidates {
		if val == "" {
			continue
		}
		lv := strings.ToLower(val)
		for _, ex := range p.Exceptions {
			if ex == "" {
				continue
			}
			if strings.Contains(lv, strings.ToLower(ex)) {
				return true
			}
		}
	}
	return false
}

// matchKeywords returns the first keyword + field that fires a deny. The
// returned field is the KeywordTarget name (resource_name / namespace /
// cluster) so the audit reason can name it directly.
func (p *Profile) matchKeywords(candidates map[KeywordTarget]string, mode KeywordMatchMode) (bool, string, KeywordTarget) {
	// Build a stable iteration order for fields so the audit reason is
	// deterministic across runs (Go map iteration is randomized).
	fields := make([]KeywordTarget, 0, len(candidates))
	for f := range candidates {
		fields = append(fields, f)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i] < fields[j] })

	if mode == MatchWordBoundary {
		p.compileOnce.Do(func() {
			p.compiledKeywords = make([]*regexp.Regexp, 0, len(p.DenyKeywords))
			for _, kw := range p.DenyKeywords {
				if kw == "" {
					p.compiledKeywords = append(p.compiledKeywords, nil)
					continue
				}
				// HIGH-33-01 closure: cross-product semantic parity.
				// Python's iam-jit-bouncer uses [^A-Za-z0-9] as the
				// boundary class, which treats underscore as a
				// separator. Go's \b uses \w which INCLUDES
				// underscore, so the same YAML matched differently
				// across products: `prod` would match `prod_cluster`
				// in iam-jit but NOT in kbouncer. Operators who
				// shared profiles across both bouncers got silent
				// gaps in their guardrails.
				//
				// Aligning to Python's behavior — underscore IS a
				// boundary — because that matches operator intent:
				// `prod_cluster` is meant to be caught as "prod"
				// material. Both products now use the same regex
				// shape: (?i)(?:^|[^A-Za-z0-9])KW(?:$|[^A-Za-z0-9]).
				pat := `(?i)(?:^|[^A-Za-z0-9])` +
					regexp.QuoteMeta(kw) +
					`(?:$|[^A-Za-z0-9])`
				re, err := regexp.Compile(pat)
				if err != nil {
					p.compileErr = err
					p.compiledKeywords = append(p.compiledKeywords, nil)
					continue
				}
				p.compiledKeywords = append(p.compiledKeywords, re)
			}
		})
		for _, f := range fields {
			val := candidates[f]
			if val == "" {
				continue
			}
			for i, re := range p.compiledKeywords {
				if re == nil {
					continue
				}
				if re.MatchString(val) {
					return true, p.DenyKeywords[i], f
				}
			}
		}
		return false, "", ""
	}

	// MatchSubstring (case-insensitive contains).
	for _, f := range fields {
		val := candidates[f]
		if val == "" {
			continue
		}
		lv := strings.ToLower(val)
		for _, kw := range p.DenyKeywords {
			if kw == "" {
				continue
			}
			if strings.Contains(lv, strings.ToLower(kw)) {
				return true, kw, f
			}
		}
	}
	return false, "", ""
}

// containsFold reports whether s appears in list under case-insensitive
// equality. Used for only_clusters + deny_verbs which both want exact
// (not substring) matching but tolerant of casing.
func containsFold(list []string, s string) bool {
	if s == "" {
		return false
	}
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// DefaultProfilesPath returns ~/.kbouncer/profiles.yaml or honors
// KBOUNCER_PROFILES_PATH if set. Test sandboxes can point KBOUNCER_PROFILES_PATH
// at a tempdir so they don't write to a developer's home directory.
func DefaultProfilesPath() (string, error) {
	if override := os.Getenv("KBOUNCER_PROFILES_PATH"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("kbounce: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".kbouncer", "profiles.yaml"), nil
}

// EnsureDefaultProfilesFile writes the embedded default profiles YAML to
// path if and only if path doesn't already exist. Returns (written, error)
// where written=true when a new file was created. Parent directory is
// created with 0o700 so the file (which may contain operator team names)
// stays private.
//
// The CLI calls this at `init` time and at the start of every `run` so
// fresh installs always have something to point --profile at; existing
// files are NEVER overwritten (operator edits must survive).
func EnsureDefaultProfilesFile(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("kbounce: stat profiles %q: %w", path, err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("kbounce: mkdir %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, DefaultProfilesYAML(), 0o600); err != nil {
		return false, fmt.Errorf("kbounce: write profiles %q: %w", path, err)
	}
	return true, nil
}
