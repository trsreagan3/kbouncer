// loader.go — read + validate + filter `~/.iam-jit/dynamic-denies.yaml`
// against the v1.0 schema, returning only the rules whose `applied_to`
// includes `kbouncer`. The cross-product resolver lives in #324e; this
// loader is the read-side consumer.
//
// We deliberately do NOT pull a runtime jsonschema library — the schema
// shape is small + stable + the validation logic here is straight-line
// code. Mirrors the gbounce #324d loader byte-for-byte so the
// cross-product wire-shape stays identical per
// `[[cross-product-agent-parity]]`.
//
// On parse error the caller decides what to do — typically:
//   - First load (no prior snapshot): return error; banner says
//     `dynamic-denies: 0 rules (parse error: ...)`.
//   - Subsequent reload (we have a prior snapshot): keep the prior
//     snapshot + emit an admin-action OCSF event with
//     reason="parse_error". Per [[ibounce-honest-positioning]] we
//     fail-CLOSED here — never silently dropping rules.

package dynamicdeny

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPathEnv is the env-var name that overrides the default file
// path. Mirrors the iam-jit-wide IAM_JIT_* env-var convention from
// `[[enterprise-profile-distribution]]`.
const DefaultPathEnv = "IAM_JIT_DYNAMIC_DENIES_PATH"

// DefaultRelPath is the default path under the operator's home dir.
// `~` is resolved at lookup time via os.UserHomeDir.
const DefaultRelPath = ".iam-jit/dynamic-denies.yaml"

// BouncerName is the value the loader matches in each rule's
// `applied_to` list. Pinned here so a typo in the rest of the package
// shows up as a compile error. The cross-product resolver (#324e)
// emits the lowercase product token `kbouncer`.
const BouncerName = "kbouncer"

// SchemaVersion is the on-disk schema version this loader accepts.
// A future bump migrates here per the cross-product convention.
const SchemaVersion = "1.0"

// ProductMagic is the on-disk `product` discriminator. Matches
// `docs/schemas/dynamic-denies-v1.json::product.const`.
const ProductMagic = "iam-jit-dynamic-denies"

// ruleIDPattern matches the on-disk `dd_<ULID>` shape. ULIDs are 26
// chars of Crockford base32 (rejects I/L/O/U to avoid digit confusion).
var ruleIDPattern = regexp.MustCompile(`^dd_[0-9A-HJKMNP-TV-Z]{26}$`)

// durationPattern matches `permanent` OR `N{s,m,h,d,w}` (one or more
// digits + a single unit suffix).
var durationPattern = regexp.MustCompile(`^(permanent|[0-9]+(s|m|h|d|w))$`)

// validBouncers is the set of strings allowed inside a rule's
// `applied_to` list. The cross-product spec uses both `kbouncer`
// (the proxy product token) and the historical `kbounce` alias —
// accept both on read so a hand-edited file stays compatible.
var validBouncers = map[string]struct{}{
	"ibounce":  {},
	"kbounce":  {},
	"kbouncer": {},
	"dbounce":  {},
	"gbounce":  {},
}

// hostPattern validates the post-prefix body of namespace + cluster
// patterns. Same permissive shape as kube-apiserver names: lowercase
// alphanumeric + `-` + `.` (for FQDN-style cluster identifiers
// derived from kubeconfig cluster.server URLs).
var hostPattern = regexp.MustCompile(`^[a-z0-9.\-]+$`)

// resourceTriplePattern validates the `<group>/<version>/<resource>`
// shape. `group` is `core` for the K8s core API; `version` is `v1`
// or `v1beta1`; `resource` is lowercase plural. The compiler
// normalizes the triple at parse time so the matcher hot-path skips
// the split.
var resourceTriplePattern = regexp.MustCompile(
	`^[a-z][a-z0-9.\-]*\/[a-z0-9]+\/[a-z0-9.\-]+$`)

// ResolveDefaultPath returns the loader's default file path, honoring
// the IAM_JIT_DYNAMIC_DENIES_PATH env var. Returns an empty string
// when the home dir cannot be resolved (the caller surfaces the error
// + falls back to "no dynamic-denies file configured").
func ResolveDefaultPath() string {
	if env := strings.TrimSpace(os.Getenv(DefaultPathEnv)); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, DefaultRelPath)
}

// LoadFile reads + validates + filters the file at `path`. Returns:
//
//   - On a missing file: returns (Empty(), nil). The watcher waits for
//     the file to appear; this is NOT an error condition (an operator
//     who hasn't installed any dynamic denies still wants the proxy to
//     start cleanly).
//   - On a parse / schema / structural error: returns (Empty(), err).
//     Caller policy is "fail-closed; retain previous snapshot."
//   - On success: returns (RuleSet, nil) where RuleSet.Rules is filtered
//     to those whose `applied_to` includes `"kbouncer"` AND that
//     haven't already expired at the wall-clock the loader runs at.
func LoadFile(path string) (*RuleSet, error) {
	if path == "" {
		return Empty(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Honest no-file shape — the watcher waits for the file to
			// appear; the proxy starts up with zero dynamic rules.
			rs := Empty()
			rs.SourcePath = path
			rs.LoadedAt = time.Now().UTC()
			return rs, nil
		}
		return Empty(), fmt.Errorf("dynamic-denies: read %q: %w", path, err)
	}
	return parseAndFilter(raw, path)
}

// LoadBytes is the test-time entry point. Same shape as LoadFile but
// reads from an in-memory byte slice — handy for the unit tests that
// don't want a real on-disk file.
func LoadBytes(raw []byte, path string) (*RuleSet, error) {
	return parseAndFilter(raw, path)
}

// parseAndFilter is the shared implementation behind LoadFile +
// LoadBytes. Validates the file shape against the v1.0 schema; returns
// a filtered RuleSet on success.
func parseAndFilter(raw []byte, path string) (*RuleSet, error) {
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Empty(), fmt.Errorf("dynamic-denies: parse %q: %w", path, err)
	}
	if err := validateFile(&f); err != nil {
		return Empty(), fmt.Errorf("dynamic-denies: validate %q: %w", path, err)
	}

	now := time.Now().UTC()
	out := &RuleSet{
		SourcePath: path,
		LoadedAt:   now,
	}
	for _, r := range f.Denies {
		if !appliesToKbouncer(r) {
			continue
		}
		// Drop already-expired rules at load time so the matcher never
		// sees them. The watcher schedules a reload at expiry time for
		// not-yet-expired rules (TODO in #324e/f — for now the watcher
		// only reacts to file changes, so a permanently-loaded
		// to-be-expired rule lingers until the next operator action.
		// This is fine for the operator-set ergonomics: durations are
		// usually short + bounded by the operator's incident window).
		if r.ExpiresAt != nil && !r.ExpiresAt.IsZero() && r.ExpiresAt.Before(now) {
			continue
		}
		out.Rules = append(out.Rules, r)
		// Compile each target into a Pattern. Targets whose shape
		// doesn't match any kbouncer-recognized pattern kind are
		// silently SKIPPED — the cross-product resolver (#324e) is
		// responsible for routing ARN / URL / hostname targets to the
		// right bouncer; an applied_to list that mistakenly names
		// kbouncer for an ARN target shouldn't take down the proxy.
		for _, t := range r.Targets {
			p, ok := compilePattern(t, r.ID, r.Reason)
			if !ok {
				continue
			}
			out.Patterns = append(out.Patterns, p)
		}
	}
	return out, nil
}

// compilePattern compiles one operator-written target into a Pattern.
// Returns (Pattern{}, false) for shapes kbouncer doesn't recognize.
// Recognized shapes:
//
//   - `namespace:<body>` — namespace pattern, body honors the simple
//     glob grammar (exact, `*.<suffix>`, `<prefix>-*`).
//   - `cluster:<body>`   — cluster pattern, same glob grammar.
//   - `<group>/<version>/<resource>` — exact resource triple. `core` is
//     a synonym for the empty group (K8s core API) and is normalized
//     to `core` at compile time so the matcher's input-side normalization
//     ("" → "core") consistently aligns.
func compilePattern(raw, ruleID, reason string) (Pattern, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Pattern{}, false
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "namespace:"):
		body := strings.TrimSpace(trimmed[len("namespace:"):])
		return compileSimplePattern(PatternKindNamespace, trimmed, body, ruleID, reason)
	case strings.HasPrefix(lower, "cluster:"):
		body := strings.TrimSpace(trimmed[len("cluster:"):])
		return compileSimplePattern(PatternKindCluster, trimmed, body, ruleID, reason)
	case resourceTriplePattern.MatchString(lower):
		parts := strings.Split(lower, "/")
		if len(parts) != 3 {
			return Pattern{}, false
		}
		group := parts[0]
		// Normalize the empty-group alias so `core/v1/secrets` matches
		// what the parser emits for `/api/v1/secrets` (parser sets
		// Group="" on the request side; the matcher canonicalizes to
		// "core" before comparing).
		return Pattern{
			Kind:     PatternKindResource,
			Raw:      trimmed,
			Body:     lower,
			Group:    group,
			Version:  parts[1],
			Resource: parts[2],
			RuleID:   ruleID,
			Reason:   reason,
		}, true
	default:
		return Pattern{}, false
	}
}

// compileSimplePattern compiles a namespace OR cluster pattern body
// into a Pattern. Glob shapes supported:
//
//   - exact: `prod`
//   - leading-`*.`: `*.prod` (matches `foo.prod` AND bare `prod`)
//   - trailing-`*`: `prod-*` (matches anything starting with `prod-`)
//
// Other glob shapes are rejected by returning false; the loader skips
// them silently (operator-friendly: don't reject the whole rule when
// one of N targets is shaped wrong, but DO log + skip).
func compileSimplePattern(kind PatternKind, raw, body, ruleID, reason string) (Pattern, bool) {
	body = strings.TrimSpace(body)
	if body == "" {
		return Pattern{}, false
	}
	lower := strings.ToLower(body)
	starCount := strings.Count(lower, "*")
	switch {
	case starCount == 0:
		if !hostPattern.MatchString(lower) {
			return Pattern{}, false
		}
		return Pattern{
			Kind:   kind,
			Raw:    raw,
			Body:   lower,
			RuleID: ruleID,
			Reason: reason,
		}, true
	case starCount == 1 && strings.HasPrefix(lower, "*."):
		suffix := strings.TrimPrefix(lower, "*.")
		if suffix == "" || !hostPattern.MatchString(suffix) {
			return Pattern{}, false
		}
		return Pattern{
			Kind:       kind,
			Raw:        raw,
			Body:       lower,
			IsGlob:     true,
			GlobSuffix: suffix,
			RuleID:     ruleID,
			Reason:     reason,
		}, true
	case starCount == 1 && strings.HasSuffix(lower, "*"):
		prefix := strings.TrimSuffix(lower, "*")
		if prefix == "" || !hostPattern.MatchString(prefix) {
			return Pattern{}, false
		}
		return Pattern{
			Kind:         kind,
			Raw:          raw,
			Body:         lower,
			IsPrefixGlob: true,
			GlobPrefix:   prefix,
			RuleID:       ruleID,
			Reason:       reason,
		}, true
	default:
		return Pattern{}, false
	}
}

// validateFile runs the shape checks the cross-product schema declares.
// Returned errors name the offending field + value so an operator
// debugging a parse rejection sees exactly what to fix.
func validateFile(f *File) error {
	if f.SchemaVersion == "" {
		return errors.New("missing required field `schema_version`")
	}
	if f.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q (this kbouncer build accepts %q only)", f.SchemaVersion, SchemaVersion)
	}
	// product field is optional in the schema (no `required`), but if
	// present it must match the magic discriminator so a misrouted
	// kbouncer-config.yaml gets refused.
	if f.Product != "" && f.Product != ProductMagic {
		return fmt.Errorf("unexpected `product` value %q (this loader accepts %q only)", f.Product, ProductMagic)
	}
	if f.Denies == nil {
		// Schema requires `denies`; treat nil as missing so an operator
		// with an empty list writes `denies: []` explicitly.
		return errors.New("missing required field `denies`")
	}
	seen := map[string]struct{}{}
	for i, r := range f.Denies {
		if err := validateRule(i, &r); err != nil {
			return err
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("rule[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return nil
}

func validateRule(idx int, r *Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule[%d]: missing required field `id`", idx)
	}
	if !ruleIDPattern.MatchString(r.ID) {
		return fmt.Errorf("rule[%d]: id %q does not match required `dd_<ULID>` shape", idx, r.ID)
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("rule[%d] %q: targets is required + must have >=1 entry", idx, r.ID)
	}
	for j, t := range r.Targets {
		if strings.TrimSpace(t) == "" {
			return fmt.Errorf("rule[%d] %q: targets[%d] is empty", idx, r.ID, j)
		}
	}
	if r.Reason == "" {
		return fmt.Errorf("rule[%d] %q: reason is required + must be non-empty", idx, r.ID)
	}
	if r.Duration == "" {
		return fmt.Errorf("rule[%d] %q: duration is required", idx, r.ID)
	}
	if !durationPattern.MatchString(r.Duration) {
		return fmt.Errorf("rule[%d] %q: duration %q does not match `permanent` or `N{s|m|h|d|w}`", idx, r.ID, r.Duration)
	}
	if r.AddedBy == "" {
		return fmt.Errorf("rule[%d] %q: added_by is required", idx, r.ID)
	}
	if r.AddedAt.IsZero() {
		return fmt.Errorf("rule[%d] %q: added_at is required", idx, r.ID)
	}
	if len(r.AppliedTo) == 0 {
		return fmt.Errorf("rule[%d] %q: applied_to is required + must have >=1 entry", idx, r.ID)
	}
	for j, b := range r.AppliedTo {
		if _, ok := validBouncers[b]; !ok {
			return fmt.Errorf("rule[%d] %q: applied_to[%d] %q is not a recognized bouncer name (expected one of ibounce/kbounce/kbouncer/dbounce/gbounce)", idx, r.ID, j, b)
		}
	}
	if r.Source != "" {
		switch r.Source {
		case "cli", "mcp", "org-distributed", "imported":
			// ok
		default:
			return fmt.Errorf("rule[%d] %q: source %q is not a recognized provenance (expected one of cli/mcp/org-distributed/imported)", idx, r.ID, r.Source)
		}
	}
	return nil
}

// appliesToKbouncer reports whether a rule's `applied_to` list contains
// the kbouncer bouncer name. The cross-product resolver uses the
// `kbouncer` token; we also accept the historical `kbounce` alias so a
// hand-edited file stays compatible.
func appliesToKbouncer(r Rule) bool {
	for _, b := range r.AppliedTo {
		if b == BouncerName || b == "kbounce" {
			return true
		}
	}
	return false
}
