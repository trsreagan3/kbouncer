// Package profile — install.go
//
// `kbouncer profile install --from URL` support.
//
// Mirrors iam-jit-bouncer's `profile install` (Python) 1:1. The two
// products share the enterprise-profile-distribution shape: IT teams
// publish org-curated profiles at an HTTPS URL, engineers install
// them on day 1, and the installed profiles are read-only at the CLI
// surface so engineers can't quietly edit a deny rule out from under
// their security team.
//
// Read-only invariant:
//
//   - A profile whose Source field is non-empty and not "local" is
//     refused by UpsertProfile (the canonical write entry point used
//     by the recommender + future save-as-profile flows).
//   - `profile install` itself bypasses that check via the package-
//     private writeInstalledProfiles helper, because install IS the
//     authorized write path for non-local sources.
//   - The Source field is always FORCED to the fetch URL on install,
//     regardless of what the upstream YAML claims. A malicious
//     payload that includes `source: local` cannot escape the read-
//     only check.
//
// Security:
//
//   - HTTPS-only. An http:// URL is refused. Plaintext distribution
//     is MITM-substitutable; an attacker on the network path could
//     swap in a permissive profile and the engineer would never know.
//   - Optional --sha256 pin. IT teams should publish a sha256 in
//     onboarding docs so even a compromised distribution server
//     can't swap the file under them.
//   - All-or-nothing parse. If ANY profile in the payload fails
//     validation, none are written. Prevents a partial state where
//     half the org profiles are installed but the install LOOKED
//     like it errored.
//
// See [[enterprise-profile-distribution]] + [[creates-never-mutates]]
// in the product memory.

package profile

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/kbouncer/internal/audit"
)

// InstallExitCode is the exit code an `os.Exit` caller should use for
// install-specific failures. Mirrors the Python implementation:
//
//	2 → user / distribution error (http:// URL, sha256 mismatch,
//	    conflict without --force) — operator can fix + retry.
//	1 → server / payload error (fetch failed, malformed YAML, validation
//	    failed) — usually an upstream-curator problem.
//
// Codes are exposed as constants so the cmd/ package doesn't repeat
// the magic numbers (and so test assertions read like the Python
// tests for visual symmetry).
const (
	// InstallExitOK is returned on success.
	InstallExitOK = 0

	// InstallExitPayload is returned for payload / server problems:
	// fetch failed, YAML didn't parse, profiles object missing,
	// per-profile validation failed.
	InstallExitPayload = 1

	// InstallExitOperator is returned for operator-fixable problems:
	// http:// URL refused, sha256 mismatch, conflict without --force.
	InstallExitOperator = 2
)

// InstallError carries a structured exit code plus a human-readable
// message so the cmd/ package can map both onto stderr / os.Exit
// without re-parsing the message text.
type InstallError struct {
	ExitCode int
	Message  string
	// Underlying preserves the original error (fetch failure, YAML
	// parse error, etc.) for callers that want to chain via errors.Is
	// / errors.As. May be nil.
	Underlying error
}

// Error implements the error interface.
func (e *InstallError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Unwrap supports errors.Is / errors.As on the embedded cause.
func (e *InstallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Underlying
}

func installErr(code int, msg string) *InstallError {
	return &InstallError{ExitCode: code, Message: msg}
}

func installErrWrap(code int, msg string, cause error) *InstallError {
	return &InstallError{ExitCode: code, Message: msg, Underlying: cause}
}

// InstallOptions tunes a single `profile install` invocation.
//
// Defaults: Timeout=10s, ExpectedSHA256="", Force=false. HTTPClient
// is constructed on-demand by Install if nil — tests can inject one
// pointed at httptest.NewTLSServer to avoid real network.
type InstallOptions struct {
	// From is the HTTPS URL to fetch. Required. http:// is refused.
	From string

	// ExpectedSHA256, if non-empty, must equal the hex sha256 of the
	// fetched bytes. Case-insensitive; ":" separators are stripped so
	// `aa:bb:cc...` and `AABBCC...` both work.
	ExpectedSHA256 string

	// Force overrides the same-name-conflict refusal. Without Force,
	// install refuses if any payload profile shares a name with an
	// already-installed profile.
	Force bool

	// Timeout is the HTTPS fetch timeout. Zero → 10s default.
	Timeout time.Duration

	// HTTPClient is the client used to fetch From. Nil → a fresh
	// http.Client per call with the resolved Timeout. Tests pass a
	// client configured against httptest.NewTLSServer here so they
	// don't need real certs.
	HTTPClient *http.Client

	// ProfilesPath is the on-disk profiles.yaml to write. Empty →
	// resolve via DefaultProfilesPath (~/.kbouncer/profiles.yaml or
	// KBOUNCER_PROFILES_PATH env).
	ProfilesPath string

	// AuditEmitter, when non-nil, receives a synthetic
	// EventTypeProfileInstall event after a successful install. The
	// event carries the fetch URL + computed sha256 + installed
	// profile names so the Slice 2 non_org_profile_install rule fires
	// AT INSTALL TIME rather than waiting for the first proxied
	// decision under the installed profile to land. Nil disables the
	// emit (CLI default — `kbounce profile install` runs as a one-
	// shot command without an audit emitter; operators who want
	// install-time SIEM alerts wire one explicitly via the future
	// `--audit-log` flag on the install subcommand). Per
	// [[security-team-audit-export]] the synthetic event uses NEUTRAL
	// language + lands in the same JSONL log + HTTPS webhook the
	// per-decision events use, so a SIEM dashboard sees the install
	// as a first-class row.
	AuditEmitter audit.Emitter
}

// InstallResult summarizes a successful install. Returned by Install
// so the CLI layer can render the "installed N profile(s)" banner
// without re-fetching state.
type InstallResult struct {
	// SourceURL is the URL that was fetched (echoed back for the audit
	// trail).
	SourceURL string

	// ProfilesPath is the resolved on-disk path that was written.
	ProfilesPath string

	// InstalledNames are the names of the profiles that were written,
	// in payload order.
	InstalledNames []string

	// SHA256 is the hex sha256 of the fetched bytes. Always populated
	// so the CLI can echo it for audit purposes whether or not a pin
	// was supplied.
	SHA256 string

	// SHA256Verified is true when the caller supplied an ExpectedSHA256
	// that matched the computed hash.
	SHA256Verified bool
}

// Install fetches the URL, validates the payload, and writes the
// profiles to disk. All errors except success return an *InstallError
// with a populated ExitCode so the CLI can `os.Exit(err.ExitCode)`.
//
// The function is intentionally a pure orchestration over
// InstallFromBytes — splitting them lets tests cover the fetch path
// and the in-memory path independently.
func Install(ctx context.Context, opts InstallOptions) (*InstallResult, error) {
	if err := requireHTTPS(opts.From); err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, opts.From, nil)
	if err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("build fetch request: %v", err), err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("fetch failed: %v", err), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, installErr(InstallExitPayload,
			fmt.Sprintf("fetch failed: HTTP %d", resp.StatusCode))
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("fetch failed: read body: %v", err), err)
	}

	return InstallFromBytes(payload, opts)
}

// InstallFromBytes is the half of Install that operates on already-
// fetched bytes. Exported so tests + future programmatic callers can
// install from any byte source (e.g., a local file passed for offline
// installation) without going through the HTTPS fetch path.
//
// Even when called directly, the URL guard still applies — opts.From
// must be an https:// URL because the source is recorded on each
// profile and downstream consumers (UpsertProfile read-only check,
// `profile list` source column) expect a real URL. To install from a
// local file pass a custom HTTPClient with a file-scheme RoundTripper
// upstream; we intentionally do NOT add a file:// shortcut here, to
// keep the trust model "URL = remote-supplied = read-only" everywhere.
func InstallFromBytes(payload []byte, opts InstallOptions) (*InstallResult, error) {
	if err := requireHTTPS(opts.From); err != nil {
		return nil, err
	}

	sum := sha256.Sum256(payload)
	actualHex := hex.EncodeToString(sum[:])
	verified := false
	if opts.ExpectedSHA256 != "" {
		want := normalizeSHA256(opts.ExpectedSHA256)
		if want != actualHex {
			return nil, installErr(InstallExitOperator,
				fmt.Sprintf("sha256 mismatch:\n  expected: %s\n  actual:   %s\nrefusing to install.",
					want, actualHex))
		}
		verified = true
	}

	// Parse the YAML strictly into a generic map so we can detect
	// "missing profiles key" / "profiles is not a map" before we hand
	// off to the typed deserializer.
	var raw map[string]any
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("payload is not valid YAML: %v", err), err)
	}
	profilesAny, ok := raw["profiles"]
	if !ok {
		return nil, installErr(InstallExitPayload,
			"payload must contain a non-empty `profiles` object")
	}
	profilesMap, ok := profilesAny.(map[string]any)
	if !ok {
		return nil, installErr(InstallExitPayload,
			"payload must contain a non-empty `profiles` object")
	}
	if len(profilesMap) == 0 {
		return nil, installErr(InstallExitPayload,
			"payload must contain a non-empty `profiles` object")
	}

	// Parse each profile into a typed Profile via a roundtrip through
	// YAML so we get the same validation the loader applies (keyword
	// targets, keyword match mode, etc.). All-or-nothing: if ANY
	// profile fails validation, we error before writing anything.
	parsed, names, err := parseInstallPayload(profilesMap, opts.From)
	if err != nil {
		return nil, err
	}

	// Conflict check against existing on-disk profiles.
	resolvedPath := opts.ProfilesPath
	if resolvedPath == "" {
		rp, perr := DefaultProfilesPath()
		if perr != nil {
			return nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("resolve profiles path: %v", perr), perr)
		}
		resolvedPath = rp
	}
	existing, eerr := readProfilesFile(resolvedPath)
	if eerr != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("read existing profiles: %v", eerr), eerr)
	}
	var conflicts []conflictRow
	for _, name := range names {
		if prior, ok := existing[name]; ok {
			conflicts = append(conflicts, conflictRow{
				Name:        name,
				PriorSource: priorSourceLabel(prior),
			})
		}
	}
	if len(conflicts) > 0 && !opts.Force {
		var b strings.Builder
		b.WriteString("the following profiles already exist; pass --force to overwrite:\n")
		for _, c := range conflicts {
			fmt.Fprintf(&b, "  %s  (current source: %s)\n", c.Name, c.PriorSource)
		}
		return nil, installErr(InstallExitOperator, strings.TrimRight(b.String(), "\n"))
	}

	// Write. We bypass UpsertProfile's read-only check because the
	// install path IS the authorized write surface for non-local
	// sources; UpsertProfile gates the recommender's save-as-profile
	// flow, not this command.
	if err := writeInstalledProfiles(resolvedPath, parsed, names); err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("write profiles: %v", err), err)
	}

	// Emit the synthetic EventTypeProfileInstall event AFTER the
	// on-disk write succeeds so the audit trail reflects "the profile
	// was installed" rather than "we tried to install and may have
	// failed at the last step". The Slice 2 non_org_profile_install
	// rule picks this up at install-time when its approved-URL gate
	// rejects the source. No-op when AuditEmitter is nil (the CLI's
	// default — the `kbounce profile install` one-shot command runs
	// without an audit emitter unless the operator wires one
	// explicitly).
	audit.EmitProfileInstall(context.Background(), opts.AuditEmitter,
		names, opts.From, actualHex, verified)

	return &InstallResult{
		SourceURL:      opts.From,
		ProfilesPath:   resolvedPath,
		InstalledNames: names,
		SHA256:         actualHex,
		SHA256Verified: verified,
	}, nil
}

type conflictRow struct {
	Name        string
	PriorSource string
}

func priorSourceLabel(p *Profile) string {
	if p == nil {
		return "local"
	}
	if p.Source == "" {
		return "local"
	}
	return p.Source
}

// requireHTTPS refuses non-https URLs early so we don't even attempt
// the fetch. Empty / unparseable URLs are also refused for clarity.
func requireHTTPS(rawURL string) *InstallError {
	if rawURL == "" {
		return installErr(InstallExitOperator,
			"refusing to fetch: --from URL is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return installErrWrap(InstallExitOperator,
			fmt.Sprintf("refusing to fetch from %q: not a valid URL: %v", rawURL, err), err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return installErr(InstallExitOperator,
			fmt.Sprintf("refusing to fetch from %q: only https:// URLs are allowed "+
				"(MITM-substitutable plaintext is an attack vector against "+
				"IT-distributed profiles).", rawURL))
	}
	return nil
}

func normalizeSHA256(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.TrimSpace(s)
	return s
}

// parseInstallPayload validates every profile in the payload BEFORE
// returning. Returns the parsed Profile structs (with Source forced
// to sourceURL on each) plus the YAML key order so the caller can
// preserve it in the on-disk file + the success banner.
//
// We re-serialize each body map through YAML so the existing
// Profile.validate() runs without us duplicating its logic here.
func parseInstallPayload(profilesMap map[string]any, sourceURL string) ([]*Profile, []string, *InstallError) {
	// Preserve insertion order from the parsed map. Go's map iteration
	// is randomized, but yaml.v3 emits keys in iteration order of the
	// underlying map when round-tripping; we accept that the order is
	// not strictly deterministic from the upstream YAML. For the
	// banner + the on-disk file we sort alphabetically to keep the
	// output stable across runs.
	names := make([]string, 0, len(profilesMap))
	for name := range profilesMap {
		names = append(names, name)
	}
	// Stable, alphabetical order so the banner + on-disk write match
	// what `profile list` shows.
	sortStrings(names)

	parsed := make([]*Profile, 0, len(names))
	for _, name := range names {
		bodyAny := profilesMap[name]
		body, ok := bodyAny.(map[string]any)
		if !ok {
			// Allow an explicitly null body (`name:` with no fields) —
			// install treats that as an empty profile body, mirroring
			// the loader which synthesizes an empty Profile for nil.
			if bodyAny == nil {
				body = map[string]any{}
			} else {
				return nil, nil, installErr(InstallExitPayload,
					fmt.Sprintf("profile %q must be a YAML object", name))
			}
		}
		// Force source to the fetch URL BEFORE validation so a
		// malicious payload can't sneak source:"local" past us.
		body["source"] = sourceURL

		// Round-trip through YAML to leverage the typed Profile loader
		// + validate() that LoadProfiles already uses. This keeps the
		// "one definition of valid" rule.
		bodyYAML, err := yaml.Marshal(body)
		if err != nil {
			return nil, nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("profile %q: re-encode for validation: %v", name, err), err)
		}
		var p Profile
		if err := yaml.Unmarshal(bodyYAML, &p); err != nil {
			return nil, nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("profile %q failed to parse: %v", name, err), err)
		}
		p.Name = name
		p.Source = sourceURL // belt-and-braces; in case the round trip dropped it
		if verr := p.validate(); verr != nil {
			return nil, nil, installErr(InstallExitPayload,
				fmt.Sprintf("profile %q failed validation: %v", name, verr))
		}
		parsed = append(parsed, &p)
	}
	return parsed, names, nil
}

// sortStrings is an internal alias kept tiny + dependency-free so we
// don't have to import "sort" into this file (yaml.v3 already pulls
// indirectly). Stable lex order.
func sortStrings(s []string) {
	// Simple insertion sort — n is small (the # of profiles in one
	// install bundle, usually < 20) and we avoid pulling sort into
	// the install hot path. If a customer ever ships hundreds of
	// profiles in one bundle, swap to sort.Strings.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// readProfilesFile returns the on-disk profile map (name → *Profile)
// or an empty map when the file doesn't exist. Errors only on YAML
// parse failures of an existing file — we deliberately do NOT
// synthesize a "none" profile here (unlike LoadProfiles) because the
// install path's conflict check should compare against what's
// actually persisted, not what LoadProfiles would synthesize.
func readProfilesFile(path string) (map[string]*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]*Profile{}, nil
		}
		return nil, err
	}
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("parse profiles yaml at %s: %w", path, err)
	}
	out := map[string]*Profile{}
	for name, p := range pf.Profiles {
		if p == nil {
			p = &Profile{}
		}
		p.Name = name
		out[name] = p
	}
	return out, nil
}

// writeInstalledProfiles persists the installed profiles to the on-
// disk profiles.yaml. Existing profiles NOT touched by this install
// are preserved verbatim (we merge into the existing file, we don't
// rewrite from scratch — operator edits to other profiles must survive).
//
// Conflict resolution: same-name profiles are OVERWRITTEN (the caller
// has already passed the --force gate by the time we get here).
//
// Atomicity: we write to a temp file in the same directory and rename
// over the target so a crash mid-write leaves the prior file intact
// rather than truncated.
func writeInstalledProfiles(path string, profiles []*Profile, _ []string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}

	// Load existing file (if any) into the typed profileFile so we
	// can merge.
	merged := profileFile{Profiles: map[string]*Profile{}}
	if raw, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(raw, &merged); err != nil {
			return fmt.Errorf("parse existing profiles yaml: %w", err)
		}
		if merged.Profiles == nil {
			merged.Profiles = map[string]*Profile{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat existing profiles yaml: %w", err)
	}

	// Apply incoming profiles. Each carries its Source = URL already.
	for _, p := range profiles {
		merged.Profiles[p.Name] = p
	}

	out, err := yaml.Marshal(&merged)
	if err != nil {
		return fmt.Errorf("encode profiles yaml: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup on early return; ignore error since success
	// path renames it away first.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// UpsertProfile persists a single profile to profiles.yaml — insert
// if absent, replace if present.
//
// Read-only invariant: refuses to overwrite a profile whose existing
// Source field is anything other than empty/"local". Org-distributed
// profiles installed via `profile install --from URL` are read-only
// at this CLI surface (see [[enterprise-profile-distribution]]).
// Engineers who want to override an org profile must pick a new
// personal name.
//
// `profile install` itself bypasses this check via
// writeInstalledProfiles — UpsertProfile guards the recommender's
// save-as-profile flow (the kbouncer equivalent of the iam-jit-
// bouncer recommend --save-as-profile path), not the install command.
//
// We accept *Profile (not Profile) because Profile embeds a sync.Once
// for lazy keyword-regex compilation; go vet's copylocks check
// rightly complains if we pass it by value. Callers that want pass-
// by-value ergonomics can do `UpsertProfile(&Profile{...}, path)`.
func UpsertProfile(p *Profile, path string) error {
	if p == nil || p.Name == "" {
		return errors.New("kbounce: UpsertProfile: Name is required")
	}
	resolved := path
	if resolved == "" {
		rp, err := DefaultProfilesPath()
		if err != nil {
			return fmt.Errorf("kbounce: resolve profiles path: %w", err)
		}
		resolved = rp
	}
	if dir := filepath.Dir(resolved); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("kbounce: mkdir %q: %w", dir, err)
		}
	}

	merged := profileFile{Profiles: map[string]*Profile{}}
	if raw, err := os.ReadFile(resolved); err == nil {
		if err := yaml.Unmarshal(raw, &merged); err != nil {
			return fmt.Errorf("kbounce: parse existing profiles yaml: %w", err)
		}
		if merged.Profiles == nil {
			merged.Profiles = map[string]*Profile{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("kbounce: read profiles yaml: %w", err)
	}

	// READ-ONLY check: refuse to clobber an org-distributed profile.
	if prior, exists := merged.Profiles[p.Name]; exists && prior != nil {
		if !prior.IsLocalSource() {
			return fmt.Errorf(
				"profile %q is sourced from %q and is read-only. "+
					"Pick a different name for your local override.",
				p.Name, prior.Source)
		}
	}

	return upsertProfileClean(resolved, p, &merged)
}

// upsertProfileClean is the actual persistence step, factored out so
// the public UpsertProfile reads top-to-bottom.
func upsertProfileClean(path string, p *Profile, merged *profileFile) error {
	name := p.Name
	if name == "" {
		return errors.New("kbounce: UpsertProfile: Name is required")
	}
	if merged.Profiles == nil {
		merged.Profiles = map[string]*Profile{}
	}
	// Store the same pointer; Name field is yaml:"-" so it's skipped
	// during marshal regardless. We do NOT clear p.Name (it's caller-
	// owned), nor do we copy the struct (the sync.Once inside makes
	// that unsafe + go vet's copylocks check rejects it).
	merged.Profiles[name] = p

	out, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("kbounce: encode profiles yaml: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("kbounce: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("kbounce: write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("kbounce: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("kbounce: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("kbounce: rename into place: %w", err)
	}
	return nil
}

// InsecureTLSClientForTests returns an *http.Client that skips TLS
// verification. Test-only helper exported for the install_test.go
// suite so httptest.NewTLSServer (which presents a self-signed cert)
// can be the fetch target. Production code must NEVER pass this to
// Install — it would defeat the HTTPS trust model.
//
// Kept in the production package (not _test.go) so the cmd/ tests
// can use it too without duplicating the client config. Named with
// "Insecure" + "ForTests" so it's obvious in code review.
func InsecureTLSClientForTests() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			//nolint:gosec // intentional: test fixture for httptest.NewTLSServer
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
