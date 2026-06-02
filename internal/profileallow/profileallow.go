// Package profileallow implements the per-bouncer "easy profile
// extension" surface — the symmetric flip of dynamic-deny rules.
//
// #386 / §A25 Phase 2 (kbouncer). Mirrors the iam-jit Python
// profile_allow module (iam-roles commit 99ca1b6) so the
// cross-product UX stays parity-aligned per
// [[cross-product-agent-parity]].
//
// Single entry point: AddProfileAllowRule. It:
//
//  1. Validates inputs (target / action / reason; refuses "*" as a
//     target per the design memo's "force operator specificity"
//     requirement).
//  2. Reads the current profile YAML.
//  3. Refuses to mutate org-distributed profiles (matches
//     profile.UpsertProfile's read-only check).
//  4. Decides whether to auto-apply (operator + opt-in for agent) or
//     queue for approval (agent + default-off).
//  5. Appends a new ProfileAllowRule to the profile's AllowRules
//     slice with provenance metadata embedded in the Note field.
//  6. Persists via profile.UpsertProfile.
//
// The pending-approval queue path is SHARED across all bouncers
// (~/.iam-jit/bouncer/profile-allow-pending.jsonl). All bouncers
// append to the same JSONL file so ibounce's queue inspector sees
// every bouncer's pending entries.
//
// Per [[creates-never-mutates]]: additive — new code, new package,
// no refactor of the existing profile package.
package profileallow

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/profile"
)

// AdminAction names the OCSF admin-action wire values this package
// emits. Mirrors the Python ibounce module's wire shape so the
// security-team dashboard sees identical event types across
// products per [[cross-product-agent-parity]].
const (
	AdminActionProfileAllowAdded             audit.AdminAction = "profile.allow.added"
	AdminActionProfileAllowRequestedByAgent  audit.AdminAction = "profile.allow.requested_by_agent"
)

// AllowAgentSelfGrantEnv is the env var the operator sets to opt in
// to agent-driven allows. Default OFF — agent attempts to add to
// allow_rules without this flag set are queued for operator
// confirmation. Matches the Python ibounce default + the variable
// name (so a single env-var setting opts in across the suite).
const AllowAgentSelfGrantEnv = "IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT"

// PendingApprovalsPathEnv overrides the agent-pending-approval queue
// path. Default lives in ~/.iam-jit/bouncer/profile-allow-pending.jsonl
// — the SAME path the Python ibounce module uses, so a queue
// inspector that hits the shared file sees pending entries from
// every bouncer.
const PendingApprovalsPathEnv = "IAM_JIT_PROFILE_ALLOW_PENDING_PATH"

// EasyAllowOriginTag is the substring marker the Note field carries
// so the audit trail can distinguish operator-installed allows from
// generator-installed allows. Same tag the Python module uses.
const EasyAllowOriginTag = "[easy_allow]"

// SourceCLI / SourceMCP / SourceMCPPending name the request origin
// recorded in the provenance note's "via=" segment + the audit
// event's source field. Mirrors the Python module's source values.
const (
	SourceCLI         = "cli"
	SourceMCP         = "mcp"
	SourceMCPPending  = "mcp_pending"
)

// agentSources is the set of source values subject to the agent-
// self-grant gate. Mirrors _AGENT_SOURCES in the Python module.
var agentSources = map[string]struct{}{
	SourceMCP: {},
}

// Error carries a structured operations-layer error. The Code lets
// the CLI map to an exit status + the MCP tool picks the right
// structured payload. Mirrors ProfileAllowError in the Python
// module.
type Error struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func newErr(code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

func newErrDetail(code, msg string, details map[string]any) *Error {
	return &Error{Code: code, Message: msg, Details: details}
}

// Options tunes a single AddProfileAllowRule invocation.
type Options struct {
	// Target is the kbouncer-shape target pattern. Refuses "*"
	// per [[creates-never-mutates]]: the easy-allow surface is
	// deliberately narrower than "allow everything".
	Target string

	// Actions is the list of "verb:resource" strings to allow.
	// For kbouncer the canonical shape mirrors ibounce's
	// "service:Action" so the cross-product CLI is symmetric.
	// Each action lands verbatim in a profile.ProfileAllowRule
	// Pattern, which the kbouncer evaluator now consumes
	// (Profile.Evaluate + matchAnyAllowRule); the rule's ArnScope
	// (from Target) is enforced as a namespace floor when it names
	// a namespace.
	Actions []string

	// Reason is the operator/agent-supplied explanation;
	// surfaces in the Note field + the admin-action audit
	// event. Required.
	Reason string

	// Duration is a Go-style duration ("3h", "7d") or
	// "permanent" / "" (default). When non-permanent, the
	// rule's note carries an expires=<iso> segment; today the
	// duration is advisory metadata — operators remove expired
	// rules via YAML edit. Future phase wires an expiry sweeper.
	Duration string

	// ProfileName names the profile to mutate. "" → active
	// profile (resolved via Options.ActiveProfile when set,
	// otherwise the resolver inside add picks one).
	ProfileName string

	// ActiveProfile names the currently-active profile (the
	// value of --profile / KBOUNCER_PROFILE at proxy start).
	// Used as the fallback when ProfileName is empty. May be
	// empty when no profile is selected; the operation errors
	// out honestly per [[ibounce-honest-positioning]].
	ActiveProfile string

	// Source names the request origin. "cli" by default.
	Source string

	// Actor is the identity recorded in the note + audit event.
	// Empty → resolved from $USER / $LOGNAME / "local-operator".
	Actor string

	// ProfilesPath overrides the on-disk profiles.yaml location
	// (tests inject here). Empty → profile.DefaultProfilesPath().
	ProfilesPath string

	// QueuePath overrides the pending-approvals JSONL path
	// (tests inject here).
	QueuePath string

	// AllowAgentSelfGrant is an explicit override of the env-var
	// gate. nil → consult the env var. *true → always auto-apply
	// MCP requests; *false → always queue.
	AllowAgentSelfGrant *bool

	// AuditEmitter, when non-nil, receives the
	// admin-action OCSF event the operation generates. Nil →
	// no-op (the CLI default; operators wire an emitter
	// explicitly).
	AuditEmitter audit.Emitter
}

// Result summarizes the outcome of AddProfileAllowRule.
type Result struct {
	// Status is "applied" (rule appended + persisted) or
	// "pending_approval" (agent request queued).
	Status string

	// ProfileName names the profile mutated (or queued
	// against).
	ProfileName string

	// ProfilePath is the on-disk path the rule was written to.
	// Empty on the pending-approval path.
	ProfilePath string

	// Actions echoes the actions added.
	Actions []string

	// Target echoes the target.
	Target string

	// Reason echoes the reason.
	Reason string

	// Duration echoes the duration string ("" for permanent).
	Duration string

	// ExpiresAt is the ISO-8601 UTC expiry computed from
	// Duration. Empty for permanent.
	ExpiresAt string

	// Actor names the operator/agent.
	Actor string

	// Source echoes the request source.
	Source string

	// RuleCountAfter is the length of AllowRules in the
	// mutated profile after the append.
	RuleCountAfter int

	// PendingEntry is the queue entry written when Status is
	// "pending_approval"; nil otherwise.
	PendingEntry map[string]any
}

// AddProfileAllowRule appends a profile allow rule (or queues it
// for approval). The single entry point both the CLI command + the
// MCP tool dispatch into.
func AddProfileAllowRule(opts Options) (*Result, error) {
	if err := validateTargetActions(opts.Target, opts.Actions); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.Reason) == "" {
		return nil, newErr("missing_reason",
			"--reason is required (surfaces in note + audit event)")
	}

	source := opts.Source
	if source == "" {
		source = SourceCLI
	}
	actor := strings.TrimSpace(opts.Actor)
	if actor == "" {
		actor = resolveActor()
	}

	durationStr, expiresAt, derr := parseDurationToExpiry(opts.Duration)
	if derr != nil {
		return nil, derr
	}

	profilesPath := opts.ProfilesPath
	if profilesPath == "" {
		p, err := profile.DefaultProfilesPath()
		if err != nil {
			return nil, fmt.Errorf("kbounce: resolve profiles path: %w", err)
		}
		profilesPath = p
	}

	profiles, lerr := profile.LoadProfiles(profilesPath)
	if lerr != nil {
		return nil, fmt.Errorf("kbounce: load profiles: %w", lerr)
	}

	targetName := opts.ProfileName
	if targetName == "" {
		targetName = opts.ActiveProfile
	}
	if targetName == "" {
		targetName = profile.FullUserProfileName
	}
	targetProfile, perr := profiles.Active(targetName)
	if perr != nil {
		return nil, newErrDetail("profile_not_found",
			fmt.Sprintf("profile %q not found; available: %s",
				targetName, strings.Join(profiles.NamesSorted(), ", ")),
			map[string]any{"profile_name": targetName})
	}

	if err := refuseOrgDistributed(targetProfile); err != nil {
		return nil, err
	}

	selfGrantEnabled := agentSelfGrantEnabled(opts.AllowAgentSelfGrant)
	isAgent := isAgentSource(source)
	queued := isAgent && !selfGrantEnabled

	if queued {
		// Pending path: write to the shared JSONL queue, return
		// status=pending_approval; profile is NOT mutated.
		entry, qerr := enqueuePending(pendingEntryInput{
			Target:      opts.Target,
			Actions:     opts.Actions,
			Reason:      strings.TrimSpace(opts.Reason),
			Duration:    durationStr,
			ExpiresAt:   expiresAt,
			ProfileName: targetProfile.Name,
			Actor:       actor,
			Source:      source,
			Bouncer:     "kbounce",
		}, opts.QueuePath)
		if qerr != nil {
			return nil, fmt.Errorf("kbounce: enqueue pending: %w", qerr)
		}
		emitAuditEvent(opts.AuditEmitter, audit.AdminActionInput{
			Action:     AdminActionProfileAllowRequestedByAgent,
			Actor:      actor,
			Source:     audit.AdminActionSourceMCP,
			EntityKind: "profile",
			EntityName: targetProfile.Name,
			After:      entry,
			ExtraExt: map[string]any{
				"target":     opts.Target,
				"actions":    opts.Actions,
				"reason":     strings.TrimSpace(opts.Reason),
				"pending_id": entry["id"],
				"status":     "pending_approval",
			},
		})
		return &Result{
			Status:         "pending_approval",
			ProfileName:    targetProfile.Name,
			ProfilePath:    "",
			Actions:        append([]string(nil), opts.Actions...),
			Target:         opts.Target,
			Reason:         strings.TrimSpace(opts.Reason),
			Duration:       durationStr,
			ExpiresAt:      expiresAt,
			Actor:          actor,
			Source:         source,
			RuleCountAfter: len(targetProfile.AllowRules),
			PendingEntry:   entry,
		}, nil
	}

	// Apply path: append new ProfileAllowRule entries (one per
	// action) and persist via UpsertProfile.
	note := buildProvenanceNote(noteInput{
		Reason:    strings.TrimSpace(opts.Reason),
		Actor:     actor,
		Source:    source,
		Duration:  durationStr,
		ExpiresAt: expiresAt,
	})

	newRules := append([]profile.ProfileAllowRule(nil), targetProfile.AllowRules...)
	for _, act := range opts.Actions {
		newRules = append(newRules, profile.ProfileAllowRule{
			Pattern:  act,
			ArnScope: opts.Target,
			Note:     note,
		})
	}

	// Pass-by-pointer per UpsertProfile's contract (Profile embeds
	// a sync.Once). We mutate a shallow copy of the slice; the
	// pointer to the Profile is the same instance LoadProfiles
	// returned, but UpsertProfile writes its current AllowRules
	// to disk so the mutation persists.
	targetProfile.AllowRules = newRules
	if err := profile.UpsertProfile(targetProfile, profilesPath); err != nil {
		return nil, fmt.Errorf("kbounce: upsert profile: %w", err)
	}

	emitAuditEvent(opts.AuditEmitter, audit.AdminActionInput{
		Action:     AdminActionProfileAllowAdded,
		Actor:      actor,
		Source:     audit.AdminActionSource(source),
		EntityKind: "profile",
		EntityName: targetProfile.Name,
		After: map[string]any{
			"rule_count": len(newRules),
		},
		ExtraExt: map[string]any{
			"target":     opts.Target,
			"actions":    opts.Actions,
			"reason":     strings.TrimSpace(opts.Reason),
			"duration":   durationStr,
			"expires_at": expiresAt,
		},
	})

	return &Result{
		Status:         "applied",
		ProfileName:    targetProfile.Name,
		ProfilePath:    profilesPath,
		Actions:        append([]string(nil), opts.Actions...),
		Target:         opts.Target,
		Reason:         strings.TrimSpace(opts.Reason),
		Duration:       durationStr,
		ExpiresAt:      expiresAt,
		Actor:          actor,
		Source:         source,
		RuleCountAfter: len(newRules),
		PendingEntry:   nil,
	}, nil
}

// validateTargetActions mirrors the Python _validate_target_action.
func validateTargetActions(target string, actions []string) *Error {
	if strings.TrimSpace(target) == "" {
		return newErr("missing_target", "--target is required")
	}
	if strings.TrimSpace(target) == "*" {
		return newErr("target_too_broad",
			"--target '*' is refused; profile allows must be specific. "+
				"Use a glob (e.g. namespaces/staging-*) or an exact "+
				"resource. Per [[creates-never-mutates]] the easy-allow "+
				"surface is deliberately narrower than 'allow everything'.")
	}
	if len(actions) == 0 {
		return newErr("missing_action",
			"--action is required (one or more verb:resource strings)")
	}
	for _, a := range actions {
		if strings.TrimSpace(a) == "" || !strings.Contains(a, ":") {
			return newErr("bad_action",
				fmt.Sprintf("action %q must be a 'verb:resource' string "+
					"(e.g. apps/deployments:get)", a))
		}
	}
	return nil
}

// refuseOrgDistributed mirrors the Python _refuse_org_distributed.
func refuseOrgDistributed(p *profile.Profile) *Error {
	if p == nil {
		return newErr("profile_not_found", "no active profile")
	}
	if !p.IsLocalSource() {
		return newErrDetail("org_distributed",
			fmt.Sprintf("profile %q is org-distributed (source=%q) and "+
				"read-only at the easy-allow surface. Create a local "+
				"profile by copying it to a new local name and `profile "+
				"allow` that.", p.Name, p.Source),
			map[string]any{
				"profile_name": p.Name,
				"source":       p.Source,
			})
	}
	return nil
}

// agentSelfGrantEnabled consults the explicit override OR the env var.
func agentSelfGrantEnabled(override *bool) bool {
	if override != nil {
		return *override
	}
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(AllowAgentSelfGrantEnv)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func isAgentSource(s string) bool {
	_, ok := agentSources[s]
	return ok
}

// parseDurationToExpiry parses a Go-style duration into
// (duration_str, expires_at_iso). "" / "permanent" → ("", "").
func parseDurationToExpiry(d string) (string, string, *Error) {
	s := strings.TrimSpace(d)
	if s == "" || s == "permanent" {
		return "", "", nil
	}
	// Accept Go duration shorthand + days/weeks suffixes mirroring
	// the Python parser. The dynamic-deny pkg has the same parsing;
	// to keep this package dependency-light we handle "Nd" + "Nw"
	// here and pass everything else to time.ParseDuration.
	var dur time.Duration
	switch {
	case strings.HasSuffix(s, "d"):
		n, perr := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if perr != nil {
			return s, "", nil
		}
		dur = time.Duration(n) * 24 * time.Hour
	case strings.HasSuffix(s, "w"):
		n, perr := strconv.Atoi(strings.TrimSuffix(s, "w"))
		if perr != nil {
			return s, "", nil
		}
		dur = time.Duration(n) * 7 * 24 * time.Hour
	default:
		parsed, perr := time.ParseDuration(s)
		if perr != nil {
			// Pass-through metadata; expiry stays empty.
			return s, "", nil
		}
		dur = parsed
	}
	exp := time.Now().UTC().Add(dur).Truncate(time.Second)
	return s, exp.Format("2006-01-02T15:04:05Z"), nil
}

type noteInput struct {
	Reason    string
	Actor     string
	Source    string
	Duration  string
	ExpiresAt string
}

func buildProvenanceNote(in noteInput) string {
	base := fmt.Sprintf("%s %s -- by=%s via=%s",
		EasyAllowOriginTag, in.Reason, in.Actor, in.Source)
	if in.ExpiresAt != "" {
		return base + " expires=" + in.ExpiresAt
	}
	if in.Duration != "" {
		return base + " duration=" + in.Duration
	}
	return base
}

// resolveActor mirrors dynamic_denies.store.resolve_operator.
func resolveActor() string {
	for _, k := range []string{"USER", "LOGNAME"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return "local-operator"
}

// ---------------------------------------------------------------------
// Pending queue
// ---------------------------------------------------------------------

type pendingEntryInput struct {
	Target      string
	Actions     []string
	Reason      string
	Duration    string
	ExpiresAt   string
	ProfileName string
	Actor       string
	Source      string
	Bouncer     string
}

// ResolvePendingPath returns the path to the shared pending-approvals
// JSONL queue. Explicit > env var > default.
func ResolvePendingPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := strings.TrimSpace(os.Getenv(PendingApprovalsPathEnv)); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".iam-jit", "bouncer", "profile-allow-pending.jsonl"), nil
}

func enqueuePending(in pendingEntryInput, explicitPath string) (map[string]any, error) {
	qp, err := ResolvePendingPath(explicitPath)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(qp); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	entry := map[string]any{
		"id":           newPendingID(),
		"requested_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"target":       in.Target,
		"actions":      in.Actions,
		"reason":       in.Reason,
		"duration":     in.Duration,
		"expires_at":   in.ExpiresAt,
		"profile_name": in.ProfileName,
		"actor":        in.Actor,
		"source":       in.Source,
		"bouncer":      in.Bouncer,
		"status":       "pending",
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(qp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return nil, err
	}
	_ = os.Chmod(qp, 0o600)
	return entry, nil
}

// ListPending reads every pending-approval entry from the JSONL
// queue. Returns an empty slice when the file is absent.
func ListPending(explicitPath string) ([]map[string]any, error) {
	qp, err := ResolvePendingPath(explicitPath)
	if err != nil {
		return nil, err
	}
	raw, rerr := os.ReadFile(qp)
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, rerr
	}
	out := []map[string]any{}
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		var entry map[string]any
		if jerr := json.Unmarshal([]byte(s), &entry); jerr != nil {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

// _ULID_ALPHABET is the Crockford base32 alphabet used by the dd_ /
// pa_ id generator. Matches the Python ULID body so the wire shape
// is identical across products.
const ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newPendingID returns a pa_<26-char-Crockford-base32> id. The body
// is a 48-bit ms timestamp + 80-bit random tail encoded as 26 chars.
// Mirrors the Python _new_pending_id shape.
func newPendingID() string {
	now := uint64(time.Now().UTC().UnixMilli()) & ((1 << 48) - 1)
	rnd := make([]byte, 10) // 80 bits
	_, _ = rand.Read(rnd)
	tsChars := make([]byte, 10)
	for i := 9; i >= 0; i-- {
		tsChars[i] = ulidAlphabet[now&0x1F]
		now >>= 5
	}
	randChars := make([]byte, 16)
	var bits uint64
	var nbits uint
	idx := 0
	for _, b := range rnd {
		bits = (bits << 8) | uint64(b)
		nbits += 8
		for nbits >= 5 {
			nbits -= 5
			randChars[idx] = ulidAlphabet[(bits>>nbits)&0x1F]
			idx++
			if idx == 16 {
				break
			}
		}
		if idx == 16 {
			break
		}
	}
	return "pa_" + string(tsChars) + string(randChars)
}

// ---------------------------------------------------------------------
// Audit emit (best-effort; nil emitter = no-op)
// ---------------------------------------------------------------------

func emitAuditEvent(em audit.Emitter, in audit.AdminActionInput) {
	if em == nil {
		return
	}
	if in.Action == "" {
		in.Action = AdminActionProfileAllowAdded
	}
	audit.EmitAdminAction(context.Background(), em, in)
}
