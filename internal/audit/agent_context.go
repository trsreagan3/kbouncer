// agent_context.go implements the per-product agent-identity layer
// described in [[agent-identity-in-audit]]:
//
//   - Feature 1: agent fingerprinting from three sources, in priority
//     order (MCP clientInfo > User-Agent > process-tree).
//   - Feature 2: per-MCP-connection session ID (UUID v7, time-ordered)
//     bound across every audit event emitted under that connection.
//
// Cross-product invariants (mirrored byte-for-byte in ibounce + dbounce):
//
//   - Agent block lives under unmapped.iam_jit.agent so downstream SIEM
//     ingest auto-categorizes it the same way across the Bounce suite.
//   - DetectedFrom names the WHERE-from so an analyst reading the row
//     can weight the signal ("mcp_clientinfo" is high confidence;
//     "process_tree" is best-effort).
//   - Process-tree fields (process_exe / parent_exe) are gated as
//     SENSITIVE per [[security-team-positioning-safety-not-surveillance]]:
//     they reveal the operator's local tooling. They land in the local
//     JSONL log + SQLite (operator owns those) but are STRIPPED from
//     the HTTPS webhook body by default. Operator opts in via
//     SetWebhookProcessTree(true).
//   - Session IDs are UUID v7 (time-ordered random); never a counter.
//     Predictable IDs would let a malicious agent forge "this call
//     came from session X" — see the [[agent-identity-in-audit]] Don't
//     list.
//   - Unknown / non-MCP / non-fingerprint-able sources are explicitly
//     marked AgentNameUnknown rather than silently dropped, per
//     [[scorer-is-ground-truth]] (best-effort is honest; pretending to
//     know is not).
package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
)

// AgentNameUnknown is the sentinel populated when no detection source
// fired. Callers MUST still see a populated agent block (so analysts
// can filter "show me events where agent was unknown") rather than a
// missing one.
const AgentNameUnknown = "unknown"

// Detection-source enum values for unmapped.iam_jit.agent.detected_from.
// Stable strings — keep in sync across ibounce / kbounce / dbounce / gbounce.
//
// #318 / §A16 — DetectionSourceHTTPHeader is the cross-bouncer canonical
// value when the inbound `X-Agent-Name` + `X-Agent-Session-Id` headers
// fire. HTTPHeaderNameOnly is the partial-detection variant (name
// passed validation but session_id was absent or invalid).
const (
	DetectionSourceMCPClientInfo      = "mcp_clientinfo"
	DetectionSourceUserAgent          = "user_agent"
	DetectionSourceProcessTree        = "process_tree"
	DetectionSourceHTTPHeader         = "http_header"
	DetectionSourceHTTPHeaderNameOnly = "http_header_name_only"
	DetectionSourceUnknown            = "unknown"
)

// agentNameRe matches the documented X-Agent-Name validation rules:
// alphanumerics, dots, underscores, dashes; max 64 chars. Mirrors
// gbounce's `agentNameRe` + ibounce's `is_valid_agent_name` regex
// byte-for-byte so a SIEM query on `unmapped.iam_jit.agent.name=X` is
// portable across the Bounce suite. Shell-injection characters ($, `,
// ", ', ;, |, &, newline, ...) are rejected so an attacker who controls
// the inbound header can't smuggle shell payloads into a log line a
// downstream operator might `grep | sh`.
var agentNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// IsValidAgentName returns true when s matches the canonical
// X-Agent-Name shape. Cross-product invariant: a name accepted by
// kbouncer MUST be accepted by every other Bouncer.
func IsValidAgentName(s string) bool { return agentNameRe.MatchString(s) }

// AgentInfo is the populated agent-identity record for one audit
// event. Mirrors the OCSF wire shape under unmapped.iam_jit.agent;
// the audit/event.go OCSFAgent struct serializes this 1:1.
//
// All fields are best-effort + may be empty. Name + DetectedFrom are
// the only fields the wire shape guarantees non-empty (DetectedFrom
// defaults to "unknown" so reviewers can filter on it).
type AgentInfo struct {
	// Name is the agent identity ("claude-code", "cursor", "devin",
	// "codex", "kubectl", "client-go", "unknown", ...). Mapped from
	// clientInfo.name (MCP), parsed from User-Agent, or derived from
	// the parent-process exe path (process tree). See
	// fingerprintFromUserAgent for the parser.
	Name string

	// Version is the agent version string when known (e.g. "1.2.3" /
	// "v1.28.0"). Empty when undetectable.
	Version string

	// SessionID is the per-MCP-connection UUID v7. Empty for proxy-
	// observed traffic that wasn't routed through an MCP connection
	// (e.g. a bare kubectl run from a script).
	SessionID string

	// DetectedFrom names the detection-source priority that fired.
	// One of DetectionSource* constants.
	DetectedFrom string

	// ProcessExe is the absolute path to the connecting client's
	// process exe when the process-tree fallback fired. SENSITIVE —
	// stripped from webhook bodies by default per
	// [[security-team-positioning-safety-not-surveillance]].
	ProcessExe string

	// ParentExe is the absolute path to the connecting client's
	// PARENT process exe. SENSITIVE — same stripping policy as
	// ProcessExe.
	ParentExe string

	// RawUserAgent is the literal User-Agent header value when the
	// User-Agent source fired but no mapping rule matched. Lets
	// analysts build their own filters for tools we don't know about.
	// Truncated to RawUserAgentMaxLen to bound the audit-row width.
	RawUserAgent string

	// HeaderRejection is the #320 / §A18 structured breadcrumb that
	// lands at `unmapped.iam_jit.ext.agent_header_rejection` when
	// the inbound X-Agent-Name / X-Agent-Session-Id headers failed
	// validation. Stamped at request-time (resolveAgentInfo) +
	// threaded onto the OCSF event via FromDecision so a SOC analyst
	// querying the audit log can see which request had a
	// misconfigured agent SDK + which reason (charset / length).
	// NEVER includes the raw value — only the rejected value's
	// length, for safe forensics per
	// [[security-team-positioning-safety-not-surveillance]]. Single
	// map when one header failed, []any of maps when both failed.
	HeaderRejection any
}

// RawUserAgentMaxLen caps RawUserAgent so a pathological client can't
// blow up the audit-row size. 256 bytes is generous for a well-formed
// UA + accommodates Mozilla-product strings with vendor extensions.
const RawUserAgentMaxLen = 256

// ToOCSFAgent converts an AgentInfo into the OCSF wire shape
// (unmapped.iam_jit.agent). Always returns a non-nil pointer with at
// least Name + DetectedFrom populated so reviewers can filter on
// "agent unknown" as a first-class signal.
func (a AgentInfo) ToOCSFAgent() *OCSFAgent {
	name := a.Name
	if name == "" {
		name = AgentNameUnknown
	}
	detectedFrom := a.DetectedFrom
	if detectedFrom == "" {
		detectedFrom = DetectionSourceUnknown
	}
	out := &OCSFAgent{
		Name:         name,
		Version:      a.Version,
		SessionID:    a.SessionID,
		DetectedFrom: detectedFrom,
		ProcessExe:   a.ProcessExe,
		ParentExe:    a.ParentExe,
		RawUserAgent: a.RawUserAgent,
	}
	return out
}

// NewSessionID mints a UUID v7 — time-ordered + random per RFC 9562
// (formerly draft-ietf-uuidrev-rfc4122bis). UUID v7 was chosen over a
// counter so a malicious agent can't forge "this came from session N"
// by guessing the next id. On the rare uuid.NewV7 error (system entropy
// hiccup), fall back to uuid.New (v4) — still unguessable, just not
// time-ordered.
func NewSessionID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// Fallback to v4 — still random + unguessable; we lose the
		// time-ordering property but never want to crash a customer
		// MCP connection on a transient entropy hiccup.
		return uuid.New().String()
	}
	return id.String()
}

// ---------------------------------------------------------------------
// User-Agent fingerprinting
// ---------------------------------------------------------------------

// userAgentRule matches one User-Agent shape. The first matching rule
// wins (rules ordered most-specific → most-general). Mirror the table
// across the Bounce suite so a customer's saved SIEM queries port over.
type userAgentRule struct {
	// match is a regex matched against the full User-Agent string;
	// case-insensitive (the package compiles with (?i)).
	match *regexp.Regexp
	// name is the canonical agent name written to the audit row.
	name string
	// versionGroup, when > 0, names the submatch index that holds the
	// version string (0 = no version capture).
	versionGroup int
}

// userAgentRules is the kbounce User-Agent classifier table. Per
// [[scorer-is-ground-truth]] this is a flat lookup, not an LLM call —
// new entries need a User-Agent example pasted into the test corpus
// + a row added here.
//
// Compiled lazily (var initializer runs at package init) so the
// regex cost is paid once.
var userAgentRules = []userAgentRule{
	// kubectl carries a distinctive UA string of the shape
	// "kubectl/v1.28.3 (darwin/arm64) kubernetes/abc1234". The
	// version capture grabs the leading semver-ish token.
	{
		match:        regexp.MustCompile(`(?i)\bkubectl/(v?[\d.]+)`),
		name:         "kubectl",
		versionGroup: 1,
	},
	// helm CLI: "Helm/v3.13.2".
	{
		match:        regexp.MustCompile(`(?i)\bhelm/(v?[\d.]+)`),
		name:         "helm",
		versionGroup: 1,
	},
	// k9s TUI: "k9s/v0.27.4".
	{
		match:        regexp.MustCompile(`(?i)\bk9s/(v?[\d.]+)`),
		name:         "k9s",
		versionGroup: 1,
	},
	// argocd CLI: "argocd-cli/v2.8.0".
	{
		match:        regexp.MustCompile(`(?i)\bargocd-cli/(v?[\d.]+)`),
		name:         "argocd-cli",
		versionGroup: 1,
	},
	// flux CLI: "flux/v2.1.0".
	{
		match:        regexp.MustCompile(`(?i)\bflux/(v?[\d.]+)`),
		name:         "flux",
		versionGroup: 1,
	},
	// kustomize: "kustomize/v5.0.0".
	{
		match:        regexp.MustCompile(`(?i)\bkustomize/(v?[\d.]+)`),
		name:         "kustomize",
		versionGroup: 1,
	},
	// Bare client-go (e.g. an operator or controller): the canonical
	// UA shape is "kubernetes/<commit> (os/arch) kubernetes/<commit>".
	// We capture the leading kubernetes-token version when present.
	{
		match:        regexp.MustCompile(`(?i)^kubernetes/(v?[\w.]+)`),
		name:         "client-go",
		versionGroup: 1,
	},
	// Generic Go HTTP client (script-driven calls, custom controllers
	// that didn't set a UA). Lower priority than client-go above.
	{
		match:        regexp.MustCompile(`(?i)^Go-http-client/(v?[\d.]+)`),
		name:         "go-http-client",
		versionGroup: 1,
	},
	// curl / wget — ad-hoc human / script debugging. Map them so an
	// analyst sees "this was a shell debug session" rather than
	// "unknown."
	{
		match:        regexp.MustCompile(`(?i)^curl/(v?[\d.]+)`),
		name:         "curl",
		versionGroup: 1,
	},
	{
		match:        regexp.MustCompile(`(?i)^Wget/(v?[\d.]+)`),
		name:         "wget",
		versionGroup: 1,
	},
}

// FingerprintFromUserAgent maps a User-Agent header into an AgentInfo
// using the userAgentRules table. Returns AgentInfo{Name: "unknown",
// DetectedFrom: "user_agent", RawUserAgent: ua} when no rule matches
// (rather than dropping the signal) so analysts can build queries on
// the raw value.
//
// Empty input yields an empty AgentInfo (DetectedFrom: "unknown") so
// the caller can fall through to the process-tree source.
func FingerprintFromUserAgent(ua string) AgentInfo {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return AgentInfo{DetectedFrom: DetectionSourceUnknown}
	}
	for _, rule := range userAgentRules {
		m := rule.match.FindStringSubmatch(ua)
		if m == nil {
			continue
		}
		info := AgentInfo{
			Name:         rule.name,
			DetectedFrom: DetectionSourceUserAgent,
		}
		if rule.versionGroup > 0 && rule.versionGroup < len(m) {
			info.Version = m[rule.versionGroup]
		}
		return info
	}
	// No rule fired — keep the raw UA so analysts can still query it.
	return AgentInfo{
		Name:         AgentNameUnknown,
		DetectedFrom: DetectionSourceUserAgent,
		RawUserAgent: truncate(ua, RawUserAgentMaxLen),
	}
}

// truncate caps s to max bytes, appending "..." when it shortens the
// input. Byte-safe (multi-byte runes at the boundary are dropped, not
// split, by the explicit bound). Used to keep RawUserAgent small.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// FingerprintFromMCPClientInfo builds an AgentInfo from the MCP
// initialize handshake's clientInfo object. Per the MCP spec the
// clientInfo carries `name` + `version` strings; we map name to a
// canonical agent identity (case-insensitive) + pass version through
// verbatim. Returns DetectedFrom: DetectionSourceMCPClientInfo so
// reviewers know the source.
//
// Empty name → unknown agent with mcp_clientinfo as the source so the
// presence of an MCP connection is still recorded.
func FingerprintFromMCPClientInfo(name, version string) AgentInfo {
	canonical := canonicalAgentName(name)
	if canonical == "" {
		canonical = AgentNameUnknown
	}
	return AgentInfo{
		Name:         canonical,
		Version:      version,
		DetectedFrom: DetectionSourceMCPClientInfo,
	}
}

// canonicalAgentName lowercases + de-aliases a client-supplied name
// into the canonical Bounce-suite agent vocabulary. New mappings:
// add the alias here + a row in agent_context_test.go's case table.
func canonicalAgentName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "":
		return ""
	// Claude Code variants the wild has shipped.
	case "claude-code", "claude_code", "claude code", "claudecode",
		"@anthropic/claude-code":
		return "claude-code"
	// Cursor IDE.
	case "cursor", "cursor-ide", "cursor.sh":
		return "cursor"
	// Devin (Cognition).
	case "devin", "cognition-devin", "devin-ai":
		return "devin"
	// OpenAI Codex CLI (rebranded from "openai-codex").
	case "codex", "openai-codex", "codex-cli":
		return "codex"
	// Windsurf (Codeium).
	case "windsurf", "codeium-windsurf":
		return "windsurf"
	// Continue.dev.
	case "continue", "continue-dev", "continue.dev":
		return "continue"
	}
	return n
}

// ---------------------------------------------------------------------
// Process-tree fingerprinting (best-effort, OS-conditional)
// ---------------------------------------------------------------------

// FingerprintFromProcessTree walks the process tree starting at PID
// and populates ProcessExe + ParentExe by reading /proc on Linux. On
// macOS /proc isn't available; we fall back to os.Executable for
// ProcessExe only (parent walk needs platform-specific syscalls we
// don't want to bring in). DetectedFrom is always set to
// DetectionSourceProcessTree on a non-zero PID even when fields stay
// empty so reviewers can see the source was attempted.
//
// SENSITIVE per [[security-team-positioning-safety-not-surveillance]]:
// the populated fields land in the local JSONL log + SQLite but are
// stripped from the HTTPS webhook body unless the operator opts in.
// See event.go RedactForWebhook.
func FingerprintFromProcessTree(pid int) AgentInfo {
	if pid <= 0 {
		return AgentInfo{DetectedFrom: DetectionSourceUnknown}
	}
	info := AgentInfo{
		Name:         AgentNameUnknown,
		DetectedFrom: DetectionSourceProcessTree,
	}
	if runtime.GOOS == "linux" {
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
			info.ProcessExe = exe
			info.Name = canonicalAgentNameFromExe(filepath.Base(exe))
		}
		if ppid := readPPIDLinux(pid); ppid > 0 {
			if pexe, err := os.Readlink("/proc/" + strconv.Itoa(ppid) + "/exe"); err == nil {
				info.ParentExe = pexe
				// If we couldn't classify from the child's exe, try the
				// parent (e.g. node → claude-code spawns python → mcp).
				if info.Name == AgentNameUnknown {
					info.Name = canonicalAgentNameFromExe(filepath.Base(pexe))
				}
			}
		}
	}
	if info.Name == "" {
		info.Name = AgentNameUnknown
	}
	return info
}

// readPPIDLinux parses /proc/<pid>/stat to extract the parent PID
// (field 4 per proc(5)). Returns 0 on any error. Stat-field 2 (comm)
// is parenthesized + may contain spaces / parens itself, so we slice
// after the LAST closing paren before splitting.
func readPPIDLinux(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	close := strings.LastIndex(s, ")")
	if close < 0 || close+2 >= len(s) {
		return 0
	}
	tail := strings.Fields(s[close+1:])
	// tail[0] = state, tail[1] = ppid (per proc(5) — fields 3,4 of
	// the line; we sliced off the (comm) part above).
	if len(tail) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(tail[1])
	if err != nil {
		return 0
	}
	return ppid
}

// canonicalAgentNameFromExe maps a process basename (e.g. "claude",
// "cursor", "node") to a canonical agent name. Best-effort — many
// agents run under generic interpreters (node, python) so this often
// returns AgentNameUnknown.
func canonicalAgentNameFromExe(exeName string) string {
	n := strings.ToLower(exeName)
	// Strip trailing .exe (Windows).
	n = strings.TrimSuffix(n, ".exe")
	switch n {
	case "claude", "claude-code":
		return "claude-code"
	case "cursor":
		return "cursor"
	case "devin":
		return "devin"
	case "codex":
		return "codex"
	case "windsurf":
		return "windsurf"
	case "kubectl":
		return "kubectl"
	}
	return AgentNameUnknown
}

// ---------------------------------------------------------------------
// Registry — in-memory store of {session_id -> AgentInfo}
// ---------------------------------------------------------------------

// Registry maps MCP session IDs to their bound AgentInfo. Used by the
// proxy hot-path so a request that carries an MCP session_id header
// (or that arrives from a PID matched to a registered session) gets
// the same agent block as the originating MCP tool call.
//
// A nil *Registry is safe for read access — Lookup returns the zero
// AgentInfo. Writes via Register / Forget on a nil pointer are no-ops.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]AgentInfo
	// active counts non-Forgot sessions for the MCP server's
	// SESSION_ENDED accounting. Atomic so a Status() snapshot doesn't
	// hold the lock.
	active atomic.Int64
}

// NewRegistry constructs an empty Registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]AgentInfo)}
}

// Register binds an AgentInfo to a session ID. Idempotent — repeat
// calls with the same id overwrite (e.g. clientInfo arrives after the
// session ID was already minted).
func (r *Registry) Register(sessionID string, info AgentInfo) {
	if r == nil || sessionID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.sessions[sessionID]
	r.sessions[sessionID] = info
	if !existed {
		r.active.Add(1)
	}
}

// Lookup returns the AgentInfo bound to sessionID, or the zero value
// (with SessionID populated) when nothing is registered. Always
// populates SessionID on the returned info so the audit row carries
// the id even when the agent block is otherwise empty.
func (r *Registry) Lookup(sessionID string) AgentInfo {
	if r == nil || sessionID == "" {
		return AgentInfo{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if info, ok := r.sessions[sessionID]; ok {
		info.SessionID = sessionID
		return info
	}
	return AgentInfo{SessionID: sessionID}
}

// Forget removes a session ID from the registry. Returns the removed
// AgentInfo so the caller can emit a SESSION_ENDED event with the
// matching agent block. Returns the zero value when nothing was
// registered.
func (r *Registry) Forget(sessionID string) AgentInfo {
	if r == nil || sessionID == "" {
		return AgentInfo{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	info, ok := r.sessions[sessionID]
	if !ok {
		return AgentInfo{}
	}
	delete(r.sessions, sessionID)
	r.active.Add(-1)
	info.SessionID = sessionID
	return info
}

// ActiveCount returns the number of currently-registered sessions.
// Atomic-loaded; safe to call concurrently with Register / Forget.
func (r *Registry) ActiveCount() int64 {
	if r == nil {
		return 0
	}
	return r.active.Load()
}

// ---------------------------------------------------------------------
// SESSION_ENDED event
// ---------------------------------------------------------------------

// NewSessionEndedEvent builds the synthetic SESSION_ENDED audit event
// emitted when an MCP connection closes (Feature 2 of
// [[agent-identity-in-audit]]). Shape is the SAME as a decision event
// minus the api/resource/dst_endpoint fields; activity_id=99 / status=
// Other / severity=Informational per the same conventions used by
// AUDIT_DROPPED.
//
// Customers query "all events from session X" with a single
// session_id filter; this event marks the end-of-life of the session
// so the analyst sees both bookends.
func NewSessionEndedEvent(info AgentInfo) Event {
	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         nowUnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   ActivityOther,
		ActivityName: "session_ended",
		TypeUID:      ClassUID*100 + ActivityOther,
		TypeName:     typeNameForActivity(ActivityOther),
		SeverityID:   SeverityInformational,
		Severity:     "Informational",
		StatusID:     StatusOther,
		Status:       "Other",
		StatusDetail: "MCP agent session ended (connection closed)",
		API: OCSFAPI{
			Service: OCSFAPIService{Name: "kubernetes"},
			Request: OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypeSessionEnded),
				Agent:     info.ToOCSFAgent(),
			},
		},
		EventType: EventTypeSessionEnded,
	}
}
