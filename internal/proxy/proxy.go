// Package proxy implements the kbouncer HTTP server.
//
// K-Slice 1 ships the observation-only layer: every inbound request is
// parsed, classified, evaluated against a (currently empty) rule set,
// recorded in the audit log, and surfaced back to the caller as JSON.
// No request is forwarded to a real kube-apiserver yet — that is
// K-Slice 2. Until then the proxy is a pure observability tool:
// pointing kubectl at it shows the parsed verb/resource/namespace
// breakdown of every call kubectl would have made, with the verdict
// kbouncer WOULD have applied.
//
// The two operating modes mirror iam-jit-bouncer's so the audit-log
// semantics, mental model, and CLI flags stay consistent across the
// two products:
//
//   - cooperative (default): every call is parsed + verdict logged but
//     always forwarded (when forwarding lands in K-Slice 2). Useful for
//     iterating fast and previewing what transparent mode WOULD block.
//   - transparent: DENY verdicts return 403 to the client without
//     forwarding. ALLOW verdicts forward. The enforcement mode for
//     locked-down environments.
//
// The proxy NEVER mutates cluster state directly; every state change
// is the apiserver's, after kbouncer's gate has chosen to forward.
// See [[creates-never-mutates]] in the product memory.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/parser"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
	"github.com/trsreagan3/kbouncer/internal/tasks"
	"github.com/trsreagan3/kbouncer/internal/upstream"
)

// Mode is the proxy's operating mode. First-class user choice — not a
// version/phase distinction. The user picks at deployment time via the
// --mode CLI flag; per-task scope can override later (K-Slice 3).
type Mode string

const (
	// ModeCooperative parses + logs every call but never enforces. The
	// SDK / kubectl client sees the same behavior it would without
	// kbouncer (after K-Slice 2's forwarding lands). Useful for solo
	// devs and for previewing what transparent mode would block.
	ModeCooperative Mode = "cooperative"

	// ModeTransparent enforces verdicts: DENY → 403 to the client,
	// ALLOW → forward (K-Slice 2). The locked-down-environment default.
	ModeTransparent Mode = "transparent"
)

// IsValid returns true if m is one of the known modes.
func (m Mode) IsValid() bool {
	switch m {
	case ModeCooperative, ModeTransparent:
		return true
	}
	return false
}

// DefaultPolicy controls what happens in transparent mode when no rule
// matches a parsed request. Mirrors iam-jit-bouncer's default-policy
// flag.
type DefaultPolicy string

const (
	// DefaultPolicyAllow allows un-matched requests through.
	DefaultPolicyAllow DefaultPolicy = "allow"
	// DefaultPolicyDeny denies un-matched requests (the secure default).
	DefaultPolicyDeny DefaultPolicy = "deny"
)

// IsValid returns true if p is one of the known default policies.
func (p DefaultPolicy) IsValid() bool {
	switch p {
	case DefaultPolicyAllow, DefaultPolicyDeny:
		return true
	}
	return false
}

// Config is the runtime configuration for the proxy. Built from CLI
// flags; passed to Serve.
type Config struct {
	// Host is the interface the listener binds to. Defaults to
	// 127.0.0.1 — the proxy is a local-only credential-handling
	// surface and must never bind externally by default. See
	// [[local-only-safety-mode]] in the product memory.
	Host string

	// Port is the TCP port to listen on. Defaults to 8766 (distinct
	// from iam-jit-bouncer's 8767 so the two products can coexist on
	// the same machine without colliding).
	Port int

	// Mode picks cooperative vs transparent. Defaults to cooperative
	// because lean-permissive is the safer onboarding default per
	// [[safety-mode-lean-permissive]].
	Mode Mode

	// DefaultPolicy decides what transparent mode does when no rule
	// matches. Defaults to DefaultPolicyDeny (the secure default).
	DefaultPolicy DefaultPolicy

	// ActiveProfile is the environment profile evaluated BEFORE the
	// per-task scope and global rule engine. A profile deny is a hard
	// floor — a permissive task scope CANNOT override it. nil disables
	// profile evaluation entirely (equivalent to the "none" profile).
	//
	// The CLI populates this from the --profile flag or KBOUNCER_PROFILE
	// env var (K-Slice 7). Auto-detection from kubectl context lands in
	// K-Slice 8.
	ActiveProfile *profile.Profile

	// Cluster is the current kubeconfig cluster name (when known),
	// surfaced into the profile's ParsedRequest for only_clusters
	// matching and the "cluster" keyword target. Empty when the proxy
	// can't determine the cluster.
	Cluster string

	// PromptOnDeny gates the #5 async deny-prompt UX. When true, every
	// transparent-mode DENY also writes a pending_prompts row so the
	// operator can later answer (always-allow / add-to-profile /
	// ignore) via `kbouncer prompts answer`. Async — the agent is
	// denied immediately; the answer takes effect on the NEXT call of
	// the same shape. The enqueue ONLY fires when ALL of:
	// PromptOnDeny=true, Mode=Transparent, verdict=Deny, no pause
	// active (pauses already bypass enforcement). Defaults false so
	// nothing is enqueued by default.
	PromptOnDeny bool

	// SyncPromptOnDeny is the #203 synchronous variant of PromptOnDeny.
	// When true (transparent mode + no pause + DENY verdict), the proxy
	// request goroutine BLOCKS for up to SyncPromptTimeout waiting for
	// the operator to answer via `kbounce prompts answer`. An allow
	// answer (always / profile) → the request is forwarded to upstream
	// and the upstream response is returned to the agent. A deny answer
	// (ignore) or a timeout → the original 403 is returned (per
	// SyncPromptDefault when the channel never fires).
	//
	// Mutually exclusive with PromptOnDeny in the CLI: the run command
	// rejects both flags on the same invocation so the operator picks
	// one UX explicitly. In COOPERATIVE mode this flag is silently
	// ignored (the deny is advisory; nothing to block on).
	//
	// Defaults false so the existing async + no-prompt paths are
	// unchanged for callers that don't opt in.
	SyncPromptOnDeny bool

	// SyncPromptTimeout caps how long the proxy goroutine waits for the
	// operator's answer. Zero defaults to 30s when SyncPromptOnDeny is
	// true. Bounded to [5s, 300s] by the CLI; values outside that range
	// are surfaced as a configuration error rather than silently
	// clamped.
	SyncPromptTimeout time.Duration

	// SyncPromptDefault picks the verdict applied on timeout / context
	// cancel (the operator never answered). Either DefaultPolicyAllow
	// or DefaultPolicyDeny. The cautious default is "deny" — same shape
	// as DefaultPolicy.
	SyncPromptDefault DefaultPolicy

	// Upstream is the resolved kube-apiserver target the proxy forwards
	// ALLOW verdicts to (K-Slice 2). Nil disables forwarding and the
	// proxy keeps the K-Slice 1 observation-only JSON-body behavior —
	// preserved so the K-Slice 1 + 7 tests keep working unchanged and
	// so the proxy can boot in observation-only mode when no kubeconfig
	// is reachable.
	Upstream *upstream.Upstream

	// TaskOwner is the owner slot the evaluator consults when looking
	// up the active task (K-Slice 3). Empty string = the default-owner
	// slot (single-laptop / single-session deployment shape; matches
	// the Python iam-jit-bouncer Slice B semantics). Non-empty owners
	// (Slice C of the Python pattern) let multiple agent sessions on
	// the same machine each have their own task scope; ships in
	// kbouncer K-Slice 6 once the MCP path needs it.
	TaskOwner string

	// TLSCertPath / TLSKeyPath, when both non-empty, switch the inbound
	// listener from plain HTTP to HTTPS. K-Slice 4. The cert is loaded
	// at Serve() time; tests can call ServeListener with a pre-built
	// tls.Listener to bypass file I/O.
	//
	// Plain HTTP is preserved as the default so the "I just installed;
	// testing" loop doesn't need cert generation. Operators who want
	// HTTPS run `kbouncer init-tls` once + pass --tls-cert / --tls-key
	// on subsequent runs.
	TLSCertPath string
	TLSKeyPath  string

	// RequireClientCertCAPath, when non-empty, opts the listener into
	// mTLS: inbound connections MUST present a client certificate
	// signed by the CA bundle at this path. Defaults to no client-cert
	// requirement (any TCP client that completes a TLS handshake can
	// reach the proxy). This is the "only my kubectl context can
	// connect" tier; the operator must supply the CA bundle (kbouncer
	// does not issue client certs — see internal/tlsmat for why).
	//
	// Ignored when TLSCertPath / TLSKeyPath are unset (mTLS without
	// TLS is meaningless).
	RequireClientCertCAPath string

	// AuditEmitter, when non-nil, receives every decision event the
	// proxy makes — fanned out to a JSONL log file + an optional
	// HTTPS webhook by the audit Manager. Slice 1 of the security-
	// team audit-export feature (see [[security-team-audit-export]]).
	// nil disables both channels; the SQLite audit row written via
	// writeDecisionForTask is still the canonical source of truth
	// regardless.
	AuditEmitter audit.Emitter

	// AgentRegistry, when non-nil, is the in-process map of
	// MCP-session-id → AgentInfo populated by the MCP server's
	// initialize handler. Proxy hot-path reads it on each inbound
	// request that carries the X-Kbouncer-Session-Id header so the
	// resulting audit event inherits the bound agent identity. Per
	// [[agent-identity-in-audit]] Feature 2. nil disables the lookup
	// (audit row still emits a User-Agent-derived agent block).
	AgentRegistry *audit.Registry
}

// DefaultConfig returns the production-safe defaults applied when CLI
// flags / construction omit them.
func DefaultConfig() Config {
	return Config{
		Host:              "127.0.0.1",
		Port:              8766,
		Mode:              ModeCooperative,
		DefaultPolicy:     DefaultPolicyDeny,
		SyncPromptTimeout: DefaultSyncPromptTimeout,
		SyncPromptDefault: DefaultPolicyDeny,
	}
}

// DefaultSyncPromptTimeout is the wait the sync deny-prompt flow uses
// when SyncPromptOnDeny is on but SyncPromptTimeout is unset. 30s is
// long enough for an operator to switch windows + read the prompt
// without making an automation pipeline visibly stall.
const DefaultSyncPromptTimeout = 30 * time.Second

// MinSyncPromptTimeout / MaxSyncPromptTimeout bound what the CLI will
// accept. <5s is shorter than realistic human reaction; >300s is long
// enough that the agent client's own request timeout fires first and
// confuses the audit trail.
const (
	MinSyncPromptTimeout = 5 * time.Second
	MaxSyncPromptTimeout = 300 * time.Second
)

// Normalize fills in any zero-valued fields on c with DefaultConfig()
// values and returns the resulting Config. Callers (Serve, tests,
// CLI) use it so a partially-populated Config still has the expected
// defaults applied consistently.
func (c Config) Normalize() Config {
	d := DefaultConfig()
	if c.Host == "" {
		c.Host = d.Host
	}
	if c.Port == 0 {
		c.Port = d.Port
	}
	if c.Mode == "" {
		c.Mode = d.Mode
	}
	if c.DefaultPolicy == "" {
		c.DefaultPolicy = d.DefaultPolicy
	}
	if c.SyncPromptTimeout == 0 {
		c.SyncPromptTimeout = d.SyncPromptTimeout
	}
	if c.SyncPromptDefault == "" {
		c.SyncPromptDefault = d.SyncPromptDefault
	}
	return c
}

// RequestObservation is what the proxy observed + decided about one
// inbound HTTP request. Surfaced as the JSON response body in K-Slice 1
// so tests, CLI inspection, and future tooling can consume verdicts
// without parsing logs.
type RequestObservation struct {
	At                time.Time `json:"at"`
	Method            string    `json:"method"`
	Path              string    `json:"path"`
	ParsedVerb        string    `json:"parsed_verb,omitempty"`
	ParsedGroup       string    `json:"parsed_group,omitempty"`
	ParsedVersion     string    `json:"parsed_version,omitempty"`
	ParsedResource    string    `json:"parsed_resource,omitempty"`
	ParsedNamespace   string    `json:"parsed_namespace,omitempty"`
	ParsedName        string    `json:"parsed_name,omitempty"`
	ParsedSubresource string    `json:"parsed_subresource,omitempty"`
	IsWatch           bool      `json:"is_watch"`
	IsDryRun          bool      `json:"is_dry_run"`
	DecisionVerdict   string    `json:"decision_verdict"`
	DecisionReason    string    `json:"decision_reason"`
	ModeAtDecision    string    `json:"mode_at_decision"`
	// Enforced is true only when mode=transparent AND verdict=deny.
	// In cooperative mode every verdict has Enforced=false (advisory).
	Enforced bool `json:"enforced"`
	// DecisionSource names the rule layer that produced the verdict.
	// Known values: "profile" (K-Slice 7), "task" (K-Slice 3),
	// "global" (K-Slice 3), "default" (no rule matched; fell through to
	// the default policy), "unclassifiable" (parser rejected the URL).
	// Surfaced into the audit log so reviewers can answer "which layer
	// blocked this?" without re-running the request.
	DecisionSource string `json:"decision_source"`
	// ProfileName names the active profile at decision time, or "" when
	// no profile is active. Carried into the audit row so the operator
	// can correlate "we changed profiles at 14:02" with a wave of denies.
	ProfileName string `json:"profile_name,omitempty"`

	// StreamKind, set in K-Slice 5, names the streaming code path the
	// proxy chose for this request: "watch" (chunked-body forwarder),
	// "spdy" (hijack + bidirectional pipe for exec/port-forward/attach/
	// websocket), or "" (the K-Slice 2 buffered REST path). Carried
	// into the audit row so post-hoc review can filter to "show me
	// only the exec sessions" without re-parsing URL shapes.
	StreamKind string `json:"stream_kind,omitempty"`

	// DecisionID is the audit-row id assigned to this decision (the
	// SQLite AUTOINCREMENT pk on decisions). Zero when no store was
	// configured (pure-evaluation unit tests) or the write failed.
	// Surfaced into the observation so the handle() sync-prompt path
	// can pass it through to AddSyncPendingPrompt without re-querying.
	// Not JSON-serialized into the observation-only response body —
	// the audit row id is an internal handle, not part of the agent-
	// facing contract.
	DecisionID int64 `json:"-"`
}

// Verdict values used in observations + the audit log.
const (
	VerdictAllow = "allow"
	VerdictDeny  = "deny"
)

// DecisionSource constants name the rule layer that produced a verdict.
// Mirrors the columns the audit-review tooling joins on across kbouncer
// and iam-jit-bouncer — keep these strings stable.
const (
	// SourceProfile means an environment profile (K-Slice 7) fired the
	// verdict. Profile denies are a hard floor: a permissive task scope
	// cannot override them.
	SourceProfile = "profile"
	// SourceTask means the active per-task scope (K-Slice 3) fired.
	SourceTask = "task"
	// SourceGlobal means a global rule (K-Slice 3) fired.
	SourceGlobal = "global"
	// SourceDefault means no rule matched and the default policy applied.
	SourceDefault = "default"
	// SourceUnclassifiable means the parser could not classify the URL.
	SourceUnclassifiable = "unclassifiable"
)

// DecisionSourceHeader is the HTTP response header the proxy sets on
// every gated request. Lowercase ASCII; HTTP normalizes header names
// case-insensitively but cURL prints the literal we send.
//
// Tests + the read-only audit CLI key off this header to confirm WHICH
// layer produced the verdict without parsing the JSON body.
const DecisionSourceHeader = "x-kbouncer-decision-source"

// EvaluateRequest is the pure-function evaluator for one inbound HTTP
// request. It parses, runs the (currently minimal) rule engine, and
// records the decision to the store.
//
// Backwards-compatible thin wrapper around EvaluateRequestWithProfile —
// kept so K-Slice 1 callers (and the original test suite) keep working
// unchanged. New callers should prefer EvaluateRequestWithProfile so
// they get profile evaluation, cluster context, and decision_source
// labelling.
//
// store may be nil during pure-evaluation unit tests; if so, no audit
// row is written. Production callers always pass a real store.
func EvaluateRequest(r *http.Request, st *store.Store, mode Mode, defaultPolicy DefaultPolicy) *RequestObservation {
	return EvaluateRequestWithProfile(r, st, mode, defaultPolicy, nil, "")
}

// EvalOptions controls the optional behaviors layered onto the basic
// evaluator (#6a pause-aware enforcement, #5 prompt-on-deny enqueue,
// K-Slice 3 task scope owner filter). Plain struct so the call site
// stays readable; a nil/zero value disables the optional behaviors
// and reproduces the K-Slice 7 EvaluateRequestWithProfile semantics.
type EvalOptions struct {
	// PromptOnDeny mirrors Config.PromptOnDeny — when true, every
	// transparent-mode DENY writes a pending_prompts row.
	PromptOnDeny bool

	// SyncPromptOnDeny mirrors Config.SyncPromptOnDeny. When true, the
	// evaluator SKIPS the async PromptOnDeny enqueue (the handle()
	// path will run AddSyncPendingPrompt itself with a sync_wait_id —
	// we don't want both an async row AND a sync row for the same
	// decision; the sync flow's row IS the answer surface).
	SyncPromptOnDeny bool

	// TaskOwner names the owner slot whose active task scope (if any)
	// is consulted by K-Slice 3's task-aware decision flow. Empty
	// string = the default-owner slot (single-laptop / single-session
	// deployment; matches Python iam-jit-bouncer Slice B). Mirrors
	// Config.TaskOwner; the proxy server populates it from there.
	TaskOwner string

	// StreamKind, set by the proxy in K-Slice 5, tags the decision row
	// so reviewers can answer "did this open a long-lived stream?"
	// without re-parsing the request URL. One of: "watch", "spdy", ""
	// (not a stream). Pure-evaluator callers (tests) leave it empty.
	StreamKind string

	// AuditEmitter, when non-nil, receives a copy of every decision
	// as a structured Event for fan-out to the JSONL log file +
	// HTTPS webhook (security-team audit-export, Slice 1). nil
	// disables the export channels; the SQLite audit row is still
	// written either way.
	AuditEmitter audit.Emitter

	// AuditHost / AuditUpstream populate the schema's host + upstream
	// fields. Set by the proxy server from Config.Host:Port + the
	// resolved upstream URL. Pure-evaluator callers leave both empty.
	AuditHost     string
	AuditUpstream string

	// AuditProfileSource carries the active profile's Source URL into
	// the audit event so the Slice 2 non_org_profile_install rule can
	// flag decisions backed by a non-allowlisted profile. Empty / "local"
	// = user-edited (no alert); an https URL = installed via
	// `kbounce profile install --from URL`. The proxy server populates
	// it from Config.ActiveProfile.Source.
	AuditProfileSource string

	// AgentRegistry, when non-nil, is consulted to resolve an MCP
	// session-id header on the inbound request into a registered
	// AgentInfo (per [[agent-identity-in-audit]] Feature 2). When the
	// header is absent (e.g. raw kubectl call) the evaluator falls back
	// to User-Agent fingerprinting; both sources land in the OCSF
	// unmapped.iam_jit.agent block. Pure-evaluator callers leave it
	// nil — the audit row still emits a default {name:"unknown",
	// detected_from:"unknown"} block.
	AgentRegistry *audit.Registry
}

// SessionHeaderName is the inbound HTTP header an MCP-aware client can
// set to bind a proxied SDK call to an MCP session ID. The proxy
// looks this up in opts.AgentRegistry to inherit the session's bound
// agent fingerprint. Lowercase per Go's HTTP header normalization;
// kept distinct from the bouncer's response headers (x-kbouncer-*).
//
// Per [[agent-identity-in-audit]] Don't list: session IDs are UUID v7
// (random) so an inbound header value that doesn't match a registered
// session is recorded as-is (best-effort) but NEVER trusted to inherit
// another session's agent identity.
const SessionHeaderName = "X-Kbouncer-Session-Id"

// EvaluateRequestWithProfile is the K-Slice 7 evaluator. It runs the
// composition order documented on the profile package:
//
//  1. Profile rules (deny_keywords, only_clusters, deny_verbs) — hard floor
//  2. Per-task scope     (K-Slice 3)
//  3. Global rule engine (K-Slice 3)
//  4. Default policy     (fall-through)
//
// activeProfile may be nil (or the "none" profile) to disable profile
// evaluation entirely. cluster is the kubeconfig cluster name when
// known; surfaced into the profile's ParsedRequest for only_clusters
// matching. Empty cluster + a profile with only_clusters set will deny
// fail-closed (we can't prove the request targets an allowed cluster).
//
// Side effect: writes the decision row to store. Audit-write failures
// are logged at WARN but never propagated — same policy as iam-jit-bouncer.
func EvaluateRequestWithProfile(
	r *http.Request,
	st *store.Store,
	mode Mode,
	defaultPolicy DefaultPolicy,
	activeProfile *profile.Profile,
	cluster string,
) *RequestObservation {
	return EvaluateRequestFull(r, st, mode, defaultPolicy, activeProfile, cluster, EvalOptions{})
}

// EvaluateRequestFull is the full-shape evaluator that also threads
// EvalOptions (#6a pause-aware enforcement, #5 prompt-on-deny
// enqueue). The earlier EvaluateRequest / EvaluateRequestWithProfile
// shapes are kept as thin wrappers so K-Slice 1 + 7 callers keep
// working unchanged.
func EvaluateRequestFull(
	r *http.Request,
	st *store.Store,
	mode Mode,
	defaultPolicy DefaultPolicy,
	activeProfile *profile.Profile,
	cluster string,
	opts EvalOptions,
) *RequestObservation {
	now := time.Now().UTC()
	mode = normalizeMode(mode)
	defaultPolicy = normalizeDefaultPolicy(defaultPolicy)

	// Resolve the per-request agent-identity record once at the top
	// of the evaluator so every emitAuditEvent branch carries the
	// SAME agent block. Per [[agent-identity-in-audit]] the priority
	// is: registered MCP session-id header > User-Agent fingerprint
	// > empty (audit defaults to "unknown" / "unknown").
	agentInfo := resolveAgentInfo(opts, r)

	// #6a — timed bypass / "pause." If an operator-initiated pause is
	// active, the proxy demotes effective behavior to COOPERATIVE for
	// this decision: the verdict text is preserved (so audit reviewers
	// see what WOULD have been denied) but enforcement is suspended.
	// The pause_id is recorded on the audit row so reviewers can ask
	// "what calls happened inside the pause window?" with a single
	// SQL filter.
	//
	// Per [[safety-mode-lean-permissive]]: the audit trail does the
	// work; the bypass is acceptable precisely because every call
	// during it is logged with pause_id linkage + the pause itself is
	// its own audit row.
	var activePause *store.PauseRow
	if st != nil {
		ap, err := st.GetActivePause()
		if err != nil {
			recordLookupError(err, "kbounce: pause-lookup failed")
		} else {
			activePause = ap
		}
	}
	effectiveMode := mode
	if activePause != nil && mode == ModeTransparent {
		effectiveMode = ModeCooperative
	}

	parsed, err := parser.Parse(r)
	if err != nil || parsed == nil {
		// Unclassifiable — synthetic deny so the forwarding layer
		// (K-Slice 2) refuses. Cooperative mode still logs but does
		// not enforce; transparent mode 403s the client.
		path := ""
		method := ""
		if r != nil {
			if r.URL != nil {
				path = r.URL.Path
				if r.URL.RawQuery != "" {
					path = path + "?" + r.URL.RawQuery
				}
			}
			method = r.Method
		}
		obs := &RequestObservation{
			At:              now,
			Method:          method,
			Path:            path,
			DecisionVerdict: VerdictDeny,
			DecisionReason:  "unclassifiable request — does not match any known kube-apiserver URL shape",
			ModeAtDecision:  string(effectiveMode),
			Enforced:        effectiveMode == ModeTransparent,
			DecisionSource:  SourceUnclassifiable,
			StreamKind:      opts.StreamKind,
		}
		decisionID := writeDecision(st, obs, activePause)
		emitAuditEvent(opts, agentInfo, obs, parsed, "", activePause)
		maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
		return obs
	}

	obs := &RequestObservation{
		At:                now,
		Method:            parsed.Method,
		Path:              parsed.RawPath,
		ParsedVerb:        parsed.Verb,
		ParsedGroup:       parsed.Group,
		ParsedVersion:     parsed.Version,
		ParsedResource:    parsed.Resource,
		ParsedNamespace:   parsed.Namespace,
		ParsedName:        parsed.Name,
		ParsedSubresource: parsed.Subresource,
		IsWatch:           parsed.IsWatch,
		IsDryRun:          parsed.IsDryRun,
		ModeAtDecision:    string(effectiveMode),
		StreamKind:        opts.StreamKind,
	}
	if activeProfile != nil {
		obs.ProfileName = activeProfile.Name
	}

	// Composition order step 1: profile rules. Profile denies are a hard
	// floor — a permissive task scope or global rule cannot override
	// them. Short-circuit on a profile deny so the audit row + response
	// header surface SourceProfile.
	if activeProfile != nil {
		pv := activeProfile.Evaluate(&profile.ParsedRequest{
			Verb:             parsed.Verb,
			Method:           parsed.Method,
			Group:            parsed.Group,
			Resource:         parsed.Resource,
			Subresource:      parsed.Subresource,
			Namespace:        parsed.Namespace,
			ResourceName:     parsed.Name,
			Cluster:          cluster,
			IsDryRun:         parsed.IsDryRun,
			IsImpersonation:  parsed.IsImpersonation,
			ImpersonatedUser: parsed.ImpersonatedUser,
		})
		if pv.Denied {
			obs.DecisionVerdict = VerdictDeny
			obs.DecisionReason = pv.Reason
			obs.DecisionSource = SourceProfile
			obs.Enforced = effectiveMode == ModeTransparent
			decisionID := writeDecision(st, obs, activePause)
			emitAuditEvent(opts, agentInfo, obs, parsed, "", activePause)
			maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
			return obs
		}
	}

	// K-Slice 3: build the request view the rule + task engines consume.
	// Same parser output, just reshaped into the rules package's
	// ParsedRequest (kept distinct from parser.ParsedRequest so the
	// rule engine has no parser-package dependency — symmetric to the
	// profile.ParsedRequest separation).
	ruleReq := &rules.ParsedRequest{
		Verb:        parsed.Verb,
		Resource:    parsed.Resource,
		Namespace:   parsed.Namespace,
		Name:        parsed.Name,
		Group:       parsed.Group,
		Subresource: parsed.Subresource,
	}

	// Composition order step 2: active task scope (if any). Load via
	// the store's owner-scoped lookup; auto-expires past-due tasks
	// before returning. Task-explicit-deny wins over everything below
	// (and over global allow). Task-allow narrows the agent's positive
	// declaration but does NOT lift profile-denies (those already
	// short-circuited above).
	var activeTask *tasks.Scope
	if st != nil {
		at, terr := st.GetActiveTask(opts.TaskOwner)
		if terr != nil {
			// Read failure: log + fall through as "no active task" so
			// a transient SQLite hiccup doesn't crash the proxy. Same
			// policy as the pause lookup above.
			recordLookupError(terr, "kbounce: active-task lookup failed")
		} else {
			activeTask = at
		}
	}
	if activeTask != nil {
		if td := activeTask.DenyRuleSet().Evaluate(ruleReq); td != nil {
			obs.DecisionVerdict = VerdictDeny
			obs.DecisionReason = fmt.Sprintf(
				"task-explicit-deny rule (task %s, pattern %q)",
				activeTask.TaskID, td.Rule.Pattern)
			obs.DecisionSource = SourceTask
			obs.Enforced = effectiveMode == ModeTransparent
			decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID)
			emitAuditEvent(opts, agentInfo, obs, parsed, activeTask.TaskID, activePause)
			maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
			return obs
		}
	}

	// Composition order step 3: global rules from the rules table.
	// Loaded fresh per decision in K-Slice 3 (small table; if it grows
	// we'll add an in-memory cache invalidated by a config-event hook).
	// Global explicit-deny ALWAYS wins (the admin's baseline can't be
	// overridden by a task-allow). Global explicit-allow stands when
	// there's no active task; with a task active, it composes with the
	// task-allow flow per the iam-jit-bouncer Python decisions order.
	var ruleSet *rules.RuleSet
	if st != nil {
		rs, rerr := st.LoadRuleSet()
		if rerr != nil {
			recordLookupError(rerr, "kbounce: load ruleset failed")
		} else {
			ruleSet = rs
		}
	}
	var globalMatch *rules.EvalResult
	if ruleSet != nil {
		globalMatch = ruleSet.Evaluate(ruleReq)
	}
	if globalMatch != nil && globalMatch.Effect == rules.EffectDeny {
		// Global explicit-deny — fires regardless of any task scope.
		obs.DecisionVerdict = VerdictDeny
		obs.DecisionReason = fmt.Sprintf(
			"explicit-deny rule (pattern %q)", globalMatch.Rule.Pattern)
		obs.DecisionSource = SourceGlobal
		obs.Enforced = effectiveMode == ModeTransparent
		decisionID := writeDecisionForTaskMaybe(st, obs, activePause, activeTask)
		emitAuditEvent(opts, agentInfo, obs, parsed, activeTaskID(activeTask), activePause)
		maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
		return obs
	}

	// Composition order step 4: task-allow (when a task is active).
	// A task-allow match → ALLOW (the agent's positive declaration is
	// what the task is for; global-deny already handled above).
	if activeTask != nil {
		if ta := activeTask.AllowRuleSet().Evaluate(ruleReq); ta != nil && ta.Effect == rules.EffectAllow {
			obs.DecisionVerdict = VerdictAllow
			obs.DecisionReason = fmt.Sprintf(
				"task-allow rule (task %s, pattern %q)",
				activeTask.TaskID, ta.Rule.Pattern)
			obs.DecisionSource = SourceTask
			obs.Enforced = false
			decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID)
			emitAuditEvent(opts, agentInfo, obs, parsed, activeTask.TaskID, activePause)
			maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
			return obs
		}
		// No task-allow match. Two sub-cases (mirror Python decisions.py):
		//   (a) Global ALLOW matched → ALLOW (the global baseline still
		//       blessed this call; the task scope didn't narrow it but
		//       didn't reject it either).
		//   (b) Otherwise → DENY out-of-task-scope. With a task active,
		//       the agent's positive declaration IS the allowlist —
		//       unmatched-by-task = "not part of the task; deny."
		if globalMatch != nil && globalMatch.Effect == rules.EffectAllow {
			obs.DecisionVerdict = VerdictAllow
			obs.DecisionReason = fmt.Sprintf(
				"explicit-allow rule (global, pattern %q; not declared in task %s)",
				globalMatch.Rule.Pattern, activeTask.TaskID)
			obs.DecisionSource = SourceGlobal
			obs.Enforced = false
			decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID)
			emitAuditEvent(opts, agentInfo, obs, parsed, activeTask.TaskID, activePause)
			maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
			return obs
		}
		obs.DecisionVerdict = VerdictDeny
		obs.DecisionReason = fmt.Sprintf(
			"out-of-task-scope (task %s active; unmatched by task allow rules)",
			activeTask.TaskID)
		obs.DecisionSource = SourceTask
		obs.Enforced = effectiveMode == ModeTransparent
		decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID)
		emitAuditEvent(opts, agentInfo, obs, parsed, activeTask.TaskID, activePause)
		maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
		return obs
	}

	// No active task: a global explicit-allow stands if it matched.
	if globalMatch != nil && globalMatch.Effect == rules.EffectAllow {
		obs.DecisionVerdict = VerdictAllow
		obs.DecisionReason = fmt.Sprintf(
			"explicit-allow rule (pattern %q)", globalMatch.Rule.Pattern)
		obs.DecisionSource = SourceGlobal
		obs.Enforced = false
		decisionID := writeDecision(st, obs, activePause)
		emitAuditEvent(opts, agentInfo, obs, parsed, "", activePause)
		maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
		return obs
	}

	// Composition order step 5: default policy fallthrough.
	verdict := VerdictAllow
	reason := "default policy: allow (no rule matched)"
	if defaultPolicy == DefaultPolicyDeny {
		verdict = VerdictDeny
		reason = "default policy: deny (no rule matched)"
	}
	obs.DecisionVerdict = verdict
	obs.DecisionReason = reason
	obs.DecisionSource = SourceDefault
	obs.Enforced = effectiveMode == ModeTransparent && verdict == VerdictDeny

	decisionID := writeDecision(st, obs, activePause)
	emitAuditEvent(opts, agentInfo, obs, parsed, activeTaskID(activeTask), activePause)
	maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
	return obs
}

// activeTaskID returns the active task id when t is non-nil, "" otherwise.
// Centralizes the nil-check so the emit-event call sites stay readable.
func activeTaskID(t *tasks.Scope) string {
	if t == nil {
		return ""
	}
	return t.TaskID
}

// emitAuditEvent fans the canonical DecisionInput off to the
// audit.Emitter (security-team audit-export, Slice 1) when one is
// configured. No-op when opts.AuditEmitter is nil — both export
// channels are opt-in; the SQLite audit row is the canonical
// source of truth regardless.
//
// Per [[security-team-audit-export]]: this is the SINGLE call site
// in the proxy that publishes export events. The Emit method is
// non-blocking by contract (bounded chans + drop-on-overflow on
// each consumer), so the proxy hot-path never waits on disk or
// network here.
//
// Per [[agent-identity-in-audit]]: the request's User-Agent + (when
// set) X-Kbouncer-Session-Id header populate the OCSF agent block.
// MCP-bound sessions (resolved via opts.AgentRegistry) take priority
// over UA fingerprinting since the clientInfo handshake is higher-
// fidelity than UA parsing.
func emitAuditEvent(opts EvalOptions, agent audit.AgentInfo, obs *RequestObservation, parsed *parser.ParsedRequest, taskID string, activePause *store.PauseRow) {
	if opts.AuditEmitter == nil {
		return
	}
	in := audit.DecisionInput{
		At:             obs.At,
		DecisionID:     obs.DecisionID,
		Mode:           obs.ModeAtDecision,
		Profile:        obs.ProfileName,
		Verdict:        obs.DecisionVerdict,
		Reason:         obs.DecisionReason,
		DecisionSource: obs.DecisionSource,
		Enforced:       obs.Enforced,
		Host:           opts.AuditHost,
		Upstream:       opts.AuditUpstream,
		Method:         obs.Method,
		Path:           obs.Path,
		StreamKind:     obs.StreamKind,
		TaskID:         taskID,
		ProfileSource:  opts.AuditProfileSource,
		AdminFallback:  activePause != nil,
		Agent:          agent,
	}
	if parsed != nil {
		in.ParsedVerb = parsed.Verb
		in.ParsedGroup = parsed.Group
		in.ParsedVersion = parsed.Version
		in.ParsedResource = parsed.Resource
		in.ParsedNamespace = parsed.Namespace
		in.ParsedName = parsed.Name
		in.ParsedSubresource = parsed.Subresource
		in.IsWatch = parsed.IsWatch
		in.IsDryRun = parsed.IsDryRun
	}
	ev := audit.FromDecision(in)
	opts.AuditEmitter.Emit(context.Background(), ev)
}

// resolveAgentInfo derives the per-request AgentInfo from (in
// priority order, per [[agent-identity-in-audit]]):
//
//  1. X-Kbouncer-Session-Id header → AgentRegistry lookup. The MCP
//     server registers its clientInfo + session-id at handshake; a
//     proxied SDK call that carries the header inherits the bound
//     agent identity.
//  2. User-Agent header → audit.FingerprintFromUserAgent. kubectl /
//     client-go / helm / k9s / etc. all carry distinctive UA strings.
//  3. nil request → empty AgentInfo (audit emits the default
//     {name:"unknown", detected_from:"unknown"} block).
//
// Process-tree fingerprinting is NOT performed here — the proxy
// sees an inbound TCP connection but not the client PID (would
// require platform-specific /proc/net/tcp lookups for inode → pid
// resolution, which is fragile + Linux-only). The MCP server does
// process-tree detection at handshake-time when stdio gives a clean
// parent-PID anchor.
func resolveAgentInfo(opts EvalOptions, r *http.Request) audit.AgentInfo {
	if r == nil {
		return audit.AgentInfo{}
	}
	if opts.AgentRegistry != nil {
		if sid := r.Header.Get(SessionHeaderName); sid != "" {
			info := opts.AgentRegistry.Lookup(sid)
			if info.Name != "" {
				return info
			}
			// Header set but not registered → record the session id
			// untrusted (best-effort) + still derive name from UA.
			ua := audit.FingerprintFromUserAgent(r.Header.Get("User-Agent"))
			ua.SessionID = sid
			return ua
		}
	}
	return audit.FingerprintFromUserAgent(r.Header.Get("User-Agent"))
}

// maybeEnqueuePrompt writes a pending_prompts row when ALL of:
// PromptOnDeny=true, the *originally-requested* mode is transparent
// (cooperative DENYs are advisory; no prompt to surface), the verdict
// is DENY, and no pause is active (a pause already bypasses
// enforcement; the agent isn't being denied).
//
// `mode` is the originally-requested mode, NOT effectiveMode — once a
// pause is active we KNOW we don't want to enqueue, but we still
// shouldn't enqueue for cooperative-mode requests just because they
// were demoted to cooperative for unrelated reasons. The pause guard
// below makes that distinction safe.
//
// #203 — SyncPromptOnDeny SUPERSEDES PromptOnDeny: when sync mode is
// on, this function is a no-op. The handle() path runs
// AddSyncPendingPrompt itself with a fresh sync_wait_id so the row
// + the in-memory waiter are created atomically.
func maybeEnqueuePrompt(
	st *store.Store,
	opts EvalOptions,
	mode Mode,
	activePause *store.PauseRow,
	decisionID int64,
	obs *RequestObservation,
	parsed *parser.ParsedRequest,
) {
	if st == nil || decisionID <= 0 {
		return
	}
	if opts.SyncPromptOnDeny {
		// Sync flow takes ownership of the enqueue; don't write an async
		// row too — the audit story would be confusing (two prompts for
		// one decision) + the operator could end up answering the wrong
		// one.
		return
	}
	if !opts.PromptOnDeny {
		return
	}
	if mode != ModeTransparent {
		// Cooperative-mode DENYs never actually block the agent; no
		// reason to surface a prompt. Matches the Python behavior.
		return
	}
	if obs.DecisionVerdict != VerdictDeny {
		return
	}
	if activePause != nil {
		// Pause already bypasses enforcement — agent isn't denied;
		// nothing to prompt about.
		return
	}
	input := store.PromptInput{
		DecisionID: decisionID,
		DenyReason: obs.DecisionReason,
	}
	if parsed != nil {
		input.Verb = parsed.Verb
		input.Group = parsed.Group
		input.Version = parsed.Version
		input.Resource = parsed.Resource
		input.Namespace = parsed.Namespace
		input.Name = parsed.Name
	}
	if _, err := st.AddPendingPrompt(input); err != nil {
		recordLookupError(err, "kbounce: prompt-enqueue failed")
	}
}

// writeDecision persists the observation + returns the assigned row
// id (0 when no row was written; callers gate the prompt-enqueue path
// on a positive id).
//
// Nil store is a no-op (test path). Write failures are logged but
// never propagated — audit-write failure is a high-signal alert but
// must NOT crash the proxy.
//
// activePause threads the pause window id (if any) so the decision
// row links back to the pause via decisions.pause_id — single-JOIN
// post-hoc review ("what calls happened inside pause N?").
func writeDecision(st *store.Store, obs *RequestObservation, activePause *store.PauseRow) int64 {
	return writeDecisionForTask(st, obs, activePause, "")
}

// writeDecisionForTask is the task-id-aware variant of writeDecision.
// Threads the active task_id onto the audit row so post-hoc per-task
// review (TaskReviewSummary) can join cleanly.
//
// Side effect: also stores the assigned id back onto obs.DecisionID
// so the handle() sync-prompt path can read it without round-tripping
// through the return value.
func writeDecisionForTask(st *store.Store, obs *RequestObservation, activePause *store.PauseRow, taskID string) int64 {
	if st == nil {
		return 0
	}
	row := store.DecisionRow{
		At:                obs.At,
		Method:            obs.Method,
		Path:              obs.Path,
		ParsedVerb:        obs.ParsedVerb,
		ParsedGroup:       obs.ParsedGroup,
		ParsedVersion:     obs.ParsedVersion,
		ParsedResource:    obs.ParsedResource,
		ParsedNamespace:   obs.ParsedNamespace,
		ParsedName:        obs.ParsedName,
		ParsedSubresource: obs.ParsedSubresource,
		IsWatch:           obs.IsWatch,
		IsDryRun:          obs.IsDryRun,
		DecisionVerdict:   obs.DecisionVerdict,
		DecisionReason:    obs.DecisionReason,
		ModeAtDecision:    obs.ModeAtDecision,
		Enforced:          obs.Enforced,
		DecisionSource:    obs.DecisionSource,
		ProfileName:       obs.ProfileName,
		TaskID:            taskID,
		IsStream:          obs.StreamKind != "",
		StreamKind:        obs.StreamKind,
	}
	if activePause != nil {
		pid := activePause.ID
		row.PauseID = &pid
	}
	id, err := st.RecordDecision(row)
	if err != nil {
		recordLookupError(err, "kbounce: audit-write failed")
		return 0
	}
	obs.DecisionID = id
	return id
}

// writeDecisionForTaskMaybe is a convenience wrapper that passes the
// task id when an active task exists, "" otherwise. Used by the
// global-deny branch where a task may or may not be active.
func writeDecisionForTaskMaybe(st *store.Store, obs *RequestObservation, activePause *store.PauseRow, activeTask *tasks.Scope) int64 {
	if activeTask == nil {
		return writeDecisionForTask(st, obs, activePause, "")
	}
	return writeDecisionForTask(st, obs, activePause, activeTask.TaskID)
}

func normalizeMode(m Mode) Mode {
	if m.IsValid() {
		return m
	}
	return ModeCooperative
}

func normalizeDefaultPolicy(p DefaultPolicy) DefaultPolicy {
	if p.IsValid() {
		return p
	}
	return DefaultPolicyDeny
}

// Server wraps the http.Server so callers can Serve + Shutdown
// cleanly during tests and CLI signal handling.
type Server struct {
	cfg   Config
	store *store.Store
	http  *http.Server
}

// lookupErrorsCounter is a process-wide counter of lookup-class
// failures the proxy has observed (pause lookup, active-task lookup,
// ruleset load, prompt enqueue, audit write). Surfaced via /healthz
// as `lookup_errors_counter` per UAT-K2 MED-K2-06 — mirrors the
// Python iam-jit-bouncer healthz field of the same name. Package-
// level + atomic so EvaluateRequestFull (a package function) can
// increment without changing function signatures. healthz reads it
// via LookupErrorsCount().
var lookupErrorsCounter atomic.Int64

// recordLookupError increments the lookup-error counter + logs the
// underlying error at WARN. Centralized so we have one definition of
// "what counts as a lookup error" for the healthz surface.
func recordLookupError(err error, msg string) {
	if err == nil {
		return
	}
	lookupErrorsCounter.Add(1)
	log.Warn().Err(err).Msg(msg)
}

// LookupErrorsCount returns the current value of the package-level
// lookup error counter. Exposed for test inspection + healthz.
func LookupErrorsCount() int64 {
	return lookupErrorsCounter.Load()
}

// ResetLookupErrorsCount zeros the counter. Test-only helper so
// independent tests can assert deltas without cross-test contamination.
func ResetLookupErrorsCount() {
	lookupErrorsCounter.Store(0)
}

// NewServer constructs the proxy server. The caller still has to call
// Serve to bind + accept. Useful for tests that want a configured
// server they can introspect before binding.
func NewServer(cfg Config, st *store.Store) *Server {
	cfg = cfg.Normalize()
	s := &Server{cfg: cfg, store: st}
	mux := http.NewServeMux()
	// /healthz is a liveness probe — never goes through proxy
	// evaluation (so it doesn't pollute the audit log), never
	// touches upstream. Returns 200 + a small JSON body that
	// callers (monit, k8s liveness probe, supervisor scripts) can
	// regex against. Registering BEFORE the catch-all "/" so the
	// exact-match path wins ServeMux precedence.
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/", s.handle)
	s.http = &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Addr returns the bound address, useful for tests using port 0.
func (s *Server) Addr() string { return s.http.Addr }

// SetAddr overrides the bound address. Tests use this with port 0 to
// pick an ephemeral port.
func (s *Server) SetAddr(addr string) { s.http.Addr = addr }

// Serve starts the listener and blocks until Shutdown is called or
// the listener errors. Returns http.ErrServerClosed on clean shutdown.
//
// When the Config has TLSCertPath + TLSKeyPath set, the listener
// speaks HTTPS (K-Slice 4). Otherwise plain HTTP (the default for the
// "I just installed; testing" loop).
func (s *Server) Serve() error {
	log.Info().
		Str("host", s.cfg.Host).
		Int("port", s.cfg.Port).
		Str("mode", string(s.cfg.Mode)).
		Str("default_policy", string(s.cfg.DefaultPolicy)).
		Bool("tls", s.cfg.TLSCertPath != "" && s.cfg.TLSKeyPath != "").
		Bool("require_client_cert", s.cfg.RequireClientCertCAPath != "").
		Msg("kbounce proxy starting")
	if s.cfg.TLSCertPath != "" && s.cfg.TLSKeyPath != "" {
		tlsCfg, err := s.buildListenerTLSConfig()
		if err != nil {
			return err
		}
		s.http.TLSConfig = tlsCfg
		// ListenAndServeTLS with empty cert/key strings honors the
		// pre-loaded tls.Config above. Lets us share the same code path
		// for both --tls-cert (file path) and --require-client-cert
		// (CA bundle file path).
		return s.http.ListenAndServeTLS("", "")
	}
	return s.http.ListenAndServe()
}

// buildListenerTLSConfig loads the cert + key (and the optional client-
// auth CA bundle) into a *tls.Config suitable for the inbound listener.
//
// Audit-cadence notes (per [[audit-cadence-discipline]]):
//   - MinVersion = TLS 1.2; we never negotiate TLS 1.0/1.1 inbound.
//   - When RequireClientCertCAPath is set, ClientAuth =
//     RequireAndVerifyClientCert (NOT VerifyClientCertIfGiven) — half-
//     enforced mTLS is a footgun + leaves the listener accepting
//     anonymous connections silently.
//   - We never set InsecureSkipVerify here — the inbound listener has
//     no upstream to verify; this flag would be a no-op + confusing in
//     review, so leave it absent.
func (s *Server) buildListenerTLSConfig() (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"kbounce: load TLS cert pair (%s / %s): %w",
			s.cfg.TLSCertPath, s.cfg.TLSKeyPath, err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}
	if s.cfg.RequireClientCertCAPath != "" {
		caBytes, err := os.ReadFile(s.cfg.RequireClientCertCAPath)
		if err != nil {
			return nil, fmt.Errorf(
				"kbounce: read client-cert CA bundle %q: %w",
				s.cfg.RequireClientCertCAPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf(
				"kbounce: client-cert CA bundle at %q is not valid PEM",
				s.cfg.RequireClientCertCAPath)
		}
		tlsCfg.ClientCAs = pool
		// CRIT note: RequireAndVerifyClientCert FAILS the handshake when
		// no client cert is presented. VerifyClientCertIfGiven would
		// permit anonymous clients silently — a footgun masquerading
		// as mTLS. We pick the strict shape on purpose.
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

// ServeListener starts serving on a pre-bound listener. Used by tests
// (httptest) and by the CLI when it wants to bind explicitly.
func (s *Server) ServeListener(l net.Listener) error {
	return s.http.Serve(l)
}

// Shutdown initiates a graceful shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// handle is the catch-all HTTP handler.
//
// K-Slice 2 behavior (this build):
//
//   - Evaluate the request (parser + profile + rule engine + default
//     policy). Same evaluator the K-Slice 1 + 7 tests exercise.
//   - On a transparent-mode DENY: return 403 with a K8s-shaped error
//     body (apiVersion: v1, kind: Status, status: Failure, code: 403)
//     so kubectl says "Error: ... forbidden" rather than "unparseable
//     JSON". Decision-source header still set.
//   - On an ALLOW (cooperative OR transparent) with an Upstream
//     configured: rewrite onto the upstream URL, strip hop-by-hop
//     headers, forward via the pooled http.Client, stream the response
//     back.
//   - On an ALLOW with NO upstream configured: fall back to K-Slice 1's
//     observation JSON body so the existing observation-only test
//     suite + the bare `kbouncer run` (no kubeconfig + no --upstream)
//     paths keep working.
//   - On an ALLOW where the inbound Host header points off-allowlist:
//     refuse with 403 + x-kbouncer-refusal=forward-host-mismatch.
//     Mirrors iam-jit-bouncer's CRIT-32-01 closure.
//   - On a forwarding failure (timeout, DNS, TLS, connection refused):
//     return 502 with a kbouncer-shaped JSON error so a debugging
//     operator can tell "the proxy reached but couldn't talk to the
//     apiserver" from "the proxy refused."
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// K-Slice 5: classify streaming BEFORE evaluating so the audit row
	// can be tagged is_stream + stream_kind. The classification is a
	// pure read of the inbound headers + query — no I/O.
	streamKind := classifyStream(r)

	// #203 — sync-prompt is only meaningful in transparent mode. The
	// CLI rejects --sync-prompt-on-deny in cooperative mode with a
	// warning, but be defensive here too: a config-built-in-process
	// (tests, library users) that sets the flag in cooperative mode
	// must not trigger the sync path. Compute the effective flag once
	// so EvalOptions + the post-eval guard both see the same value.
	syncPromptActive := s.cfg.SyncPromptOnDeny && s.cfg.Mode == ModeTransparent

	upstreamLabel := ""
	if s.cfg.Upstream != nil {
		upstreamLabel = s.cfg.Upstream.Host()
	}
	profileSource := ""
	if s.cfg.ActiveProfile != nil {
		profileSource = s.cfg.ActiveProfile.Source
	}
	obs := EvaluateRequestFull(
		r, s.store, s.cfg.Mode, s.cfg.DefaultPolicy,
		s.cfg.ActiveProfile, s.cfg.Cluster,
		EvalOptions{
			PromptOnDeny:       s.cfg.PromptOnDeny,
			SyncPromptOnDeny:   syncPromptActive,
			TaskOwner:          s.cfg.TaskOwner,
			StreamKind:         string(streamKind),
			AuditEmitter:       s.cfg.AuditEmitter,
			AuditHost:          net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port)),
			AuditUpstream:      upstreamLabel,
			AuditProfileSource: profileSource,
			AgentRegistry:      s.cfg.AgentRegistry,
		},
	)

	// Set the decision-source header BEFORE WriteHeader (Go HTTP
	// requires headers go in before the first WriteHeader / Write).
	w.Header().Set(DecisionSourceHeader, obs.DecisionSource)
	if obs.ProfileName != "" {
		w.Header().Set("x-kbouncer-profile", obs.ProfileName)
	}

	// Transparent + DENY → 403 with K8s-shaped error, no forward.
	// This branch fires BEFORE the streaming/hijack code so a denied
	// exec or watch never opens a long-lived connection. The audit
	// row is already written by EvaluateRequestFull (tagged with the
	// stream kind so reviewers see which exec the agent tried).
	if obs.Enforced {
		// #203 sync-prompt flow: if --sync-prompt-on-deny is set and
		// we have a store + a real audit row, block waiting for the
		// operator's answer instead of immediately 403'ing. An allow
		// answer is acted on by re-running the request through the
		// forwarding layer; a deny answer / timeout keeps the original
		// 403 behavior.
		if syncPromptActive && s.store != nil && obs.DecisionID > 0 {
			if s.handleSyncPromptDeny(w, r, obs) {
				return
			}
			// handleSyncPromptDeny returned false → it deferred back to
			// the default 403 path (operator answered "ignore" or
			// timeout chose deny). Fall through.
		}
		writeK8sForbidden(w, obs)
		return
	}

	// ALLOW (either mode) OR cooperative-mode DENY.
	// If no upstream configured, preserve K-Slice 1 observation JSON
	// behavior so existing tests + observation-only deploys keep
	// working unchanged.
	if s.cfg.Upstream == nil {
		writeObservationBody(w, obs)
		return
	}

	// Outbound host allowlist (mirror of iam-jit-bouncer CRIT-32-01).
	// The inbound Host header is attacker-controllable; reject anything
	// that doesn't match the upstream URL the operator pinned.
	inboundHost := r.Host
	if !hostAllowed(inboundHost, s.cfg.Upstream) {
		log.Warn().
			Str("inbound_host", inboundHost).
			Str("upstream_host", s.cfg.Upstream.Host()).
			Msg("kbounce: refused forward — inbound Host does not match upstream")
		writeHostMismatch(w, obs, inboundHost, s.cfg.Upstream.Host())
		return
	}

	// K-Slice 5: streaming paths.
	switch streamKind {
	case StreamKindWatch:
		forwardWatchStreaming(w, r, s.cfg.Upstream, obs)
		return
	case StreamKindSPDY:
		forwardUpgrade(w, r, s.cfg.Upstream, obs)
		return
	}

	// K-Slice 2 buffered path (the default for REST calls).
	upReq, err := buildUpstreamRequest(r, s.cfg.Upstream)
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: build upstream request failed")
		writeBadGateway(w, obs, err)
		return
	}

	resp, err := s.cfg.Upstream.Client.Do(upReq)
	if err != nil {
		log.Warn().Err(err).
			Str("upstream", upstreamURLForLog(s.cfg.Upstream.URL)).
			Msg("kbounce: forward to apiserver failed")
		writeBadGateway(w, obs, err)
		return
	}
	defer resp.Body.Close()

	writeUpstreamResponse(w, resp, obs)
}

// writeObservationBody is the observation-only JSON fallback used when
// no upstream apiserver is configured. Lets observation-only deploys +
// the test suite keep working unchanged.
//
// UAT-K2 MED-K2-04: the JSON wrapper field is `_observation_only_note`
// (renamed from `_slice1_note`, which leaked internal task
// terminology).
func writeObservationBody(w http.ResponseWriter, obs *RequestObservation) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	body := struct {
		Observation         *RequestObservation `json:"proxy_observation"`
		ObservationOnlyNote string              `json:"_observation_only_note"`
	}{
		Observation: obs,
		ObservationOnlyNote: "kbounce is running in observation-only mode (no " +
			"upstream apiserver configured). Decisions are logged + returned " +
			"as JSON; the kubectl / SDK client will NOT see a kube-apiserver " +
			"response shape. Configure --upstream or --kubeconfig to forward " +
			"ALLOW verdicts to a real apiserver.",
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode observation response failed")
	}
}

// writeK8sForbidden returns 403 with a K8s-shaped Status error body
// (apiVersion: v1, kind: Status). kubectl + client-go parse this
// shape natively and print a clean "Error: ... forbidden" instead of
// surfacing kbouncer's JSON as an unparseable response.
//
// Schema reference: kubernetes/apimachinery/pkg/apis/meta/v1/types.go
// (Status).
func writeK8sForbidden(w http.ResponseWriter, obs *RequestObservation) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(VerdictHeader, obs.DecisionVerdict)
	w.Header().Set("x-kbouncer-mode", obs.ModeAtDecision)
	w.WriteHeader(http.StatusForbidden)
	body := map[string]any{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message": "kbounce denied: " + obs.DecisionReason +
			" (decision_source=" + obs.DecisionSource + ")",
		"reason": "Forbidden",
		"details": map[string]any{
			"kbouncer_decision_source": obs.DecisionSource,
			"kbouncer_profile":         obs.ProfileName,
			"kbouncer_verb":            obs.ParsedVerb,
			"kbouncer_resource":        obs.ParsedResource,
			"kbouncer_namespace":       obs.ParsedNamespace,
		},
		"code": 403,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode forbidden response failed")
	}
}

// writeHostMismatch refuses with 403 + x-kbouncer-refusal=
// forward-host-mismatch. The body is kbouncer-shaped (NOT a K8s
// Status) because the request never reached the gating engine in a
// way the apiserver shape can sensibly describe — this is the proxy
// refusing to act as an exfil channel.
func writeHostMismatch(w http.ResponseWriter, obs *RequestObservation, inboundHost, upstreamHost string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(VerdictHeader, "deny")
	w.Header().Set(RefusalHeader, "forward-host-mismatch")
	w.WriteHeader(http.StatusForbidden)
	body := map[string]any{
		"error": "kbounce refused to forward — inbound Host does not match upstream",
		"refusal_reason": "The inbound Host header points to a target outside " +
			"the configured upstream apiserver. kbouncer refuses to act as a " +
			"redirector for attacker-controlled Host headers.",
		"inbound_host":  inboundHost,
		"upstream_host": upstreamHost,
		"verb":          obs.ParsedVerb,
		"resource":      obs.ParsedResource,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode host-mismatch response failed")
	}
}

// writeBadGateway returns 502 with a kbouncer-shaped JSON error. Used
// when the proxy reached the gating engine + decided to forward but
// the apiserver was unreachable / errored at the transport layer.
//
// Distinct from a K8s Status body so a debugging operator can tell
// "the apiserver rejected" (would have been a proxied response with
// real apiserver content) from "the proxy couldn't talk to the
// apiserver" (this branch).
func writeBadGateway(w http.ResponseWriter, obs *RequestObservation, cause error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(VerdictHeader, obs.DecisionVerdict)
	w.Header().Set("x-kbouncer-forward-error", "true")
	w.WriteHeader(http.StatusBadGateway)
	body := map[string]any{
		"error":          "kbounce forward to kube-apiserver failed",
		"upstream_error": cause.Error(),
		"verb":           obs.ParsedVerb,
		"resource":       obs.ParsedResource,
		"namespace":      obs.ParsedNamespace,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode bad-gateway response failed")
	}
}

// healthz responds 200 with a small JSON liveness payload. Bypasses
// proxy evaluation entirely — never writes to the audit log, never
// touches upstream — so monitoring probes don't show up as
// "decisions" in the operator's audit tail. Counts decisions as a
// liveness signal: if the underlying SQLite store can serve a
// COUNT(*), we're alive enough for traffic.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// HealthzPause is the small payload surfaced under "pause" when a
	// pause window is currently open. Lets monitors flag a window
	// that's still open (e.g. ops left it on overnight by mistake)
	// without us having to invent a separate probe endpoint.
	type HealthzPause struct {
		ID        int64  `json:"id"`
		StartedAt string `json:"started_at"`
		EndsAt    string `json:"ends_at"`
		Reason    string `json:"reason,omitempty"`
	}
	payload := struct {
		Status               string        `json:"status"`
		Mode                 string        `json:"mode"`
		DefaultPolicy        string        `json:"default_policy"`
		ActiveProfile        string        `json:"active_profile"`
		DecisionsCount       int64         `json:"decisions_count"`
		LookupErrorsCounter  int64         `json:"lookup_errors_counter"`
		Pause                *HealthzPause `json:"pause"`
	}{
		Status:              "ok",
		Mode:                string(s.cfg.Mode),
		DefaultPolicy:       string(s.cfg.DefaultPolicy),
		LookupErrorsCounter: LookupErrorsCount(),
	}
	if s.cfg.ActiveProfile != nil {
		payload.ActiveProfile = s.cfg.ActiveProfile.Name
	}
	if s.store != nil {
		if n, err := s.store.CountDecisions(); err == nil {
			payload.DecisionsCount = n
		} else {
			// Store unreachable — flip to degraded so liveness probes
			// can pick it up. Still 200 because the proxy process
			// itself is alive; readiness probes should use a
			// separate signal in a later slice if needed.
			payload.Status = "degraded"
		}
		// #6a — surface active pause window so monitors can flag a
		// window that's still open (e.g. ops left it on overnight by
		// mistake) without us having to invent a separate probe
		// endpoint. Pause-read failure is non-fatal: probes care
		// about liveness; the pause field will just be null.
		if active, err := s.store.GetActivePause(); err == nil && active != nil {
			payload.Pause = &HealthzPause{
				ID:        active.ID,
				StartedAt: active.StartedAt,
				EndsAt:    active.EndsAt,
				Reason:    active.Reason,
			}
		}
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode /healthz response failed")
	}
}

// EnsureLogger applies a minimal zerolog config when the caller has
// not set one. CLI calls this at startup so library users (tests)
// get plain JSON logs without configuring the logger themselves.
//
// Default level is InfoLevel — Debug-level entries (e.g. UAT-K2
// HIGH-K2-04's "no-kubeconfig" notice) stay quiet unless the operator
// opts into verbose logging via KBOUNCER_LOG_LEVEL=debug.
func EnsureLogger() {
	zerolog.TimeFieldFormat = time.RFC3339
	level := zerolog.InfoLevel
	if v := os.Getenv("KBOUNCER_LOG_LEVEL"); v != "" {
		if parsed, err := zerolog.ParseLevel(v); err == nil {
			level = parsed
		}
	}
	zerolog.SetGlobalLevel(level)
}

// ParseMode parses a CLI flag value into a Mode, returning an error
// for unknown values. Kept in the proxy package so cmd/ doesn't have
// to repeat the validation.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	if m.IsValid() {
		return m, nil
	}
	return "", fmt.Errorf("kbounce: unknown mode %q (want cooperative or transparent)", s)
}

// ParseDefaultPolicy parses a CLI flag value into a DefaultPolicy.
func ParseDefaultPolicy(s string) (DefaultPolicy, error) {
	p := DefaultPolicy(s)
	if p.IsValid() {
		return p, nil
	}
	return "", fmt.Errorf("kbounce: unknown default policy %q (want allow or deny)", s)
}

// ErrInvalidConfig is surfaced when a Config fails validation before
// Serve binds. Kept exported so callers can errors.Is check.
var ErrInvalidConfig = errors.New("kbounce: invalid proxy config")
