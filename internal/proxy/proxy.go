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
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/kbouncer/internal/audit"
	"github.com/trsreagan3/kbouncer/internal/dynamicdeny"
	"github.com/trsreagan3/kbouncer/internal/kbenv"
	"github.com/trsreagan3/kbouncer/internal/parser"
	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
	"github.com/trsreagan3/kbouncer/internal/structureddeny"
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

	// AuditHealthCheck, when non-nil, is called by /healthz to
	// determine whether the proxy should return 503 instead of 200.
	// Wired by the CLI to the audit Heartbeater's Healthy() method
	// (per [[prompt-injection-disable-bouncer-threat]] +
	// [[audit-export-failure-visibility]]): when the heartbeatGapRule
	// detects a missed-tick gap, the watchdog flips unhealthy and
	// /healthz starts returning 503 so an external supervisor (k8s
	// liveness probe, monit) sees the same silenced-audit-export
	// signal the SIEM-side `heartbeat_gap` rule trips on. nil = the
	// /healthz handler keeps its baseline 200 (healthcheck always
	// passes — heartbeat feature disabled).
	AuditHealthCheck func() bool

	// AgentRegistry, when non-nil, is the in-process map of
	// MCP-session-id → AgentInfo populated by the MCP server's
	// initialize handler. Proxy hot-path reads it on each inbound
	// request that carries the X-Kbouncer-Session-Id header so the
	// resulting audit event inherits the bound agent identity. Per
	// [[agent-identity-in-audit]] Feature 2. nil disables the lookup
	// (audit row still emits a User-Agent-derived agent block).
	AgentRegistry *audit.Registry

	// BulkAnswerThreshold tunes the burst detector that powers the
	// [[bulk-prompt-answer-ux]] memo. When N DENY prompts are enqueued
	// within BulkAnswerWindow seconds (defaults: 5 prompts in 60s),
	// the proxy emits a BURST_DETECTED event the operator's next
	// `kbounce prompts bulk-answer` call surfaces. Zero values fall
	// back to BurstThresholdDefault / BurstWindowDefault.
	BulkAnswerThreshold int
	BulkAnswerWindow    time.Duration
	BulkAnswerCooldown  time.Duration

	// AuditEventsToken (#271) is the bearer token clients must present
	// on GET /audit/events when the proxy is bound off-loopback. Empty +
	// loopback bind = no auth (the loopback bind is itself the trust
	// anchor); empty + external bind = the CLI refuses to start. The
	// audit-events handler reads this directly.
	AuditEventsToken string

	// DynamicDenyWatcher (#324b) is the kbouncer consumer of the
	// cross-product `~/.iam-jit/dynamic-denies.yaml` file. When non-nil,
	// the evaluator consults the watcher's snapshot AFTER profile +
	// meta-discovery short-circuits but BEFORE the per-task + global
	// rule evaluation, so a dynamic-deny match beats profile-allow +
	// task-allow + global-allow per the cross-product design doc's
	// "deny always wins over allow" rule. Per [[creates-never-mutates]]
	// the field is additive — when nil the evaluator behavior is
	// byte-identical to the pre-#324b shape. The audit event the
	// matcher produces carries `unmapped.iam_jit.ext.deny_source="dynamic"`
	// + `unmapped.iam_jit.ext.dynamic_deny_rule_id="dd_..."` so a SIEM
	// analyst can pivot on either field.
	DynamicDenyWatcher *dynamicdeny.Watcher

	// DiskPressure (#461 / §A63c) is the optional disk-pressure
	// circuit-breaker state. When non-nil the proxy:
	//   - surfaces an audit_log block on /healthz with disk usage +
	//     mode + refuse_requests flag,
	//   - returns 503 (with the #459 structured-deny shape) on every
	//     request when state.RefuseRequests() reports true (pause-
	//     requests mode at critical / emergency),
	//   - starts a background periodic goroutine in Serve() that ticks
	//     every DiskPressureCheckInterval to re-evaluate state +
	//     emit admin-action disk_pressure.transition OCSF events on
	//     status changes.
	// When nil the proxy behavior is byte-identical to the pre-#461
	// shape per [[creates-never-mutates]].
	DiskPressure *audit.DiskPressureState
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

	// DenySource is "dynamic" when a #324b dynamic-deny rule fired the
	// verdict, or "" when it didn't. Surfaces into the audit event
	// under `unmapped.iam_jit.ext.deny_source` so a SIEM analyst can
	// pivot on the source-flavor without re-parsing the rule body.
	// Per [[cross-product-agent-parity]] the wire shape mirrors
	// gbounce's deny_source field.
	DenySource string `json:"deny_source,omitempty"`

	// DynamicDenyRuleID is the `dd_<ULID>` id of the dynamic-deny rule
	// that fired (when DenySource == "dynamic"). Surfaces into the
	// audit event under `unmapped.iam_jit.ext.dynamic_deny_rule_id`.
	// Empty when no dynamic-deny rule fired.
	DynamicDenyRuleID string `json:"dynamic_deny_rule_id,omitempty"`
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
	// SourceProfileAllow means a profile allow_rule (composition Order 7)
	// explicitly allowed the request. Mirrors profile.SourceProfileAllow;
	// fires only after every profile deny layer + the dynamic-deny floor
	// abstained, and short-circuits before task + global rules.
	SourceProfileAllow = "profile.allow"
	// SourceTask means the active per-task scope (K-Slice 3) fired.
	SourceTask = "task"
	// SourceGlobal means a global rule (K-Slice 3) fired.
	SourceGlobal = "global"
	// SourceDefault means no rule matched and the default policy applied.
	SourceDefault = "default"
	// SourceUnclassifiable means the parser could not classify the URL.
	SourceUnclassifiable = "unclassifiable"
	// SourceMetaDiscovery means the parser identified the URL as a
	// kube-apiserver meta/discovery read (OpenAPI schema, API-version
	// list, /version, /healthz, /readyz, /livez, /metrics) — see
	// parser.ParsedRequest.IsMetaRead. The proxy short-circuits these
	// to ALLOW so kubectl + client-go bootstrap traffic doesn't get
	// blocked under safe-default (#301). Reported in the audit row so
	// reviewers can filter discovery noise out of decision queries.
	SourceMetaDiscovery = "meta-discovery"
	// SourceDynamic means a #324b dynamic-deny rule from
	// `~/.iam-jit/dynamic-denies.yaml` fired the verdict. The audit
	// event carries `unmapped.iam_jit.ext.deny_source="dynamic"` +
	// `unmapped.iam_jit.ext.dynamic_deny_rule_id="dd_..."` so a SIEM
	// analyst can pivot on either field. Dynamic-deny beats
	// profile-allow + task-allow + global-allow per the cross-product
	// design doc's "deny always wins over allow" rule.
	SourceDynamic = "dynamic-deny"
)

// DenySourceStatic + DenySourceDynamic are the canonical values
// surfaced on a deny audit event under `ext.deny_source`. Mirrors the
// gbounce #324d wire shape byte-for-byte per
// [[cross-product-agent-parity]]. kbouncer doesn't have a "static"
// dimension yet (profile / task / global denies don't claim the
// label), so the value is set ONLY when a dynamic-deny rule fires —
// the absence of the field means "not a dynamic deny."
const (
	DenySourceStatic  = "static"
	DenySourceDynamic = "dynamic"
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

	// BurstDetector, when non-nil, is fed by the prompt-enqueue path so
	// the [[bulk-prompt-answer-ux]] flow can surface a BURST_DETECTED
	// event after N async prompts in T seconds. Pure-evaluator callers
	// + the sync-prompt path leave it nil (sync-flow waiters do their
	// own UX; bulk-answer's target is the async per-call queue).
	BurstDetector *BurstDetector

	// OnPauseLookup, when non-nil, is invoked once per
	// EvaluateRequestFull call with the result of the proxy's
	// store.GetActivePause() lookup (nil when no pause is active).
	// Lets the Server hook the pause-lookup so it can detect
	// open-edge / close-edge transitions across requests + emit the
	// synthetic EventTypeAdminFallbackGrant + EventTypePauseEnd events
	// without the evaluator itself owning audit-event semantics. Per
	// [[security-team-audit-export]] the proxy hot-path is the single
	// observer wired to the audit emitter, so even pause state
	// mutations from one-shot CLI commands (`pause start` / `pause
	// stop`) get audit-exported through here on the next inbound
	// request. nil = no-op (test callers + the
	// EvaluateRequestWithProfile thin wrapper leave it unset).
	OnPauseLookup func(active *store.PauseRow)

	// RecordRejectedAgentHeader, when non-nil, is invoked once per
	// inbound `X-Agent-Name` or `X-Agent-Session-Id` header that fails
	// validation (#318 / §A16). The Server hooks this to bump a per-
	// Server `totalAgentHeadersRejected` counter surfaced on /healthz so
	// operators see agent-config drift the same way across the Bounce
	// suite. nil = silent rejection (pure-evaluator + test callers).
	// Per [[security-team-positioning-safety-not-surveillance]]: the
	// rejection is SAFETY (operator visibility); the value is NEVER
	// written into the audit event.
	RecordRejectedAgentHeader func(headerName, rawValue string)

	// DynamicDenies (#324b) is the in-memory snapshot of dynamic-deny
	// rules the evaluator consults AFTER profile + meta-discovery
	// short-circuits but BEFORE per-task + global rule evaluation.
	// nil disables the channel (pure-evaluator + test callers + the
	// pre-#324b shape — same shape as the rest of the optional behaviors
	// on EvalOptions). When non-nil, a Match → DENY verdict with
	// DenySource="dynamic" + DynamicDenyRuleID="dd_..." on the
	// observation. Mirrors gbounce's union-static-and-dynamic at-match
	// pattern; kbouncer has no static-deny dimension yet so the union
	// is dynamic-only.
	DynamicDenies *dynamicdeny.RuleSet

	// OnDynamicDenyMatch, when non-nil, is invoked exactly once per
	// dynamic-deny match so the Server can bump a /healthz counter
	// without the evaluator having to own the audit-package wiring.
	// nil = silent (the verdict still applies + the audit event still
	// carries the deny_source / dynamic_deny_rule_id fields).
	OnDynamicDenyMatch func(rule *dynamicdeny.Pattern)

	// OnProfileAllowMatch, when non-nil, is invoked exactly once per
	// profile allow_rule match (composition Order 7 ALLOW) so the Server
	// can bump the total_profile_allows /healthz counter without the
	// evaluator owning the counter wiring. nil = silent (the ALLOW
	// verdict still applies). Mirrors OnDynamicDenyMatch.
	OnProfileAllowMatch func()
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
	// Hook the lookup so the Server can detect pause open/close
	// transitions across requests + emit the synthetic
	// EventTypeAdminFallbackGrant + EventTypePauseEnd events. Fires
	// BEFORE the decision flow so the open-edge event lands in the
	// audit log ahead of the first per-decision DECISION event the
	// pause window enables (preserves SIEM-side time ordering).
	if opts.OnPauseLookup != nil {
		opts.OnPauseLookup(activePause)
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
		decisionID := writeDecision(st, obs, activePause, agentInfo)
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
	// header surface SourceProfile. A profile allow_rule match is recorded
	// in profileAllow and applied after the dynamic-deny floor (deny
	// always wins over a profile-allow).
	var profileAllow bool
	var profileAllowReason string
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
			decisionID := writeDecision(st, obs, activePause, agentInfo)
			emitAuditEvent(opts, agentInfo, obs, parsed, "", activePause)
			maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
			return obs
		}
		// Profile allow_rule match (composition Order 7) is recorded here
		// but NOT short-circuited yet: the dynamic-deny layer below is a
		// "deny always wins over allow" floor (see its comment) so a
		// dynamic-deny must beat a profile-allow. We therefore defer the
		// profile-allow short-circuit until AFTER the dynamic-deny check.
		profileAllow = pv.Allowed
		profileAllowReason = pv.Reason
	}

	// #301: meta / discovery short-circuit. kubectl + client-go bootstrap
	// by hitting OpenAPI schema, API-version discovery, /version,
	// /healthz, /readyz, /livez, /metrics BEFORE issuing any resource
	// call. The parser flags these as IsMetaRead=true (GET-only;
	// Resource="meta:<kind>"). Without an explicit allow they fall
	// through to the default-deny policy and every kubectl invocation
	// fails before doing useful work.
	//
	// Per [[creates-never-mutates]] the carve-out is narrow: GET only,
	// fixed prefix set in parser.classifyMetaPath. Per
	// [[scorer-is-ground-truth]] the fix is parser-side (recognize the
	// shape) — we do NOT widen safe-default's DenyVerbs to cover the
	// gap. Per [[safety-mode-lean-permissive]] the call is read-only
	// metadata; allowing it without prompting is the correct UX. The
	// profile check above still runs first so a custom profile that
	// adds e.g. `deny_keywords: [meta]` keeps full control — IsMetaRead
	// is a fall-through allow, not a hard override.
	if parsed.IsMetaRead {
		obs.DecisionVerdict = VerdictAllow
		obs.DecisionReason = fmt.Sprintf(
			"meta/discovery read (%s): kube-apiserver bootstrap surface "+
				"(OpenAPI / version / health / metrics / api-group discovery)",
			parsed.Resource)
		obs.DecisionSource = SourceMetaDiscovery
		obs.Enforced = false
		decisionID := writeDecision(st, obs, activePause, agentInfo)
		emitAuditEvent(opts, agentInfo, obs, parsed, "", activePause)
		maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
		return obs
	}

	// #324b — dynamic-deny check. Consults the in-memory snapshot from
	// `~/.iam-jit/dynamic-denies.yaml` AFTER profile + meta-discovery
	// short-circuits but BEFORE per-task + global rule evaluation, so
	// a dynamic-deny match beats profile-allow + task-allow +
	// global-allow per the cross-product design doc's "deny always
	// wins over allow" rule. Mirrors gbounce #324d's "dynamic union'd
	// into the matcher" shape; the wire-shape observation carries
	// DenySource + DynamicDenyRuleID so a SIEM analyst can pivot on
	// either field.
	if opts.DynamicDenies != nil {
		matchInput := dynamicdeny.MatchInput{
			Namespace: parsed.Namespace,
			Cluster:   cluster,
			Group:     parsed.Group,
			Version:   parsed.Version,
			Resource:  parsed.Resource,
		}
		if matched := opts.DynamicDenies.Match(matchInput); matched != nil {
			obs.DecisionVerdict = VerdictDeny
			obs.DecisionReason = fmt.Sprintf(
				"matched dynamic-deny rule %s (%s)",
				matched.RuleID, matched.Raw)
			obs.DecisionSource = SourceDynamic
			obs.DenySource = DenySourceDynamic
			obs.DynamicDenyRuleID = matched.RuleID
			obs.Enforced = effectiveMode == ModeTransparent
			if opts.OnDynamicDenyMatch != nil {
				opts.OnDynamicDenyMatch(matched)
			}
			decisionID := writeDecision(st, obs, activePause, agentInfo)
			emitAuditEvent(opts, agentInfo, obs, parsed, "", activePause)
			maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
			return obs
		}
	}

	// Composition order step 1.6: profile allow_rule match. Deferred from
	// the profile-rules block so the dynamic-deny floor above ("deny always
	// wins over allow") gets first refusal. An allow_rule could not have
	// co-occurred with a profile DENY (the evaluator only consults
	// allow_rules after every profile deny layer abstains), so reaching
	// here with profileAllow=true means the operator explicitly blessed
	// this request shape. Short-circuit to ALLOW before task + global
	// rules, mirroring dbounce's Order-4 allow layer.
	if profileAllow {
		if opts.OnProfileAllowMatch != nil {
			opts.OnProfileAllowMatch()
		}
		obs.DecisionVerdict = VerdictAllow
		obs.DecisionReason = profileAllowReason
		obs.DecisionSource = SourceProfileAllow
		obs.Enforced = false
		decisionID := writeDecision(st, obs, activePause, agentInfo)
		emitAuditEvent(opts, agentInfo, obs, parsed, "", activePause)
		maybeEnqueuePrompt(st, opts, mode, activePause, decisionID, obs, parsed)
		return obs
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
			decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID, agentInfo)
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
		decisionID := writeDecisionForTaskMaybe(st, obs, activePause, activeTask, agentInfo)
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
			decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID, agentInfo)
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
			decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID, agentInfo)
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
		decisionID := writeDecisionForTask(st, obs, activePause, activeTask.TaskID, agentInfo)
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
		decisionID := writeDecision(st, obs, activePause, agentInfo)
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

	decisionID := writeDecision(st, obs, activePause, agentInfo)
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

// observePauseTransition is the OnPauseLookup callback the Server
// passes into EvaluateRequestFull. Detects open-edge / close-edge
// pause transitions across consecutive requests + emits the synthetic
// EventTypeAdminFallbackGrant / EventTypePauseEnd events through the
// audit emitter. No-op when no audit emitter is wired (the synthetic
// events have nowhere to land).
//
// Atomicity: the lastSeenPauseID atomic carries the previously-
// observed id; the compare-and-swap-shaped update (Load + Store) is
// safe under concurrent inbound requests because we only emit on a
// detected delta + we tolerate at-most-once-per-request emit cadence
// (occasional duplicate grant events for a single window are
// acceptable; a SIEM dedupes by pause_id + activity_name anyway).
//
// End-kind lookup: on a close-edge (prevID != 0 && current == nil),
// query the store for the closed pause's end_kind so the synthetic
// event accurately distinguishes "resumed_early" from "expired".
// Lookup failure is non-fatal — we still emit the event with an
// "unknown" kind so an analyst sees the closure (better partial
// information than silence).
func (s *Server) observePauseTransition(active *store.PauseRow) {
	if s == nil || s.cfg.AuditEmitter == nil {
		return
	}
	curID := int64(0)
	if active != nil {
		curID = active.ID
	}
	prevID := s.lastSeenPauseID.Swap(curID)
	if prevID == curID {
		return
	}
	ctx := context.Background()
	// Close-edge first so SIEM-side time ordering shows the prior
	// window's close before the new window's open in the N → M case.
	if prevID != 0 {
		endKind, endedBy := s.lookupClosedPauseKind(prevID)
		audit.EmitPauseEnd(ctx, s.cfg.AuditEmitter, prevID, endKind, endedBy)
	}
	if curID != 0 && active != nil {
		endsAtMilli := parseStorePauseTimeMilli(active.EndsAt)
		audit.EmitAdminFallbackGrant(ctx, s.cfg.AuditEmitter,
			curID, active.Reason, active.StartedBy, endsAtMilli)
	}
}

// lookupClosedPauseKind queries the store for a previously-active
// pause's end_kind ("resumed_early" / "expired") so the synthetic
// pause-end event accurately distinguishes operator-initiated closure
// from auto-revert. Returns ("unknown", "") on lookup failure / row-
// not-found — the synthetic event still fires so a SIEM sees the
// closure (better partial information than silence).
func (s *Server) lookupClosedPauseKind(pauseID int64) (kind, endedBy string) {
	if s == nil || s.store == nil || pauseID <= 0 {
		return "unknown", ""
	}
	rows, err := s.store.ListRecentPauses(50)
	if err != nil {
		recordLookupError(err, "kbounce: pause-end-kind lookup failed")
		return "unknown", ""
	}
	for _, r := range rows {
		if r.ID != pauseID {
			continue
		}
		kind = r.EndKind
		if kind == "" {
			kind = "unknown"
		}
		// pause_events.started_by is the open-edge actor; the store
		// doesn't track a separate ended_by (per the EndPause docstring
		// the column is future work). Pass the opener as the best
		// available actor for the closure event so an analyst at least
		// sees WHO owns the window when the closure record itself
		// lacks an actor; "expired" closures legitimately have no
		// human actor (the store auto-reverted), so an empty endedBy
		// is fine on that path too.
		endedBy = r.StartedBy
		return kind, endedBy
	}
	return "unknown", ""
}

// parseStorePauseTimeMilli converts the store's RFC3339-ish
// "2006-01-02T15:04:05Z" timestamp string into Unix milliseconds for
// embedding in the synthetic event's ext block. Returns 0 on parse
// failure so the builder omits the field (per the event's omitempty-
// shaped contract — a missing ends_at is more honest than a wrong one).
func parseStorePauseTimeMilli(ts string) int64 {
	if ts == "" {
		return 0
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", ts)
	if err != nil {
		return 0
	}
	return t.UTC().UnixMilli()
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
		At:                obs.At,
		DecisionID:        obs.DecisionID,
		Mode:              obs.ModeAtDecision,
		Profile:           obs.ProfileName,
		Verdict:           obs.DecisionVerdict,
		Reason:            obs.DecisionReason,
		DecisionSource:    obs.DecisionSource,
		Enforced:          obs.Enforced,
		Host:              opts.AuditHost,
		Upstream:          opts.AuditUpstream,
		Method:            obs.Method,
		Path:              obs.Path,
		StreamKind:        obs.StreamKind,
		TaskID:            taskID,
		ProfileSource:     opts.AuditProfileSource,
		AdminFallback:     activePause != nil,
		Agent:             agent,
		DenySource:        obs.DenySource,
		DynamicDenyRuleID: obs.DynamicDenyRuleID,
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
// priority order, per [[agent-identity-in-audit]] +
// [[cross-product-agent-parity]]):
//
//  1. **Cross-bouncer X-Agent-* headers** (#318 / §A16) — the canonical
//     `X-Agent-Name` + `X-Agent-Session-Id` headers documented in
//     `docs/AGENT-ATTRIBUTION.md`. HIGHEST precedence: when the agent
//     explicitly declares itself via the canonical headers, that wins
//     over heuristic detection. Mirrors gbounce's #308 pattern
//     byte-for-byte so a SIEM query on
//     `unmapped.iam_jit.agent.session_id=X` resolves across all four
//     Bounce products. Invalid headers are dropped (audited as
//     `name="unknown"` / `detected_from="unknown"`) + counted on
//     /healthz via the per-Server counter.
//  2. X-Kbouncer-Session-Id header → AgentRegistry lookup. The MCP
//     server registers its clientInfo + session-id at handshake; a
//     proxied SDK call that carries the header inherits the bound
//     agent identity.
//  3. User-Agent header → audit.FingerprintFromUserAgent. kubectl /
//     client-go / helm / k9s / etc. all carry distinctive UA strings.
//  4. nil request → empty AgentInfo (audit emits the default
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
	// #318 / §A16 — cross-bouncer X-Agent-* header parity. Read +
	// validate the canonical headers BEFORE the MCP / UA fallbacks.
	//
	// #320 / §A18: collect structured rejection breadcrumbs so the
	// audit event surfaces which header failed + why + the rejected
	// value's length under
	// `unmapped.iam_jit.ext.agent_header_rejection`. Pre-§A18 the
	// rejection signal was the /healthz counter + the truncated
	// stderr line; SOC analysts querying the audit log directly
	// couldn't see WHICH request had the misconfigured agent SDK.
	rawName := r.Header.Get("X-Agent-Name")
	rawSessionID := r.Header.Get("X-Agent-Session-Id")
	validatedName := ""
	validatedSessionID := ""
	var rejectionBreadcrumbs []map[string]any
	if rawName != "" {
		if audit.IsValidAgentName(rawName) {
			validatedName = rawName
		} else {
			if opts.RecordRejectedAgentHeader != nil {
				opts.RecordRejectedAgentHeader("X-Agent-Name", rawName)
			}
			rejectionBreadcrumbs = append(rejectionBreadcrumbs,
				audit.BuildAgentHeaderRejectionBreadcrumb(
					audit.AgentNameField,
					audit.ClassifyAgentNameRejection(rawName),
					len(rawName),
				))
		}
	}
	if rawSessionID != "" {
		if audit.IsValidSessionID(rawSessionID) {
			validatedSessionID = rawSessionID
		} else {
			if opts.RecordRejectedAgentHeader != nil {
				opts.RecordRejectedAgentHeader("X-Agent-Session-Id", rawSessionID)
			}
			rejectionBreadcrumbs = append(rejectionBreadcrumbs,
				audit.BuildAgentHeaderRejectionBreadcrumb(
					audit.AgentSessionIDField,
					audit.ClassifyAgentSessionIDRejection(rawSessionID),
					len(rawSessionID),
				))
		}
	}
	// Helper to splice the rejection breadcrumb onto whichever
	// AgentInfo we eventually return. Single map for one failure;
	// []any of maps for both. Empty rejectionBreadcrumbs is a no-op.
	withRejection := func(info audit.AgentInfo) audit.AgentInfo {
		if len(rejectionBreadcrumbs) == 0 {
			return info
		}
		if len(rejectionBreadcrumbs) == 1 {
			info.HeaderRejection = rejectionBreadcrumbs[0]
		} else {
			bs := make([]any, 0, len(rejectionBreadcrumbs))
			for _, b := range rejectionBreadcrumbs {
				bs = append(bs, b)
			}
			info.HeaderRejection = bs
		}
		return info
	}
	if validatedName != "" {
		// Header path wins. `detected_from=http_header` when both pieces
		// validated; `http_header_name_only` for partial. Per
		// [[cross-product-agent-parity]] the partial variant lets SIEM
		// filters distinguish full from partial header attribution.
		detectedFrom := audit.DetectionSourceHTTPHeader
		if validatedSessionID == "" {
			detectedFrom = audit.DetectionSourceHTTPHeaderNameOnly
		}
		return withRejection(audit.AgentInfo{
			Name:         validatedName,
			SessionID:    validatedSessionID,
			DetectedFrom: detectedFrom,
		})
	}
	if opts.AgentRegistry != nil {
		if sid := r.Header.Get(SessionHeaderName); sid != "" {
			info := opts.AgentRegistry.Lookup(sid)
			if info.Name != "" {
				// Explicit X-Agent-Session-Id (when present without a
				// name) overlays the registry-bound info so cross-bouncer
				// correlation works even when the name fell through to
				// MCP.
				if validatedSessionID != "" {
					info.SessionID = validatedSessionID
				}
				return withRejection(info)
			}
			// Header set but not registered → record the session id
			// untrusted (best-effort) + still derive name from UA.
			ua := audit.FingerprintFromUserAgent(r.Header.Get("User-Agent"))
			ua.SessionID = sid
			if validatedSessionID != "" {
				ua.SessionID = validatedSessionID
			}
			return withRejection(ua)
		}
	}
	ua := audit.FingerprintFromUserAgent(r.Header.Get("User-Agent"))
	if validatedSessionID != "" {
		// Bare X-Agent-Session-Id with no name fell through to UA. Still
		// thread the session id so cross-bouncer correlation works.
		ua.SessionID = validatedSessionID
	}
	return withRejection(ua)
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
	id, err := st.AddPendingPrompt(input)
	if err != nil {
		recordLookupError(err, "kbounce: prompt-enqueue failed")
		return
	}
	// Feed the burst detector ONLY on a real new-row insert (id == prior
	// row from idempotent re-enqueue would inflate the count). The
	// detector is per-process; the persisted BURST_DETECTED row is the
	// cross-process signal.
	if id > 0 && opts.BurstDetector != nil {
		opts.BurstDetector.OnPromptEnqueued()
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
//
// agent carries the fingerprinted AgentInfo so the persisted row
// retains the same identity the JSONL log + webhook see (#289 closes
// the kbounce-agent-identity-sqlite-gap). Empty AgentInfo →
// agent_name + agent_session_id columns stay NULL.
func writeDecision(st *store.Store, obs *RequestObservation, activePause *store.PauseRow, agent audit.AgentInfo) int64 {
	return writeDecisionForTask(st, obs, activePause, "", agent)
}

// writeDecisionForTask is the task-id-aware variant of writeDecision.
// Threads the active task_id onto the audit row so post-hoc per-task
// review (TaskReviewSummary) can join cleanly.
//
// Side effect: also stores the assigned id back onto obs.DecisionID
// so the handle() sync-prompt path can read it without round-tripping
// through the return value.
//
// agent: per-call AgentInfo persisted into decisions.agent_name +
// decisions.agent_session_id (#289). Only the name + session id make
// it to SQLite — version + process_exe + parent_exe + raw_user_agent
// stay in the live JSONL/webhook stream (operator owns the local
// stream at full fidelity; the SQLite columns are the minimum needed
// for the post-hoc queryable identity surface used by audit-tail /
// investigate / web UI / /audit/events).
func writeDecisionForTask(st *store.Store, obs *RequestObservation, activePause *store.PauseRow, taskID string, agent audit.AgentInfo) int64 {
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
		AgentName:         agent.Name,
		AgentSessionID:    agent.SessionID,
		// #320 / §A18: persist the REAL detection source instead of
		// letting the read path heuristically infer it (the old
		// agentInfoFromDecisionRow mis-labelled http_header-detected
		// events as mcp_clientinfo whenever a session_id was set).
		// agent.DetectedFrom comes straight from the request-side
		// resolver (resolveAgentInfo / handleAgentHeadersForDecision)
		// so the SQLite-backed /audit/events projection sees the same
		// label the JSONL log + webhook stream already carry.
		DetectedFrom: agent.DetectedFrom,
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
func writeDecisionForTaskMaybe(st *store.Store, obs *RequestObservation, activePause *store.PauseRow, activeTask *tasks.Scope, agent audit.AgentInfo) int64 {
	if activeTask == nil {
		return writeDecisionForTask(st, obs, activePause, "", agent)
	}
	return writeDecisionForTask(st, obs, activePause, activeTask.TaskID, agent)
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

	// burstDetector observes the prompt-enqueue rate + emits a
	// BURST_DETECTED event when the operator's threshold is crossed.
	// Powers the [[bulk-prompt-answer-ux]] flow. nil disables emission
	// (e.g. tests that don't pass a store).
	burstDetector *BurstDetector

	// activeProfile is the hot-swap-aware active profile pointer.
	// Initialized from cfg.ActiveProfile at construction; replaced by
	// the profile-reload watcher (powered by store.profile_reload_signal)
	// when the bulk-answer profile-switch option fires. Reads go
	// through ActiveProfile(); writes only from the watcher goroutine
	// or test-only SetActiveProfile.
	profileMu     sync.RWMutex
	activeProfile *profile.Profile

	// watcherMu serializes start/stop of the background watchers so
	// Serve() (start) + Shutdown() (stop) racing across goroutines
	// can't simultaneously read + write the stop channels. Without
	// this the -race detector flags the test that calls Shutdown
	// immediately after Serve starts.
	watcherMu sync.Mutex

	// watcherWG tracks the background watcher goroutines so Shutdown
	// can wait for them to fully exit before returning. Without this
	// `t.Cleanup(func() { st.Close() })` in tests can race a
	// mid-poll watcher iteration against the store handle closing —
	// surfaces as "sql: database is closed" warns + an inflated
	// lookup_errors_counter on subsequent assertions.
	watcherWG sync.WaitGroup

	// profileReloadStop cancels the background profile-reload watcher.
	// Closed by Shutdown; nil when no watcher was launched (no store
	// configured or test path).
	profileReloadStop chan struct{}

	// expiredRulesSweepStop cancels the background expired-rules
	// sweeper (cosmetic counter; rules are filtered at LoadRuleSet
	// time regardless). nil when no sweeper was launched.
	expiredRulesSweepStop chan struct{}

	// diskPressureStop cancels the background disk-pressure check
	// loop (#461 / §A63c). nil when DiskPressure was not configured
	// in cfg. Closed by Shutdown so the audit emit channel can drain
	// before the manager close fires.
	diskPressureStop chan struct{}

	// lastSeenPauseID tracks the most recently observed active pause id
	// (0 = no pause active). The proxy hot-path's pause-lookup
	// observes transitions from this value to detect:
	//   0 → N: operator opened a pause window → emit synthetic
	//          EventTypeAdminFallbackGrant ONCE so a SIEM sees the
	//          window's open edge as a single high-signal row.
	//   N → 0: the previously-active pause is gone (auto-expired by
	//          the store's lazy GC inside GetActivePause, OR resumed
	//          early via `kbounce pause stop`) → emit synthetic
	//          EventTypePauseEnd ONCE with the persisted end_kind so a
	//          SIEM can pair it with the open-edge event.
	//   N → M (N != 0, M != 0, N != M): unusual but possible if the
	//          operator stops one pause + starts another between two
	//          requests → emit pause-end for N then grant for M.
	// Per [[security-team-audit-export]]: the proxy hot-path is the
	// single observer with the audit emitter wired, so even pause
	// state mutations from one-shot CLI commands (`pause start` /
	// `pause stop`) get audit-exported through the proxy on the next
	// inbound request — no separate CLI-side emitter wiring needed.
	lastSeenPauseID atomic.Int64

	// totalAgentHeadersRejected (#318 / §A16) counts inbound
	// `X-Agent-Name` / `X-Agent-Session-Id` headers that failed
	// validation. Surfaced via /healthz so operators see agent-config
	// drift (e.g. a misconfigured agent setting the header to a
	// shell-injection payload) without grepping stderr. Mirrors
	// gbounce's field of the same name byte-for-byte per
	// [[cross-product-agent-parity]].
	totalAgentHeadersRejected atomic.Int64

	// dynamicDeny (#324b) is the optional dynamic-deny YAML watcher.
	// Held on the Server so the request hot path can read its
	// snapshot under the watcher's RWMutex + so /healthz + the
	// mgmt-port reload handler can introspect it without re-walking
	// the cfg pointer.
	dynamicDeny *dynamicdeny.Watcher

	// totalDynamicDenyMatches counts dynamic-deny matches across the
	// proxy's lifetime. Surfaced via /healthz.
	totalDynamicDenyMatches atomic.Int64
	// totalDynamicDenyReloads / totalDynamicDenyParseErrors mirror the
	// watcher's internal counters; the Server's CLI-wired emit
	// callback bumps these so /healthz reflects activity without
	// reaching into the watcher's private fields.
	totalDynamicDenyReloads     atomic.Int64
	totalDynamicDenyParseErrors atomic.Int64

	// totalProfileAllows counts profile allow_rule matches (composition
	// Order 7 ALLOWs, source=profile.allow) across the proxy's lifetime.
	// Surfaced via /healthz as total_profile_allows for parity with
	// gbounce's total_mitm_allows counter.
	totalProfileAllows atomic.Int64
}

// recordRejectedAgentHeader bumps the per-Server rejection counter +
// logs one stderr line (truncated raw value, control chars replaced
// with '?'). Wired into EvalOptions.RecordRejectedAgentHeader so
// EvaluateRequestFull can surface invalid inbound X-Agent-* headers
// without the evaluator owning audit semantics. Mirrors gbounce's
// `logAgentHeaderRejected` Go function.
//
// Per [[security-team-positioning-safety-not-surveillance]]: surfacing
// the rejection is SAFETY (operator sees attribution gap); the
// truncation is privacy-shaped (we don't echo arbitrary unbounded
// header bodies into the log). The header VALUE is NEVER written into
// the audit event regardless.
func (s *Server) recordRejectedAgentHeader(headerName, rawValue string) {
	if s == nil {
		return
	}
	s.totalAgentHeadersRejected.Add(1)
	truncated := rawValue
	if len(truncated) > 32 {
		truncated = truncated[:32] + "..."
	}
	clean := make([]byte, 0, len(truncated))
	for i := 0; i < len(truncated); i++ {
		c := truncated[i]
		if c < 0x20 || c > 0x7e {
			clean = append(clean, '?')
		} else {
			clean = append(clean, c)
		}
	}
	log.Warn().
		Str("header", headerName).
		Str("value", string(clean)).
		Msg("kbounce: rejected invalid X-Agent-* header — request audited as anonymous")
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
//
// Side-effects per [[bulk-prompt-answer-ux]]:
//   - Constructs a burst detector from cfg.BulkAnswer* fields. The
//     detector observes prompt enqueues via the EvalOptions
//     BurstDetector field threaded through handle().
//   - The profile-reload watcher + expired-rules sweeper are started by
//     Serve / ServeListener so a NewServer-only test doesn't leak
//     goroutines.
func NewServer(cfg Config, st *store.Store) *Server {
	cfg = cfg.Normalize()
	s := &Server{
		cfg:           cfg,
		store:         st,
		activeProfile: cfg.ActiveProfile,
		dynamicDeny:   cfg.DynamicDenyWatcher,
	}
	s.burstDetector = NewBurstDetector(st, BurstDetectorOptions{
		Threshold: cfg.BulkAnswerThreshold,
		Window:    cfg.BulkAnswerWindow,
		Cooldown:  cfg.BulkAnswerCooldown,
	})
	mux := http.NewServeMux()
	// /healthz is a liveness probe — never goes through proxy
	// evaluation (so it doesn't pollute the audit log), never
	// touches upstream. Returns 200 + a small JSON body that
	// callers (monit, k8s liveness probe, supervisor scripts) can
	// regex against. Registering BEFORE the catch-all "/" so the
	// exact-match path wins ServeMux precedence.
	mux.HandleFunc("/healthz", s.healthz)
	// #276 — GET /schemas/config serves the embedded
	// kbounce-config.schema.json byte-for-byte. Agents that want to
	// validate a proposed `kbounce config import` payload against
	// the LIVE bouncer's accepted shape fetch this rather than
	// relying on a stale GitHub URL. Per [[cross-product-agent-
	// parity]]: ibounce + dbounce + gbounce ship the same endpoint
	// shape with their own product schema. READ-ONLY; no auth
	// (matches /healthz — the schema is non-sensitive metadata).
	mux.HandleFunc("/schemas/config", schemasConfigHandler)
	// #271 — GET /audit/events ships the headless audit-tail query
	// surface. Same filter language as `kbounce audit tail --filter`;
	// the cross-bouncer `iam-jit audit query` CLI calls this endpoint
	// in parallel against each reachable bouncer to produce a single
	// merged stream. Registered BEFORE the catch-all "/" so the exact
	// path wins ServeMux precedence (matches /healthz handling above).
	mux.HandleFunc("/audit/events", auditEventsHandler(st, cfg.AuditEventsToken))
	// #324b — POST /admin/dynamic-denies/reload mgmt endpoint. Useful
	// for the cross-bouncer fan-out CLI (#324e) which writes the YAML
	// then POSTs each Bounce product's mgmt port to confirm rules are
	// live. Same auth model as /audit/events. Registered BEFORE the
	// catch-all "/" so the exact path wins ServeMux precedence.
	//
	// #524 BB-3 — defense-in-depth middleware closes the residual gap
	// when a future code path bypasses the CLI's bind-time
	// --audit-events-token requirement (config-file loader, programmatic
	// embed, test harness). Handler-internal bearer check ALSO fires
	// (belt-and-suspenders); requireMgmtAuth adds the "external bind
	// without token → 503" failure case the handler-internal check
	// can't enforce because it has no view of the bind host.
	mux.HandleFunc("/admin/dynamic-denies/reload",
		requireMgmtAuth(s.dynamicDenyReloadHandler(cfg.AuditEventsToken),
			cfg.AuditEventsToken, cfg.Host))
	// #386 / §A25 Phase 2 — POST /admin/profile/reload mgmt endpoint.
	// Re-reads profiles.yaml from disk + hot-swaps the active profile
	// pointer so a `kbounce profile allow` mutation takes effect on
	// the very next decision without a bouncer restart. Same auth
	// model as /audit/events. Mirrors ibounce's response shape so the
	// cross-bouncer fan-out (iam-jit profile allow) sees consistent
	// JSON across products per [[cross-product-agent-parity]].
	mux.HandleFunc("/admin/profile/reload",
		requireMgmtAuth(s.profileReloadHandler(cfg.AuditEventsToken, ""),
			cfg.AuditEventsToken, cfg.Host))
	// #272 — GET / serves the minimal live audit-stream web UI. The
	// page polls /audit/events every 2 s. kbounce's proxy port doubles
	// as the mgmt port, so the UI shares the ServeMux with the k8s
	// API catch-all. auditEventsUIRoot intercepts ONLY exact `GET /`
	// (the browser landing path) and falls through to s.handle for
	// every k8s API path (`/api/...`, `/apis/...`, ...) and every
	// non-GET verb. Same auth model as /audit/events.
	mux.HandleFunc("/", auditEventsUIRoot(
		auditEventsUIHandler(cfg.AuditEventsToken),
		s.handle,
	))
	s.http = &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// ActiveProfile returns the hot-swap-aware active profile pointer.
// Reads under the same RWMutex the profile-reload watcher writes
// under so a request goroutine sees a coherent profile even mid-swap.
func (s *Server) ActiveProfile() *profile.Profile {
	if s == nil {
		return nil
	}
	s.profileMu.RLock()
	defer s.profileMu.RUnlock()
	return s.activeProfile
}

// SetActiveProfile is the test + watcher entrypoint that hot-swaps the
// proxy's active profile pointer. The next inbound request reads the
// new profile via ActiveProfile(); requests in-flight at swap time
// keep the profile they evaluated against (the pointer is read once
// per request).
//
// Per [[creates-never-mutates]]: this swaps a POINTER kbounce owns;
// it does NOT modify the profile YAML on disk (profiles install +
// edit through the separate `kbounce profile install` path).
func (s *Server) SetActiveProfile(p *profile.Profile) {
	if s == nil {
		return
	}
	s.profileMu.Lock()
	s.activeProfile = p
	s.profileMu.Unlock()
}

// BurstDetector returns the proxy's burst detector. Exposed for tests +
// the /healthz introspection path. nil-safe (Snapshot() handles a nil
// receiver).
func (s *Server) BurstDetector() *BurstDetector {
	if s == nil {
		return nil
	}
	return s.burstDetector
}

// ProfileReloadPollInterval is how often the profile-reload watcher
// checks the store for an unacked profile_reload_signal row. 1s is
// a fair trade between "operator switches profile, see it apply
// within a click" + "we don't hammer SQLite." Tests can override
// the watcher entirely by not calling Serve.
const ProfileReloadPollInterval = 1 * time.Second

// ExpiredRulesSweepInterval is how often the expired-rules sweeper
// re-counts expired rows. The count is cosmetic (LoadRuleSet filters
// by wall-clock regardless); the sweeper exists to surface a stable
// number in /healthz + future audit-export channels.
const ExpiredRulesSweepInterval = 30 * time.Second

// startBackgroundWatchers launches the profile-reload watcher + the
// expired-rules cosmetic sweeper. Called from Serve / ServeListener so
// a NewServer-only test doesn't leak goroutines. Idempotent on multiple
// calls (no-ops the second time).
func (s *Server) startBackgroundWatchers() {
	if s == nil {
		return
	}
	s.watcherMu.Lock()
	defer s.watcherMu.Unlock()
	// #461 / §A63c — start disk-pressure check loop. Doesn't depend
	// on s.store; runs even on observation-only deploys so a
	// kbouncer with no upstream still surfaces disk state on
	// /healthz. Per [[deliberate-feature-completion]].
	if s.cfg.DiskPressure != nil && s.diskPressureStop == nil {
		s.diskPressureStop = make(chan struct{})
		s.watcherWG.Add(1)
		go func(stop chan struct{}) {
			defer s.watcherWG.Done()
			audit.RunDiskPressureLoop(context.Background(), s.cfg.DiskPressure, s.cfg.AuditEmitter, stop)
		}(s.diskPressureStop)
	}
	if s.store == nil {
		return
	}
	if s.profileReloadStop == nil {
		s.profileReloadStop = make(chan struct{})
		s.watcherWG.Add(1)
		go func(stop chan struct{}) {
			defer s.watcherWG.Done()
			s.runProfileReloadWatcher(stop)
		}(s.profileReloadStop)
	}
	if s.expiredRulesSweepStop == nil {
		s.expiredRulesSweepStop = make(chan struct{})
		s.watcherWG.Add(1)
		go func(stop chan struct{}) {
			defer s.watcherWG.Done()
			s.runExpiredRulesSweeper(stop)
		}(s.expiredRulesSweepStop)
	}
}

// stopBackgroundWatchers closes both watcher stop channels + waits for
// the goroutines to exit. Called by Shutdown. Idempotent.
//
// Wait-for-exit semantics are load-bearing: tests routinely call
// `t.Cleanup(func() { st.Close() })` AFTER Shutdown returns, so the
// store handle must NOT be in use by a still-running watcher
// goroutine when Shutdown returns. Without the WaitGroup the
// watcher's next mid-poll iteration would race the close +
// surface as "sql: database is closed" warns that inflate the
// lookup_errors_counter on subsequent assertions.
func (s *Server) stopBackgroundWatchers() {
	if s == nil {
		return
	}
	s.watcherMu.Lock()
	if s.profileReloadStop != nil {
		close(s.profileReloadStop)
		s.profileReloadStop = nil
	}
	if s.expiredRulesSweepStop != nil {
		close(s.expiredRulesSweepStop)
		s.expiredRulesSweepStop = nil
	}
	if s.diskPressureStop != nil {
		close(s.diskPressureStop)
		s.diskPressureStop = nil
	}
	s.watcherMu.Unlock()
	// Wait WITHOUT the mutex held so a mid-flight watcher reaching
	// for s.store doesn't deadlock against a future startBackground
	// Watchers (e.g. ServeListener re-call in a long-running test).
	s.watcherWG.Wait()
}

// runProfileReloadWatcher polls the store's profile_reload_signal row
// at ProfileReloadPollInterval. When an unacked signal appears, the
// watcher loads the named profile via profile.LoadProfiles +
// hot-swaps the proxy's active profile pointer via SetActiveProfile +
// acks the signal so it doesn't re-fire.
//
// On any error (profile load fails, profile name unknown), the watcher
// logs at WARN + acks anyway so a typo'd profile name doesn't pin the
// signal forever — the operator sees the warning in stderr + can
// re-issue the bulk-answer with the correct name.
func (s *Server) runProfileReloadWatcher(stop chan struct{}) {
	t := time.NewTicker(ProfileReloadPollInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.pollProfileReloadOnce()
		}
	}
}

// pollProfileReloadOnce is the inner step of runProfileReloadWatcher.
// Factored so tests can drive a deterministic single-step poll
// without depending on a real ticker.
func (s *Server) pollProfileReloadOnce() {
	if s == nil || s.store == nil {
		return
	}
	sig, err := s.store.GetProfileReloadSignal()
	if err != nil {
		// Silently skip on "database is closed" — this is the test-
		// teardown race where the watcher fires after t.Cleanup closed
		// the store. Counting this as a lookup error would inflate the
		// lookup_errors_counter assertion in TestHealthz_Includes
		// LookupErrorsCounter (and is genuinely cosmetic — a closed
		// store can't help the watcher anyway).
		if !isClosedDBError(err) {
			recordLookupError(err, "kbounce: profile-reload signal read failed")
		}
		return
	}
	if sig == nil || sig.AppliedAt != "" {
		return
	}
	// Resolve profiles.yaml path the same way newRunCmd does. Config
	// doesn't carry ProfilesPath today (the CLI loads profiles +
	// passes the resolved Profile pointer); the watcher just resolves
	// the default path so a hot-swap honors the same file the operator
	// edited.
	path, derr := profile.DefaultProfilesPath()
	if derr != nil {
		recordLookupError(derr, "kbounce: profile-reload resolve path failed")
		_ = s.store.AckProfileReloadSignal()
		return
	}
	profiles, lerr := profile.LoadProfiles(path)
	if lerr != nil {
		recordLookupError(lerr, "kbounce: profile-reload load profiles failed")
		_ = s.store.AckProfileReloadSignal()
		return
	}
	prof, aerr := profiles.Active(sig.ProfileName)
	if aerr != nil {
		log.Warn().
			Str("requested_profile", sig.ProfileName).
			Err(aerr).
			Msg("kbounce: profile-reload signal references unknown profile; ignoring")
		_ = s.store.AckProfileReloadSignal()
		return
	}
	s.SetActiveProfile(prof)
	log.Info().
		Str("requested_profile", sig.ProfileName).
		Str("requested_by", sig.RequestedBy).
		Msg("kbounce: profile hot-swapped via bulk-answer signal")
	_ = s.store.AckProfileReloadSignal()
}

// runExpiredRulesSweeper periodically counts expired bulk-answer rules
// so /healthz + future audit-export channels have a stable number to
// surface. The sweeper does NOT delete rows (per [[creates-never-
// mutates]] — the audit history is preserved); it just refreshes a
// cosmetic counter. LoadRuleSet is the load-bearing filter.
func (s *Server) runExpiredRulesSweeper(stop chan struct{}) {
	t := time.NewTicker(ExpiredRulesSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if s.store == nil {
				continue
			}
			n, err := s.store.CountExpiredRules(time.Now().UTC())
			if err != nil {
				// Same test-teardown race as the profile-reload watcher:
				// suppress the lookup-error increment when the cause is
				// "database is closed."
				if !isClosedDBError(err) {
					recordLookupError(err, "kbounce: expired-rules sweep failed")
				}
				continue
			}
			expiredRulesCounter.Store(n)
		}
	}
}

// isClosedDBError reports whether err originates from a database/sql
// operation against a handle that was already Close()'d. We string-
// match because database/sql.ErrConnDone wraps the "database is closed"
// case inconsistently across drivers; matching the message is the
// portable check.
func isClosedDBError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return stringContains(msg, "database is closed") ||
		stringContains(msg, "sql: database is closed")
}

// stringContains is a tiny indirection that avoids importing "strings"
// at the top of this file just for the one call site. Keeps the
// helper local + cheap.
func stringContains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// expiredRulesCounter is the package-level cache the sweeper writes +
// healthz reads. Atomic so the watcher + handlers don't race.
var expiredRulesCounter atomic.Int64

// ExpiredRulesCount returns the most-recent cached count of rules
// whose expires_at has passed. Used by /healthz + tests. Returns 0
// when no sweeper has run yet.
func ExpiredRulesCount() int64 {
	return expiredRulesCounter.Load()
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
	s.startBackgroundWatchers()
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
	s.startBackgroundWatchers()
	return s.http.Serve(l)
}

// Shutdown initiates a graceful shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	s.stopBackgroundWatchers()
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
	// #461 / §A63c — disk-pressure circuit breaker. In pause-requests
	// mode at critical / emergency the proxy refuses every inbound
	// request with 503 + the #459 structured-deny body BEFORE
	// running the evaluator. Refusing pre-evaluation avoids a
	// metadata-write race when the disk is already at the wall.
	// Other modes (rotate-aggressively / archive-and-purge) never
	// flip refuse_requests so this is a no-op for them.
	if s.cfg.DiskPressure != nil && s.cfg.DiskPressure.RefuseRequests() {
		writeDiskPressurePause(w, s.cfg.DiskPressure.Snapshot())
		return
	}
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
	// Hot-swap-aware: ActiveProfile reads under the same RWMutex the
	// bulk-answer profile-switch watcher writes under, so a request
	// goroutine sees a coherent profile pointer even mid-swap.
	activeProfile := s.ActiveProfile()
	profileSource := ""
	if activeProfile != nil {
		profileSource = activeProfile.Source
	}
	obs := EvaluateRequestFull(
		r, s.store, s.cfg.Mode, s.cfg.DefaultPolicy,
		activeProfile, s.cfg.Cluster,
		EvalOptions{
			PromptOnDeny:              s.cfg.PromptOnDeny,
			SyncPromptOnDeny:          syncPromptActive,
			TaskOwner:                 s.cfg.TaskOwner,
			StreamKind:                string(streamKind),
			AuditEmitter:              s.cfg.AuditEmitter,
			AuditHost:                 net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port)),
			AuditUpstream:             upstreamLabel,
			AuditProfileSource:        profileSource,
			AgentRegistry:             s.cfg.AgentRegistry,
			BurstDetector:             s.burstDetector,
			OnPauseLookup:             s.observePauseTransition,
			RecordRejectedAgentHeader: s.recordRejectedAgentHeader,
			// #324b — dynamic-deny snapshot for the evaluator. nil-safe;
			// snapshot is read under the watcher's RWMutex so the hot
			// path sees a coherent view even mid-reload.
			DynamicDenies: s.DynamicDenySnapshot(),
			OnDynamicDenyMatch: func(_ *dynamicdeny.Pattern) {
				s.BumpDynamicDenyMatch()
			},
			OnProfileAllowMatch: func() {
				s.totalProfileAllows.Add(1)
			},
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

	// #459 / §A57b — merge the structured-deny payload (built by the
	// internal structureddeny package, the Go port of the Python
	// iam_jit.structured_deny module) into the wire body. Per
	// [[creates-never-mutates]] the existing K8s-Status-shaped fields
	// (kind / apiVersion / metadata / status / message / reason /
	// details / code) are PRESERVED unchanged so kubectl + client-go
	// keep parsing the body natively; the structured-deny fields are
	// additive. Per [[cross-product-agent-parity]] the wire field
	// names match Python ibounce exactly so an agent can grep either
	// bouncer's 403 with the same jq query.
	deny := structureddeny.Build(structureddeny.BuildOptions{
		Bouncer:               "kbouncer",
		Action:                kbouncerStructuredDenyAction(obs),
		Resource:              kbouncerStructuredDenyResource(obs),
		DenyReason:            obs.DecisionReason,
		DenySource:            kbouncerStructuredDenySource(obs),
		RuleIDIfDynamic:       obs.DynamicDenyRuleID,
		SuggestedAllowCommand: kbouncerSuggestedAllowCommand(obs),
	})

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
		// #459 — structured-deny additive fields per
		// [[ambient-value-prop-and-friction-framing]] +
		// [[cross-product-agent-parity]].
		"caught_by_bouncer":                  deny.CaughtByBouncer,
		"is_likely_injection_classification": deny.IsLikelyInjectionClassification,
		"suggested_allow_command":            deny.SuggestedAllowCommand,
		"recommended_action":                 deny.RecommendedAction,
		"deny_event_id":                      deny.DenyEventID,
		"classifier_hook":                    deny.ClassifierHook,
		"deny_source_classified":             deny.DenySourceClassified,
		"structured_deny_schema_version":     deny.StructuredDenySchemaVersion,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode forbidden response failed")
	}
}

// kbouncerStructuredDenyAction builds the kbouncer-shaped action
// "<group>/<resource>:<verb>" used by the structureddeny heuristic.
// Falls back to the verb alone when no group/resource is parsed.
func kbouncerStructuredDenyAction(obs *RequestObservation) string {
	verb := obs.ParsedVerb
	resource := obs.ParsedResource
	group := obs.ParsedGroup
	if resource == "" && verb == "" {
		return ""
	}
	var head string
	switch {
	case group != "" && resource != "":
		head = group + "/" + resource
	case resource != "":
		head = resource
	default:
		return verb
	}
	if verb == "" {
		return head
	}
	return head + ":" + verb
}

// kbouncerStructuredDenyResource builds the kbouncer-shaped resource
// identifier ("<namespace>/<name>" / "<namespace>" / "<name>" / "").
func kbouncerStructuredDenyResource(obs *RequestObservation) string {
	switch {
	case obs.ParsedNamespace != "" && obs.ParsedName != "":
		return obs.ParsedNamespace + "/" + obs.ParsedName
	case obs.ParsedNamespace != "":
		return obs.ParsedNamespace
	default:
		return obs.ParsedName
	}
}

// kbouncerStructuredDenySource maps kbouncer's DecisionSource +
// DenySource onto the Python deny_source enum the structureddeny
// package understands. Keeps the wire-level deny_source_classified
// stable across the Python+Go bouncers per [[cross-product-agent-parity]].
func kbouncerStructuredDenySource(obs *RequestObservation) string {
	if obs.DenySource == "dynamic" {
		return "dynamic_deny"
	}
	switch obs.DecisionSource {
	case SourceProfile:
		return "static_profile"
	case SourceTask:
		return "task_scope"
	case SourceGlobal:
		return "global_scope"
	case SourceDefault:
		return "safe_default"
	case SourceUnclassifiable:
		return "unclassifiable"
	}
	if obs.DecisionSource != "" {
		return obs.DecisionSource
	}
	return "unknown"
}

// kbouncerSuggestedAllowCommand synthesizes the one-line `kbounce
// profile allow ...` command the agent SHOULD prompt the operator to
// run if the deny looks legitimate. When the deny is a dynamic-deny
// rule the command starts with `#` so DeriveRecommendedAction routes
// to rephrase+retry (dynamic-deny rules aren't allow-able from the
// CLI; the operator has to edit the rule file).
func kbouncerSuggestedAllowCommand(obs *RequestObservation) string {
	if obs.DenySource == "dynamic" {
		return "# dynamic-deny rule " + obs.DynamicDenyRuleID +
			" — edit the dynamic-deny YAML to allow this; rephrase+retry"
	}
	action := kbouncerStructuredDenyAction(obs)
	if action == "" {
		return ""
	}
	target := kbouncerStructuredDenyResource(obs)
	if target == "" {
		target = "*"
	}
	return "kbounce profile allow --target " + target +
		" --action " + action +
		" --reason '<why is this safe?>'"
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
	// #544 / MRR-5 M3 — cross-bouncer parity llm_budget shape. Go
	// bouncers don't run LLM per [[bouncer-zero-llm-when-agent-in-loop]]
	// (they're deterministic by default), so the field is the constant
	// {"enabled": false}. Honest per [[ibounce-honest-positioning]] —
	// NOT a stub. Returned unconditionally so a cross-bouncer SRE
	// composite monitor (MRR-5 §2) sees the same key set across all
	// four bouncers. If kbouncer ever adds optional LLM features,
	// expand to match ibounce's full enabled-shape (used_today_usd,
	// cap_per_day_usd, remaining_usd, percent_consumed,
	// approaching_limit).
	type HealthzLlmBudget struct {
		Enabled bool `json:"enabled"`
	}
	payload := struct {
		Status                      string                       `json:"status"`
		Mode                        string                       `json:"mode"`
		DefaultPolicy               string                       `json:"default_policy"`
		ActiveProfile               string                       `json:"active_profile"`
		AllowRulesInActiveProfile   int                          `json:"allow_rules_in_active_profile"`
		TotalProfileAllows          int64                        `json:"total_profile_allows"`
		DecisionsCount              int64                        `json:"decisions_count"`
		LookupErrorsCounter         int64                        `json:"lookup_errors_counter"`
		AuditExportHealthy          bool                         `json:"audit_export_healthy"`
		TotalAgentHeadersRejected   int64                        `json:"total_agent_headers_rejected"`
		Pause                       *HealthzPause                `json:"pause"`
		DynamicDeniesEnabled        bool                         `json:"dynamic_denies_enabled"`
		DynamicDeniesCount          int                          `json:"dynamic_denies_count"`
		DynamicDeniesPath           string                       `json:"dynamic_denies_path,omitempty"`
		TotalDynamicDenyMatches     int64                        `json:"total_dynamic_deny_matches"`
		TotalDynamicDenyReloads     int64                        `json:"total_dynamic_deny_reloads"`
		TotalDynamicDenyParseErrors int64                        `json:"total_dynamic_deny_parse_errors"`
		AuditLog                    *audit.DiskPressureSnapshot  `json:"audit_log,omitempty"`
		// #544 / MRR-5 M2 — top-level chain_initialized bool. True iff
		// the audit-export emitter is wired (cfg.AuditEmitter != nil);
		// False covers both "audit export not configured at all" AND
		// "emitter construction failed". Closes the cold-start gap
		// noted in MRR-5-MONITORING-RUNBOOK.md §6 M2 where audit-init
		// failure surfaced in the bouncer log but NOT on /healthz
		// until the first decision tried to emit. Per
		// [[cross-product-agent-parity]] all four bouncers surface the
		// same field for SRE composite monitors.
		ChainInitialized bool             `json:"chain_initialized"`
		AuditChain       map[string]any   `json:"audit_chain"`
		LlmBudget        HealthzLlmBudget `json:"llm_budget"`
	}{
		Status:                      "ok",
		Mode:                        string(s.cfg.Mode),
		DefaultPolicy:               string(s.cfg.DefaultPolicy),
		LookupErrorsCounter:         LookupErrorsCount(),
		AuditExportHealthy:          true,
		TotalAgentHeadersRejected:   s.totalAgentHeadersRejected.Load(),
		DynamicDeniesEnabled:        s.dynamicDeny != nil,
		DynamicDeniesCount:          s.dynamicDenyActiveCount(),
		DynamicDeniesPath:           s.dynamicDenyPath(),
		TotalDynamicDenyMatches:     s.totalDynamicDenyMatches.Load(),
		TotalDynamicDenyReloads:     s.totalDynamicDenyReloads.Load(),
		TotalDynamicDenyParseErrors: s.totalDynamicDenyParseErrors.Load(),
		LlmBudget:                   HealthzLlmBudget{Enabled: false},
		TotalProfileAllows:          s.totalProfileAllows.Load(),
	}
	// ADOPT-10 / #734 — chain_initialized now reports whether the
	// tamper-evident hash-chain is ACTUALLY stamping rows (honest
	// forensic posture), not merely that an audit emitter is wired. The
	// audit_chain block surfaces the real head seq/hash + manifest
	// signature presence for SOC analysts / composite monitors.
	if s.cfg.AuditEmitter != nil {
		est := s.cfg.AuditEmitter.Status()
		payload.ChainInitialized = est.ChainEnabled
		if est.ChainEnabled {
			payload.AuditChain = map[string]any{
				"enabled":   true,
				"head_seq":  est.ChainHeadSeq,
				"head_hash": est.ChainHeadHash,
				"manifest": map[string]any{
					"configured":        est.ManifestConfigured,
					"manifests_emitted": est.ManifestsEmitted,
					"manifests_failed":  est.ManifestsFailed,
					"public_key_b64":    est.ManifestPublicKeyB64,
				},
			}
		} else {
			payload.AuditChain = map[string]any{"enabled": false}
		}
	} else {
		payload.AuditChain = map[string]any{"enabled": false}
	}
	if ap := s.ActiveProfile(); ap != nil {
		payload.ActiveProfile = ap.Name
		payload.AllowRulesInActiveProfile = len(ap.AllowRules)
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
	// Per [[prompt-injection-disable-bouncer-threat]] +
	// [[audit-export-failure-visibility]]: when the audit-export
	// heartbeat watchdog flips unhealthy (heartbeatGapRule fired),
	// /healthz returns 503 so an external supervisor (k8s liveness
	// probe, monit, supervisor scripts) sees the same silenced-
	// audit-export signal the SIEM-side rule trips on. Riding the
	// alert through the audit-export channel alone would be
	// invisible when the channel itself is the failure source.
	statusCode := http.StatusOK
	if s.cfg.AuditHealthCheck != nil && !s.cfg.AuditHealthCheck() {
		payload.Status = "degraded"
		payload.AuditExportHealthy = false
		statusCode = http.StatusServiceUnavailable
	}
	// #461 / §A63c — surface the disk-pressure subsystem on /healthz
	// + flip the HTTP response to 503 in pause-requests mode at
	// critical / emergency so an external supervisor (k8s liveness,
	// monit) sees the same paused-bouncer signal the proxy hot path
	// uses to refuse requests. Per [[ibounce-honest-positioning]] we
	// surface the state regardless of mode so operators see disk
	// trends before they cross the threshold.
	if s.cfg.DiskPressure != nil {
		snap := s.cfg.DiskPressure.Snapshot()
		payload.AuditLog = &snap
		if snap.RefuseRequests {
			payload.Status = "degraded"
			statusCode = http.StatusServiceUnavailable
		}
	}
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode /healthz response failed")
	}
}

// writeDiskPressurePause emits the 503 refusal body when the
// disk-pressure subsystem is in pause-requests mode at critical /
// emergency. Wire shape mirrors the #459 structured-deny payload so
// agents can grep the same fields they'd see from a routine policy
// deny.
//
// Per [[ambient-value-prop-and-friction-framing]] the message body
// LEADS with caught_by_bouncer + tells the operator exactly what to
// configure to change behavior. Never says "ERROR" / "BLOCKED".
func writeDiskPressurePause(w http.ResponseWriter, snap audit.DiskPressureSnapshot) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-kbouncer-refusal", "disk-pressure-pause")
	usedPct := 0.0
	if snap.UsedPct != nil {
		usedPct = *snap.UsedPct
	}
	reason := fmt.Sprintf(audit.PauseRequestsRefusalReasonTemplate, usedPct, snap.CritPct)
	sd := structureddeny.Build(structureddeny.BuildOptions{
		Bouncer:    "kbouncer",
		Action:     "disk_pressure.pause",
		DenyReason: reason,
		DenySource: "disk_pressure",
	})
	body := map[string]any{
		"kind":          "Status",
		"apiVersion":    "v1",
		"status":        "Failure",
		"message":       reason,
		"reason":        "ServiceUnavailable",
		"code":          http.StatusServiceUnavailable,
		"disk_pressure": snap,
	}
	for k, v := range sd.AsMap() {
		body[k] = v
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Warn().Err(err).Msg("kbounce: encode disk-pressure pause response failed")
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
	// kbenv accepts both KBOUNCER_LOG_LEVEL and KBOUNCE_LOG_LEVEL.
	if v := kbenv.Get("LOG_LEVEL"); v != "" {
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
