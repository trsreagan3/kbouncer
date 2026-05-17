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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/kbouncer/internal/parser"
	"github.com/trsreagan3/kbouncer/internal/store"
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
}

// DefaultConfig returns the production-safe defaults applied when CLI
// flags / construction omit them.
func DefaultConfig() Config {
	return Config{
		Host:          "127.0.0.1",
		Port:          8766,
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyDeny,
	}
}

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
}

// Verdict values used in observations + the audit log.
const (
	VerdictAllow = "allow"
	VerdictDeny  = "deny"
)

// EvaluateRequest is the pure-function evaluator for one inbound HTTP
// request. It parses, runs the (currently minimal) rule engine, and
// records the decision to the store.
//
// Rule logic for K-Slice 1 is intentionally trivial: with no rules
// loaded (rule engine ships in K-Slice 3), every well-formed request
// falls through to the default policy. Malformed requests always
// receive a synthetic deny so the proxy can refuse forwarding when
// K-Slice 2 plugs in.
//
// Side effect: writes the decision row to store. A write failure is
// logged at WARN but does not fail the request — same policy as
// iam-jit-bouncer (audit-write failure must not crash the proxy).
//
// store may be nil during pure-evaluation unit tests; if so, no audit
// row is written. Production callers always pass a real store.
func EvaluateRequest(r *http.Request, st *store.Store, mode Mode, defaultPolicy DefaultPolicy) *RequestObservation {
	now := time.Now().UTC()
	mode = normalizeMode(mode)
	defaultPolicy = normalizeDefaultPolicy(defaultPolicy)

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
			ModeAtDecision:  string(mode),
			Enforced:        mode == ModeTransparent,
		}
		writeDecision(st, obs)
		return obs
	}

	// K-Slice 1: with no rules loaded, every classifiable request falls
	// through to the default policy. The reason string makes the audit
	// log self-explanatory so reviewers don't wonder why a request was
	// allowed/denied without a rule match.
	verdict := VerdictAllow
	reason := "default policy: allow (no rules loaded; K-Slice 1)"
	if defaultPolicy == DefaultPolicyDeny {
		verdict = VerdictDeny
		reason = "default policy: deny (no rules loaded; K-Slice 1)"
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
		DecisionVerdict:   verdict,
		DecisionReason:    reason,
		ModeAtDecision:    string(mode),
		Enforced:          mode == ModeTransparent && verdict == VerdictDeny,
	}
	writeDecision(st, obs)
	return obs
}

// writeDecision persists the observation. Nil store is a no-op (test
// path). Write failures are logged but never propagated — audit-write
// failure is a high-signal alert but must NOT crash the proxy.
func writeDecision(st *store.Store, obs *RequestObservation) {
	if st == nil {
		return
	}
	_, err := st.RecordDecision(store.DecisionRow{
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
	})
	if err != nil {
		log.Warn().Err(err).Msg("kbouncer: audit-write failed")
	}
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

// NewServer constructs the proxy server. The caller still has to call
// Serve to bind + accept. Useful for tests that want a configured
// server they can introspect before binding.
func NewServer(cfg Config, st *store.Store) *Server {
	cfg = cfg.Normalize()
	s := &Server{cfg: cfg, store: st}
	mux := http.NewServeMux()
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
func (s *Server) Serve() error {
	log.Info().
		Str("host", s.cfg.Host).
		Int("port", s.cfg.Port).
		Str("mode", string(s.cfg.Mode)).
		Str("default_policy", string(s.cfg.DefaultPolicy)).
		Msg("kbouncer proxy starting")
	return s.http.ListenAndServe()
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

// handle is the catch-all HTTP handler. K-Slice 1 returns the
// observation as JSON; K-Slice 2 will replace this with real
// forwarding to the kube-apiserver on allow.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	obs := EvaluateRequest(r, s.store, s.cfg.Mode, s.cfg.DefaultPolicy)
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if obs.Enforced {
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
	body := struct {
		Observation *RequestObservation `json:"proxy_observation"`
		SliceNote   string              `json:"_slice1_note"`
	}{
		Observation: obs,
		SliceNote: "K-Slice 1 returns observations only. Forwarding ships " +
			"in K-Slice 2; until then the kubectl / SDK client will see " +
			"this JSON body and fail to parse it as a kube-apiserver response.",
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Encoding into an in-memory buffer should never fail; log and
		// move on so a test failure surfaces.
		log.Warn().Err(err).Msg("kbouncer: encode response failed")
	}
}

// EnsureLogger applies a minimal zerolog config when the caller has
// not set one. CLI calls this at startup so library users (tests)
// get plain JSON logs without configuring the logger themselves.
func EnsureLogger() {
	zerolog.TimeFieldFormat = time.RFC3339
	if log.Logger.GetLevel() == zerolog.NoLevel {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// ParseMode parses a CLI flag value into a Mode, returning an error
// for unknown values. Kept in the proxy package so cmd/ doesn't have
// to repeat the validation.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	if m.IsValid() {
		return m, nil
	}
	return "", fmt.Errorf("kbouncer: unknown mode %q (want cooperative or transparent)", s)
}

// ParseDefaultPolicy parses a CLI flag value into a DefaultPolicy.
func ParseDefaultPolicy(s string) (DefaultPolicy, error) {
	p := DefaultPolicy(s)
	if p.IsValid() {
		return p, nil
	}
	return "", fmt.Errorf("kbouncer: unknown default policy %q (want allow or deny)", s)
}

// ErrInvalidConfig is surfaced when a Config fails validation before
// Serve binds. Kept exported so callers can errors.Is check.
var ErrInvalidConfig = errors.New("kbouncer: invalid proxy config")
