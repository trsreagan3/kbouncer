// dynamic_deny_reload.go — #324b POST /admin/dynamic-denies/reload
// handler on the kbouncer mgmt port (same port as /audit/events;
// kbouncer's proxy port doubles as the mgmt port).
//
// The handler triggers an immediate reload of the dynamic-deny YAML
// from disk + returns a structured JSON payload describing the result.
// Useful for the cross-bouncer fan-out CLI (#324e), which will write
// the YAML on the operator's host + call this endpoint on each Bounce
// product's mgmt port to confirm "rules are live."
//
// Success shape (mirrors gbounce #324d byte-for-byte modulo the
// product name in `rules_applied_to_kbouncer`):
//
//	HTTP 200 application/json
//	{
//	  "reloaded": true,
//	  "rules_count": N,
//	  "rules_applied_to_kbouncer": M,
//	  "path": "/home/.../dynamic-denies.yaml"
//	}
//
// Error shape (parse / schema failure on the file):
//
//	HTTP 422 application/json
//	{
//	  "reloaded": false,
//	  "error": "<structured error>",
//	  "previous_rules_count": N
//	}
//
// Other error shapes:
//
//	HTTP 405: non-POST verb
//	HTTP 401 / 403: bearer-token gate (mirrors /audit/events)
//	HTTP 503: watcher not configured (operator started without
//	          --dynamic-denies-path)
//
// Per [[cross-product-agent-parity]] the shape mirrors the other
// Bounce products; the cross-bouncer CLI keys on the same JSON shape
// regardless of which product replied.

package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/trsreagan3/kbouncer/internal/dynamicdeny"
)

// dynamicDenyReloadHandler builds the POST /admin/dynamic-denies/reload
// handler. Pass requireBearer="" to allow unauthenticated requests
// (loopback-only deploys); a non-empty token gates external binds.
func (s *Server) dynamicDenyReloadHandler(requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeReloadError(w, http.StatusMethodNotAllowed, "only POST is supported")
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeReloadError(w, http.StatusUnauthorized, "Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearerToken(ah)
			if !ok || tok != requireBearer {
				writeReloadError(w, http.StatusForbidden, "bearer token rejected")
				return
			}
		}
		if s.dynamicDeny == nil {
			writeReloadError(w, http.StatusServiceUnavailable,
				"dynamic-deny watcher not configured (kbouncer was started without --dynamic-denies-path)")
			return
		}
		rs, err := s.dynamicDeny.ReloadNow(dynamicdeny.ReasonReloadRequested)
		if err != nil {
			prev := 0
			if rs != nil {
				prev = len(rs.Rules)
			}
			body := map[string]any{
				"reloaded":             false,
				"error":                err.Error(),
				"previous_rules_count": prev,
				"path":                 s.dynamicDeny.Path(),
			}
			writeReloadJSON(w, http.StatusUnprocessableEntity, body)
			return
		}
		// On a successful reload bump the reload counter so /healthz +
		// the operator-side `kbouncer` instrumentation reflects the
		// activity.
		s.BumpDynamicDenyReload()
		applied := 0
		if rs != nil {
			applied = len(rs.Rules)
		}
		body := map[string]any{
			"reloaded":                  true,
			"rules_count":               applied,
			"rules_applied_to_kbouncer": applied,
			"path":                      s.dynamicDeny.Path(),
		}
		writeReloadJSON(w, http.StatusOK, body)
	}
}

// BumpDynamicDenyReload + BumpDynamicDenyParseError are exposed for
// the CLI layer's emit-func wiring. The CLI installs an emit callback
// on the watcher that bumps these counters + tees the OCSF admin-action
// event into the audit-log sink.
func (s *Server) BumpDynamicDenyReload()     { s.totalDynamicDenyReloads.Add(1) }
func (s *Server) BumpDynamicDenyParseError() { s.totalDynamicDenyParseErrors.Add(1) }

// BumpDynamicDenyMatch is the per-match counter bump invoked from the
// evaluator's OnDynamicDenyMatch callback. Surfaces in /healthz.
func (s *Server) BumpDynamicDenyMatch() { s.totalDynamicDenyMatches.Add(1) }

// DynamicDenySnapshot returns the current dynamic-deny snapshot for
// the request hot-path + /healthz + tests. Returns nil when the
// watcher isn't configured. Safe for concurrent use.
func (s *Server) DynamicDenySnapshot() *dynamicdeny.RuleSet {
	if s == nil || s.dynamicDeny == nil {
		return nil
	}
	return s.dynamicDeny.Snapshot()
}

// dynamicDenyActiveCount returns the number of rules currently in the
// dynamic-deny watcher's snapshot (post-filter, kbouncer-applicable
// rules only).
func (s *Server) dynamicDenyActiveCount() int {
	snap := s.DynamicDenySnapshot()
	if snap == nil {
		return 0
	}
	return len(snap.Rules)
}

// dynamicDenyPath returns the on-disk path the watcher consults, or
// "" when the watcher is disabled.
func (s *Server) dynamicDenyPath() string {
	if s == nil || s.dynamicDeny == nil {
		return ""
	}
	return s.dynamicDeny.Path()
}

// writeReloadError emits a structured-error JSON body with the given
// status code.
func writeReloadError(w http.ResponseWriter, status int, msg string) {
	writeReloadJSON(w, status, map[string]any{
		"reloaded": false,
		"error":    msg,
	})
}

// writeReloadJSON writes an arbitrary JSON body with the given status
// code. Local helper so the reload handler doesn't pull on the
// audit_events helpers (which are scoped to the audit-events shape).
func writeReloadJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
