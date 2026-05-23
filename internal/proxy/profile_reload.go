// profile_reload.go — #386 / §A25 Phase 2 POST /admin/profile/reload
// handler on the kbouncer mgmt port (same port as
// /admin/dynamic-denies/reload).
//
// The endpoint re-reads ~/.kbouncer/profiles.yaml (or the path
// resolved by profile.DefaultProfilesPath) from disk + hot-swaps
// the proxy's active profile pointer via SetActiveProfile so a
// `kbounce profile allow` mutation takes effect on the very next
// decision without a bouncer restart.
//
// Success shape (mirrors ibounce's response byte-for-byte modulo
// the product name in active_profile):
//
//	HTTP 200 application/json
//	{
//	  "reloaded": true,
//	  "active_profile": "<name>",
//	  "rules_in_active_profile": N,
//	  "deny_verbs_in_active_profile": M
//	}
//
// Error shapes:
//
//	HTTP 405: non-POST verb
//	HTTP 401 / 403: bearer-token gate (mirrors /audit/events)
//	HTTP 400: parse error on the YAML
//	HTTP 409: active profile is missing from the reloaded file
//
// Per [[cross-product-agent-parity]] the shape is parity-aligned
// with ibounce; the cross-bouncer fan-out keys on the same JSON
// shape regardless of which product replied.

package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/trsreagan3/kbouncer/internal/profile"
)

// profileReloadHandler builds the POST /admin/profile/reload handler.
// Pass requireBearer="" to allow unauthenticated requests (loopback-
// only deploys); a non-empty token gates external binds.
func (s *Server) profileReloadHandler(requireBearer string, profilesPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProfileReloadError(w, http.StatusMethodNotAllowed, "only POST is supported")
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeProfileReloadError(w, http.StatusUnauthorized, "Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearerToken(ah)
			// §A99 — constant-time compare; see audit_events.go.
			if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(requireBearer)) != 1 {
				writeProfileReloadError(w, http.StatusForbidden, "bearer token rejected")
				return
			}
		}

		current := s.ActiveProfile()
		// If profile system isn't in use (no active profile),
		// treat reload as a successful no-op per [[ibounce-honest-
		// positioning]] — better than 503ing a cross-product fan-out
		// call when the operator chose to run without a profile.
		if current == nil || current.Name == "" {
			writeProfileReloadJSON(w, http.StatusOK, map[string]any{
				"reloaded":                true,
				"no_active_profile":       true,
				"active_profile":          "",
				"rules_in_active_profile": 0,
			})
			return
		}

		resolvedPath := profilesPath
		if resolvedPath == "" {
			rp, perr := profile.DefaultProfilesPath()
			if perr != nil {
				writeProfileReloadJSON(w, http.StatusInternalServerError, map[string]any{
					"reloaded": false,
					"error":    "resolve_path_failed",
					"detail":   perr.Error(),
				})
				return
			}
			resolvedPath = rp
		}

		fresh, lerr := profile.LoadProfiles(resolvedPath)
		if lerr != nil {
			writeProfileReloadJSON(w, http.StatusBadRequest, map[string]any{
				"reloaded":       false,
				"error":          "parse_error",
				"detail":         lerr.Error(),
				"active_profile": current.Name,
			})
			return
		}

		resolved, aerr := fresh.Active(current.Name)
		if aerr != nil {
			writeProfileReloadJSON(w, http.StatusConflict, map[string]any{
				"reloaded": false,
				"error":    "active_profile_missing_from_file",
				"detail": "active profile " + current.Name +
					" no longer present in profiles.yaml; refusing to silently swap",
				"active_profile": current.Name,
			})
			return
		}

		s.SetActiveProfile(resolved)
		writeProfileReloadJSON(w, http.StatusOK, map[string]any{
			"reloaded":                     true,
			"active_profile":               resolved.Name,
			"rules_in_active_profile":      len(resolved.AllowRules),
			"deny_verbs_in_active_profile": len(resolved.DenyVerbs),
		})
	}
}

func writeProfileReloadError(w http.ResponseWriter, status int, msg string) {
	writeProfileReloadJSON(w, status, map[string]any{
		"reloaded": false,
		"error":    msg,
	})
}

func writeProfileReloadJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
