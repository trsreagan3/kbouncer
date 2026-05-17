// K-Slice 2 — request forwarding to the kube-apiserver.
//
// On an ALLOW verdict (cooperative OR transparent mode), the proxy
// rewrites the inbound request's URL onto the configured upstream's
// host + scheme, strips RFC 7230 hop-by-hop headers, then issues the
// request via the shared pooled http.Client and streams the response
// back to the inbound client.
//
// LOAD-BEARING invariants (parallel to iam-jit-bouncer's Slice 2):
//
//   - kbouncer NEVER re-signs / re-authenticates a request. The inbound
//     Authorization header (bearer token, etc.) is forwarded verbatim to
//     the apiserver. The apiserver is the identity authority.
//   - Hop-by-hop headers (Connection, Keep-Alive, TE, Transfer-Encoding,
//     Upgrade, Proxy-Authenticate, Proxy-Authorization) are stripped per
//     RFC 7230 §6.1. Trailer / Content-Length are recomputed by the
//     transport.
//   - The OUTBOUND host is the ALLOWLIST. kbouncer forwards exactly to
//     the upstream URL it resolved at startup. An inbound Host header
//     pointing elsewhere is REFUSED with x-kbouncer-refusal=
//     forward-host-mismatch. Mirrors the iam-jit-bouncer CRIT-32-01
//     closure for the K8s shape.
//   - TLS verification is forced by default. The operator must pass
//     --insecure-skip-tls-verify to disable it; never inferred.
//
// Things K-Slice 2 deliberately does NOT do:
//
//   - Streaming watch / exec / port-forward / attach. These need
//     HTTP/2 + bidirectional streaming nuances; deferred to K-Slice 5.
//     Watch requests in this slice complete the GET (the apiserver
//     holds the connection open) but K-Slice 5 will properly stream
//     events as they arrive instead of waiting for the whole response.
//   - mTLS on the proxy listener (client cert presentation to kubectl).
//     Deferred to K-Slice 4.

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/kbouncer/internal/upstream"
)

// hopByHopHeaders are stripped before forwarding. Lowercase for the
// case-insensitive comparison. Lifted from RFC 7230 §6.1.
//
// Content-Length is included because the Go transport recomputes it
// from the body bytes; forwarding the inbound value risks a mismatch
// if any earlier middleware altered the body.
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-length":      {},
}

// stripHopHeaders returns a copy of in with RFC 7230 hop-by-hop headers
// removed. The Connection header may itself name additional fields that
// should be treated as hop-by-hop (per the RFC); we honor those too so
// a downstream-injected `Connection: X-Custom` removes `X-Custom`.
//
// The Authorization header is intentionally NOT stripped — bearer
// tokens are end-to-end credentials the apiserver must see. The
// `Proxy-Authorization` header IS stripped per spec.
func stripHopHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))

	// Collect any extra hop-by-hop names the Connection header points to.
	extraHopHeaders := map[string]struct{}{}
	for _, conn := range in.Values("Connection") {
		for _, tok := range strings.Split(conn, ",") {
			tok = strings.TrimSpace(strings.ToLower(tok))
			if tok != "" {
				extraHopHeaders[tok] = struct{}{}
			}
		}
	}

	for k, vs := range in {
		lk := strings.ToLower(k)
		if _, ok := hopByHopHeaders[lk]; ok {
			continue
		}
		if _, ok := extraHopHeaders[lk]; ok {
			continue
		}
		// Copy the slice so callers can't mutate ours through the alias.
		cpy := make([]string, len(vs))
		copy(cpy, vs)
		out[k] = cpy
	}
	return out
}

// RefusalHeader is the response header kbouncer sets when it rejects
// a request for a reason that is NOT a rule-engine verdict (e.g. the
// outbound host allowlist tripped). Tests + audit-log readers key off
// this so a host-mismatch refusal is distinguishable from a profile
// deny without parsing the JSON body.
const RefusalHeader = "x-kbouncer-refusal"

// VerdictHeader carries the rule-engine verdict on a successful
// forward so curl-driven smoke tests can confirm "this got allowed +
// proxied" without parsing the JSON. Distinct from the
// decision-source header (which names the layer that decided).
const VerdictHeader = "x-kbouncer-verdict"

// hostAllowed compares the inbound Host header (if any) against the
// upstream URL's host. An empty inbound Host is allowed — many HTTP
// clients omit the header on direct loopback connections, and the
// proxy itself reassigns the URL onto the upstream before forwarding.
//
// When the inbound Host IS set, it must match the upstream host
// (case-insensitive). This is the WB32-01-equivalent closure for
// kbouncer: an attacker-controlled Host header should not be able to
// pivot the proxy onto an arbitrary destination.
func hostAllowed(inboundHost string, up *upstream.Upstream) bool {
	if up == nil {
		return false
	}
	if inboundHost == "" {
		return true
	}
	want := strings.ToLower(up.Host())
	got := strings.ToLower(inboundHost)
	if want == got {
		return true
	}
	// Allow the case where the client passed `Host: <host>` without the
	// port and the upstream has one (kubectl strips :443 sometimes), and
	// vice versa.
	wantHost, _ := splitHostMaybePort(want)
	gotHost, _ := splitHostMaybePort(got)
	return wantHost != "" && wantHost == gotHost
}

func splitHostMaybePort(hp string) (string, string) {
	i := strings.LastIndex(hp, ":")
	if i < 0 || strings.Contains(hp, "]") && !strings.HasSuffix(hp, "]") {
		// IPv6-without-port or plain host.
		return hp, ""
	}
	if i < 0 {
		return hp, ""
	}
	return hp[:i], hp[i+1:]
}

// buildUpstreamRequest produces a fresh *http.Request aimed at the
// upstream URL, carrying the inbound body + a cleaned header set.
//
// The inbound request's URL Path + RawQuery are appended to the
// upstream's base URL — so a client GET to http://127.0.0.1:8766
// /api/v1/pods becomes a GET to https://<apiserver>/api/v1/pods.
//
// The inbound body is buffered into memory in K-Slice 2. K-Slice 5
// will replace this with streaming for watch / exec / port-forward.
// For a typical kubectl REST call the body is small (<100KB) so the
// memory cost is acceptable; the buffering simplifies retry + audit
// + the upstream Content-Length recomputation path.
func buildUpstreamRequest(in *http.Request, up *upstream.Upstream) (*http.Request, error) {
	out := *up.URL
	out.Path = singleJoinPath(up.URL.Path, in.URL.Path)
	out.RawQuery = in.URL.RawQuery

	var body io.Reader
	if in.Body != nil && in.Body != http.NoBody {
		buf, err := io.ReadAll(in.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(in.Context(), in.Method, out.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header = stripHopHeaders(in.Header)
	// Force the upstream Host header to the apiserver's host — many
	// kube-apiservers (and any TLS-terminating frontend) check the SNI
	// + Host header for routing. Don't leak our loopback Host through.
	req.Host = up.Host()
	return req, nil
}

// singleJoinPath joins a base path and a request path, avoiding double
// slashes. The apiserver URL almost always has an empty path; the
// inbound path always starts with "/".
func singleJoinPath(base, inbound string) string {
	switch {
	case base == "" || base == "/":
		return inbound
	case strings.HasSuffix(base, "/") && strings.HasPrefix(inbound, "/"):
		return base + strings.TrimPrefix(inbound, "/")
	case !strings.HasSuffix(base, "/") && !strings.HasPrefix(inbound, "/"):
		return base + "/" + inbound
	default:
		return base + inbound
	}
}

// writeUpstreamResponse copies the apiserver's response back to the
// inbound client: headers (with hop-by-hop stripped), status, body.
//
// Errors during the body copy are logged but cannot be surfaced to the
// client at that point (we've already written the status). K-Slice 5
// will add per-event error reporting for streaming responses.
func writeUpstreamResponse(w http.ResponseWriter, resp *http.Response, obs *RequestObservation) {
	cleaned := stripHopHeaders(resp.Header)
	for k, vs := range cleaned {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	// Surface kbouncer verdict + mode + decision-source on the OUTBOUND
	// response so downstream tooling can correlate without re-parsing.
	w.Header().Set(VerdictHeader, obs.DecisionVerdict)
	w.Header().Set("x-kbouncer-mode", obs.ModeAtDecision)
	w.Header().Set(DecisionSourceHeader, obs.DecisionSource)
	if obs.ProfileName != "" {
		w.Header().Set("x-kbouncer-profile", obs.ProfileName)
	}
	// Cooperative-mode advisory denial: surface what transparent mode
	// would have done, even though we forwarded.
	if obs.DecisionVerdict == VerdictDeny && !obs.Enforced {
		w.Header().Set("x-kbouncer-advisory", "would-deny-in-transparent")
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Warn().Err(err).Msg("kbounce: response-body copy failed mid-stream")
	}
}

// upstreamURLForLog stringifies the upstream URL for log lines without
// risking nil-deref.
func upstreamURLForLog(u *url.URL) string {
	if u == nil {
		return "<nil>"
	}
	return u.String()
}
