// K-Slice 5 — streaming subresources: watch / exec / port-forward /
// attach / follow-log.
//
// K-Slice 2 deferred true streaming: ?watch=true requests, SPDY/
// WebSocket upgrades, and "kubectl logs -f" all buffer the response
// body into memory before flushing. That's broken for watch (kubectl
// blocks forever) and impossible for SPDY upgrades (the proxy can't
// understand the multiplexed binary stream; it must just pipe bytes).
//
// K-Slice 5 ships two new code paths:
//
//   1. Streaming forwarder (`forwardWatchStreaming`):
//      Used for `?watch=true` GETs + `kubectl logs --follow`.
//      Issues the request via the shared http.Client, then copies the
//      response body in small chunks, calling http.Flusher.Flush
//      after each write so chunks reach the client immediately.
//      io.Copy with periodic flush ≈ a streaming relay; no SPDY
//      hijacking required.
//
//   2. Hijack-and-pipe upgrader (`forwardUpgrade`):
//      Used for `Upgrade: SPDY/3.1` (exec, port-forward, attach) and
//      `Upgrade: websocket`. Hijacks the inbound TCP conn, opens a
//      raw TCP/TLS conn to the apiserver, replays the request +
//      headers, then runs bidirectional io.Copy between the two
//      conns until either side closes. kbouncer does NOT understand
//      SPDY framing — it just pipes bytes both directions, the same
//      way `kubectl proxy` does internally.
//
// Audit semantics (per task spec):
//
//   - ONE decision row per stream open (the request to START the
//     stream). NO row per chunk / per SPDY frame.
//   - The decision row is tagged is_stream=true + stream_kind in
//     {"watch", "spdy"} so post-hoc review can filter the audit log
//     to streaming events without re-parsing URL shapes.
//   - Bytes-sent / bytes-received during the stream are NOT recorded
//     in the audit log. (A future slice may add a `stream_events`
//     table for sampled byte counters; defer for now to keep K-Slice
//     5 tight.)
//
// Security audit-cadence notes (per [[audit-cadence-discipline]]):
//
//   - The hijack path opens a RAW upstream conn — the upstream's TLS
//     config (system roots, kubeconfig CA bundle, --insecure-skip-tls-
//     verify) MUST be honored exactly the same way as the K-Slice 2
//     pooled-Client path. We derive the dialer's tls.Config from the
//     upstream.Upstream's existing Client.Transport so there is ONE
//     source of truth for "what trust anchor do we use against the
//     apiserver?" — no separate code path can silently skip verify.
//   - Stream hijacking is gated on the SAME evaluator that gates REST
//     requests. The decision row is written BEFORE the hijack so a
//     transparent-mode DENY refuses with 403 and the connection is
//     never hijacked.
//   - The 101 Switching Protocols response is sent to the inbound
//     client AFTER the upstream's 101 arrives — kbouncer doesn't
//     synthesize the upgrade response itself + can't escalate a
//     non-upgrade upstream response into a hijack.

package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/kbouncer/internal/upstream"
)

// StreamKind names what kind of streaming this request is. Stored in
// the audit row's stream_kind column so reviewers can filter to "show
// me only the exec / port-forward sessions."
type StreamKind string

const (
	// StreamKindNone — not a streaming request.
	StreamKindNone StreamKind = ""
	// StreamKindWatch — `?watch=true` (or `?follow=true` for logs).
	// Streamed via chunked HTTP body with http.Flusher.
	StreamKindWatch StreamKind = "watch"
	// StreamKindSPDY — SPDY or WebSocket Upgrade (exec, port-forward,
	// attach). Streamed via http.Hijacker + bidirectional io.Copy.
	StreamKindSPDY StreamKind = "spdy"
)

// classifyStream picks the streaming code path for an inbound request.
//
//   - An Upgrade header on the inbound request → StreamKindSPDY
//     (the client wants to switch protocols; we have to hijack).
//   - A `?watch=true` or `?follow=true` query → StreamKindWatch
//     (the client wants the body to stream chunk-by-chunk).
//   - Otherwise → StreamKindNone (use the K-Slice 2 buffered path).
func classifyStream(r *http.Request) StreamKind {
	if r == nil {
		return StreamKindNone
	}
	// Upgrade header is the strongest signal — once present, we MUST
	// hijack or the connection is broken. Connection header should
	// contain "upgrade" too (RFC 7230 §6.7) but we accept Upgrade alone
	// because some K8s clients omit Connection.
	if r.Header.Get("Upgrade") != "" {
		return StreamKindSPDY
	}
	q := r.URL.Query()
	if isTrueish(q.Get("watch")) || isTrueish(q.Get("follow")) {
		return StreamKindWatch
	}
	return StreamKindNone
}

// isTrueish accepts kubectl's loose convention for boolean query
// values: presence + canonical "true" / "1" all count. "false" / "0" /
// empty are false. Mirrors what kube-apiserver itself accepts.
func isTrueish(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

// forwardWatchStreaming is the K-Slice 5 chunked-body forwarder. Used
// for `?watch=true` GETs + `kubectl logs --follow`. Issues the request
// via the shared pooled Client (same trust model as K-Slice 2), then
// copies the response body in small chunks, calling http.Flusher.Flush
// after each write so chunks reach the client immediately.
//
// Returns http.ErrAbortHandler-style errors to the caller; the caller
// has already written headers + status by the time we get into the copy
// loop, so a mid-stream error is logged but cannot be surfaced as a
// different status code.
func forwardWatchStreaming(
	w http.ResponseWriter,
	r *http.Request,
	up *upstream.Upstream,
	obs *RequestObservation,
) {
	upReq, err := buildUpstreamRequestStreaming(r, up)
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: build streaming upstream request failed")
		writeBadGateway(w, obs, err)
		return
	}
	// IMPORTANT: a watch stream MUST NOT use the Client.Timeout (which
	// caps total request duration including body read). The shared
	// pooled Client has a 30s default Timeout from upstream.Resolve —
	// fine for REST but it would kill a long-lived watch. We dispatch
	// through a copy of the Client with Timeout cleared.
	streamingClient := *up.Client
	streamingClient.Timeout = 0

	resp, err := streamingClient.Do(upReq)
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: forward watch stream failed")
		writeBadGateway(w, obs, err)
		return
	}
	defer resp.Body.Close()

	// Apply hop-by-hop strip + decision headers BEFORE WriteHeader.
	cleaned := stripHopHeaders(resp.Header)
	for k, vs := range cleaned {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set(VerdictHeader, obs.DecisionVerdict)
	w.Header().Set("x-kbouncer-mode", obs.ModeAtDecision)
	w.Header().Set(DecisionSourceHeader, obs.DecisionSource)
	w.Header().Set("x-kbouncer-stream", string(StreamKindWatch))
	if obs.ProfileName != "" {
		w.Header().Set("x-kbouncer-profile", obs.ProfileName)
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	// Copy in small chunks + flush after each so kubectl sees events
	// land as the apiserver emits them. bufio.Scanner-style line
	// splitting is too restrictive (watch may emit binary frames in
	// some configurations); a small fixed buffer is the universally
	// correct shape.
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				// Client disconnected mid-stream. Logged but not
				// surfaced — common when kubectl Ctrl+Cs a watch.
				log.Debug().Err(werr).Msg("kbounce: client closed watch stream")
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				log.Debug().Err(rerr).Msg("kbounce: watch stream upstream ended")
			}
			return
		}
	}
}

// buildUpstreamRequestStreaming is like buildUpstreamRequest (K-Slice 2)
// but does NOT buffer the inbound body into memory. The request body
// reader is passed through so the upstream sees chunks as the client
// sends them — critical for `kubectl exec` stdin, port-forward, etc.
func buildUpstreamRequestStreaming(in *http.Request, up *upstream.Upstream) (*http.Request, error) {
	out := *up.URL
	out.Path = singleJoinPath(up.URL.Path, in.URL.Path)
	out.RawQuery = in.URL.RawQuery

	var body io.Reader
	if in.Body != nil && in.Body != http.NoBody {
		body = in.Body // pass-through; NEVER ReadAll on a streaming request
	}
	req, err := http.NewRequestWithContext(in.Context(), in.Method, out.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header = stripHopHeaders(in.Header)
	req.Host = up.Host()
	return req, nil
}

// forwardUpgrade is the hijack-and-pipe SPDY/WebSocket upgrader. Used
// for `Upgrade: SPDY/3.1` (exec, port-forward, attach) and
// `Upgrade: websocket`.
//
// Flow:
//
//  1. Hijack the inbound conn (we need raw byte access after the
//     upgrade succeeds). Done BEFORE dialing upstream so a hijack-
//     unsupported writer fails fast.
//  2. Dial the upstream — raw TCP for http://, TLS for https://. The
//     TLS config is derived from the upstream's existing pooled-Client
//     Transport so the trust anchor matches the K-Slice 2 forward
//     path exactly. (Audit-cadence safeguard.)
//  3. Write the request line + headers (Upgrade preserved, hop-by-hop
//     stripped EXCEPT Upgrade + Connection which are required for the
//     upgrade handshake).
//  4. Read the upstream's response status line + headers. If 101 →
//     replay them to the inbound conn + enter bidirectional copy.
//     If anything else → replay status + headers + body to the
//     inbound conn and close (the apiserver refused the upgrade).
//  5. Bidirectional io.Copy(inbound, upstream) + io.Copy(upstream,
//     inbound) until either side closes.
func forwardUpgrade(
	w http.ResponseWriter,
	r *http.Request,
	up *upstream.Upstream,
	obs *RequestObservation,
) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		// Should not happen with the stdlib http.Server; surface the
		// failure cleanly so a test harness that wraps the response
		// writer gets a useful error instead of a panic.
		log.Warn().Msg("kbounce: response writer does not implement Hijacker; cannot upgrade")
		writeBadGateway(w, obs, fmt.Errorf("response writer not hijackable"))
		return
	}

	// Step 1: hijack inbound.
	inboundConn, inboundBuf, err := hj.Hijack()
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: hijack inbound conn failed")
		// We can't writeBadGateway here — hijack failure means the
		// writer is in an undefined state. Log + return.
		return
	}
	defer inboundConn.Close()

	// Step 2: dial upstream.
	upstreamConn, err := dialUpstream(up)
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: dial upstream for upgrade failed")
		// Best-effort write a 502 onto the hijacked inbound conn so the
		// client sees a reason; ignore write error (the inbound may
		// already be closed).
		_, _ = inboundConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n" +
			"Content-Type: application/json\r\n" +
			"x-kbouncer-forward-error: true\r\n" +
			"x-kbouncer-stream: spdy\r\n" +
			"Connection: close\r\n\r\n" +
			`{"error":"kbounce forward to apiserver failed","upstream_error":"` +
			escapeJSON(err.Error()) + `"}`))
		return
	}
	defer upstreamConn.Close()

	// Step 3: write the request line + headers to upstream.
	if err := writeUpgradeRequestToUpstream(upstreamConn, r, up); err != nil {
		log.Warn().Err(err).Msg("kbounce: write upgrade request to upstream failed")
		return
	}

	// Step 4: relay upstream response headers to inbound. We read with
	// bufio.NewReader(upstreamConn) — peek at the status line + headers
	// without consuming the body bytes. For an upgrade-success (101)
	// the body bytes ARE the SPDY/WebSocket frames; they must flow into
	// the bidirectional copy below, not be buffered + dropped.
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: read upstream upgrade response failed")
		return
	}

	// Replay response status line + headers verbatim to inbound. We
	// add kbouncer trace headers BEFORE the blank-line terminator.
	resp.Header.Set(VerdictHeader, obs.DecisionVerdict)
	resp.Header.Set("x-kbouncer-mode", obs.ModeAtDecision)
	resp.Header.Set(DecisionSourceHeader, obs.DecisionSource)
	resp.Header.Set("x-kbouncer-stream", string(StreamKindSPDY))
	if obs.ProfileName != "" {
		resp.Header.Set("x-kbouncer-profile", obs.ProfileName)
	}
	if err := writeResponseStatusAndHeaders(inboundConn, resp); err != nil {
		log.Warn().Err(err).Msg("kbounce: write upgrade response to inbound failed")
		return
	}

	// If the upstream did NOT 101 (apiserver refused the upgrade), we
	// still need to relay the body verbatim so the client sees the
	// error. After that the connection closes naturally.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_, _ = io.Copy(inboundConn, resp.Body)
		_ = resp.Body.Close()
		return
	}

	// Step 5: bidirectional copy until either side closes.
	// We pass the bufio.Reader, NOT the raw upstreamConn, on the
	// upstream → inbound direction because bufio may have peeked
	// post-headers bytes already. The other direction uses inboundBuf's
	// Reader for the same reason (the inbound client may have sent
	// pipelined upgrade-data bytes before we finished writing
	// headers).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, inboundBuf.Reader)
		// Half-close upstream-write so apiserver knows client done.
		if cw, ok := upstreamConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(inboundConn, upstreamReader)
		if cw, ok := inboundConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// dialUpstream opens a raw TCP (or TLS) conn to the upstream's host.
// Reuses the upstream Client's tls.Config so the trust anchor matches
// the K-Slice 2 pooled-Client path exactly — there is one source of
// truth for "what CA bundle do we trust against the apiserver?"
//
// Returns an error if the upstream's transport is not the expected
// shape (unusual; would require a test using a hand-rolled
// http.Client). In that case the upgrade just fails cleanly.
func dialUpstream(up *upstream.Upstream) (net.Conn, error) {
	if up == nil || up.URL == nil {
		return nil, errors.New("kbounce: upstream missing")
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	host := up.URL.Host
	switch strings.ToLower(up.URL.Scheme) {
	case "http":
		return dialer.Dial("tcp", host)
	case "https":
		var tlsCfg *tls.Config
		if tr, ok := up.Client.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
			tlsCfg = tr.TLSClientConfig.Clone()
		} else {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostnameForSNI(host)}
		}
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = hostnameForSNI(host)
		}
		return tls.DialWithDialer(dialer, "tcp", host, tlsCfg)
	default:
		return nil, fmt.Errorf("kbounce: upstream scheme %q not supported for upgrade", up.URL.Scheme)
	}
}

func hostnameForSNI(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

// writeUpgradeRequestToUpstream writes the HTTP/1.1 request line +
// headers to the upstream conn. Body, if any, is left for the
// bidirectional copy to handle (an upgrade request body is rare but
// permitted by RFC 7230).
//
// Hop-by-hop headers are stripped EXCEPT for Upgrade + Connection,
// which are the WHOLE POINT of the upgrade handshake and must reach
// the upstream verbatim.
func writeUpgradeRequestToUpstream(conn net.Conn, r *http.Request, up *upstream.Upstream) error {
	path := singleJoinPath(up.URL.Path, r.URL.Path)
	if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}
	if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\n", r.Method, path); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "Host: %s\r\n", up.Host()); err != nil {
		return err
	}
	// Strip hop-by-hop EXCEPT Upgrade + Connection. We have to write
	// our own header iteration rather than reuse stripHopHeaders
	// because that helper drops both.
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if lk == "host" {
			continue
		}
		// Always-strip even on upgrade.
		switch lk {
		case "proxy-authenticate", "proxy-authorization", "te", "trailers",
			"transfer-encoding", "content-length", "keep-alive":
			continue
		}
		for _, v := range vs {
			if _, err := fmt.Fprintf(conn, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		return err
	}
	return nil
}

// writeResponseStatusAndHeaders writes the status line + headers of a
// hijacked response to the inbound conn. We don't use resp.Write()
// because that would also drain + write the body, which we want to
// hand off to the bidirectional copy for upgrade success cases.
func writeResponseStatusAndHeaders(conn net.Conn, resp *http.Response) error {
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n",
		resp.StatusCode, http.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			if _, err := fmt.Fprintf(conn, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		return err
	}
	return nil
}

// escapeJSON does the minimum JSON-string escaping we need for the
// error payload inside the synthesized 502 line. Avoids pulling
// encoding/json into the hijack-error path for the sake of one string.
func escapeJSON(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				_, _ = fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
