// #203 — synchronous deny-prompt v1.1 handler.
//
// When --sync-prompt-on-deny is set, a transparent-mode DENY does NOT
// immediately 403 the agent. Instead, the proxy enqueues a sync
// pending_prompts row (tagged with a per-request sync_wait_id) and
// blocks the request goroutine on the in-memory waiter channel that
// the store hands back. The operator answers via the existing
// `kbounce prompts answer` surface (or the MCP equivalent); the
// answer is translated into a PromptDecision the goroutine receives
// + acts on:
//
//   - PromptAnswerKindAlways / Profile  → forward + return upstream's
//     response (this is the agent-helpful side of the UX; the
//     operator is essentially saying "this one is fine, go").
//   - PromptAnswerKindIgnore            → return the original 403.
//   - Timeout / ctx cancel              → return the SyncPromptDefault
//     verdict (default deny).
//
// Crash safety: the in-memory waiter map lives in store.Store. On
// proxy restart, any in-flight sync prompts are LOST — but so is the
// request goroutine they were serving, so the agent has already
// disconnected. The pending_prompts row is still on disk and the
// operator can answer it via the CLI (which will then be a no-op
// wake; ListWaitingSyncPrompts filters those out so the MCP tool
// only shows ACTIVE waits). See [[deliberate-feature-completion]] +
// the #203 spec for the design rationale.
//
// Composition with the rest of the proxy:
//
//   - The pause-active guard already runs inside EvaluateRequestFull;
//     by the time we get here with obs.Enforced=true we KNOW no pause
//     is active, so no second pause check is needed.
//   - The EvalOptions.SyncPromptOnDeny flag short-circuits
//     maybeEnqueuePrompt's async write so we don't end up with
//     duplicate (async + sync) rows for one decision.
//   - Per [[ibounce-honest-positioning]]: this is a DETERRENT UX for
//     legitimate human-in-loop review — not an adversarial defense.
//     A motivated bypass would simply not opt into the flag.
//   - Per [[creates-never-mutates]]: the sync flow does not modify
//     existing IAM / K8s state beyond the audit-log + prompts table
//     it owns.

package proxy

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/kbouncer/internal/store"
)

// SyncPromptResponseHeader is set on every response that went through
// the sync-prompt waiter so audit-log readers + tests can confirm
// "this 403 came back AFTER a sync-prompt wait" vs "this 403 was the
// fast-path async deny." Lowercase ASCII per the project convention.
const SyncPromptResponseHeader = "x-kbouncer-sync-prompt"

// SyncPromptResolution values for SyncPromptResponseHeader.
const (
	SyncPromptResolutionAllow   = "allow"
	SyncPromptResolutionDeny    = "deny"
	SyncPromptResolutionTimeout = "timeout"
)

// handleSyncPromptDeny is invoked on a transparent-mode DENY when
// --sync-prompt-on-deny is on. Blocks for up to SyncPromptTimeout
// waiting for the operator's answer. Returns true when the response
// has been fully written (allow → forwarded + responded; deny/timeout
// → 403 written here with the sync-prompt resolution header). The
// only false return is the enqueue-failed defensive branch where the
// caller writes the default 403 itself.
func (s *Server) handleSyncPromptDeny(
	w http.ResponseWriter,
	r *http.Request,
	obs *RequestObservation,
) bool {
	input := store.PromptInput{
		DecisionID: obs.DecisionID,
		DenyReason: obs.DecisionReason,
		Verb:       obs.ParsedVerb,
		Group:      obs.ParsedGroup,
		Version:    obs.ParsedVersion,
		Resource:   obs.ParsedResource,
		Namespace:  obs.ParsedNamespace,
		Name:       obs.ParsedName,
	}
	syncID, ch, err := s.store.AddSyncPendingPrompt(input)
	if err != nil {
		recordLookupError(err, "kbounce: sync-prompt enqueue failed")
		// Fall back to the fast-path 403; the caller writes it.
		w.Header().Set(SyncPromptResponseHeader, SyncPromptResolutionDeny+"-enqueue-failed")
		return false
	}
	// Always release the waiter slot on return so the in-memory map
	// can't leak — covers the timeout / ctx-cancel paths where the
	// store didn't get to delete the entry itself.
	defer s.store.ForgetSyncWaiter(syncID)

	timeout := s.cfg.SyncPromptTimeout
	if timeout <= 0 {
		timeout = DefaultSyncPromptTimeout
	}

	log.Debug().
		Str("sync_wait_id", syncID).
		Int64("decision_id", obs.DecisionID).
		Dur("timeout", timeout).
		Msg("kbounce: sync-prompt waiting for operator answer")

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case decision := <-ch:
		if decision.Allow {
			log.Debug().
				Str("sync_wait_id", syncID).
				Str("kind", decision.Kind).
				Msg("kbounce: sync-prompt resolved ALLOW — forwarding to upstream")
			w.Header().Set(SyncPromptResponseHeader, SyncPromptResolutionAllow)
			s.forwardSyncPromptAllow(w, r, obs)
			return true
		}
		log.Debug().
			Str("sync_wait_id", syncID).
			Str("kind", decision.Kind).
			Msg("kbounce: sync-prompt resolved DENY — returning 403")
		w.Header().Set(SyncPromptResponseHeader, SyncPromptResolutionDeny)
		writeK8sForbidden(w, obs)
		return true
	case <-timer.C:
		// Timeout → apply SyncPromptDefault. If default=allow, treat
		// the call like an answered-allow; otherwise return 403.
		if s.cfg.SyncPromptDefault == DefaultPolicyAllow {
			log.Info().
				Str("sync_wait_id", syncID).
				Dur("timeout", timeout).
				Msg("kbounce: sync-prompt timeout; default=allow → forwarding")
			w.Header().Set(SyncPromptResponseHeader, SyncPromptResolutionTimeout+"-allow")
			s.forwardSyncPromptAllow(w, r, obs)
			return true
		}
		log.Info().
			Str("sync_wait_id", syncID).
			Dur("timeout", timeout).
			Msg("kbounce: sync-prompt timeout; default=deny → returning 403")
		w.Header().Set(SyncPromptResponseHeader, SyncPromptResolutionTimeout)
		writeK8sForbidden(w, obs)
		return true
	case <-r.Context().Done():
		// Inbound client gave up; nothing to write — the connection is
		// torn down. Still need to release the waiter slot (deferred).
		log.Debug().
			Str("sync_wait_id", syncID).
			Msg("kbounce: sync-prompt request context cancelled before answer")
		return true
	}
}

// forwardSyncPromptAllow runs the same forward path the ALLOW-verdict
// branch in handle() takes. Implemented here (rather than calling
// back into handle()) so the sync-prompt code owns its own header
// + observation-fallback semantics — handle() would also try to
// re-evaluate, which we'd then have to suppress.
func (s *Server) forwardSyncPromptAllow(w http.ResponseWriter, r *http.Request, obs *RequestObservation) {
	if s.cfg.Upstream == nil {
		// Observation-only deploy: nothing to forward to. Surface the
		// observation body so the agent client sees the same shape the
		// async path would have produced if the deny had been cleared
		// at the rule layer.
		writeObservationBody(w, obs)
		return
	}
	if !hostAllowed(r.Host, s.cfg.Upstream) {
		log.Warn().
			Str("inbound_host", r.Host).
			Str("upstream_host", s.cfg.Upstream.Host()).
			Msg("kbounce: sync-prompt allow but inbound Host does not match upstream — refusing")
		writeHostMismatch(w, obs, r.Host, s.cfg.Upstream.Host())
		return
	}
	// We don't run through the streaming classifier here: by definition
	// the sync-prompt wait already cost wall-clock time, so a streaming
	// kind (watch/exec) the agent intended is no longer realistic — the
	// client is probably long gone. The buffered REST path is the safe
	// + correct choice for the small "operator-cleared this one call"
	// audience the sync flow targets.
	upReq, err := buildUpstreamRequest(r, s.cfg.Upstream)
	if err != nil {
		log.Warn().Err(err).Msg("kbounce: sync-prompt build upstream request failed")
		writeBadGateway(w, obs, err)
		return
	}
	resp, err := s.cfg.Upstream.Client.Do(upReq)
	if err != nil {
		log.Warn().Err(err).
			Str("upstream", upstreamURLForLog(s.cfg.Upstream.URL)).
			Msg("kbounce: sync-prompt forward to apiserver failed")
		writeBadGateway(w, obs, err)
		return
	}
	defer resp.Body.Close()
	writeUpstreamResponse(w, resp, obs)
}
