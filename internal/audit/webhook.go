package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WebhookPusher pushes audit events to an HTTPS endpoint. Queued
// (bounded chan) + retried with exponential backoff. Never blocks
// the proxy hot-path: when the queue is full, the event is dropped
// + a synthetic AUDIT_DROPPED event is enqueued so the downstream
// consumer sees the gap rather than getting silently-dropped
// events.
//
// Enterprise-tier feature (license-gated at the CLI; this package
// does the transport, the CLI decides whether to construct one).
//
// Token handling: the bearer token is set on outgoing requests
// only. It is NEVER logged, NEVER printed in error messages, NEVER
// serialized into event bodies or status responses. Per the
// security-team-audit-export spec the token never leaks to /healthz,
// the JSONL log, the startup banner, or retry error messages.
type WebhookPusher struct {
	url           string
	maskedURL     string // userinfo + query stripped for safe logging
	token         string
	allowInternal bool
	batchSize     int
	client        *http.Client

	// preset selects the per-vendor adapter that builds the outgoing
	// (url, headers, body) tuple. Generic = backward-compat Bearer +
	// JSON-array body, byte-identical to the Slice 1 shape.
	preset        Preset
	tags          string
	sentinelTable string

	queue   chan Event
	done    chan struct{}
	wg      sync.WaitGroup
	closeOnce sync.Once

	total     atomic.Int64
	dropped   atomic.Int64
	inFlight  atomic.Int64
	lastErr   atomic.Value // string, with token + URL userinfo masked
}

// WebhookOptions configures a WebhookPusher. URL + Token are
// required; the CLI rejects empty token (the security-team consumer
// surface MUST authenticate; rolling a Bearer is the lowest-friction
// shape).
type WebhookOptions struct {
	URL           string
	Token         string
	AllowInternal bool
	BatchSize     int
	QueueDepth    int
	// Preset selects the per-vendor adapter. Empty / "generic" =
	// backward-compat Bearer + JSON-array body. Named presets layer
	// vendor-native fields + auth headers per [[audit-webhook-presets]].
	Preset Preset
	// Tags is an operator-supplied free-form string appended to
	// Datadog's ddtags. Ignored by other presets (but threaded through
	// so MCP status / banner can surface what was configured).
	Tags string
	// SentinelTable names the Log Analytics custom-log table for the
	// sentinel preset. Defaults to SentinelDefaultTable when unset.
	SentinelTable string
	// HTTPClient lets tests inject a custom transport (httptest.Server).
	// Production callers leave nil → a sensible default with bounded
	// timeouts.
	HTTPClient *http.Client
	// LookupHost lets tests inject a stub resolver for the SSRF gate.
	// nil → net.LookupHost.
	LookupHost func(string) ([]string, error)
}

// MaxWebhookAttempts caps how many times we retry a failed push
// before dropping. 5 attempts with 1s→32s backoff = up to 63s of
// per-event delivery time, which is a reasonable upper bound on
// "downstream collector hiccup" without holding the queue forever
// during a real outage.
const MaxWebhookAttempts = 5

// webhookBackoffs is the exponential backoff schedule, in order.
// Capped at 32s per the security-team-audit-export memo.
var webhookBackoffs = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
}

// DefaultWebhookQueueDepth bounds the in-memory channel. 1000 is
// large enough to absorb a few seconds of busy proxy traffic during
// a collector hiccup without blocking; small enough that a stuck
// collector is reflected back via AUDIT_DROPPED quickly enough to
// alert.
const DefaultWebhookQueueDepth = 1000

// NewWebhookPusher constructs + starts a WebhookPusher. The worker
// goroutine runs until ctx is cancelled or Close() is called.
//
// Runs the SSRF gate against opts.URL synchronously so a misconfigured
// URL surfaces at startup rather than on the first decision event.
func NewWebhookPusher(ctx context.Context, opts WebhookOptions) (*WebhookPusher, error) {
	if opts.URL == "" {
		return nil, errors.New("audit: webhook requires a URL")
	}
	if opts.Token == "" {
		return nil, errors.New("audit: webhook requires a Bearer token (--audit-webhook-token)")
	}
	if !strings.HasPrefix(opts.URL, "https://") {
		return nil, fmt.Errorf(
			"audit: webhook URL must be https:// (got %s); plaintext webhooks " +
				"would expose audit events on the wire", maskURL(opts.URL))
	}
	if err := GuardWebhookURL(opts.URL, opts.AllowInternal, opts.LookupHost); err != nil {
		return nil, err
	}
	depth := opts.QueueDepth
	if depth <= 0 {
		depth = DefaultWebhookQueueDepth
	}
	batch := opts.BatchSize
	if batch <= 0 {
		batch = 1
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	preset := opts.Preset
	if preset == "" {
		preset = PresetGeneric
	}
	// Validate the preset name at construction so a typo surfaces at
	// startup rather than on the first decision event.
	if _, err := ParsePreset(string(preset)); err != nil {
		return nil, err
	}
	wp := &WebhookPusher{
		url:           opts.URL,
		maskedURL:     maskURL(opts.URL),
		token:         opts.Token,
		allowInternal: opts.AllowInternal,
		batchSize:     batch,
		client:        client,
		preset:        preset,
		tags:          opts.Tags,
		sentinelTable: opts.SentinelTable,
		queue:         make(chan Event, depth),
		done:          make(chan struct{}),
	}
	wp.lastErr.Store("")
	wp.wg.Add(1)
	go wp.run(ctx)
	return wp, nil
}

// Push enqueues an event for the worker to deliver. Non-blocking:
// if the queue is full, the event is dropped + a synthetic
// AUDIT_DROPPED marker is enqueued in its place (so the consumer
// sees the gap). The dropped counter is incremented either way.
//
// Returns nil on enqueue success; non-nil error wrapping the drop
// when the queue is full. Callers (proxy hot-path) MUST NOT block
// on this — the return value is informational, not flow-control.
func (wp *WebhookPusher) Push(_ context.Context, ev Event) error {
	if wp == nil {
		return nil
	}
	select {
	case wp.queue <- ev:
		return nil
	default:
		dropped := wp.dropped.Add(1)
		// Try to enqueue an AUDIT_DROPPED marker non-blockingly so
		// the downstream consumer sees the gap. If even the marker
		// can't fit (truly saturated queue) we just count + move on
		// — never block the caller.
		marker := NewDroppedMarker(dropped)
		select {
		case wp.queue <- marker:
		default:
		}
		return fmt.Errorf("audit webhook queue full (depth=%d); event dropped", cap(wp.queue))
	}
}

// run is the worker goroutine.
func (wp *WebhookPusher) run(ctx context.Context) {
	defer wp.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wp.done:
			return
		case ev := <-wp.queue:
			wp.deliver(ctx, ev)
		}
	}
}

// deliver runs the retry loop for one event. Increments inFlight
// for the duration so the MCP status tool can surface queue depth +
// in-flight count separately.
//
// Per [[audit-webhook-presets]]: the preset adapter (BuildRequest)
// converts the OCSF event into the per-vendor (url, headers, body)
// tuple. The canonical OCSF event on the JSONL log file is unaffected
// — only the webhook body gets vendor-shaped.
func (wp *WebhookPusher) deliver(ctx context.Context, ev Event) {
	wp.inFlight.Add(1)
	defer wp.inFlight.Add(-1)
	cfg := PresetConfig{
		URL:           wp.url,
		Token:         wp.token,
		Tags:          wp.tags,
		SentinelTable: wp.sentinelTable,
		Product:       ProductName,
	}
	targetURL, headers, body, err := BuildRequest(wp.preset, cfg, []Event{ev})
	if err != nil {
		wp.lastErr.Store(fmt.Sprintf("build request (preset=%s): %s",
			wp.preset, maskTokenInString(err.Error(), wp.token)))
		return
	}
	for attempt := 0; attempt < MaxWebhookAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-wp.done:
			return
		default:
		}
		err := wp.sendOnce(ctx, targetURL, headers, body)
		if err == nil {
			wp.total.Add(1)
			wp.lastErr.Store("")
			return
		}
		// Mask the URL + Authorization details from the recorded
		// error so /healthz, the MCP status tool, and any log
		// scrape never see the raw token.
		wp.lastErr.Store(fmt.Sprintf(
			"webhook attempt %d/%d failed for %s: %s",
			attempt+1, MaxWebhookAttempts, wp.maskedURL, maskTokenInString(err.Error(), wp.token)))
		// Sleep before the next attempt (skipped on the final
		// attempt — no point sleeping after the last try).
		if attempt+1 < MaxWebhookAttempts {
			delay := webhookBackoffs[attempt]
			if attempt >= len(webhookBackoffs) {
				delay = webhookBackoffs[len(webhookBackoffs)-1]
			}
			select {
			case <-ctx.Done():
				return
			case <-wp.done:
				return
			case <-time.After(delay):
			}
		}
	}
	// All attempts exhausted — count the drop.
	wp.dropped.Add(1)
}

// sendOnce performs one HTTP POST with the preset-built URL, headers,
// and body. Returns nil on 2xx; an error on transport failure or
// non-2xx response. The User-Agent is set unconditionally so the
// collector can correlate the source binary across presets; per-preset
// adapters control Content-Type + auth headers.
func (wp *WebhookPusher) sendOnce(ctx context.Context, targetURL string, headers map[string]string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "kbounce-audit/"+OCSFSchemaVersion)
	resp, err := wp.client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("non-2xx response: %d", resp.StatusCode)
}

// Close stops the worker goroutine. Idempotent. Does NOT drain the
// queue — a clean shutdown can take up to MaxWebhookAttempts *
// max-backoff if the remote collector is down; we'd rather lose a
// few in-flight events on shutdown than hang the proxy process.
func (wp *WebhookPusher) Close() {
	if wp == nil {
		return
	}
	wp.closeOnce.Do(func() {
		close(wp.done)
		wp.wg.Wait()
	})
}

// Total returns the cumulative count of events successfully pushed.
func (wp *WebhookPusher) Total() int64 {
	if wp == nil {
		return 0
	}
	return wp.total.Load()
}

// Dropped returns the cumulative count of events dropped (queue
// overflow + retry exhaustion).
func (wp *WebhookPusher) Dropped() int64 {
	if wp == nil {
		return 0
	}
	return wp.dropped.Load()
}

// InFlight returns the count of events currently being delivered.
func (wp *WebhookPusher) InFlight() int64 {
	if wp == nil {
		return 0
	}
	return wp.inFlight.Load()
}

// MaskedURL returns the configured URL with userinfo + query stripped.
// Safe to surface in banners + status responses.
func (wp *WebhookPusher) MaskedURL() string {
	if wp == nil {
		return ""
	}
	return wp.maskedURL
}

// LastError returns the most recent push-failure error message, with
// the token + URL userinfo already masked. Safe to surface.
func (wp *WebhookPusher) LastError() string {
	if wp == nil {
		return ""
	}
	if v, ok := wp.lastErr.Load().(string); ok {
		return v
	}
	return ""
}

// maskURL strips userinfo (user:pass@) + query string from a URL
// string. On parse failure returns "***" rather than leaking the
// raw input (defense in depth: never echo back something we
// couldn't safely strip).
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// maskTokenInString replaces every occurrence of token in s with
// "***" so error messages we record never leak the raw token even
// if the underlying error surfaced it. Token-length guard avoids
// the degenerate empty-string case (which would otherwise replace
// every character boundary with "***").
func maskTokenInString(s, token string) string {
	if len(token) < 4 {
		return s
	}
	return strings.ReplaceAll(s, token, "***")
}
