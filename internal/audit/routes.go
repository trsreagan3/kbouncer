// Package audit — per-org notification routing engine (#280).
//
// Per [[per-org-notification-routing]]: the single --audit-webhook-url
// shape works for one team / one collector. At org scale customers
// want multi-destination routing with severity / team / product
// filters:
//
//   - SOC team's Splunk gets every Medium+ event
//   - dev team's Datadog gets only their own events
//   - on-call gets Critical -> PagerDuty + Slack
//   - everything also archives to a central S3 (fan-out)
//
// This file ships the deterministic routes engine that does that.
// One YAML file describes routes; each route has a match block, a
// list of destinations, and an on_match mode (stop default; continue
// for fan-out). Secrets live in env vars via ${ENV} interpolation;
// the YAML never carries plaintext tokens.
//
// Per [[enterprise-self-host-only]]: this is Enterprise-tier; the
// license gate mirrors ErrLicenseRequired pattern (placeholder until
// #235 license-file plumbing lands).
//
// Per [[security-team-positioning-safety-not-surveillance]]: route
// names + destination strings use NEUTRAL language. Match conditions
// are SHIPPING filters, not GATING rules.
//
// Per [[creates-never-mutates]]: routes are ADDITIVE; the engine never
// modifies the event it dispatches.
//
// Per [[no-hosted-saas]] + [[self-host-zero-billing-dependency]]:
// every destination is operator-configured; iam-jit-the-company never
// receives the routed traffic.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrRoutesLicenseRequired is the error returned when --alert-routes
// is passed without an Enterprise license. Mirrors ErrLicenseRequired
// / ErrAlertRulesLicenseRequired so the CLI's error-handling branch
// treats all three uniformly. Placeholder until #235 license-file
// plumbing lands.
var ErrRoutesLicenseRequired = fmt.Errorf(
	"--alert-routes requires an Enterprise license (placeholder — " +
		"kbounce's license-file plumbing has not yet landed; see #235). " +
		"The single-destination --audit-webhook-url channel is available " +
		"on every tier and the JSONL log writer ships everywhere.")

// Destination kinds supported in v1.0 per [[per-org-notification-
// routing]]. email / serviceNow / kafka / s3 are deferred per the
// memo until a customer asks.
const (
	DestinationWebhook   = "webhook"
	DestinationPagerDuty = "pagerduty"
	DestinationSlack     = "slack"
)

// PagerDutyEventsAPIV2URL is the documented enqueue endpoint. Raw HTTP
// POST against this URL with a routing_key + payload (no SDK dep).
// https://developer.pagerduty.com/docs/events-api-v2/overview/
const PagerDutyEventsAPIV2URL = "https://events.pagerduty.com/v2/enqueue"

// envVarRE matches ${ENV_NAME}. The entire value must be one
// reference (no concatenation; that would invite leaks via shell-
// style command substitution).
var envVarRE = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// RoutesConfig is the parsed --alert-routes YAML file. Holds the
// ordered list of routes the engine evaluates per event.
type RoutesConfig struct {
	Routes []Route
}

// Route is one routing decision. Match conditions are AND'd within
// the block; OR semantics across routes. Destinations are dispatched
// in order on a match; one destination failing does NOT stop the
// next per [[deliberate-feature-completion]].
type Route struct {
	Name         string
	Match        map[string]any
	Destinations []Destination
	// OnMatch is "stop" (default; first-match-wins) or "continue" (the
	// fan-out shape). Most customers want "stop"; "continue" is
	// reserved for the catch-all "archive everything" route at the
	// tail of the list.
	OnMatch string
}

// Destination is one (kind, body) pair plus the resolved secrets.
// Kind is one of DestinationWebhook / DestinationPagerDuty /
// DestinationSlack. The body fields are kind-specific; only the
// fields relevant for the kind are populated.
type Destination struct {
	Kind string

	// Webhook fields.
	WebhookURL           string
	WebhookToken         string
	WebhookPreset        Preset
	WebhookAllowInternal bool
	WebhookTags          string
	WebhookSentinelTable string

	// PagerDuty fields.
	PagerDutyIntegrationKey string
	PagerDutySeverity       string

	// Slack fields.
	SlackWebhookURL string

	// secretOrigins records the env-var that supplied each secret field
	// so the startup banner can mask the resolved value while still
	// telling the operator which env var was read. Internal: not part
	// of the wire shape.
	secretOrigins map[string]string
}

// Masked returns a JSON-friendly view of the destination with every
// secret-bearing field replaced by an 8-char-prefix mask. Used by
// the startup banner + the dry-run preview + the engine status
// snapshot. NEVER includes raw token / key / Slack-url values.
func (d Destination) Masked() map[string]any {
	switch d.Kind {
	case DestinationWebhook:
		return map[string]any{
			"type":           "webhook",
			"url":            maskURL(d.WebhookURL),
			"token":          maskTokenShort(d.WebhookToken),
			"preset":         string(d.WebhookPreset),
			"allow_internal": d.WebhookAllowInternal,
		}
	case DestinationPagerDuty:
		return map[string]any{
			"type":            "pagerduty",
			"integration_key": maskTokenShort(d.PagerDutyIntegrationKey),
			"severity":        d.PagerDutySeverity,
		}
	case DestinationSlack:
		host := ""
		if u, err := url.Parse(d.SlackWebhookURL); err == nil {
			host = u.Hostname()
		}
		return map[string]any{
			"type":        "slack",
			"webhook_url": fmt.Sprintf("https://%s/***", host),
		}
	}
	return map[string]any{"type": d.Kind}
}

// maskTokenShort returns "<first-8-chars>***" for a non-empty secret,
// "***" for empty. Used by the routes engine status surfaces; the
// existing maskToken in webhook.go does similar things but renders
// differently (just "***" without the 8-char prefix).
func maskTokenShort(s string) string {
	if s == "" {
		return "***"
	}
	if len(s) <= 8 {
		return s[:len(s)] + "***"
	}
	return s[:8] + "***"
}

// SecretsUsed returns a sorted list of (env_var_name,
// masked_value_prefix) pairs for the startup banner. The masked
// prefix is the first 8 characters of the resolved secret followed
// by `***` — enough to confirm "yes, the right secret loaded" without
// printing the full value to logs.
//
// Dedupes by env-var name (the same env var can appear in multiple
// destinations / routes).
func (c RoutesConfig) SecretsUsed() [][2]string {
	seen := make(map[string]string)
	for _, r := range c.Routes {
		for _, d := range r.Destinations {
			for field, env := range d.secretOrigins {
				if env == "" {
					continue
				}
				if _, ok := seen[env]; ok {
					continue
				}
				switch field {
				case "webhook_token":
					seen[env] = maskTokenShort(d.WebhookToken)
				case "pagerduty_integration_key":
					seen[env] = maskTokenShort(d.PagerDutyIntegrationKey)
				case "slack_webhook_url":
					seen[env] = maskTokenShort(d.SlackWebhookURL)
				default:
					seen[env] = "***"
				}
			}
		}
	}
	out := make([][2]string, 0, len(seen))
	for k, v := range seen {
		out = append(out, [2]string{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i][0] < out[j][0]
	})
	return out
}

// LoadRoutesConfig reads + validates an --alert-routes YAML file at
// path. Resolves every ${ENV_VAR} via os.Getenv at load time. Returns
// a structured error pointing at the offending route + field on any
// validation failure.
func LoadRoutesConfig(path string) (*RoutesConfig, error) {
	clean := filepath.Clean(path)
	// #G505 read-only path; no path traversal because the operator
	// passes the full path explicitly.
	raw, err := os.ReadFile(clean) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf(
			"audit: could not read --alert-routes file %q: %w", clean, err)
	}
	var top struct {
		Routes []rawRoute `yaml:"routes"`
	}
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf(
			"audit: --alert-routes YAML at %q: %w", clean, err)
	}
	if top.Routes == nil {
		return nil, fmt.Errorf(
			"audit: --alert-routes YAML at %q: top-level 'routes' key " +
				"is required (a list of route definitions)", clean)
	}
	if len(top.Routes) == 0 {
		return nil, fmt.Errorf(
			"audit: --alert-routes YAML at %q: 'routes' must be non-empty",
			clean)
	}
	cfg := &RoutesConfig{Routes: make([]Route, 0, len(top.Routes))}
	seenNames := make(map[string]struct{})
	for i, rr := range top.Routes {
		route, err := rr.normalize(i)
		if err != nil {
			return nil, err
		}
		if _, dup := seenNames[route.Name]; dup {
			return nil, fmt.Errorf(
				"audit: --alert-routes YAML at %q: duplicate route name %q",
				clean, route.Name)
		}
		seenNames[route.Name] = struct{}{}
		cfg.Routes = append(cfg.Routes, route)
	}
	return cfg, nil
}

// rawRoute is the wire-shape the YAML loader unmarshals into; the
// public Route type is the normalized form with secrets resolved.
type rawRoute struct {
	Name         string                   `yaml:"name"`
	Match        map[string]any           `yaml:"match"`
	Destinations []map[string]any         `yaml:"destinations"`
	OnMatch      string                   `yaml:"on_match"`
}

func (rr rawRoute) normalize(idx int) (Route, error) {
	if rr.Name == "" {
		return Route{}, fmt.Errorf(
			"audit: routes[%d].name must be a non-empty string", idx)
	}
	if rr.Match == nil {
		rr.Match = map[string]any{}
	}
	if err := validateMatchBlock(rr.Name, rr.Match); err != nil {
		return Route{}, err
	}
	if len(rr.Destinations) == 0 {
		return Route{}, fmt.Errorf(
			"audit: route %q: 'destinations' must be a non-empty list",
			rr.Name)
	}
	onMatch := strings.ToLower(rr.OnMatch)
	if onMatch == "" {
		onMatch = "stop"
	}
	if onMatch != "stop" && onMatch != "continue" {
		return Route{}, fmt.Errorf(
			"audit: route %q: on_match must be 'stop' (default) or " +
				"'continue'; got %q", rr.Name, rr.OnMatch)
	}
	dests := make([]Destination, 0, len(rr.Destinations))
	for di, raw := range rr.Destinations {
		dest, err := loadDestination(rr.Name, di, raw)
		if err != nil {
			return Route{}, err
		}
		dests = append(dests, dest)
	}
	return Route{
		Name:         rr.Name,
		Match:        rr.Match,
		Destinations: dests,
		OnMatch:      onMatch,
	}, nil
}

var validMatchOperators = map[string]struct{}{
	"equals": {}, "gte": {}, "lte": {}, "gt": {}, "lt": {},
	"in": {}, "match": {}, "glob": {},
}

func validateMatchBlock(routeName string, match map[string]any) error {
	for k, v := range match {
		if k == "" {
			return fmt.Errorf(
				"audit: route %q: match keys must be non-empty strings",
				routeName)
		}
		// Scalar condition (default equals) — no operator validation needed.
		cond, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for op := range cond {
			if _, ok := validMatchOperators[op]; !ok {
				return fmt.Errorf(
					"audit: route %q: unknown operator %q on field %q. " +
						"Supported: equals / gte / lte / gt / lt / in / match / glob",
					routeName, op, k)
			}
		}
	}
	return nil
}

// loadDestination parses one destination entry. Each entry is a
// single-key map keyed by destination type (webhook / pagerduty /
// slack).
func loadDestination(routeName string, idx int, raw map[string]any) (Destination, error) {
	if len(raw) != 1 {
		return Destination{}, fmt.Errorf(
			"audit: route %q: destination[%d] must be a single-key " +
				"mapping like '{webhook: {...}}'", routeName, idx)
	}
	var kind string
	var body any
	for k, v := range raw {
		kind, body = k, v
	}
	bodyMap, ok := body.(map[string]any)
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: destination[%d] body must be a mapping",
			routeName, idx)
	}
	switch kind {
	case DestinationWebhook:
		return loadWebhookDestination(routeName, idx, bodyMap)
	case DestinationPagerDuty:
		return loadPagerDutyDestination(routeName, idx, bodyMap)
	case DestinationSlack:
		return loadSlackDestination(routeName, idx, bodyMap)
	}
	return Destination{}, fmt.Errorf(
		"audit: route %q: unknown destination type %q; supported: %s",
		routeName, kind,
		strings.Join([]string{
			DestinationWebhook, DestinationPagerDuty, DestinationSlack,
		}, ", "))
}

func loadWebhookDestination(routeName string, idx int, body map[string]any) (Destination, error) {
	urlVal, _ := body["url"].(string)
	if urlVal == "" {
		return Destination{}, fmt.Errorf(
			"audit: route %q: webhook destination requires a 'url'",
			routeName)
	}
	resolvedURL, _, err := resolveOptionalString(
		urlVal,
		fmt.Sprintf("route %q.destinations[%d].webhook.url", routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	tokenRaw, ok := body["token"]
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: webhook destination requires a 'token' " +
				"(env-var interpolation: token: ${ENV_NAME})", routeName)
	}
	tokenStr, tokenOk := tokenRaw.(string)
	if !tokenOk {
		return Destination{}, fmt.Errorf(
			"audit: route %q: webhook destination 'token' must be a " +
				"string of the form '${ENV_NAME}'", routeName)
	}
	token, envName, err := resolveSecret(
		tokenStr,
		fmt.Sprintf("route %q.destinations[%d].webhook.token", routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	presetStr, _ := body["preset"].(string)
	if presetStr == "" {
		presetStr = string(PresetGeneric)
	}
	preset, err := ParsePreset(presetStr)
	if err != nil {
		return Destination{}, fmt.Errorf(
			"audit: route %q: %w", routeName, err)
	}
	allowInternal, _ := body["allow_internal"].(bool)
	tags, _ := body["tags"].(string)
	sentinelTable, _ := body["sentinel_table"].(string)
	if sentinelTable == "" {
		sentinelTable = SentinelDefaultTable
	}
	return Destination{
		Kind:                 DestinationWebhook,
		WebhookURL:           resolvedURL,
		WebhookToken:         token,
		WebhookPreset:        preset,
		WebhookAllowInternal: allowInternal,
		WebhookTags:          tags,
		WebhookSentinelTable: sentinelTable,
		secretOrigins:        map[string]string{"webhook_token": envName},
	}, nil
}

func loadPagerDutyDestination(routeName string, idx int, body map[string]any) (Destination, error) {
	keyRaw, ok := body["integration_key"]
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: pagerduty destination requires an " +
				"'integration_key' (env-var interpolation: " +
				"integration_key: ${ENV_NAME})", routeName)
	}
	keyStr, okStr := keyRaw.(string)
	if !okStr {
		return Destination{}, fmt.Errorf(
			"audit: route %q: pagerduty destination 'integration_key' " +
				"must be a string of the form '${ENV_NAME}'", routeName)
	}
	key, envName, err := resolveSecret(
		keyStr,
		fmt.Sprintf(
			"route %q.destinations[%d].pagerduty.integration_key",
			routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	severity, _ := body["severity"].(string)
	if severity == "" {
		severity = "warning"
	}
	severity = strings.ToLower(severity)
	switch severity {
	case "info", "warning", "error", "critical":
	default:
		return Destination{}, fmt.Errorf(
			"audit: route %q: pagerduty severity must be one of " +
				"info / warning / error / critical; got %q",
			routeName, severity)
	}
	return Destination{
		Kind:                    DestinationPagerDuty,
		PagerDutyIntegrationKey: key,
		PagerDutySeverity:       severity,
		secretOrigins: map[string]string{
			"pagerduty_integration_key": envName,
		},
	}, nil
}

func loadSlackDestination(routeName string, idx int, body map[string]any) (Destination, error) {
	urlRaw, ok := body["webhook_url"]
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: slack destination requires a 'webhook_url' " +
				"(env-var interpolation: webhook_url: ${ENV_NAME})",
			routeName)
	}
	urlStr, okStr := urlRaw.(string)
	if !okStr {
		return Destination{}, fmt.Errorf(
			"audit: route %q: slack destination 'webhook_url' must be a " +
				"string of the form '${ENV_NAME}'", routeName)
	}
	u, envName, err := resolveSecret(
		urlStr,
		fmt.Sprintf(
			"route %q.destinations[%d].slack.webhook_url", routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	return Destination{
		Kind:            DestinationSlack,
		SlackWebhookURL: u,
		secretOrigins:   map[string]string{"slack_webhook_url": envName},
	}, nil
}

// resolveSecret reads a ${ENV_NAME} reference. Bare literals are
// REFUSED at load time per the memo's "DON'T expose tokens in routes
// YAML" rule. Returns (value, env_var_name, error).
func resolveSecret(value, fieldPath string) (string, string, error) {
	m := envVarRE.FindStringSubmatch(value)
	if m == nil {
		return "", "", fmt.Errorf(
			"audit: %s: secrets must be passed as '${ENV_NAME}' " +
				"(env-var interpolation only). Bare literal tokens are " +
				"refused — keep secrets out of the YAML file", fieldPath)
	}
	env := m[1]
	resolved := os.Getenv(env)
	if resolved == "" {
		return "", "", fmt.Errorf(
			"audit: %s: env-var %q is not set in the environment " +
				"(referenced as '${%s}'). Export it before starting the " +
				"proxy", fieldPath, env, env)
	}
	return resolved, env, nil
}

// resolveOptionalString supports ${ENV_NAME} interpolation but also
// accepts bare literals (URLs are not secrets — the Slack webhook is
// the exception + it goes through resolveSecret).
func resolveOptionalString(value, fieldPath string) (string, string, error) {
	m := envVarRE.FindStringSubmatch(value)
	if m == nil {
		return value, "", nil
	}
	env := m[1]
	resolved, ok := os.LookupEnv(env)
	if !ok {
		return "", "", fmt.Errorf(
			"audit: %s: env-var %q is not set (referenced as " +
				"'${%s}'). Export it before starting the proxy",
			fieldPath, env, env)
	}
	return resolved, env, nil
}

// ============================================================================
// Match-condition evaluator
// ============================================================================

// EvaluateMatch returns true when every (path, condition) pair in
// match holds for ev. Empty match block matches everything (the
// fallback-route shape). Pure function; reused by the dry-run
// preview + the runtime dispatcher.
func EvaluateMatch(ev map[string]any, match map[string]any) bool {
	if len(match) == 0 {
		return true
	}
	for path, cond := range match {
		if !fieldMatches(ev, path, cond) {
			return false
		}
	}
	return true
}

func fieldMatches(ev map[string]any, path string, cond any) bool {
	values := walkPath(ev, path)
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if matchOne(v, cond) {
			return true
		}
	}
	return false
}

// walkPath walks a dotted path through ev. Supports `a.b.c` and
// `a.b[].c` for list-walks. Returns every value found along the path.
func walkPath(ev map[string]any, path string) []any {
	parts := strings.Split(path, ".")
	stack := []any{ev}
	for _, p := range parts {
		next := make([]any, 0, len(stack))
		listWalk := strings.HasSuffix(p, "[]")
		if listWalk {
			p = strings.TrimSuffix(p, "[]")
		}
		for _, cur := range stack {
			m, ok := cur.(map[string]any)
			if !ok {
				continue
			}
			val, ok := m[p]
			if !ok {
				continue
			}
			if listWalk {
				if arr, ok := val.([]any); ok {
					next = append(next, arr...)
					continue
				}
				continue
			}
			next = append(next, val)
		}
		stack = next
		if len(stack) == 0 {
			return nil
		}
	}
	return stack
}

func matchOne(value, cond any) bool {
	condMap, ok := cond.(map[string]any)
	if !ok {
		// Scalar shorthand = equals.
		return equalsAny(value, cond)
	}
	if len(condMap) == 0 {
		return true
	}
	for op, target := range condMap {
		if !applyOperator(value, op, target) {
			return false
		}
	}
	return true
}

func applyOperator(value any, op string, target any) bool {
	switch op {
	case "equals":
		return equalsAny(value, target)
	case "gte", "lte", "gt", "lt":
		vi, vok := coerceInt(value)
		ti, tok := coerceInt(target)
		if !vok || !tok {
			return false
		}
		switch op {
		case "gte":
			return vi >= ti
		case "lte":
			return vi <= ti
		case "gt":
			return vi > ti
		case "lt":
			return vi < ti
		}
	case "in":
		arr, ok := target.([]any)
		if !ok {
			return false
		}
		for _, t := range arr {
			if equalsAny(value, t) {
				return true
			}
		}
		return false
	case "match":
		s, sok := value.(string)
		ts, tsok := target.(string)
		if !sok || !tsok {
			return false
		}
		re, err := regexp.Compile("^" + ts + "$")
		if err != nil {
			return false
		}
		return re.MatchString(s)
	case "glob":
		s, sok := value.(string)
		ts, tsok := target.(string)
		if !sok || !tsok {
			return false
		}
		return globMatch(strings.ToLower(ts), strings.ToLower(s))
	}
	return false
}

func equalsAny(a, b any) bool {
	// JSON numbers come through as float64; the YAML loader uses int.
	// Normalize by attempting an int coerce first.
	if ai, aok := coerceInt(a); aok {
		if bi, bok := coerceInt(b); bok {
			return ai == bi
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func coerceInt(v any) (int64, bool) {
	switch x := v.(type) {
	case bool:
		// Refuse bool -> int coercion so `severity_id: {gte: 0}` doesn't
		// match true/false. Mirrors the ibounce loader's behavior.
		return 0, false
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case float32:
		return int64(x), true
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// globMatch is a case-sensitive glob matcher supporting `*` wildcards.
// Callers lowercase both sides for case-insensitive matching (per the
// memo's documented operator semantics).
func globMatch(pattern, value string) bool {
	// Fast path: no wildcards = literal equality.
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	// First segment must match the prefix.
	if parts[0] != "" {
		if !strings.HasPrefix(value, parts[0]) {
			return false
		}
		pos = len(parts[0])
	}
	for _, seg := range parts[1 : len(parts)-1] {
		if seg == "" {
			continue
		}
		idx := strings.Index(value[pos:], seg)
		if idx < 0 {
			return false
		}
		pos += idx + len(seg)
	}
	if last := parts[len(parts)-1]; last != "" {
		if !strings.HasSuffix(value, last) {
			return false
		}
		if len(value)-len(last) < pos {
			return false
		}
	}
	return true
}

// SelectRoutes returns the ordered list of routes that matched ev,
// honoring on_match semantics. Pure function; exposed for the dry-run
// preview + the runtime dispatcher + tests.
func SelectRoutes(ev map[string]any, routes []Route) []Route {
	out := make([]Route, 0, len(routes))
	for _, r := range routes {
		if EvaluateMatch(ev, r.Match) {
			out = append(out, r)
			if r.OnMatch == "stop" {
				break
			}
		}
	}
	return out
}

// ============================================================================
// Runtime engine — per-destination dispatch
// ============================================================================

// RoutesEngine is the runtime that the audit Manager hands events to
// when --alert-routes is configured. Holds the parsed config + a
// shared HTTP client + bounded in-memory queue + per-destination
// stats.
//
// Failure isolation: each destination's send runs in its own
// goroutine inside the worker; a 500 from PagerDuty does NOT stop
// Slack from receiving the same event, and a route returning a
// transient error does NOT stop subsequent routes.
//
// Backward compat with the single-webhook surface: when the engine
// is wired into the Manager, the Manager skips the legacy
// WebhookPusher dispatch (the CLI parse-time gate warns the operator
// if both flags are set).
type RoutesEngine struct {
	cfg     *RoutesConfig
	client  *http.Client
	product string

	queue chan map[string]any
	done  chan struct{}
	wg    sync.WaitGroup

	closeOnce sync.Once

	totalDropped atomic.Int64

	// Per-destination stats indexed by (routeName, destIdx) -> *destStats.
	stats   map[string]*destStats
	statsMu sync.RWMutex
}

type destStats struct {
	TotalSent       atomic.Int64
	TotalFailed     atomic.Int64
	LastErr         atomic.Value // string
	LastStatus      atomic.Int64
	LastAttemptUnix atomic.Int64
	LastSuccessUnix atomic.Int64
}

// RoutesEngineOptions configures a RoutesEngine. Cfg is required;
// HTTPClient defaults to a sensible 10s-timeout client; QueueDepth
// defaults to DefaultWebhookQueueDepth.
type RoutesEngineOptions struct {
	Cfg        *RoutesConfig
	HTTPClient *http.Client
	QueueDepth int
	Product    string
}

// NewRoutesEngine constructs + starts a routes engine. The worker
// goroutine runs until ctx is cancelled or Close() is called.
//
// Runs the SSRF gate on every webhook destination upfront so a
// misconfigured URL surfaces at startup rather than on the first
// matching event.
func NewRoutesEngine(ctx context.Context, opts RoutesEngineOptions) (*RoutesEngine, error) {
	if opts.Cfg == nil {
		return nil, errors.New("audit: routes engine requires a non-nil config")
	}
	depth := opts.QueueDepth
	if depth <= 0 {
		depth = DefaultWebhookQueueDepth
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	prod := opts.Product
	if prod == "" {
		prod = "kbouncer"
	}
	for _, r := range opts.Cfg.Routes {
		for _, d := range r.Destinations {
			if d.Kind != DestinationWebhook {
				continue
			}
			if !strings.HasPrefix(d.WebhookURL, "https://") &&
				!strings.HasPrefix(d.WebhookURL, "http://") {
				return nil, fmt.Errorf(
					"audit: route %q: webhook URL must use http:// or " +
						"https:// scheme", r.Name)
			}
			if d.WebhookAllowInternal {
				continue
			}
			if err := GuardWebhookURL(
				d.WebhookURL, false, nil,
			); err != nil {
				return nil, fmt.Errorf(
					"audit: route %q: webhook URL refused: %w", r.Name, err)
			}
		}
	}
	eng := &RoutesEngine{
		cfg:     opts.Cfg,
		client:  client,
		product: prod,
		queue:   make(chan map[string]any, depth),
		done:    make(chan struct{}),
		stats:   make(map[string]*destStats),
	}
	for _, r := range opts.Cfg.Routes {
		for di := range r.Destinations {
			key := destStatsKey(r.Name, di)
			s := &destStats{}
			s.LastErr.Store("")
			eng.stats[key] = s
		}
	}
	eng.wg.Add(1)
	go eng.run(ctx)
	return eng, nil
}

func destStatsKey(routeName string, idx int) string {
	return fmt.Sprintf("%s#%d", routeName, idx)
}

// Push enqueues one event. NEVER blocks. NEVER returns an error
// (drops on overflow + bumps a counter the status snapshot exposes).
func (e *RoutesEngine) Push(_ context.Context, ev Event) {
	if e == nil {
		return
	}
	// Marshal the typed OCSF Event to a generic map so the match engine
	// can walk dotted paths uniformly. Round-trips through JSON.
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return
	}
	select {
	case e.queue <- m:
	default:
		e.totalDropped.Add(1)
	}
}

// Close drains the engine + waits for the worker to exit. Idempotent.
func (e *RoutesEngine) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		close(e.done)
	})
	e.wg.Wait()
}

func (e *RoutesEngine) run(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case ev := <-e.queue:
			e.dispatch(ctx, ev)
		}
	}
}

func (e *RoutesEngine) dispatch(ctx context.Context, ev map[string]any) {
	hits := SelectRoutes(ev, e.cfg.Routes)
	for _, route := range hits {
		for di, dest := range route.Destinations {
			// Failure isolation: each destination wrapped in its own
			// recover-safe call so one bad config doesn't poison the worker.
			func(routeName string, dIdx int, d Destination) {
				defer func() {
					if r := recover(); r != nil {
						slog.Warn(
							"routes engine dispatch panic",
							"route", routeName,
							"dest_idx", dIdx,
							"recover", fmt.Sprintf("%v", r),
						)
					}
				}()
				err := e.dispatchOne(ctx, route, dIdx, d, ev)
				if err != nil {
					stats := e.statsFor(routeName, dIdx)
					stats.TotalFailed.Add(1)
					stats.LastErr.Store(maskSecretsInError(err.Error()))
					slog.Warn(
						"routes engine dispatch failed",
						"route", routeName,
						"dest_idx", dIdx,
						"kind", d.Kind,
						"error", maskSecretsInError(err.Error()),
					)
				}
			}(route.Name, di, dest)
		}
	}
}

func (e *RoutesEngine) statsFor(routeName string, idx int) *destStats {
	e.statsMu.RLock()
	s, ok := e.stats[destStatsKey(routeName, idx)]
	e.statsMu.RUnlock()
	if ok {
		return s
	}
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	s = &destStats{}
	s.LastErr.Store("")
	e.stats[destStatsKey(routeName, idx)] = s
	return s
}

// dispatchOne sends one event to one destination. Returns nil on
// 2xx; non-nil error on any other status (no retry in the v1.0
// engine per the memo: ship routes engine + dry-run together; retry
// per-dest is a post-launch concern if customers ask).
func (e *RoutesEngine) dispatchOne(
	ctx context.Context, route Route, idx int, d Destination, ev map[string]any,
) error {
	stats := e.statsFor(route.Name, idx)
	stats.LastAttemptUnix.Store(time.Now().Unix())
	switch d.Kind {
	case DestinationWebhook:
		return e.postWebhook(ctx, route, idx, d, ev, stats)
	case DestinationPagerDuty:
		return e.postPagerDuty(ctx, route, idx, d, ev, stats)
	case DestinationSlack:
		return e.postSlack(ctx, route, idx, d, ev, stats)
	}
	return fmt.Errorf("unknown destination kind %q", d.Kind)
}

func (e *RoutesEngine) postWebhook(
	ctx context.Context, route Route, idx int, d Destination,
	ev map[string]any, stats *destStats,
) error {
	// Reconstruct a typed Event from the generic map so BuildRequest
	// can use the preset adapter. We need this round-trip because the
	// adapters work off Event structs (+ EventsToMaps internally) and
	// we already lost the type at Push() time.
	typedEv, err := mapToEvent(ev)
	if err != nil {
		return fmt.Errorf("preset build round-trip: %w", err)
	}
	cfg := PresetConfig{
		URL:           d.WebhookURL,
		Token:         d.WebhookToken,
		Tags:          d.WebhookTags,
		SentinelTable: d.WebhookSentinelTable,
		Product:       e.product,
	}
	targetURL, headers, body, err := BuildRequest(
		d.WebhookPreset, cfg, []Event{typedEv},
	)
	if err != nil {
		return err
	}
	return e.doPost(ctx, targetURL, headers, body, stats)
}

func (e *RoutesEngine) postPagerDuty(
	ctx context.Context, route Route, idx int, d Destination,
	ev map[string]any, stats *destStats,
) error {
	payload := pagerDutyPayload(ev, d, e.product)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   fmt.Sprintf("%s-audit-export/1.0", e.product),
	}
	return e.doPost(ctx, PagerDutyEventsAPIV2URL, headers, body, stats)
}

func (e *RoutesEngine) postSlack(
	ctx context.Context, route Route, idx int, d Destination,
	ev map[string]any, stats *destStats,
) error {
	payload := slackPayload(ev, e.product)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   fmt.Sprintf("%s-audit-export/1.0", e.product),
	}
	return e.doPost(ctx, d.SlackWebhookURL, headers, body, stats)
}

func (e *RoutesEngine) doPost(
	ctx context.Context, targetURL string, headers map[string]string,
	body []byte, stats *destStats,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	stats.LastStatus.Store(int64(resp.StatusCode))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		stats.TotalSent.Add(1)
		stats.LastSuccessUnix.Store(time.Now().Unix())
		return nil
	}
	return fmt.Errorf(
		"upstream HTTP %d from %s", resp.StatusCode, maskURL(targetURL))
}

// pagerDutyPayload builds the Events API v2 enqueue payload. The
// custom_details carry the full OCSF event so the on-call engineer
// can drill in from the PagerDuty UI.
func pagerDutyPayload(ev map[string]any, d Destination, product string) map[string]any {
	op := nestedString(ev, "api.operation")
	evtType := nestedString(ev, "unmapped.iam_jit.event_type")
	summary := fmt.Sprintf("iam-jit %s", product)
	if evtType != "" {
		summary += " — " + evtType
	}
	if op != "" {
		summary += " — " + op
	}
	if len(summary) > 1024 {
		summary = summary[:1024]
	}
	return map[string]any{
		"routing_key":  d.PagerDutyIntegrationKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":        summary,
			"source":         fmt.Sprintf("iam-jit/%s", product),
			"severity":       d.PagerDutySeverity,
			"custom_details": ev,
		},
	}
}

// slackPayload builds the incoming-webhook JSON payload. Neutral
// language per [[security-team-positioning-safety-not-surveillance]].
func slackPayload(ev map[string]any, product string) map[string]any {
	op := nestedString(ev, "api.operation")
	evtType := nestedString(ev, "unmapped.iam_jit.event_type")
	actor := nestedString(ev, "actor.user.name")
	parts := []string{fmt.Sprintf("iam-jit %s", product)}
	if evtType != "" {
		parts = append(parts, evtType)
	}
	if op != "" {
		parts = append(parts, op)
	}
	if actor != "" {
		parts = append(parts, "actor="+actor)
	}
	return map[string]any{"text": strings.Join(parts, " — ")}
}

// nestedString walks a dotted path through ev + returns the value as
// a string. Returns "" when the field is missing or not a string.
func nestedString(ev map[string]any, path string) string {
	values := walkPath(ev, path)
	if len(values) == 0 {
		return ""
	}
	if s, ok := values[0].(string); ok {
		return s
	}
	return ""
}

// mapToEvent round-trips a generic map back to a typed Event so the
// preset adapter can use it. Tolerant of missing fields (preset
// adapters degrade gracefully when fields are absent).
func mapToEvent(m map[string]any) (Event, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return Event{}, err
	}
	var ev Event
	if err := json.Unmarshal(b, &ev); err != nil {
		return Event{}, err
	}
	return ev, nil
}

// maskSecretsInError is the cheap-defense pass that replaces any high-
// entropy-looking token in an error message with "<masked>" before
// the message is handed to the logger. Conservative: any contiguous
// [A-Za-z0-9_-] run of 16+ chars is treated as a secret.
var secretLikeRE = regexp.MustCompile(`[A-Za-z0-9_\-]{16,}`)

func maskSecretsInError(s string) string {
	return secretLikeRE.ReplaceAllString(s, "<masked>")
}

// Status returns a snapshot of per-route + per-destination counters
// for the MCP / banner. NEVER includes any secret value.
type RoutesEngineStatus struct {
	Configured     bool                   `json:"configured"`
	RouteCount     int                    `json:"route_count"`
	EngineDropped  int64                  `json:"engine_dropped"`
	QueueDepth     int                    `json:"queue_depth"`
	Routes         []RoutesEngineRouteStatus `json:"routes"`
}

type RoutesEngineRouteStatus struct {
	Name             string                       `json:"name"`
	OnMatch          string                       `json:"on_match"`
	Destinations     []map[string]any             `json:"destinations"`
	DestinationStats []map[string]any             `json:"destination_stats"`
}

func (e *RoutesEngine) Status() RoutesEngineStatus {
	if e == nil {
		return RoutesEngineStatus{}
	}
	rs := make([]RoutesEngineRouteStatus, 0, len(e.cfg.Routes))
	for _, r := range e.cfg.Routes {
		dests := make([]map[string]any, 0, len(r.Destinations))
		dstats := make([]map[string]any, 0, len(r.Destinations))
		for di, d := range r.Destinations {
			dests = append(dests, d.Masked())
			s := e.statsFor(r.Name, di)
			lastErr, _ := s.LastErr.Load().(string)
			dstats = append(dstats, map[string]any{
				"total_sent":        s.TotalSent.Load(),
				"total_failed":      s.TotalFailed.Load(),
				"last_error":        lastErr,
				"last_status_code":  s.LastStatus.Load(),
				"last_attempt_unix": s.LastAttemptUnix.Load(),
				"last_success_unix": s.LastSuccessUnix.Load(),
			})
		}
		rs = append(rs, RoutesEngineRouteStatus{
			Name:             r.Name,
			OnMatch:          r.OnMatch,
			Destinations:     dests,
			DestinationStats: dstats,
		})
	}
	return RoutesEngineStatus{
		Configured:    true,
		RouteCount:    len(e.cfg.Routes),
		EngineDropped: e.totalDropped.Load(),
		QueueDepth:    len(e.queue),
		Routes:        rs,
	}
}
