// Package parser turns a raw HTTP request aimed at a Kubernetes
// kube-apiserver into a structured [ParsedRequest] the proxy can match
// rules against.
//
// The parser is intentionally narrow in scope for K-Slice 1:
//
//   - It does NOT validate the bearer token / client certificate. The
//     real apiserver does that on the forward path (K-Slice 2). We only
//     need to inspect what the client sent so the gating layer can
//     decide whether to forward.
//   - It does NOT call the cluster to resolve names, owner references,
//     RBAC bindings, or admission policies. Pure URL/header parsing.
//   - It does NOT understand CRDs as a first-class concept; CRDs flow
//     through the named-group code path naturally (any /apis/{g}/{v}/...
//     URL is parsed structurally even if the group is unknown to us).
//
// URL shapes the parser understands (mirroring the kube-apiserver
// REST conventions):
//
//	Core API (group="", version="v1"):
//	  /api/v1/{resource}                                  cluster-scoped list/create
//	  /api/v1/{resource}/{name}                           cluster-scoped get/update/patch/delete
//	  /api/v1/namespaces/{ns}/{resource}                  namespaced list/create
//	  /api/v1/namespaces/{ns}/{resource}/{name}           namespaced get/update/patch/delete
//	  /api/v1/namespaces/{ns}/{resource}/{name}/{sub}     subresource (exec, log, status, ...)
//
//	Named API groups:
//	  /apis/{group}/{version}/{resource}                  cluster-scoped
//	  /apis/{group}/{version}/{resource}/{name}           cluster-scoped named
//	  /apis/{group}/{version}/namespaces/{ns}/{resource}                namespaced
//	  /apis/{group}/{version}/namespaces/{ns}/{resource}/{name}         namespaced named
//	  /apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/{sub}   subresource
//
//	Apiserver meta / discovery (GET-only, no resource-set; flagged
//	IsMetaRead=true so the proxy can short-circuit to ALLOW under any
//	profile that doesn't already enumerate them). #301:
//	  /openapi/v2[/...]            OpenAPI v2 schema (kubectl + client-go bootstrap)
//	  /openapi/v3[/...]            OpenAPI v3 schema (kubectl 1.24+ default; per-group document)
//	  /api                         core-API version list
//	  /apis                        named-group list
//	  /api/{version}               core-API resource list (e.g. /api/v1)
//	  /apis/{group}/{version}      named-group resource list (no /{resource} tail)
//	  /version                     apiserver build/version info
//	  /healthz, /readyz, /livez    health/readiness probes (kubelet + load balancers)
//	  /healthz/*, /readyz/*, /livez/* subprobe paths (etcd, scheduler, etc.)
//	  /metrics                     Prometheus exposition (apiserver internal metrics)
//
//	These are populated with Verb="get", Group="", Resource="meta:<kind>",
//	IsMetaRead=true. ONLY GET is accepted; POST/PUT/PATCH/DELETE on any
//	of these prefixes returns ErrMalformedURL so the default policy
//	decides (apiserver itself would 405 the write).
//
// Verb inference combines HTTP method + URL shape + query params:
//
//	GET    /resource              → list
//	GET    /resource?watch=true   → watch (IsWatch=true)
//	GET    /resource/name         → get
//	POST   /resource              → create
//	PUT    /resource/name         → update
//	PATCH  /resource/name         → patch
//	DELETE /resource/name         → delete
//	DELETE /resource              → deletecollection
//	POST   /resource/name/exec    → exec (subresource becomes the verb)
//	POST   /resource/name/portforward → portforward
//	POST   /resource/name/attach  → attach
//	GET    /resource/name/log     → log (read-only subresource)
//
// dryRun=All in the query string flips IsDryRun.
package parser

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ParsedRequest is the structured view of one inbound kube-apiserver
// HTTP request that the rule engine consumes.
//
// All string fields default to "" (not pointer) so JSON-encoded
// observations stay flat and readable in the audit log. Callers
// distinguish "empty namespace because cluster-scoped" from "empty
// namespace because parser failed" by checking the error return of
// [Parse], not by sentinel values on the struct.
type ParsedRequest struct {
	// Verb is the K8s-canonical verb (get, list, watch, create, update,
	// patch, delete, deletecollection) OR the subresource name when the
	// URL targets a subresource (exec, portforward, attach, log, ...).
	// Subresources are first-class verbs in K8s RBAC, so the rule
	// engine treats them the same way.
	Verb string

	// Group is the API group, e.g. "apps", "batch", "rbac.authorization.k8s.io".
	// Empty string for the core API ("/api/v1/...").
	Group string

	// Version is the API version, e.g. "v1", "v1beta1".
	Version string

	// Resource is the plural lowercase resource name, e.g. "pods",
	// "deployments", "configmaps".
	Resource string

	// Namespace is the namespace from the URL, or "" for cluster-scoped
	// requests (including the special list-across-all-namespaces shape).
	Namespace string

	// Name is the named object the URL targets, or "" for collection-
	// level operations (list, create, deletecollection).
	Name string

	// Subresource is the trailing path segment when present, e.g.
	// "exec", "log", "status", "scale", "portforward", "attach".
	// When set, [Verb] is set to the same value.
	Subresource string

	// IsWatch is true when ?watch=true (or ?watch=1) is set on a list URL.
	IsWatch bool

	// IsDryRun is true when ?dryRun=All is set. K8s rejects every other
	// dryRun value, so we only honor exactly "All" (matching apiserver).
	IsDryRun bool

	// RawPath is the unmodified request path (including query string)
	// preserved for the audit log so reviewers can replay exactly what
	// the client sent.
	RawPath string

	// Method is the upper-case HTTP method, useful for log readers and
	// for downstream layers that re-derive verbs.
	Method string

	// BearerTokenPresent is true if an "Authorization: Bearer ..."
	// header was present. We do NOT capture the token value — that
	// would be a credential-handling surface the parser should not
	// hold. The proxy forwards the header verbatim; the apiserver is
	// authoritative.
	BearerTokenPresent bool

	// IsImpersonation is true when ANY of the kube-apiserver
	// impersonation header family was present:
	//
	//   - Impersonate-User              (canonical principal)
	//   - Impersonate-Group             (multi-value)
	//   - Impersonate-Uid               (canonical user UID)
	//   - Impersonate-Extra-*           (operator-defined attributes)
	//
	// The "Impersonate-Extra-*" family uses a header-name prefix,
	// NOT a fixed name — every distinct attribute lives under its
	// own Impersonate-Extra-{attr-name} header. We scan ALL header
	// names for the prefix (case-insensitive) so a request that
	// only carries Impersonate-Extra-scopes (no Impersonate-User /
	// -Group) is still flagged. Closes Gap-K-9 from the Opus
	// readonly-profile audit + the audit-cadence note (a) in the
	// commit body that landed it.
	IsImpersonation bool

	// ImpersonatedUser is the value of the Impersonate-User header
	// when present, else "". Carried into the audit reason string
	// so reviewers can see who the caller tried to masquerade as
	// without having to consult the raw header dump.
	ImpersonatedUser string

	// ImpersonatedGroups is the slice of Impersonate-Group header
	// values (the header can appear multiple times — apiserver
	// concatenates them as a multi-value header). Empty when none
	// were present. Kept for the audit row's structured field;
	// not currently used in the deny reason.
	ImpersonatedGroups []string

	// IsStream is true when the URL shape itself indicates a streaming
	// subresource (exec / attach / portforward) OR ?watch=true /
	// ?follow=true is set. URL-derived; the proxy may also set this
	// via the Upgrade header (see proxy.classifyStream). Closes UAT-K2
	// HIGH-K2-05: the URL parser was the only layer that could decide
	// this for exec/attach/portforward when a client didn't send an
	// Upgrade header on the initial request.
	IsStream bool

	// StreamKind names the streaming type the URL implies. One of:
	// "watch", "exec", "attach", "portforward", "log", or "" (none).
	// Mirrors proxy.StreamKind but is URL-derived rather than header-
	// derived. The proxy combines both signals when recording the
	// audit row.
	StreamKind string

	// IsMetaRead is true when the request targets a kube-apiserver
	// meta/discovery surface (OpenAPI schemas, API-version + group
	// discovery, server version, health/readiness/liveness probes,
	// Prometheus /metrics) rather than a Kubernetes API resource.
	// These are bootstrap reads kubectl + client-go issue BEFORE any
	// real operation; denying them blocks every kubectl call before it
	// can do useful work (#301).
	//
	// When IsMetaRead=true:
	//   - Verb is "get" (HTTP GET only — POST/PUT/PATCH/DELETE on any
	//     meta path returns ErrMalformedURL so the default policy
	//     decides; apiserver itself 405s the write anyway)
	//   - Group is "" (server-internal; not part of any API group)
	//   - Resource is "meta:<kind>" — e.g. "meta:openapi-schema",
	//     "meta:api-discovery", "meta:api-group-discovery",
	//     "meta:version", "meta:health", "meta:metrics"
	//   - Namespace / Name / Subresource are "" (no resource targeting)
	//
	// The proxy short-circuits to ALLOW under any active profile
	// (safe-default included) because these surfaces carry no resource
	// data + no mutating capability. Per [[creates-never-mutates]]
	// the carve-out is narrow: GET method + exact-prefix match against
	// the metaPathKinds table; everything else still flows through the
	// standard rule engine.
	IsMetaRead bool
}

// ErrMalformedURL is returned by [Parse] when the request URL does not
// match any known kube-apiserver path shape. The proxy treats this as
// an unclassifiable call and applies its default policy.
var ErrMalformedURL = errors.New("kbounce: malformed kube-apiserver URL")

// Parse builds a [ParsedRequest] from the inbound HTTP request.
//
// Pure function; does not consume the request body. (K-Slice 1 routes
// every decision off URL + headers; later slices that need PATCH body
// inspection will take a separate code path.)
func Parse(r *http.Request) (*ParsedRequest, error) {
	if r == nil || r.URL == nil {
		return nil, ErrMalformedURL
	}

	method := strings.ToUpper(r.Method)
	path := r.URL.Path
	rawPath := path
	if r.URL.RawQuery != "" {
		rawPath = path + "?" + r.URL.RawQuery
	}

	imp, impUser, impGroups := parseImpersonation(r.Header)
	out := &ParsedRequest{
		Method:             method,
		RawPath:            rawPath,
		BearerTokenPresent: hasBearerToken(r.Header),
		IsImpersonation:    imp,
		ImpersonatedUser:   impUser,
		ImpersonatedGroups: impGroups,
	}

	// Routing: /api/v1/... (core) vs /apis/{group}/{version}/... (named).
	// Trim leading + trailing slashes so the splitter behaves consistently
	// for "/api/v1/pods" and "/api/v1/pods/" alike.
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil, ErrMalformedURL
	}
	segments := strings.Split(trimmed, "/")

	// #301: meta / discovery surfaces (OpenAPI, version, healthz, metrics,
	// API-group discovery). kubectl + client-go hit these BEFORE any
	// resource call — denying them blocked every kubectl invocation under
	// safe-default. Fast-path them as Verb=get + Resource="meta:<kind>" so
	// the rest of the evaluator treats them as read-only metadata. GET
	// only; writes are ErrMalformedURL (apiserver 405s them too).
	if kind, ok := classifyMetaPath(method, segments); ok {
		out.Verb = "get"
		out.Group = ""
		out.Resource = "meta:" + kind
		out.IsMetaRead = true
		// Discovery URLs don't honor ?watch / ?dryRun; skip the query
		// parsing branch below by returning here. Method is already on
		// the struct; RawPath captured the query string for the audit
		// log either way.
		return out, nil
	}

	switch segments[0] {
	case "api":
		// Core API: /api/{version}/{resource}...
		// /api alone + /api/{version} alone (no /{resource} tail) are
		// API-version + resource-list discovery — handled above as
		// IsMetaRead. Anything reaching this branch HAS a resource tail.
		if len(segments) < 3 {
			return nil, ErrMalformedURL
		}
		out.Group = "" // core
		out.Version = segments[1]
		if err := parseResourceTail(out, segments[2:]); err != nil {
			return nil, err
		}
	case "apis":
		// Named API group: /apis/{group}/{version}/{resource}...
		// /apis alone + /apis/{group}/{version} alone (no /{resource}
		// tail) are group-discovery — handled above as IsMetaRead.
		if len(segments) < 4 {
			return nil, ErrMalformedURL
		}
		out.Group = segments[1]
		out.Version = segments[2]
		if err := parseResourceTail(out, segments[3:]); err != nil {
			return nil, err
		}
	default:
		// Anything else (no /api or /apis prefix and not a recognized
		// meta path) is unclassifiable; the default policy decides.
		return nil, ErrMalformedURL
	}

	// Query-param flags.
	q := r.URL.Query()
	if isTruthy(q.Get("watch")) {
		out.IsWatch = true
	}
	// K8s apiserver only honors dryRun=All; any other value is rejected
	// upstream. We mirror that strict check so a request like
	// dryRun=None doesn't mislabel the audit row.
	if q.Get("dryRun") == "All" {
		out.IsDryRun = true
	}

	// Verb inference. If a subresource is present it wins; otherwise
	// derive from method + whether Name is set.
	out.Verb = inferVerb(method, out)

	// UAT-K2 HIGH-K2-05: set IsStream + StreamKind based on URL shape.
	// The proxy will also set these via the Upgrade header (see
	// proxy.classifyStream); URL-level detection is the floor so an
	// exec/attach/portforward call without an Upgrade header still gets
	// tagged correctly in the audit log.
	switch out.Subresource {
	case "exec", "attach", "portforward":
		out.IsStream = true
		out.StreamKind = out.Subresource
	case "log":
		// Logs stream when ?follow=true; the apiserver treats unfollow'd
		// logs as a buffered REST read. Mirror the apiserver's behavior.
		if isTruthy(q.Get("follow")) {
			out.IsStream = true
			out.StreamKind = "log"
		}
	}
	if out.IsWatch {
		out.IsStream = true
		if out.StreamKind == "" {
			out.StreamKind = "watch"
		}
	}

	return out, nil
}

// parseResourceTail consumes the segments after the API root and
// populates Namespace / Resource / Name / Subresource on the parsed
// request. It accepts the post-version segments only; the caller has
// already set Group + Version.
func parseResourceTail(out *ParsedRequest, segs []string) error {
	if len(segs) == 0 {
		// e.g. "/api/v1" alone — discovery endpoint, not a resource call.
		return ErrMalformedURL
	}

	// Detect the namespaced prefix: "namespaces/{ns}/...".
	// The path "/api/v1/namespaces" alone (list namespaces) is handled
	// by the cluster-scoped branch below — segs[0] is "namespaces" but
	// there is no further "/{ns}" segment, so we treat it as a resource
	// named "namespaces" at cluster scope.
	if segs[0] == "namespaces" && len(segs) >= 3 {
		// segs = ["namespaces", "{ns}", "{resource}", ...]
		out.Namespace = segs[1]
		return parseClusterScopedTail(out, segs[2:])
	}
	// "namespaces/{ns}" with no further segments is get/update on the
	// namespace object itself — handle in the cluster-scoped path.
	if segs[0] == "namespaces" && len(segs) == 2 {
		out.Resource = "namespaces"
		out.Name = segs[1]
		return nil
	}

	// Otherwise it's a cluster-scoped resource path.
	return parseClusterScopedTail(out, segs)
}

// parseClusterScopedTail handles the segments after the namespace
// prefix is stripped (or absent). The shapes are:
//
//	{resource}
//	{resource}/{name}
//	{resource}/{name}/{subresource}[/{additional}...]
func parseClusterScopedTail(out *ParsedRequest, segs []string) error {
	if len(segs) == 0 {
		return ErrMalformedURL
	}
	out.Resource = segs[0]
	if len(segs) == 1 {
		return nil
	}
	out.Name = segs[1]
	if len(segs) == 2 {
		return nil
	}
	// Subresource is the next segment; any further segments (e.g.
	// /pods/foo/proxy/some/path) get folded into the subresource so the
	// audit log preserves the full request shape. K8s RBAC matches on
	// the bare subresource token (the first one), so the rule engine
	// only needs that token; full text stays in RawPath.
	out.Subresource = segs[2]
	return nil
}

// inferVerb derives the K8s-canonical verb from method + URL shape.
// When a subresource is present, the subresource name IS the verb.
// (kube-apiserver/RBAC treats "exec" + "portforward" + "log" as
// distinct verbs gated independently from "get" / "create" / etc.)
func inferVerb(method string, p *ParsedRequest) string {
	if p.Subresource != "" {
		return p.Subresource
	}
	named := p.Name != ""
	switch method {
	case http.MethodGet:
		if p.IsWatch {
			return "watch"
		}
		if named {
			return "get"
		}
		return "list"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		if named {
			return "delete"
		}
		return "deletecollection"
	case http.MethodHead:
		// HEAD is rare in kube-apiserver clients; treat as a get if
		// named, list otherwise, so audit reasoning stays consistent.
		if named {
			return "get"
		}
		return "list"
	default:
		// OPTIONS / TRACE / CONNECT etc. should not reach the
		// apiserver; surface the lowercased method so the audit log
		// shows what arrived.
		return strings.ToLower(method)
	}
}

// hasBearerToken returns true iff any Authorization header starts with
// "Bearer ". We tolerate case-insensitive scheme matching since some
// clients lowercase the scheme.
func hasBearerToken(h http.Header) bool {
	for _, v := range h.Values("Authorization") {
		if len(v) >= 7 && strings.EqualFold(v[:7], "Bearer ") {
			return true
		}
	}
	return false
}

// parseImpersonation scans the kube-apiserver impersonation header
// family and returns (any-present, Impersonate-User value, all
// Impersonate-Group values).
//
// Headers consulted:
//
//   - Impersonate-User              (single value)
//   - Impersonate-Group             (multi-value)
//   - Impersonate-Uid               (single value)
//   - Impersonate-Extra-{anything}  (header-name prefix; per-attribute)
//
// The Extra-* family uses a name PREFIX (not a fixed header name),
// so we iterate every header in the map and compare the (canonical-
// case) prefix. Go's net/http canonicalizes header names to
// "Impersonate-Extra-Foo" on insert, so MIME-canonical prefix match
// is the right check. Closes Gap-K-9 + addresses audit-cadence
// note (a): a request that carries ONLY Impersonate-Extra-scopes
// (no -User / -Group) is still flagged.
func parseImpersonation(h http.Header) (bool, string, []string) {
	const extraPrefix = "Impersonate-Extra-"

	any := false
	user := h.Get("Impersonate-User")
	if user != "" {
		any = true
	}
	groups := h.Values("Impersonate-Group")
	if len(groups) > 0 {
		any = true
	}
	if h.Get("Impersonate-Uid") != "" {
		any = true
	}
	if !any {
		// Only scan all header names if the cheap canonical lookups
		// didn't already flip the flag. CanonicalMIMEHeaderKey ensures
		// the inbound headers match the prefix's canonical case.
		for name := range h {
			if strings.HasPrefix(name, extraPrefix) {
				any = true
				break
			}
		}
	}
	return any, user, groups
}

// isTruthy treats "true", "1", and "True" as true. Anything else is
// false. Matches K8s apiserver's looser parsing of ?watch=… (apiserver
// accepts "1" alongside "true").
func isTruthy(s string) bool {
	switch strings.ToLower(s) {
	case "true", "1":
		return true
	}
	return false
}

// classifyMetaPath inspects the request's method + path segments and
// returns the meta-path kind (e.g. "openapi-schema", "api-discovery",
// "version", "health", "metrics") when the request targets a known
// kube-apiserver meta surface AND uses GET. Returns ("", false) for
// everything else.
//
// Closes #301: kubectl + client-go bootstrap by hitting these surfaces
// BEFORE any resource call (OpenAPI v3 schema discovery, API-version
// list, group-resource discovery). Treating them as ErrMalformedURL
// blocked every kubectl invocation under safe-default.
//
// Per [[creates-never-mutates]] the carve-out is narrow:
//
//   - GET method only. Any other method (POST/PUT/PATCH/DELETE) is left
//     unclassifiable so the default policy decides. The apiserver
//     itself 405s writes on every one of these surfaces, so refusing
//     to fast-path them is the safe default.
//   - Exact segment-prefix match against a static table. No wildcards,
//     no regex, no recursive matching that could be tricked by a
//     CRD whose plural happens to be "openapi" or "version".
//   - Discovery paths with /api or /apis prefix only count when the
//     length is short enough that there's no /{resource} tail (e.g.
//     "/api/v1" yes; "/api/v1/pods" no — that's a resource list).
//
// kinds map to the "meta:<kind>" Resource value the parser writes so
// audit-log readers can filter "show me only the meta-reads" with a
// single LIKE 'meta:%' query.
func classifyMetaPath(method string, segments []string) (string, bool) {
	if method != http.MethodGet {
		// Apiserver only serves these as reads; writes 405 upstream.
		// Refuse to fast-path so the default policy decides on writes.
		return "", false
	}
	if len(segments) == 0 {
		return "", false
	}
	switch segments[0] {
	case "openapi":
		// /openapi/v2[/...] or /openapi/v3[/...] — apiserver schema
		// discovery. kubectl 1.24+ requests per-group v3 documents
		// (e.g. /openapi/v3/apis/apps/v1) BEFORE any apply. Length >= 2
		// because /openapi alone is not a real apiserver surface (the
		// server 404s it); we still recognize it as a meta-read so we
		// don't surface a confusing unclassifiable verdict to an
		// operator who pastes the path manually.
		return "openapi-schema", true
	case "version":
		// /version — apiserver build/version info. Single-segment
		// only; /version/foo is not real.
		if len(segments) == 1 {
			return "version", true
		}
		return "", false
	case "healthz", "readyz", "livez":
		// /healthz, /readyz, /livez and subprobes (e.g. /healthz/etcd,
		// /readyz/poststarthook/start-kube-apiserver-admission-initializer).
		// kubelet + load balancers + monitoring scrape these.
		return "health", true
	case "metrics":
		// /metrics — Prometheus exposition. Single segment only.
		if len(segments) == 1 {
			return "metrics", true
		}
		return "", false
	case "api":
		// /api → core-API version list.
		// /api/{version} → core-API resource list (e.g. /api/v1).
		// Anything longer has a resource tail; that's NOT a meta read.
		switch len(segments) {
		case 1:
			return "api-discovery", true
		case 2:
			return "api-version-discovery", true
		}
		return "", false
	case "apis":
		// /apis → group list.
		// /apis/{group} → group versions list (e.g. /apis/apps).
		// /apis/{group}/{version} → group-resource list (e.g. /apis/apps/v1).
		// Anything longer has a resource tail.
		switch len(segments) {
		case 1:
			return "api-discovery", true
		case 2, 3:
			return "api-group-discovery", true
		}
		return "", false
	}
	return "", false
}

// MustParseTestURL is a tiny test helper that builds an *http.Request
// from a raw URL string and method. Kept here (not in _test.go) so
// other packages' tests can compose parser fixtures cheaply without
// duplicating the http.NewRequest boilerplate.
func MustParseTestURL(method, rawURL string) *http.Request {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	req := &http.Request{
		Method: method,
		URL:    u,
		Header: http.Header{},
	}
	return req
}
