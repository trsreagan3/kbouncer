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
}

// ErrMalformedURL is returned by [Parse] when the request URL does not
// match any known kube-apiserver path shape. The proxy treats this as
// an unclassifiable call and applies its default policy.
var ErrMalformedURL = errors.New("kbouncer: malformed kube-apiserver URL")

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

	out := &ParsedRequest{
		Method:             method,
		RawPath:            rawPath,
		BearerTokenPresent: hasBearerToken(r.Header),
	}

	// Routing: /api/v1/... (core) vs /apis/{group}/{version}/... (named).
	// Trim leading + trailing slashes so the splitter behaves consistently
	// for "/api/v1/pods" and "/api/v1/pods/" alike.
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil, ErrMalformedURL
	}
	segments := strings.Split(trimmed, "/")

	switch segments[0] {
	case "api":
		// Core API: /api/{version}/...
		if len(segments) < 2 {
			return nil, ErrMalformedURL
		}
		out.Group = "" // core
		out.Version = segments[1]
		if err := parseResourceTail(out, segments[2:]); err != nil {
			return nil, err
		}
	case "apis":
		// Named API group: /apis/{group}/{version}/...
		if len(segments) < 3 {
			return nil, ErrMalformedURL
		}
		out.Group = segments[1]
		out.Version = segments[2]
		if err := parseResourceTail(out, segments[3:]); err != nil {
			return nil, err
		}
	default:
		// Other apiserver endpoints (/healthz, /metrics, /openapi/v2, /version)
		// are not resource calls — the proxy treats them as opaque and
		// forwards under a special "discovery" rule class. Slice 1 just
		// flags them malformed so the default policy decides.
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
