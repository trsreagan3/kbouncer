package parser

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Table-driven coverage of every URL shape + verb-inference rule the
// rule engine relies on. Each case is intentionally minimal so a
// failure points directly at the offending regex / branch.
func TestParse_TableDriven(t *testing.T) {
	type want struct {
		verb        string
		group       string
		version     string
		resource    string
		namespace   string
		name        string
		subresource string
		isWatch     bool
		isDryRun    bool
	}
	cases := []struct {
		name   string
		method string
		url    string
		want   want
	}{
		{
			name:   "core GET named pod → get",
			method: http.MethodGet,
			url:    "/api/v1/namespaces/default/pods/my-pod",
			want: want{
				verb: "get", group: "", version: "v1",
				resource: "pods", namespace: "default", name: "my-pod",
			},
		},
		{
			name:   "core GET pod list namespaced → list",
			method: http.MethodGet,
			url:    "/api/v1/namespaces/default/pods",
			want: want{
				verb: "list", version: "v1",
				resource: "pods", namespace: "default",
			},
		},
		{
			name:   "core GET cluster-scoped resource list → list",
			method: http.MethodGet,
			url:    "/api/v1/nodes",
			want: want{
				verb: "list", version: "v1", resource: "nodes",
			},
		},
		{
			name:   "core GET cluster-scoped resource named → get",
			method: http.MethodGet,
			url:    "/api/v1/nodes/node-1",
			want: want{
				verb: "get", version: "v1", resource: "nodes", name: "node-1",
			},
		},
		{
			name:   "watch=true → verb=watch + IsWatch",
			method: http.MethodGet,
			url:    "/api/v1/namespaces/default/pods?watch=true",
			want: want{
				verb: "watch", version: "v1",
				resource: "pods", namespace: "default", isWatch: true,
			},
		},
		{
			name:   "watch=1 also flips IsWatch",
			method: http.MethodGet,
			url:    "/api/v1/pods?watch=1",
			want: want{
				verb: "watch", version: "v1", resource: "pods", isWatch: true,
			},
		},
		{
			name:   "POST collection → create",
			method: http.MethodPost,
			url:    "/api/v1/namespaces/default/pods",
			want: want{
				verb: "create", version: "v1",
				resource: "pods", namespace: "default",
			},
		},
		{
			name:   "PUT named → update",
			method: http.MethodPut,
			url:    "/api/v1/namespaces/default/pods/my-pod",
			want: want{
				verb: "update", version: "v1",
				resource: "pods", namespace: "default", name: "my-pod",
			},
		},
		{
			name:   "PATCH named → patch",
			method: http.MethodPatch,
			url:    "/api/v1/namespaces/default/pods/my-pod",
			want: want{
				verb: "patch", version: "v1",
				resource: "pods", namespace: "default", name: "my-pod",
			},
		},
		{
			name:   "DELETE named → delete",
			method: http.MethodDelete,
			url:    "/api/v1/namespaces/default/pods/my-pod",
			want: want{
				verb: "delete", version: "v1",
				resource: "pods", namespace: "default", name: "my-pod",
			},
		},
		{
			name:   "DELETE collection → deletecollection",
			method: http.MethodDelete,
			url:    "/api/v1/namespaces/default/pods",
			want: want{
				verb: "deletecollection", version: "v1",
				resource: "pods", namespace: "default",
			},
		},
		{
			name:   "POST exec subresource → verb=exec",
			method: http.MethodPost,
			url:    "/api/v1/namespaces/default/pods/my-pod/exec",
			want: want{
				verb: "exec", version: "v1",
				resource: "pods", namespace: "default",
				name: "my-pod", subresource: "exec",
			},
		},
		{
			name:   "POST portforward subresource → verb=portforward",
			method: http.MethodPost,
			url:    "/api/v1/namespaces/default/pods/my-pod/portforward",
			want: want{
				verb: "portforward", version: "v1",
				resource: "pods", namespace: "default",
				name: "my-pod", subresource: "portforward",
			},
		},
		{
			name:   "POST attach subresource → verb=attach",
			method: http.MethodPost,
			url:    "/api/v1/namespaces/default/pods/my-pod/attach",
			want: want{
				verb: "attach", version: "v1",
				resource: "pods", namespace: "default",
				name: "my-pod", subresource: "attach",
			},
		},
		{
			name:   "GET log subresource → verb=log",
			method: http.MethodGet,
			url:    "/api/v1/namespaces/default/pods/my-pod/log",
			want: want{
				verb: "log", version: "v1",
				resource: "pods", namespace: "default",
				name: "my-pod", subresource: "log",
			},
		},
		{
			name:   "named-group GET deployment named → get",
			method: http.MethodGet,
			url:    "/apis/apps/v1/namespaces/default/deployments/my-app",
			want: want{
				verb: "get", group: "apps", version: "v1",
				resource: "deployments", namespace: "default", name: "my-app",
			},
		},
		{
			name:   "named-group list deployments cluster-wide → list",
			method: http.MethodGet,
			url:    "/apis/apps/v1/deployments",
			want: want{
				verb: "list", group: "apps", version: "v1",
				resource: "deployments",
			},
		},
		{
			name:   "named-group cluster-scoped CRD-style resource",
			method: http.MethodGet,
			url:    "/apis/rbac.authorization.k8s.io/v1/clusterroles/admin",
			want: want{
				verb: "get", group: "rbac.authorization.k8s.io", version: "v1",
				resource: "clusterroles", name: "admin",
			},
		},
		{
			name:   "named-group named with status subresource",
			method: http.MethodPut,
			url:    "/apis/apps/v1/namespaces/default/deployments/my-app/status",
			want: want{
				verb: "status", group: "apps", version: "v1",
				resource: "deployments", namespace: "default",
				name: "my-app", subresource: "status",
			},
		},
		{
			name:   "named-group named with scale subresource (HPA target)",
			method: http.MethodPatch,
			url:    "/apis/apps/v1/namespaces/default/deployments/my-app/scale",
			want: want{
				verb: "scale", group: "apps", version: "v1",
				resource: "deployments", namespace: "default",
				name: "my-app", subresource: "scale",
			},
		},
		{
			name:   "dryRun=All honored on create",
			method: http.MethodPost,
			url:    "/api/v1/namespaces/default/configmaps?dryRun=All",
			want: want{
				verb: "create", version: "v1",
				resource: "configmaps", namespace: "default", isDryRun: true,
			},
		},
		{
			name:   "dryRun=other ignored",
			method: http.MethodPost,
			url:    "/api/v1/namespaces/default/configmaps?dryRun=None",
			want: want{
				verb: "create", version: "v1",
				resource: "configmaps", namespace: "default", isDryRun: false,
			},
		},
		{
			name:   "namespaces resource itself (cluster-scoped) — named get",
			method: http.MethodGet,
			url:    "/api/v1/namespaces/kube-system",
			want: want{
				verb: "get", version: "v1",
				resource: "namespaces", name: "kube-system",
			},
		},
		{
			name:   "namespaces list (cluster-scoped) → list",
			method: http.MethodGet,
			url:    "/api/v1/namespaces",
			want: want{
				verb: "list", version: "v1", resource: "namespaces",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := MustParseTestURL(tc.method, tc.url)
			got, err := Parse(req)
			require.NoError(t, err, "parse should succeed for %q", tc.url)
			require.NotNil(t, got)

			assert.Equal(t, tc.want.verb, got.Verb, "verb")
			assert.Equal(t, tc.want.group, got.Group, "group")
			assert.Equal(t, tc.want.version, got.Version, "version")
			assert.Equal(t, tc.want.resource, got.Resource, "resource")
			assert.Equal(t, tc.want.namespace, got.Namespace, "namespace")
			assert.Equal(t, tc.want.name, got.Name, "name")
			assert.Equal(t, tc.want.subresource, got.Subresource, "subresource")
			assert.Equal(t, tc.want.isWatch, got.IsWatch, "isWatch")
			assert.Equal(t, tc.want.isDryRun, got.IsDryRun, "isDryRun")
			assert.Equal(t, tc.method, got.Method, "method preserved")
		})
	}
}

func TestParse_MalformedURLs(t *testing.T) {
	// /healthz, /metrics, /api, /apis, /api/v1, /apis/apps, /apis/apps/v1
	// + /openapi/v3[/...] are now recognized as IsMetaRead (#301) and
	// are covered by TestParse_MetaDiscoveryPaths. This set is the
	// residual unclassifiable shapes — paths that neither match a
	// resource shape nor a meta-discovery shape.
	cases := []struct {
		name string
		url  string
	}{
		{name: "root", url: "/"},
		{name: "empty path", url: ""},
		{name: "unknown top-level segment", url: "/foobar"},
		{name: "swagger.json (not a known apiserver surface)", url: "/swagger.json"},
		{name: "namespaced prefix but no resource", url: "/api/v1/namespaces/default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// "/api/v1/namespaces/default" is intentionally treated as a
			// named-get on the namespaces resource (matches K8s
			// semantics — that URL gets the "default" namespace object).
			// Drop it from the malformed set if we adjust later.
			req := MustParseTestURL(http.MethodGet, tc.url)
			got, err := Parse(req)
			if tc.url == "/api/v1/namespaces/default" {
				// This case actually parses successfully as get-namespace.
				require.NoError(t, err)
				assert.Equal(t, "namespaces", got.Resource)
				assert.Equal(t, "default", got.Name)
				return
			}
			require.Error(t, err, "expected error for %q", tc.url)
			assert.Nil(t, got)
		})
	}
}

// TestParse_MetaDiscoveryPaths covers #301: kubectl + client-go
// bootstrap by hitting OpenAPI schema, API-version + group discovery,
// /version, /healthz, /readyz, /livez, /metrics BEFORE any resource
// call. The parser must classify these as IsMetaRead=true with
// Verb="get", Group="", Resource="meta:<kind>" so the proxy can
// short-circuit ALLOW under safe-default. Writes (POST/PUT/PATCH/DELETE)
// on the same prefixes stay unclassifiable per [[creates-never-mutates]].
func TestParse_MetaDiscoveryPaths(t *testing.T) {
	allowed := []struct {
		name     string
		url      string
		wantKind string // "meta:<kind>"
	}{
		{name: "openapi v2", url: "/openapi/v2", wantKind: "meta:openapi-schema"},
		{name: "openapi v3 root", url: "/openapi/v3", wantKind: "meta:openapi-schema"},
		{name: "openapi v3 per-group core", url: "/openapi/v3/api/v1", wantKind: "meta:openapi-schema"},
		{name: "openapi v3 per-group apps", url: "/openapi/v3/apis/apps/v1", wantKind: "meta:openapi-schema"},
		{name: "openapi v3 deeply nested group", url: "/openapi/v3/apis/rbac.authorization.k8s.io/v1", wantKind: "meta:openapi-schema"},
		{name: "version", url: "/version", wantKind: "meta:version"},
		{name: "healthz", url: "/healthz", wantKind: "meta:health"},
		{name: "healthz subprobe", url: "/healthz/etcd", wantKind: "meta:health"},
		{name: "readyz", url: "/readyz", wantKind: "meta:health"},
		{name: "readyz poststarthook", url: "/readyz/poststarthook/start-kube-apiserver-admission-initializer", wantKind: "meta:health"},
		{name: "livez", url: "/livez", wantKind: "meta:health"},
		{name: "metrics", url: "/metrics", wantKind: "meta:metrics"},
		{name: "core API root", url: "/api", wantKind: "meta:api-discovery"},
		{name: "core API version list", url: "/api/v1", wantKind: "meta:api-version-discovery"},
		{name: "named-group root", url: "/apis", wantKind: "meta:api-discovery"},
		{name: "named-group versions list", url: "/apis/apps", wantKind: "meta:api-group-discovery"},
		{name: "named-group resource list", url: "/apis/apps/v1", wantKind: "meta:api-group-discovery"},
		{name: "named-group resource list dotted group", url: "/apis/rbac.authorization.k8s.io/v1", wantKind: "meta:api-group-discovery"},
	}
	for _, tc := range allowed {
		t.Run("GET "+tc.name, func(t *testing.T) {
			req := MustParseTestURL(http.MethodGet, tc.url)
			got, err := Parse(req)
			require.NoError(t, err, "GET %q must classify as meta-read, not malformed", tc.url)
			require.NotNil(t, got)
			assert.True(t, got.IsMetaRead, "IsMetaRead must be true for %q", tc.url)
			assert.Equal(t, "get", got.Verb, "verb must be 'get' for meta paths")
			assert.Equal(t, "", got.Group, "group must be empty for meta paths")
			assert.Equal(t, tc.wantKind, got.Resource, "resource must be %q", tc.wantKind)
			assert.Empty(t, got.Namespace, "namespace must be empty for meta paths")
			assert.Empty(t, got.Name, "name must be empty for meta paths")
			assert.Empty(t, got.Subresource, "subresource must be empty for meta paths")
		})
	}

	// Writes on these surfaces stay unclassifiable: the apiserver 405s
	// them and per [[creates-never-mutates]] kbounce refuses to fast-
	// path anything mutating-shaped through meta-discovery.
	writeMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	writePaths := []string{"/openapi/v3/api/v1", "/version", "/healthz", "/metrics", "/api/v1", "/apis/apps/v1"}
	for _, m := range writeMethods {
		for _, p := range writePaths {
			t.Run(m+" "+p+" must stay unclassifiable", func(t *testing.T) {
				req := MustParseTestURL(m, p)
				_, err := Parse(req)
				require.Error(t, err, "%s %q must NOT fast-path as meta-read", m, p)
			})
		}
	}
}

// TestParse_ResourceTailNotMistakenForMeta confirms my classifyMetaPath
// length checks don't accidentally swallow real resource calls that
// happen to start with /api or /apis. /api/v1/pods is 3 segments and
// /apis/apps/v1/deployments is 4; both have resource tails and must
// flow through the standard parse path (NOT IsMetaRead).
func TestParse_ResourceTailNotMistakenForMeta(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		resource string
	}{
		{name: "core list pods", url: "/api/v1/pods", resource: "pods"},
		{name: "core named pod", url: "/api/v1/namespaces/default/pods/p", resource: "pods"},
		{name: "named-group list deployments", url: "/apis/apps/v1/deployments", resource: "deployments"},
		{name: "named-group named deployment", url: "/apis/apps/v1/namespaces/default/deployments/d", resource: "deployments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := MustParseTestURL(http.MethodGet, tc.url)
			got, err := Parse(req)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.False(t, got.IsMetaRead, "%q is a real resource call, must NOT be IsMetaRead", tc.url)
			assert.Equal(t, tc.resource, got.Resource)
		})
	}
}

func TestParse_NilRequest(t *testing.T) {
	got, err := Parse(nil)
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestParse_BearerTokenExtraction(t *testing.T) {
	t.Run("bearer present", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiIs.example")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.True(t, got.BearerTokenPresent)
	})
	t.Run("bearer absent", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.False(t, got.BearerTokenPresent)
	})
	t.Run("other auth scheme not counted as bearer", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.False(t, got.BearerTokenPresent)
	})
	t.Run("lowercase bearer scheme accepted", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Set("Authorization", "bearer abc")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.True(t, got.BearerTokenPresent)
	})
}

func TestParse_RawPathPreservesQuery(t *testing.T) {
	req := MustParseTestURL(http.MethodGet, "/api/v1/pods?watch=true&timeoutSeconds=60")
	got, err := Parse(req)
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/pods?watch=true&timeoutSeconds=60", got.RawPath)
}

// TestParse_ImpersonationHeaderFamily closes Gap-K-9 from the Opus
// readonly-profile audit. The parser must flag IsImpersonation true
// when ANY of the impersonation header family is present —
// Impersonate-User / Impersonate-Group / Impersonate-Uid /
// Impersonate-Extra-* (the last is a NAME PREFIX, not a fixed
// header). Audit-cadence note (a): a request that carries only
// Impersonate-Extra-scopes must still flip the flag.
func TestParse_ImpersonationHeaderFamily(t *testing.T) {
	t.Run("none present", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.False(t, got.IsImpersonation)
		assert.Empty(t, got.ImpersonatedUser)
		assert.Empty(t, got.ImpersonatedGroups)
	})

	t.Run("Impersonate-User", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Set("Impersonate-User", "cluster-admin")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.True(t, got.IsImpersonation)
		assert.Equal(t, "cluster-admin", got.ImpersonatedUser)
	})

	t.Run("Impersonate-Group multi-value", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Add("Impersonate-Group", "system:masters")
		req.Header.Add("Impersonate-Group", "system:authenticated")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.True(t, got.IsImpersonation)
		assert.Equal(t, []string{"system:masters", "system:authenticated"}, got.ImpersonatedGroups)
	})

	t.Run("Impersonate-Uid alone", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Set("Impersonate-Uid", "abc-123")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.True(t, got.IsImpersonation,
			"Impersonate-Uid alone must flip the flag")
	})

	t.Run("Impersonate-Extra-* prefix only", func(t *testing.T) {
		// Audit-cadence note (a): only Extra-* present (no User /
		// Group / Uid) must still flag the request. The Extra-*
		// family uses a header-name prefix, not a fixed name.
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Set("Impersonate-Extra-Scopes", "view")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.True(t, got.IsImpersonation,
			"Impersonate-Extra-* prefix-only request must flip the flag")
	})

	t.Run("Impersonate-Extra-* + Impersonate-User together", func(t *testing.T) {
		req := MustParseTestURL(http.MethodGet, "/api/v1/pods")
		req.Header.Set("Impersonate-User", "ci-runner")
		req.Header.Set("Impersonate-Extra-Tenant", "team-alpha")
		got, err := Parse(req)
		require.NoError(t, err)
		assert.True(t, got.IsImpersonation)
		assert.Equal(t, "ci-runner", got.ImpersonatedUser)
	})
}
