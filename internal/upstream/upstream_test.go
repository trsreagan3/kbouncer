package upstream

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kubeconfigTemplate is a minimal kubeconfig that points at a fake
// apiserver. CA data is empty (skipped); the test patches insecure
// behavior only where it explicitly opts in.
const kubeconfigTemplate = `apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://apiserver.example.com:6443
    insecure-skip-tls-verify: true
contexts:
- name: test-ctx
  context:
    cluster: test-cluster
    user: test-user
users:
- name: test-user
  user:
    token: t0k3n
current-context: test-ctx
`

func writeKubeconfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestResolve_UpstreamFlagWins(t *testing.T) {
	// With --upstream set, the resolver uses that URL even if a
	// kubeconfig is loadable. This is the "operator pins an apiserver"
	// path documented on the Options struct.
	kc := writeKubeconfig(t, kubeconfigTemplate)
	up, err := Resolve(Options{
		UpstreamURL:    "https://override.example.com:6443",
		KubeconfigPath: kc,
	})
	require.NoError(t, err)
	require.NotNil(t, up)
	assert.Equal(t, "override.example.com:6443", up.Host())
	assert.Equal(t, "flag", up.Source)
}

func TestResolve_KubeconfigFallback(t *testing.T) {
	kc := writeKubeconfig(t, kubeconfigTemplate)
	up, err := Resolve(Options{KubeconfigPath: kc})
	require.NoError(t, err)
	require.NotNil(t, up)
	assert.Equal(t, "apiserver.example.com:6443", up.Host())
	assert.Contains(t, up.Source, "kubeconfig:")
	// The kubeconfig explicitly said insecure → resolver honors it.
	assert.True(t, up.InsecureSkipTLSVerify,
		"insecure-skip-tls-verify in kubeconfig must propagate to the resolved Upstream")
}

func TestResolve_NoUpstreamYieldsError(t *testing.T) {
	// No --upstream, no kubeconfig, no env, not in cluster → fail.
	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", t.TempDir()) // forces no ~/.kube/config
	_, err := Resolve(Options{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoUpstream)
}

func TestResolve_RejectsNonHTTPScheme(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "ftp://apiserver.example.com:6443"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestResolve_RejectsMalformedURL(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "::not a url"})
	require.Error(t, err)
}

func TestResolve_InsecureSkipFlagPropagates(t *testing.T) {
	// The flag must propagate even when the kubeconfig didn't request it.
	up, err := Resolve(Options{
		UpstreamURL:           "https://local.cluster.example:6443",
		InsecureSkipTLSVerify: true,
	})
	require.NoError(t, err)
	require.NotNil(t, up)
	assert.True(t, up.InsecureSkipTLSVerify)
}

func TestUpstream_HostHelpers(t *testing.T) {
	u, _ := url.Parse("https://apiserver.example.com:6443")
	up := &Upstream{URL: u}
	assert.Equal(t, "apiserver.example.com:6443", up.Host())

	var nilUp *Upstream
	assert.Empty(t, nilUp.Host(), "nil Upstream must not panic")
}

func TestHostnameOnly(t *testing.T) {
	assert.Equal(t, "apiserver.example.com",
		hostnameOnly("apiserver.example.com:6443"))
	assert.Equal(t, "apiserver.example.com",
		hostnameOnly("apiserver.example.com"))
}
