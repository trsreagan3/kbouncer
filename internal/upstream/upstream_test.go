package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// writeCABundle generates a self-signed CA cert and writes it as a PEM
// file in a temp dir, returning the path. Used by the #379
// --upstream-ca-bundle tests so we exercise a REAL x509 cert pool, not
// a hand-rolled PEM string.
func writeCABundle(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kbounce-test-upstream-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NotEmpty(t, pemBytes)

	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

// TestResolve_UpstreamCABundleLoaded proves a valid --upstream-ca-bundle
// is parsed into the outbound TLS config's RootCAs — and that the pool
// is exactly our single self-signed cert (proving it was loaded from
// the file, not system roots) per #379.
func TestResolve_UpstreamCABundleLoaded(t *testing.T) {
	caPath := writeCABundle(t)
	up, err := Resolve(Options{
		UpstreamURL:          "https://private.cluster.example:6443",
		UpstreamCABundlePath: caPath,
	})
	require.NoError(t, err)
	require.NotNil(t, up)

	tr, ok := up.Client.Transport.(*http.Transport)
	require.True(t, ok, "upstream transport must be *http.Transport")
	require.NotNil(t, tr.TLSClientConfig, "TLS config must be set for an https upstream")
	pool := tr.TLSClientConfig.RootCAs
	require.NotNil(t, pool, "RootCAs must be set when --upstream-ca-bundle is supplied")

	// A custom pool seeded from exactly one cert has exactly one subject
	// — a system-roots pool would have dozens. This proves the bundle
	// REPLACED (not augmented with) system roots.
	subjects := pool.Subjects() //nolint:staticcheck // Subjects() is fine for test assertions
	assert.Len(t, subjects, 1,
		"the pool must contain exactly the single cert from the bundle (not system roots)")

	// And the subject must be our test CA's CN.
	wantPool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(caPath)
	require.NoError(t, err)
	require.True(t, wantPool.AppendCertsFromPEM(pemBytes))
	assert.Equal(t, wantPool.Subjects(), subjects) //nolint:staticcheck
}

// TestResolve_UpstreamCABundleMissingFails proves a non-existent CA
// bundle path is a HARD startup failure (no silent fallback to system
// roots) and the error is classified via ErrCABundle so the CLI can
// refuse to start.
func TestResolve_UpstreamCABundleMissingFails(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL:          "https://private.cluster.example:6443",
		UpstreamCABundlePath: filepath.Join(t.TempDir(), "does-not-exist.pem"),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCABundle)
}

// TestResolve_UpstreamCABundleNotPEMFails proves a file that exists but
// contains no valid PEM certs fails startup loudly (never falls back).
func TestResolve_UpstreamCABundleNotPEMFails(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(bad, []byte("this is not a certificate\n"), 0o600))
	_, err := Resolve(Options{
		UpstreamURL:          "https://private.cluster.example:6443",
		UpstreamCABundlePath: bad,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCABundle)
	assert.Contains(t, err.Error(), "no valid PEM")
}

// TestResolve_UpstreamCABundleOnHTTPFails proves supplying a CA bundle
// for a plain-http upstream is rejected (a CA bundle can only verify a
// TLS upstream; silently ignoring it would mislead the operator).
func TestResolve_UpstreamCABundleOnHTTPFails(t *testing.T) {
	caPath := writeCABundle(t)
	_, err := Resolve(Options{
		UpstreamURL:          "http://plain.cluster.example:8080",
		UpstreamCABundlePath: caPath,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCABundle)
	assert.Contains(t, err.Error(), "plain HTTP")
}
