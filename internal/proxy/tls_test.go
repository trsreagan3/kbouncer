package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/tlsmat"
)

// generateTestTLSMaterial runs tlsmat.Init in a tempdir and returns the
// generated paths. Shared helper for K-Slice 4 tests so each case is
// short.
func generateTestTLSMaterial(t *testing.T) *tlsmat.InitResult {
	t.Helper()
	dir := t.TempDir()
	res, err := tlsmat.Init(tlsmat.InitOptions{Dir: dir})
	require.NoError(t, err)
	return res
}

// clientWithCA returns an *http.Client that trusts the given PEM CA
// file. The proxy's HTTPS listener uses a self-signed cert; this client
// is the kubectl-shaped consumer with the CA pinned via
// `certificate-authority` (mirrors the documented operator workflow).
func clientWithCA(t *testing.T, caPath string) *http.Client {
	t.Helper()
	caBytes, err := os.ReadFile(caPath)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caBytes))
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}
}

// clientWithCAAndClientCert is like clientWithCA but ALSO presents a
// client cert/key pair for mTLS-required listeners.
func clientWithCAAndClientCert(t *testing.T, caPath, certPath, keyPath string) *http.Client {
	t.Helper()
	caBytes, err := os.ReadFile(caPath)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caBytes))
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      pool,
				Certificates: []tls.Certificate{pair},
			},
		},
	}
}

// startServerWithListener picks a random port via net.Listen("tcp", "127.0.0.1:0"),
// then hands the listener to the proxy. Tests get the bound URL +
// cleanup is handled via t.Cleanup.
//
// useTLS=true wraps the listener in TLS using cfg.TLSCertPath/Key. When
// cfg.RequireClientCertCAPath is also set, the wrapper enforces mTLS.
func startServerWithListener(t *testing.T, cfg Config, useTLS bool) (*Server, string) {
	t.Helper()
	st := freshStore(t)
	s := NewServer(cfg, st)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	scheme := "http"
	if useTLS {
		tlsCfg, err := s.buildListenerTLSConfig()
		require.NoError(t, err)
		ln = tls.NewListener(ln, tlsCfg)
		scheme = "https"
	}
	go func() {
		_ = s.ServeListener(ln)
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s, fmt.Sprintf("%s://%s", scheme, ln.Addr().String())
}

// ---------------------------------------------------------------------
// HTTPS listener: kubectl-shaped client speaks TLS to the proxy
// ---------------------------------------------------------------------

func TestTLSListener_HTTPSClientCanReachProxy(t *testing.T) {
	mat := generateTestTLSMaterial(t)
	cfg := Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		TLSCertPath:   mat.ServerCertPath,
		TLSKeyPath:    mat.ServerKeyPath,
	}
	_, baseURL := startServerWithListener(t, cfg, true)

	client := clientWithCA(t, mat.CACertPath)
	resp, err := client.Get(baseURL + "/api/v1/namespaces/default/pods/my-pod")
	require.NoError(t, err, "kubectl-shaped HTTPS client must reach the proxy")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// K-Slice 1 observation body is what we get with no upstream wired —
	// proves the request reached the gating layer.
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "proxy_observation")
}

func TestTLSListener_RejectsClientWithoutCA(t *testing.T) {
	mat := generateTestTLSMaterial(t)
	cfg := Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		TLSCertPath:   mat.ServerCertPath,
		TLSKeyPath:    mat.ServerKeyPath,
	}
	_, baseURL := startServerWithListener(t, cfg, true)

	// Default client with no CA + no insecure-skip — must fail TLS verify
	// because the proxy's cert is signed by a self-signed CA the client
	// has never seen. This is the regression guard for "we didn't
	// silently fall back to plain HTTP."
	resp, err := http.Get(baseURL + "/healthz")
	require.Error(t, err)
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// ---------------------------------------------------------------------
// mTLS: client cert required + CA gates which clients can connect
// ---------------------------------------------------------------------

func TestTLSListener_MTLS_RejectsClientWithoutCert(t *testing.T) {
	mat := generateTestTLSMaterial(t)
	cfg := Config{
		Mode:                    ModeCooperative,
		DefaultPolicy:           DefaultPolicyAllow,
		TLSCertPath:             mat.ServerCertPath,
		TLSKeyPath:              mat.ServerKeyPath,
		RequireClientCertCAPath: mat.CACertPath, // any cert signed by our CA accepted
	}
	_, baseURL := startServerWithListener(t, cfg, true)

	// Client trusts the server CA but presents NO client cert. mTLS in
	// strict mode (RequireAndVerifyClientCert) MUST fail the handshake.
	// Audit-cadence note: this is the regression guard against the
	// VerifyClientCertIfGiven footgun — anonymous clients must be
	// rejected, not silently accepted.
	client := clientWithCA(t, mat.CACertPath)
	_, err := client.Get(baseURL + "/healthz")
	require.Error(t, err, "mTLS-strict listener must reject anonymous TLS clients")
}

func TestTLSListener_MTLS_AcceptsClientWithSignedCert(t *testing.T) {
	mat := generateTestTLSMaterial(t)
	// Reuse the server.crt/server.key as a "client cert" — it is signed
	// by our CA + has ExtKeyUsageServerAuth which Go accepts as
	// well-formed for client auth in the absence of explicit
	// ExtKeyUsageClientAuth requirements on the verifier.
	// Production deployments would issue dedicated client certs; this
	// test only proves "a cert signed by the trusted CA is accepted."
	cfg := Config{
		Mode:                    ModeCooperative,
		DefaultPolicy:           DefaultPolicyAllow,
		TLSCertPath:             mat.ServerCertPath,
		TLSKeyPath:              mat.ServerKeyPath,
		RequireClientCertCAPath: mat.CACertPath,
	}
	_, baseURL := startServerWithListener(t, cfg, true)

	client := clientWithCAAndClientCert(t, mat.CACertPath,
		mat.ServerCertPath, mat.ServerKeyPath)
	resp, err := client.Get(baseURL + "/healthz")
	require.NoError(t, err, "client cert signed by trusted CA must be accepted")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTLSListener_MTLS_RejectsClientCertSignedByDifferentCA(t *testing.T) {
	// Server CA + server cert.
	serverMat := generateTestTLSMaterial(t)
	// Different CA (a fresh init in a fresh dir) — the client cert this
	// produces is well-formed but NOT signed by serverMat.CA. The
	// listener must reject it.
	otherMat := generateTestTLSMaterial(t)

	cfg := Config{
		Mode:                    ModeCooperative,
		DefaultPolicy:           DefaultPolicyAllow,
		TLSCertPath:             serverMat.ServerCertPath,
		TLSKeyPath:              serverMat.ServerKeyPath,
		RequireClientCertCAPath: serverMat.CACertPath,
	}
	_, baseURL := startServerWithListener(t, cfg, true)

	client := clientWithCAAndClientCert(t, serverMat.CACertPath,
		otherMat.ServerCertPath, otherMat.ServerKeyPath)
	_, err := client.Get(baseURL + "/healthz")
	require.Error(t, err, "mTLS must reject client certs not signed by the configured CA")
}

// ---------------------------------------------------------------------
// Plain HTTP preserved as default
// ---------------------------------------------------------------------

func TestTLSListener_PlainHTTPRemainsDefault(t *testing.T) {
	// No TLSCertPath / TLSKeyPath — must keep listening on plain HTTP
	// so the K-Slice 1 / K-Slice 2 "I just installed; testing" loop
	// keeps working unchanged. Regression guard for the additive change.
	cfg := Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
	}
	_, baseURL := startServerWithListener(t, cfg, false)

	resp, err := http.Get(baseURL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	u, err := url.Parse(baseURL)
	require.NoError(t, err)
	assert.Equal(t, "http", u.Scheme, "default scheme must remain plain HTTP")
}

// ---------------------------------------------------------------------
// buildListenerTLSConfig surfaces useful errors
// ---------------------------------------------------------------------

func TestBuildListenerTLSConfig_RejectsBadCertPath(t *testing.T) {
	s := &Server{cfg: Config{
		TLSCertPath: "/nonexistent/cert.crt",
		TLSKeyPath:  "/nonexistent/cert.key",
	}}
	_, err := s.buildListenerTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load TLS cert pair",
		"error message must name the operation so operators know where to look")
}

func TestBuildListenerTLSConfig_RejectsBadCABundle(t *testing.T) {
	mat := generateTestTLSMaterial(t)
	// Write garbage into a file and point RequireClientCertCAPath at it.
	bad := filepath.Join(t.TempDir(), "not-a-ca.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not pem at all"), 0o600))
	s := &Server{cfg: Config{
		TLSCertPath:             mat.ServerCertPath,
		TLSKeyPath:              mat.ServerKeyPath,
		RequireClientCertCAPath: bad,
	}}
	_, err := s.buildListenerTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid PEM")
}
