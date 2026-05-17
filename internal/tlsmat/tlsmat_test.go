package tlsmat

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit_GeneratesAllFourFiles(t *testing.T) {
	dir := t.TempDir()
	res, err := Init(InitOptions{Dir: dir})
	require.NoError(t, err)
	require.NotNil(t, res)
	for _, p := range []string{res.CAKeyPath, res.CACertPath, res.ServerKeyPath, res.ServerCertPath} {
		_, statErr := os.Stat(p)
		require.NoError(t, statErr, "expected file at %s", p)
	}
}

func TestInit_CAKeyHasRestrictedPermissions(t *testing.T) {
	// chmod 0400 has no meaningful effect on Windows; the perm bits aren't
	// enforced the same way. Skip the perm assertion there.
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX perm-bit check on windows")
	}
	dir := t.TempDir()
	res, err := Init(InitOptions{Dir: dir})
	require.NoError(t, err)
	info, err := os.Stat(res.CAKeyPath)
	require.NoError(t, err)
	// We chmod 0400; assert that NO write bit is set + group/other have
	// no read bits. Exact 0400 may be reduced further by a strict umask;
	// the invariant we care about is "no leak to group/other + no write".
	mode := info.Mode().Perm()
	assert.Zero(t, mode&0o077, "ca.key must not be readable/writable by group or other (got %o)", mode)
	assert.Zero(t, mode&0o200, "ca.key must not be writable by anyone (got %o)", mode)
}

func TestInit_CertIsValidX509AndCASignsServer(t *testing.T) {
	dir := t.TempDir()
	res, err := Init(InitOptions{Dir: dir})
	require.NoError(t, err)

	caPEM, err := os.ReadFile(res.CACertPath)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "CA PEM must parse")

	serverPair, err := tls.LoadX509KeyPair(res.ServerCertPath, res.ServerKeyPath)
	require.NoError(t, err, "server cert+key must load as a tls.Certificate")
	require.NotEmpty(t, serverPair.Certificate)

	leaf, err := x509.ParseCertificate(serverPair.Certificate[0])
	require.NoError(t, err)

	// Verify the server cert chains up to the CA we just generated.
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: pool,
		// Server cert is a leaf with ExtKeyUsageServerAuth; default usage
		// list checks that.
		DNSName: "localhost",
	})
	require.NoError(t, err, "server cert must chain to the generated CA")

	// SAN sanity: 127.0.0.1 + ::1 + localhost present.
	dns := map[string]bool{}
	for _, d := range leaf.DNSNames {
		dns[d] = true
	}
	assert.True(t, dns["localhost"], "server cert SAN must include localhost")
	hasV4, hasV6 := false, false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			hasV4 = true
		}
		if ip.Equal(net.ParseIP("::1")) {
			hasV6 = true
		}
	}
	assert.True(t, hasV4, "server cert SAN must include 127.0.0.1")
	assert.True(t, hasV6, "server cert SAN must include ::1")
}

func TestInit_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	_, err := Init(InitOptions{Dir: dir})
	require.NoError(t, err)
	// A second run without --force must fail loudly so an operator
	// doesn't surprise-rotate keys (which would invalidate any kubectl
	// context pinning the prior CA).
	_, err = Init(InitOptions{Dir: dir})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists",
		"refusal message must name the conflict so the operator sees how to fix it")
}

func TestInit_OverwriteSucceedsWithForce(t *testing.T) {
	dir := t.TempDir()
	first, err := Init(InitOptions{Dir: dir})
	require.NoError(t, err)
	firstCA, err := os.ReadFile(first.CACertPath)
	require.NoError(t, err)
	second, err := Init(InitOptions{Dir: dir, Force: true})
	require.NoError(t, err)
	secondCA, err := os.ReadFile(second.CACertPath)
	require.NoError(t, err)
	assert.NotEqual(t, firstCA, secondCA,
		"--force must actually rotate the CA (different bytes)")
}

func TestInit_AdditionalSANsRespected(t *testing.T) {
	dir := t.TempDir()
	res, err := Init(InitOptions{
		Dir:            dir,
		AdditionalSANs: []string{"kbouncer.local", "192.168.1.50"},
	})
	require.NoError(t, err)
	pair, err := tls.LoadX509KeyPair(res.ServerCertPath, res.ServerKeyPath)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)

	gotDNS := map[string]bool{}
	for _, d := range leaf.DNSNames {
		gotDNS[d] = true
	}
	assert.True(t, gotDNS["kbouncer.local"], "DNS SAN must include operator-provided hostname")

	hasExtraIP := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("192.168.1.50")) {
			hasExtraIP = true
		}
	}
	assert.True(t, hasExtraIP, "IP SAN must include operator-provided IP")
}

func TestDefaultDir_HonorsEnvOverride(t *testing.T) {
	td := t.TempDir()
	t.Setenv("KBOUNCER_TLS_DIR", td)
	got, err := DefaultDir()
	require.NoError(t, err)
	assert.Equal(t, td, got)
}

func TestDefaultDir_FallsBackToHome(t *testing.T) {
	t.Setenv("KBOUNCER_TLS_DIR", "")
	got, err := DefaultDir()
	require.NoError(t, err)
	home, _ := os.UserHomeDir()
	assert.Equal(t, filepath.Join(home, ".kbouncer", "tls"), got)
}
