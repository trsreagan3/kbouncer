package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// genClientCertPEM returns a self-signed leaf cert + its EC private key as PEM,
// shaped like a kubeconfig client-cert credential.
func genClientCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "kubernetes-admin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// TestBuildTLSConfig_PresentsClientCert is the regression for the client-cert
// auth gap found in dogfooding: a kubeconfig using client-cert auth (the
// kind / k3d / minikube default) must have its cert PRESENTED to the apiserver
// in the outbound TLS config — otherwise the forwarded request arrives as
// system:anonymous and the apiserver returns 403. Bearer-token / in-cluster SA
// auth is unaffected (it rides the HTTP Authorization header, not TLS).
func TestBuildTLSConfig_PresentsClientCert(t *testing.T) {
	certPEM, keyPEM := genClientCertPEM(t)
	u, err := url.Parse("https://apiserver.example.com:6443")
	require.NoError(t, err)

	withCert := &rest.Config{}
	withCert.TLSClientConfig.CertData = certPEM
	withCert.TLSClientConfig.KeyData = keyPEM
	tlsCfg, err := buildTLSConfig(withCert, false, "", u)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	require.Len(t, tlsCfg.Certificates, 1,
		"client cert from kubeconfig must be presented to the apiserver "+
			"(else system:anonymous -> 403)")

	// No cert data (bearer-token / in-cluster path): none presented.
	noCert := &rest.Config{}
	tlsCfg2, err := buildTLSConfig(noCert, false, "", u)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg2)
	require.Empty(t, tlsCfg2.Certificates,
		"no client cert configured -> none presented (bearer-token path unaffected)")
}
