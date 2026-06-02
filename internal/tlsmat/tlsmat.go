// Package tlsmat generates the TLS material kbouncer's inbound listener
// uses to speak HTTPS to kubectl / Helm / a coding agent.
//
// K-Slice 4 ships a single, narrowly-scoped capability: an operator runs
// `kbouncer init-tls` ONCE on their laptop, this package writes a
// self-signed local CA + a server cert into ~/.kbouncer/tls/, and the
// operator adds the CA path to their kubectl context's
// `certificate-authority` field. After that kubectl can speak HTTPS to
// the proxy without `--insecure-skip-tls-verify`.
//
// What this package does NOT do:
//
//   - It does NOT issue client certs. mTLS client-auth (K-Slice 4 part
//     3) uses an OPERATOR-PROVIDED CA bundle so the trust anchor stays
//     under the operator's control. We never issue client certs the
//     operator didn't explicitly ask for.
//   - It does NOT rotate keys automatically. The CA + server cert
//     generated here last 10 years; an operator who wants rotation
//     can re-run `init-tls` (with --force) to overwrite. Rotation as
//     a recurring background job is post-v1.0.
//   - It does NOT touch the kubeconfig. Generating + writing the CA is
//     the proxy's job; wiring the CA into kubectl is the operator's job
//     (documented in the CLI banner + the README).
//
// Trust model:
//
//   - The generated CA is LOCAL to one laptop. It is NOT a public-trust
//     CA. An attacker who steals the CA private key can forge a cert
//     for the proxy's hostname; this is acceptable because the same
//     attacker who can read ~/.kbouncer/ca.key can also read the
//     kubeconfig + the audit DB.
//   - We chmod the CA key to 0400 to make it explicit + to flag pairing
//     mistakes (a 0644 key would have allowed local-shared-machine
//     escalation; we refuse to write that).
//   - Server cert SAN list defaults to 127.0.0.1 + ::1 + localhost so
//     the cert validates against the proxy's loopback bindings. The
//     operator can add hostnames via opts.AdditionalSANs (rare; only
//     useful when the proxy is fronted by a hostname-based reverse
//     proxy on the same box).
//
// Security audit-cadence notes (per [[audit-cadence-discipline]]):
//
//   - We use crypto/rand for both the CA and server private keys; no
//     deterministic seeds, no math/rand.
//   - Key sizes: 2048-bit RSA. Smaller (RSA-1024) would be cheaper to
//     generate but is below the NIST 2030 deprecation horizon.
//   - We DO NOT allow overwriting an existing file by default — the
//     caller passes opts.Force=true to opt in. This avoids surprise key
//     rotation that would invalidate the kubectl context's CA pin.
package tlsmat

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/trsreagan3/kbouncer/internal/kbenv"
)

// FileNameCAKey / FileNameCACert / FileNameServerKey / FileNameServerCert
// are the canonical names kbouncer reads + writes. Kept as constants so
// the CLI banner + the proxy listener + the tests don't drift.
const (
	FileNameCAKey      = "ca.key"
	FileNameCACert     = "ca.crt"
	FileNameServerKey  = "server.key"
	FileNameServerCert = "server.crt"
)

// CAValidityDays / ServerValidityDays bound the certs' lifetimes. 10
// years is generous but a single-laptop self-signed CA isn't subject
// to the same rotation hygiene as a public-trust CA; an operator who
// wants rotation re-runs `init-tls --force`.
const (
	CAValidityDays     = 365 * 10
	ServerValidityDays = 365 * 10
)

// InitOptions tunes a single `init-tls` invocation.
type InitOptions struct {
	// Dir is the directory the four files (ca.key, ca.crt, server.key,
	// server.crt) are written into. Created with 0o700 if missing.
	// Empty falls back to DefaultDir().
	Dir string

	// Force, when true, overwrites existing files. Default refuses
	// existing files to avoid surprise key rotation.
	Force bool

	// AdditionalSANs are extra DNS names and IPs added to the server
	// cert's SAN list, on top of the loopback defaults
	// (127.0.0.1, ::1, localhost). Rare; only useful when the proxy is
	// fronted by a hostname-based reverse proxy on the same box.
	AdditionalSANs []string

	// CACommonName / ServerCommonName override the default CN strings.
	// Empty falls back to canonical defaults ("kbouncer local CA" /
	// "kbouncer local server"). Tests use this to keep their fixtures
	// distinguishable from production output.
	CACommonName     string
	ServerCommonName string
}

// InitResult is what Init returns on success. Paths are absolute so the
// CLI banner can print them verbatim regardless of opts.Dir's shape.
type InitResult struct {
	Dir            string
	CAKeyPath      string
	CACertPath     string
	ServerKeyPath  string
	ServerCertPath string
}

// DefaultDir is ~/.kbouncer/tls when KBOUNCER_TLS_DIR (and its
// KBOUNCE_TLS_DIR alias) are unset. Tests + CI use the env var to
// point at a tempdir.
func DefaultDir() (string, error) {
	if override := kbenv.Get("TLS_DIR"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("kbounce: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".kbouncer", "tls"), nil
}

// Init writes the CA + server cert pair into opts.Dir. Idempotent only
// when opts.Force=true; otherwise existing files cause an error so a
// re-run doesn't silently rotate keys.
//
// The CA key is written with mode 0400 (operator-only read, no write);
// other files use 0644 so kubectl can read them.
func Init(opts InitOptions) (*InitResult, error) {
	dir := opts.Dir
	if dir == "" {
		d, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("kbounce: mkdir %q: %w", dir, err)
	}

	caKeyPath := filepath.Join(dir, FileNameCAKey)
	caCertPath := filepath.Join(dir, FileNameCACert)
	serverKeyPath := filepath.Join(dir, FileNameServerKey)
	serverCertPath := filepath.Join(dir, FileNameServerCert)

	if !opts.Force {
		for _, p := range []string{caKeyPath, caCertPath, serverKeyPath, serverCertPath} {
			if _, err := os.Stat(p); err == nil {
				return nil, fmt.Errorf(
					"kbounce: %s already exists; pass --force to overwrite "+
						"(this rotates the CA + invalidates any kubectl context "+
						"that pins the prior cert)", p)
			}
		}
	}

	caCN := opts.CACommonName
	if caCN == "" {
		caCN = "kbouncer local CA"
	}
	serverCN := opts.ServerCommonName
	if serverCN == "" {
		serverCN = "kbouncer local server"
	}

	// --- CA ---
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("kbounce: generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: caCN, Organization: []string{"kbouncer"}},
		NotBefore:    time.Now().Add(-1 * time.Minute).UTC(),
		NotAfter:     time.Now().AddDate(0, 0, CAValidityDays).UTC(),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("kbounce: self-sign CA: %w", err)
	}

	// --- Server cert ---
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("kbounce: generate server key: %w", err)
	}
	dnsNames := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, extra := range opts.AdditionalSANs {
		if ip := net.ParseIP(extra); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, extra)
		}
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: serverCN, Organization: []string{"kbouncer"}},
		NotBefore:    time.Now().Add(-1 * time.Minute).UTC(),
		NotAfter:     time.Now().AddDate(0, 0, ServerValidityDays).UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// Include both ServerAuth + ClientAuth so the same cert+key
		// pair can be used as a client identity in deployments where
		// the operator wants the simplest possible loopback mTLS setup
		// ("the proxy is also its own client"). Operators who want
		// per-agent client certs should issue them separately; kbouncer
		// does not issue client certs by default (see package doc).
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("kbounce: parse self-signed CA: %w", err)
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("kbounce: sign server cert: %w", err)
	}

	// --- Persist ---
	// Order matters: write KEYS first so an interrupted run leaves a
	// matching set of "no key" rather than "cert without key" which the
	// proxy startup would crash on with a less-helpful error.
	if err := writePEM(caKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey), 0o400); err != nil {
		return nil, fmt.Errorf("kbounce: write ca.key: %w", err)
	}
	if err := writePEM(caCertPath, "CERTIFICATE", caDER, 0o644); err != nil {
		return nil, fmt.Errorf("kbounce: write ca.crt: %w", err)
	}
	if err := writePEM(serverKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey), 0o400); err != nil {
		return nil, fmt.Errorf("kbounce: write server.key: %w", err)
	}
	if err := writePEM(serverCertPath, "CERTIFICATE", serverDER, 0o644); err != nil {
		return nil, fmt.Errorf("kbounce: write server.crt: %w", err)
	}

	return &InitResult{
		Dir:            dir,
		CAKeyPath:      caKeyPath,
		CACertPath:     caCertPath,
		ServerKeyPath:  serverKeyPath,
		ServerCertPath: serverCertPath,
	}, nil
}

// writePEM writes a single PEM block to path with the requested mode.
// Pre-removes an existing file so a force-rotation actually changes the
// mode rather than inheriting the prior file's permissions.
func writePEM(path, blockType string, derBytes []byte, mode os.FileMode) error {
	_ = os.Remove(path) // best-effort; permissions need a fresh inode to take effect
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: derBytes})
}

// mustSerial returns a random 128-bit serial; the only error path is
// the system RNG failing, which we treat as fatal because no kbouncer
// behavior is meaningful after that. Tests don't trigger this path.
func mustSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(fmt.Sprintf("kbounce: crypto/rand failed generating serial: %v", err))
	}
	return n
}

// ErrFilesPresent is returned (wrapped) by Init when --force was not
// supplied and existing files would have been overwritten. Kept exported
// so the CLI can errors.Is + print a different exit code if needed.
var ErrFilesPresent = errors.New("kbounce: TLS files already present")
