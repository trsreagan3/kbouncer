// Package upstream resolves the kube-apiserver URL + TLS material
// kbouncer's proxy forwards ALLOW verdicts to. K-Slice 2.
//
// Two resolution paths the proxy supports:
//
//  1. Explicit --upstream URL flag: operator pins the apiserver. The
//     CA bundle still comes from kubeconfig (if present) so TLS
//     verification stays correct, OR --insecure-skip-tls-verify lets
//     the operator opt out for self-signed local clusters.
//
//  2. Kubeconfig auto-detect (default): KUBECONFIG env var → fall back
//     to ~/.kube/config. Uses client-go's clientcmd parser — the
//     canonical way + handles the in-cluster path for sidecar deploys.
//
// What this package does NOT do:
//
//   - It does NOT load the client's bearer token. kbouncer NEVER
//     re-signs / re-authenticates a request; the inbound request's
//     Authorization header (whatever the client put there) is what
//     reaches the apiserver. The proxy is a gating layer, not an
//     identity broker. See [[creates-never-mutates]] in product memory.
//   - It does NOT call the apiserver to verify connectivity at start.
//     That's a deliberate choice: an apiserver outage on launch must
//     not block the proxy from starting (and presenting a useful 502
//     to clients).
//
// The Upstream returned is reused for every forwarded request — one
// shared http.Transport for connection pooling, one tls.Config for
// uniform verification semantics.
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ErrNoUpstream is returned when neither --upstream nor a kubeconfig
// path could be resolved into a usable apiserver URL. Surfaced as a
// startup error in the CLI so operators learn at boot — not when the
// first kubectl call lands.
var ErrNoUpstream = errors.New("kbounce: no upstream apiserver URL resolved " +
	"(pass --upstream or set KUBECONFIG / ~/.kube/config)")

// ErrCABundle wraps every failure that originates from an explicit
// --upstream-ca-bundle / KBOUNCER_UPSTREAM_CA_BUNDLE (#379): a missing
// or unreadable file, a file with no valid PEM certs, or a CA bundle
// supplied for a plain-http upstream. The CLI uses errors.Is against
// this sentinel to decide a CA-bundle problem must fail startup loudly
// rather than be demoted to observation-only mode (which would silently
// degrade upstream TLS verification).
var ErrCABundle = errors.New("kbounce: invalid --upstream-ca-bundle")

// Options carries the inputs Resolve consumes. Built from CLI flags so
// the resolver can be tested without a real env / filesystem.
type Options struct {
	// UpstreamURL, when non-empty, pins the apiserver URL. The kubeconfig
	// is still consulted for CA bundle + TLS material (so an operator
	// can override the URL without giving up TLS verification).
	UpstreamURL string

	// KubeconfigPath, when non-empty, overrides the KUBECONFIG env var
	// + the default ~/.kube/config fallback. Empty triggers the default
	// resolution chain.
	KubeconfigPath string

	// InsecureSkipTLSVerify disables TLS hostname + chain verification on
	// the OUTBOUND connection to the apiserver. Matches the kubeconfig
	// `insecure-skip-tls-verify: true` flag. Defaults false (secure).
	// The flag must be explicit — never inferred from the apiserver URL
	// scheme or the CA bundle's absence.
	InsecureSkipTLSVerify bool

	// UpstreamCABundlePath, when non-empty, points at a PEM file whose
	// certificates verify the kube-apiserver's TLS cert (#379). This is
	// for operators running a private / self-signed kube CA that isn't
	// in the kubeconfig's certificate-authority-data — e.g. a custom
	// --upstream URL fronted by an internal CA. When set, the certs in
	// this file REPLACE the kubeconfig's CA pool (rather than augmenting
	// system roots): an operator who explicitly pins a CA bundle wants
	// THAT bundle to be the trust anchor. If the file is missing,
	// unreadable, or contains no valid PEM certs, Resolve returns an
	// error so kbouncer fails loudly at startup — it MUST NOT silently
	// fall back to system roots (that would be a silent-degradation
	// security regression). Has no effect on a plain-http upstream.
	UpstreamCABundlePath string

	// ForwardTimeout caps how long the proxy waits for an apiserver
	// response. Watch / long-poll requests bypass this (K-Slice 5);
	// short-lived REST calls use it. Zero defaults to 30s.
	ForwardTimeout time.Duration
}

// Upstream is the resolved apiserver target + the shared HTTP client
// kbouncer's proxy uses for every forwarded request. Construct once at
// startup; reuse for every request.
type Upstream struct {
	// URL is the fully-qualified base URL of the apiserver (scheme +
	// host + port). Path/query/fragment from the inbound request are
	// appended to this base when forwarding.
	URL *url.URL

	// Client is the pooled http.Client used to forward requests. The
	// embedded Transport carries the TLS config (CA bundle or insecure-
	// skip) and connection-pool settings.
	Client *http.Client

	// Source describes WHERE the URL came from for the audit log +
	// startup banner. One of: "flag", "kubeconfig:<path>", "in-cluster".
	Source string

	// InsecureSkipTLSVerify is surfaced for logging so the startup
	// banner can flag the insecure path.
	InsecureSkipTLSVerify bool
}

// Host returns the host[:port] of the upstream URL — used by the
// forward-host-allowlist check in proxy.
func (u *Upstream) Host() string {
	if u == nil || u.URL == nil {
		return ""
	}
	return u.URL.Host
}

// Resolve produces an Upstream from the given options.
//
// Precedence:
//
//  1. opts.UpstreamURL (if set): used as the URL. TLS material still
//     comes from kubeconfig if one is loadable; if not, defaults to
//     system roots + the InsecureSkipTLSVerify flag.
//  2. opts.KubeconfigPath / KUBECONFIG / ~/.kube/config: full config
//     load via clientcmd. The current-context's cluster.server is the
//     URL; cluster.certificate-authority-data is the CA bundle.
//  3. In-cluster fallback (only when no kubeconfig is found): runs the
//     standard service-account-token / CA loader for sidecar deploys.
//
// Returns ErrNoUpstream when no path yields a URL.
func Resolve(opts Options) (*Upstream, error) {
	if opts.ForwardTimeout <= 0 {
		opts.ForwardTimeout = 30 * time.Second
	}

	// Try to load a kubeconfig regardless of whether --upstream was given.
	// When --upstream is set, the kubeconfig (if any) still supplies CA
	// material; this lets an operator point at a different node URL while
	// preserving TLS verification.
	restCfg, kubeconfigSource, kubeconfigErr := loadKubeconfig(opts.KubeconfigPath)

	// Determine the URL.
	var (
		urlStr string
		source string
	)
	switch {
	case opts.UpstreamURL != "":
		urlStr = opts.UpstreamURL
		source = "flag"
	case restCfg != nil && restCfg.Host != "":
		urlStr = restCfg.Host
		source = "kubeconfig:" + kubeconfigSource
	default:
		// Last resort: try in-cluster.
		ic, icErr := rest.InClusterConfig()
		if icErr == nil && ic.Host != "" {
			restCfg = ic
			urlStr = ic.Host
			source = "in-cluster"
		} else {
			// Surface the most useful error. If kubeconfig load failed,
			// the operator likely typo'd a path; report that. Otherwise
			// it's a fresh box with no config at all.
			if kubeconfigErr != nil {
				return nil, fmt.Errorf("%w: %v", ErrNoUpstream, kubeconfigErr)
			}
			return nil, ErrNoUpstream
		}
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("kbounce: parse upstream URL %q: %w", urlStr, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("kbounce: upstream URL %q missing scheme or host", urlStr)
	}
	// Reject anything other than http/https — kbouncer is an HTTP proxy
	// and won't speak unix-domain-socket apiservers (KIND, etc) in this
	// slice. Documented limitation.
	if s := strings.ToLower(parsed.Scheme); s != "http" && s != "https" {
		return nil, fmt.Errorf("kbounce: upstream URL scheme %q not supported (want http or https)", parsed.Scheme)
	}

	tlsCfg, err := buildTLSConfig(restCfg, opts.InsecureSkipTLSVerify, opts.UpstreamCABundlePath, parsed)
	if err != nil {
		return nil, err
	}

	// Pooled transport reused for every forward. Tuned for the local-
	// proxy shape: a handful of agents + kubectl invocations, not a
	// high-fanout service.
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsCfg,
		// Force HTTP/1.1 for K-Slice 2; HTTP/2 streaming nuances
		// (especially around long-poll WATCH) ship in K-Slice 5.
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{
		Transport: transport,
		// Per-request timeout covers connect + headers + body. Watch /
		// long-poll requests will set a longer per-request context in
		// K-Slice 5; the conservative default here matches kubectl's
		// default REST timeout.
		Timeout: opts.ForwardTimeout,
		// kbouncer never follows redirects on the operator's behalf —
		// surface the 3xx to the client so kubectl decides.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Upstream{
		URL:                   parsed,
		Client:                client,
		Source:                source,
		InsecureSkipTLSVerify: opts.InsecureSkipTLSVerify || (tlsCfg != nil && tlsCfg.InsecureSkipVerify),
	}, nil
}

// loadKubeconfig runs the same precedence chain kubectl uses:
//
//	explicit path > KUBECONFIG env > ~/.kube/config
//
// Returns (config, source-string, error) where source-string names
// the file actually loaded so the startup banner can show it. Missing
// files produce (nil, "", err) — callers decide whether the absence
// is fatal (no --upstream + no kubeconfig + not in-cluster).
func loadKubeconfig(explicitPath string) (*rest.Config, string, error) {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	if explicitPath != "" {
		loader.ExplicitPath = explicitPath
	}
	// If no explicit path and no KUBECONFIG env var, clientcmd falls
	// back to its default precedence (~/.kube/config). We surface the
	// actually-used file in the source string.
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{})

	// First test whether at least one file exists; clientcmd will
	// happily return an empty config otherwise.
	if explicitPath == "" && os.Getenv("KUBECONFIG") == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			path := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(path); err != nil {
				return nil, "", fmt.Errorf("kubeconfig not found at %s: %w", path, err)
			}
		} else {
			return nil, "", errors.New("no kubeconfig path and no home dir to fall back on")
		}
	}

	restCfg, err := cc.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}

	source := explicitPath
	if source == "" {
		source = os.Getenv("KUBECONFIG")
	}
	if source == "" {
		home, _ := os.UserHomeDir()
		source = filepath.Join(home, ".kube", "config")
	}
	return restCfg, source, nil
}

// buildTLSConfig produces the outbound TLS config from the rest.Config
// (if any), the operator's --insecure-skip-tls-verify flag, and an
// optional explicit --upstream-ca-bundle PEM path (#379).
//
// Order of operations:
//
//  1. If the upstream is plain HTTP, there's no TLS to configure. An
//     explicit --upstream-ca-bundle in this case is a misconfiguration
//     (the operator asked for upstream verification but the upstream
//     speaks cleartext) — we error rather than silently ignore it.
//  2. ServerName defaults to the URL's host so SNI / cert-CN match.
//  3. If --insecure-skip-tls-verify is set OR the kubeconfig requested
//     it, flip InsecureSkipVerify on. Either path is operator-explicit.
//  4. RootCAs: if an explicit --upstream-ca-bundle was given, it is the
//     trust anchor (it REPLACES the kubeconfig CA — an operator who
//     pins a CA wants exactly that one). A missing / unreadable / no-
//     valid-certs file is a HARD startup failure: we never fall back to
//     system roots, because that silent degradation would mean
//     verifying the apiserver against the wrong trust anchor. Otherwise
//     fall back to the kubeconfig's CAData / CAFile as before.
//
// Returns nil tls.Config only when the upstream is plain HTTP — Go's
// transport ignores tls.Config in that case anyway, but we keep it
// explicit to avoid surprising tooling that inspects the field.
func buildTLSConfig(restCfg *rest.Config, insecure bool, caBundlePath string, parsed *url.URL) (*tls.Config, error) {
	if strings.ToLower(parsed.Scheme) == "http" {
		// Plain HTTP: no TLS config needed. The proxy will refuse to
		// honor an http:// upstream in any environment where the kube-
		// config's standard ssl-only path applies, so callers who hit
		// this branch did so intentionally (e.g. local kind cluster
		// with HTTP envoy in front).
		if caBundlePath != "" {
			return nil, fmt.Errorf("%w: %q was set but the upstream %q is "+
				"plain HTTP — a CA bundle only verifies a TLS (https://) "+
				"upstream. Remove the CA bundle or use an https:// upstream URL.",
				ErrCABundle, caBundlePath, parsed.String())
		}
		return nil, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: hostnameOnly(parsed.Host),
	}

	if restCfg != nil && restCfg.TLSClientConfig.Insecure {
		// Kubeconfig explicitly said insecure — honor it.
		tlsCfg.InsecureSkipVerify = true
	}
	if insecure {
		tlsCfg.InsecureSkipVerify = true
	}

	// #379 — explicit operator-supplied CA bundle wins over the
	// kubeconfig CA. Fail loudly on any problem; NEVER fall back to
	// system roots (silent degradation == verifying against the wrong
	// anchor == a security regression).
	if caBundlePath != "" {
		caBytes, err := os.ReadFile(caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("%w: read %q: %w",
				ErrCABundle, caBundlePath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("%w: %q contains no valid PEM certificates",
				ErrCABundle, caBundlePath)
		}
		tlsCfg.RootCAs = pool
		return tlsCfg, nil
	}

	// Load CA bundle. Prefer CAData (inline base64); fall back to CAFile.
	var caBytes []byte
	if restCfg != nil {
		if len(restCfg.TLSClientConfig.CAData) > 0 {
			caBytes = restCfg.TLSClientConfig.CAData
		} else if restCfg.TLSClientConfig.CAFile != "" {
			b, err := os.ReadFile(restCfg.TLSClientConfig.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read kubeconfig CA file %q: %w",
					restCfg.TLSClientConfig.CAFile, err)
			}
			caBytes = b
		}
	}
	if len(caBytes) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, errors.New("kbounce: kubeconfig CA bundle is not valid PEM")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// hostnameOnly strips an optional :port off host[:port].
func hostnameOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
