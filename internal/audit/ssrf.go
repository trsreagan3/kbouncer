package audit

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// internalRanges enumerates the CIDR blocks an audit webhook URL
// MUST NOT resolve into unless the operator passed
// --allow-internal-webhook. Mirrors the dbounce MED-D8-06 closure
// pattern verbatim — webhook URLs are operator-supplied + therefore
// in the same threat model as upstream URLs (compromised config
// could redirect to cloud-metadata 169.254.169.254 to exfiltrate
// IAM creds, to RFC1918 to scan an internal network, etc.).
//
// Coverage:
//
//   - 127.0.0.0/8  — IPv4 loopback
//   - 169.254.0.0/16 — IPv4 link-local + cloud-metadata (the
//     169.254.169.254 instance-metadata endpoint is the canonical
//     SSRF target on AWS/GCP/Azure)
//   - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — RFC1918
//   - ::1/128 — IPv6 loopback
//   - fe80::/10 — IPv6 link-local
//   - fc00::/7 — RFC4193 unique local (IPv6 RFC1918 equivalent)
var internalRanges = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",
		"169.254.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			// Compile-time table; a malformed entry is a programmer
			// error. Panic at init time rather than ship a silently
			// permissive resolver.
			panic(fmt.Sprintf("audit: invalid internal CIDR %q: %v", c, err))
		}
		out = append(out, n)
	}
	return out
}()

// internalTLDSuffixes names DNS suffixes whose lookups MUST NOT
// proceed unless the operator opted in. ".internal" is the cloud-
// platform convention for private DNS (GKE, EKS internal zones);
// ".local" is mDNS / Bonjour territory. Both are common SSRF
// targets. Mirrors the dbounce MED-D8-06 suffix list.
var internalTLDSuffixes = []string{".internal", ".local"}

// GuardWebhookURL rejects webhook URLs that resolve to (or textually
// match) internal-network ranges unless the operator passed
// --allow-internal-webhook. lookup is the DNS resolver; nil →
// net.LookupHost (tests inject a stub).
//
// Hostname-suffix checks fire BEFORE DNS so `.internal` / `.local`
// lookups never leave the process when blocked. The IP allowlist
// uses net.LookupHost (NOT URL string parsing) so a DNS-rebinding
// probe like `attacker.com` resolving to 10.0.0.1 is also caught.
//
// Returns nil + nothing-to-do on schemes other than http/https
// (the webhook URL parser will reject non-HTTPS at a higher layer;
// this gate only worries about the resolved network destination).
//
// Mirrors the dbounce MED-D8-06 pattern verbatim — keep the
// behaviors aligned so security teams reviewing one product's
// SSRF gate can rely on the other product's having the same shape.
func GuardWebhookURL(rawURL string, allowInternal bool, lookup func(string) ([]string, error)) error {
	if allowInternal {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("audit: parse webhook URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("audit: webhook URL %q has no hostname", rawURL)
	}
	return guardInternalHost(host, lookup)
}

func guardInternalHost(host string, lookup func(string) ([]string, error)) error {
	lower := strings.ToLower(host)
	for _, suf := range internalTLDSuffixes {
		if strings.HasSuffix(lower, suf) {
			return fmt.Errorf(
				"audit: webhook host %q matches internal TLD suffix %q; "+
					"this is rejected by default to prevent SSRF-shaped "+
					"abuse of operator-influenced webhook URLs. Pass "+
					"--allow-internal-webhook on `kbounce run` to opt in "+
					"for a legitimate intranet collector.",
				host, suf)
		}
	}
	// If the host is already a literal IP, no DNS lookup is needed.
	if ip := net.ParseIP(host); ip != nil {
		if name, ok := matchInternalRange(ip); ok {
			return fmt.Errorf(
				"audit: webhook host %q resolves to %s which is inside "+
					"internal range %s; rejected by default (SSRF gate). "+
					"Pass --allow-internal-webhook to opt in.",
				host, ip.String(), name)
		}
		return nil
	}
	// Hostname: resolve + check every returned IP. Reject on the
	// FIRST match — DNS-rebinding-style attacks that return mixed
	// public + private IPs are still caught.
	resolver := lookup
	if resolver == nil {
		resolver = net.LookupHost
	}
	addrs, err := resolver(host)
	if err != nil {
		return fmt.Errorf(
			"audit: lookup webhook host %q: %w (refused by SSRF gate "+
				"because we can't confirm the host is public; pass "+
				"--allow-internal-webhook if this is intentional)", host, err)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if name, ok := matchInternalRange(ip); ok {
			return fmt.Errorf(
				"audit: webhook host %q resolves to %s which is inside "+
					"internal range %s; rejected by default (SSRF gate). "+
					"Pass --allow-internal-webhook to opt in.",
				host, ip.String(), name)
		}
	}
	return nil
}

func matchInternalRange(ip net.IP) (string, bool) {
	for _, n := range internalRanges {
		if n.Contains(ip) {
			return n.String(), true
		}
	}
	return "", false
}
