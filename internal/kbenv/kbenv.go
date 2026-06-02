// Package kbenv centralizes kbounce's environment-variable lookups so
// that every kbounce-namespaced env var accepts BOTH the canonical
// `KBOUNCER_` prefix and the shorter `KBOUNCE_` prefix.
//
// Why both prefixes (the footgun this closes):
//
// The binary was renamed kbouncer → kbounce in the 2026-05-17
// Bounce-suite rename ([[bounce-suite-rename]]). The env-var namespace
// was deliberately LEFT at `KBOUNCER_` so existing shell rc files kept
// working ([[bounce-suite-rename]] decision #6). But the binary, the
// docs headers, and a handful of newer vars (KBOUNCE_NO_VERSION_CHECK,
// KBOUNCE_AGENT_NAME) all say `KBOUNCE_`. An operator who types
// `export KBOUNCE_PROFILE=safe-default` (dropping the 'R' to match the
// binary name) got a SILENT no-op — kbounce only read `KBOUNCER_PROFILE`
// — and ran wide-open in passthrough mode thinking they were gated.
//
// Per [[cross-product-word-boundary]] + [[install-ux-gap-2026-05-26]]
// the fix is to accept both prefixes everywhere a kbounce env var is
// read, while documenting `KBOUNCER_` as canonical (it stays the one we
// print in banners / docs so the namespace is stable).
//
// Precedence: the canonical `KBOUNCER_` prefix wins when BOTH are set
// to a non-empty value, so an operator who has the documented form in
// their rc file is never surprised by a stray `KBOUNCE_` export from a
// sibling product. A set-but-empty value is treated as unset (the
// historical os.Getenv("")=="" callers all branch on emptiness).
package kbenv

import "os"

// CanonicalPrefix is the documented / banner-printed prefix. Stable
// across the rename per [[bounce-suite-rename]] decision #6.
const CanonicalPrefix = "KBOUNCER_"

// AliasPrefix is the shorter prefix that matches the post-rename binary
// name (`kbounce`). Accepted as a fallback so dropping the trailing 'R'
// is no longer a silent no-op.
const AliasPrefix = "KBOUNCE_"

// Lookup returns the value of the kbounce env var with the given base
// name (the part AFTER the prefix, e.g. "PROFILE" for KBOUNCER_PROFILE),
// trying the canonical `KBOUNCER_` prefix first and falling back to the
// `KBOUNCE_` alias. The bool reports whether a non-empty value was
// found under either prefix.
//
// Pass base WITHOUT a leading prefix. Passing a full var name that
// already starts with one of the prefixes is handled too (the prefix is
// stripped first) so callers migrating from a `const X = "KBOUNCER_FOO"`
// can pass either "FOO" or the old full name during the transition.
func Lookup(base string) (string, bool) {
	base = stripKnownPrefix(base)
	if v := os.Getenv(CanonicalPrefix + base); v != "" {
		return v, true
	}
	if v := os.Getenv(AliasPrefix + base); v != "" {
		return v, true
	}
	return "", false
}

// Get is the os.Getenv-shaped convenience wrapper: returns the resolved
// value (canonical prefix wins) or "" when neither prefix is set to a
// non-empty value. Drop-in replacement for
// `os.Getenv("KBOUNCER_<BASE>")`.
func Get(base string) string {
	v, _ := Lookup(base)
	return v
}

// CanonicalName returns the documented full var name for a base, e.g.
// CanonicalName("PROFILE") == "KBOUNCER_PROFILE". Useful for banners
// and error messages that should name the canonical form.
func CanonicalName(base string) string {
	return CanonicalPrefix + stripKnownPrefix(base)
}

// stripKnownPrefix removes a leading KBOUNCER_ or KBOUNCE_ so callers
// may pass either a base name or a legacy full var name.
func stripKnownPrefix(s string) string {
	if len(s) >= len(CanonicalPrefix) && s[:len(CanonicalPrefix)] == CanonicalPrefix {
		return s[len(CanonicalPrefix):]
	}
	if len(s) >= len(AliasPrefix) && s[:len(AliasPrefix)] == AliasPrefix {
		return s[len(AliasPrefix):]
	}
	return s
}
