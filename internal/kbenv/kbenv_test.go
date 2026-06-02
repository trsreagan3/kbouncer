package kbenv

import "testing"

// TestLookup_BothPrefixesResolve is the representative dual-prefix
// assertion: a kbounce env var set under EITHER the canonical
// KBOUNCER_ prefix OR the shorter KBOUNCE_ alias must resolve, so an
// operator who drops the trailing 'R' (to match the binary name) no
// longer gets a silent no-op.
func TestLookup_BothPrefixesResolve(t *testing.T) {
	const base = "PROFILE"

	// Canonical prefix resolves.
	t.Setenv("KBOUNCER_"+base, "safe-default")
	t.Setenv("KBOUNCE_"+base, "")
	if got, ok := Lookup(base); !ok || got != "safe-default" {
		t.Fatalf("KBOUNCER_%s: got (%q, %v), want (%q, true)", base, got, ok, "safe-default")
	}

	// Alias prefix resolves when canonical is unset.
	t.Setenv("KBOUNCER_"+base, "")
	t.Setenv("KBOUNCE_"+base, "dev-only")
	if got, ok := Lookup(base); !ok || got != "dev-only" {
		t.Fatalf("KBOUNCE_%s: got (%q, %v), want (%q, true)", base, got, ok, "dev-only")
	}

	// Canonical wins when BOTH are set.
	t.Setenv("KBOUNCER_"+base, "canonical")
	t.Setenv("KBOUNCE_"+base, "alias")
	if got := Get(base); got != "canonical" {
		t.Fatalf("both set: Get(%q)=%q, want canonical to win", base, got)
	}

	// Neither set → empty / not-found.
	t.Setenv("KBOUNCER_"+base, "")
	t.Setenv("KBOUNCE_"+base, "")
	if got, ok := Lookup(base); ok || got != "" {
		t.Fatalf("neither set: got (%q, %v), want (\"\", false)", got, ok)
	}
}

// TestLookup_AcceptsFullVarName asserts a caller may pass a legacy full
// var name (with a prefix) and still get dual-prefix resolution — the
// known prefix is stripped before lookup. Lets migrating call sites
// pass an existing `const X = "KBOUNCER_FOO"` unchanged.
func TestLookup_AcceptsFullVarName(t *testing.T) {
	t.Setenv("KBOUNCER_DB", "")
	t.Setenv("KBOUNCE_DB", "/tmp/kb.db")

	// Pass the canonical full name — prefix stripped → base "DB" →
	// resolves under the alias.
	if got := Get("KBOUNCER_DB"); got != "/tmp/kb.db" {
		t.Fatalf("Get(KBOUNCER_DB)=%q, want /tmp/kb.db (alias should resolve)", got)
	}
	// Pass the alias full name — same base, same result.
	if got := Get("KBOUNCE_DB"); got != "/tmp/kb.db" {
		t.Fatalf("Get(KBOUNCE_DB)=%q, want /tmp/kb.db", got)
	}
}

// TestCanonicalName always names the documented KBOUNCER_ form
// regardless of whether the caller passed a base or an aliased name.
func TestCanonicalName(t *testing.T) {
	cases := map[string]string{
		"PROFILE":          "KBOUNCER_PROFILE",
		"KBOUNCE_PROFILE":  "KBOUNCER_PROFILE",
		"KBOUNCER_PROFILE": "KBOUNCER_PROFILE",
	}
	for in, want := range cases {
		if got := CanonicalName(in); got != want {
			t.Errorf("CanonicalName(%q)=%q, want %q", in, got, want)
		}
	}
}
