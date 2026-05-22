// Package caveats surfaces relevant §B entries from the canonical
// KNOWN-CAVEATS.md doc at three discoverability surfaces:
//
//   - `kbounce run` startup banner (one-line hint when a triggering
//     config is detected)
//   - `kbounce doctor caveats` (full §B explanation per applicable
//     entry, plus link to canonical doc)
//   - MCP tool descriptions (so an agent reading `tools/list` sees
//     the caveat embedded in the description)
//
// The canonical caveat content lives in
// https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md.
// THIS package does NOT duplicate the full content — only the short
// summary string + the anchor — because:
//   - the canonical doc is owned by the iam-roles repo (concurrent
//     edit hazard if we copy verbatim across four repos);
//   - the one-line banner + the doctor's short blurb is enough to
//     point an operator at the linked anchor for the full read.
//
// Per [[deliberate-feature-completion]]: each Bounce product surfaces
// only the §B entries that genuinely apply to ITS shape. Cross-product
// entries (B13 / B14 / B15) appear in every product's caveats list;
// product-specific entries appear only in the matching repo.
package caveats

import "fmt"

// canonicalDocURL is the GitHub-rendered KNOWN-CAVEATS.md URL all
// surfaces link to. Kept centralized so a future repo move only
// updates one constant.
const canonicalDocURL = "https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md"

// Entry describes one row from KNOWN-CAVEATS §B that kbounce surfaces.
type Entry struct {
	ID          string
	Anchor      string
	BannerLine  string
	DoctorBlurb string
}

// URL builds the full GitHub URL pointing at this entry's anchor.
func (e Entry) URL() string {
	return canonicalDocURL + "#" + e.Anchor
}

// All kbounce-relevant §B entries. Per task #304:
//   - product-specific: B5 (container-internal calls)
//   - cross-product: B13, B14, B15
//
// Note: §B4 (verb-level catches) is documented in KNOWN-CAVEATS as
// ibounce-specific. kbounce's safe-default catches are similarly
// verb-shaped, but we surface that property via the MCP tool
// description directly rather than via a §B4 entry — pointing
// agents reading kbounce_active_mode at iam-jit for content-aware
// risk scoring per the task #304 spec.
var All = []Entry{
	{
		ID:     "B5",
		Anchor: "b5-kbounce-doesnt-see-container-internal-calls-design",
		BannerLine: "  caveat: kbounce sits between kubectl/client-go and the " +
			"apiserver; pod-to-pod traffic is NOT seen (see KNOWN-CAVEATS §B5)",
		DoctorBlurb: "kbounce sits between kubectl/client-go and the " +
			"kube-apiserver. Pod-to-pod service-mesh traffic does NOT flow " +
			"through that path. Per [[no-k8s-proxy-for-iam-jit]]: kbounce " +
			"is the apiserver-edge gate, not a sidecar.",
	},
	{
		ID:     "B13",
		Anchor: "b13-cross-product-1-3-concurrent-terminals-in-v10-gap--v11-raises-to-20",
		DoctorBlurb: "kbounce shares the cross-product 1-3 concurrent " +
			"terminal limit with ibounce + dbounce + gbounce. Session " +
			"attribution gets noisy past 3 concurrent terminals. v1.1 " +
			"task #296 raises this to 20.",
	},
	{
		ID:     "B14",
		Anchor: "b14-cross-product-defense-in-depth--unified-product-design-per-four-products-one-brand",
		DoctorBlurb: "kbounce is one of four Bounce products under one " +
			"brand — NOT a unified suite. ~10% of decisions show TRUE " +
			"multi-layer composition per UAT. The honest framing per " +
			"[[ibounce-honest-positioning]]: complementary products.",
	},
	{
		ID:     "B15",
		Anchor: "b15-cross-product-no-unified-deny-prompt-ui-in-v10-gap--v11",
		DoctorBlurb: "Each bouncer prompts independently in v1.0. " +
			"v1.1 brings a unified prompt-inbox UI across the suite.",
	},
}

// ByID returns the Entry with the given ID, or nil if no match.
func ByID(id string) *Entry {
	for i := range All {
		if All[i].ID == id {
			return &All[i]
		}
	}
	return nil
}

// LinkSuffix returns " (see KNOWN-CAVEATS §<ID>: <URL>)" for the
// entry with the given ID, suitable for appending to an error message
// body. Returns empty string when the ID isn't recognized.
func LinkSuffix(id string) string {
	e := ByID(id)
	if e == nil {
		return ""
	}
	return fmt.Sprintf(" (see KNOWN-CAVEATS §%s: %s)", e.ID, e.URL())
}

// CanonicalDocURL returns the base URL operators can read.
func CanonicalDocURL() string { return canonicalDocURL }

// Trigger captures the runtime conditions that determine which §B
// entries the startup banner emits. v1.0 kbounce surfaces B5 as a
// structural fact (always-on); future triggers (e.g. quiet-banner,
// containerized-bind detection) hook in here.
type Trigger struct {
	// SafeDefaultProfile is true when the active profile is
	// "safe-default" — currently unused (kbounce's safe-default
	// banner guidance is handled in cli.go's existing default-profile
	// hint). Reserved so a future verb-level explainer can hook in
	// without API churn.
	SafeDefaultProfile bool
}

// BannerLines returns the per-line banner output for the matched
// caveats. B5 always fires because kbounce's shape ALWAYS sits at
// the apiserver edge — the caveat is structural, not config-dependent.
func BannerLines(_ Trigger) []string {
	var out []string
	if e := ByID("B5"); e != nil && e.BannerLine != "" {
		out = append(out, e.BannerLine)
	}
	return out
}

// DoctorEntries returns the entries `kbounce doctor caveats` prints.
func DoctorEntries() []Entry { return All }
