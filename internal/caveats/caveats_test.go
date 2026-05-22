// Tests for the caveats discoverability surfaces.
package caveats

import (
	"strings"
	"testing"
)

func TestAllEntriesHaveURLs(t *testing.T) {
	for _, e := range All {
		if e.ID == "" {
			t.Errorf("entry without ID: %+v", e)
		}
		if e.Anchor == "" {
			t.Errorf("entry %s without anchor", e.ID)
		}
		u := e.URL()
		if !strings.HasPrefix(u, "https://github.com/") {
			t.Errorf("entry %s URL does not look like GitHub: %s", e.ID, u)
		}
		if !strings.Contains(u, e.Anchor) {
			t.Errorf("entry %s URL %s does not contain its anchor %s", e.ID, u, e.Anchor)
		}
		if e.DoctorBlurb == "" {
			t.Errorf("entry %s missing DoctorBlurb", e.ID)
		}
	}
}

func TestByIDFound(t *testing.T) {
	if e := ByID("B5"); e == nil {
		t.Fatal("ByID(B5) returned nil")
	}
	if e := ByID("BNONE"); e != nil {
		t.Fatalf("ByID(BNONE) should be nil, got %+v", e)
	}
}

func TestBannerLinesEmitsB5(t *testing.T) {
	lines := BannerLines(Trigger{})
	if len(lines) != 1 {
		t.Fatalf("expected 1 banner line (B5 always-on), got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "§B5") {
		t.Errorf("banner missing §B5: %v", lines)
	}
}

func TestDoctorEntriesCoversCrossProduct(t *testing.T) {
	ids := map[string]bool{}
	for _, e := range DoctorEntries() {
		ids[e.ID] = true
	}
	for _, must := range []string{"B5", "B13", "B14", "B15"} {
		if !ids[must] {
			t.Errorf("doctor entries missing %s", must)
		}
	}
}

func TestLinkSuffix(t *testing.T) {
	got := LinkSuffix("B5")
	if !strings.Contains(got, "§B5:") {
		t.Errorf("LinkSuffix missing §B5: %q", got)
	}
	if got := LinkSuffix("BNONE"); got != "" {
		t.Errorf("LinkSuffix unknown id should be empty, got %q", got)
	}
}
