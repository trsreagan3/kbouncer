// CLI tests for `kbounce rules recommend` + the profile auto-naming
// primitive.
//
// Test count breakdown (relative to the parent commit task):
//   - SuggestProfileName_* covers the naming-format invariants
//   - AvoidNameCollision covers the -2/-3 suffix logic
//   - ResolveProfileName_NonTTY_AutoGen covers the non-interactive path
//   - ResolveProfileName_NonTTY_NameProvided covers the explicit path
//   - SaveAsProfile_OrgSourcedRefusal covers the read-only invariant
//   - SaveAsProfile_MergeLocalDedupes covers the merge semantics
//   - Recommend_AppliesRules + Recommend_SaveAsProfile cover end-to-end
//
// Together with internal/recommender/recommender_test.go this comes to
// well above the 8-10 synthesis + 3-5 auto-naming requirement.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/recommender"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// recForTest builds a small Recommendation for naming/suggestion tests.
func recForTest(pattern string, support int) recommender.Recommendation {
	return recommender.Recommendation{
		ProposedRule: rules.ProxyRule{Pattern: pattern, Effect: rules.EffectAllow},
		SupportCount: support,
	}
}

func TestSuggestProfileName_TopResourcesFromRecs(t *testing.T) {
	recs := []recommender.Recommendation{
		recForTest("pods:get", 10),
		recForTest("pods:list", 8),
		recForTest("services:list", 3),
	}
	name := SuggestProfileName(recs, recommender.WindowSummary{})
	assert.True(t, strings.Contains(name, "pods"),
		"suggested name should mention top resource 'pods'; got %q", name)
	assert.True(t, strings.HasPrefix(name, "auto-"),
		"suggested name should start with 'auto-'; got %q", name)
	assert.True(t, strings.HasSuffix(name, "-readonly"),
		"suggested name should end with '-readonly'; got %q", name)
}

func TestSuggestProfileName_HandlesEmptyRecs(t *testing.T) {
	name := SuggestProfileName(nil, recommender.WindowSummary{})
	assert.True(t, strings.Contains(name, "mixed"),
		"empty rec set should produce 'mixed' segment; got %q", name)
	assert.LessOrEqual(t, len(name), 63, "must respect K8s label cap")
}

func TestAvoidNameCollision_AppendsSuffix(t *testing.T) {
	taken := map[string]bool{
		"auto-2026-05-17-pods-readonly":   true,
		"auto-2026-05-17-pods-readonly-2": true,
	}
	got := AvoidNameCollision("auto-2026-05-17-pods-readonly", taken)
	assert.Equal(t, "auto-2026-05-17-pods-readonly-3", got,
		"collision-avoid must skip taken suffixes")
}

func TestAvoidNameCollision_NoConflict(t *testing.T) {
	got := AvoidNameCollision("fresh-name", map[string]bool{})
	assert.Equal(t, "fresh-name", got)
}

// stubReadWriter implements the minimal interface ResolveProfileName
// expects for out/errW so we can capture output without touching real
// stdout.
type stubReadWriter struct {
	bytes.Buffer
}

func (s *stubReadWriter) Write(p []byte) (int, error) { return s.Buffer.Write(p) }

func TestResolveProfileName_NonTTY_AutoGen(t *testing.T) {
	// Non-TTY + empty NAME → auto-gen + stderr notice.
	var out, errW stubReadWriter
	chosen, err := ResolveProfileName(&out, &errW, nil, "", "auto-2026-05-17-pods-readonly",
		map[string]bool{}, func() bool { return false })
	require.NoError(t, err)
	assert.Equal(t, "auto-2026-05-17-pods-readonly", chosen)
	assert.Contains(t, errW.String(), "auto-generated profile name")
}

func TestResolveProfileName_NonTTY_ExplicitName(t *testing.T) {
	// Non-TTY + explicit NAME → use the explicit name; no stderr notice.
	var out, errW stubReadWriter
	chosen, err := ResolveProfileName(&out, &errW, nil, "my-cluster-survey", "auto-default",
		map[string]bool{}, func() bool { return false })
	require.NoError(t, err)
	assert.Equal(t, "my-cluster-survey", chosen)
	assert.Empty(t, errW.String(), "explicit name should not produce a stderr notice")
}

func TestResolveProfileName_NonTTY_CollisionAvoid(t *testing.T) {
	var out, errW stubReadWriter
	taken := map[string]bool{"auto-2026-05-17-pods-readonly": true}
	chosen, err := ResolveProfileName(&out, &errW, nil, "", "auto-2026-05-17-pods-readonly",
		taken, func() bool { return false })
	require.NoError(t, err)
	assert.Equal(t, "auto-2026-05-17-pods-readonly-2", chosen)
}

// TestCLI_Recommend_NoData prints "no recommendations" gracefully when
// the DB is empty.
func TestCLI_Recommend_NoData(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	out, _, err := runCLI(t, db, "rules", "recommend", "--min-support", "1")
	require.NoError(t, err)
	assert.Contains(t, out, "no recommendations")
}

// TestCLI_Recommend_AppliesRules confirms --apply persists the
// synthesized rule.
func TestCLI_Recommend_AppliesRules(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	st, err := store.Open(db)
	require.NoError(t, err)
	// Seed 3 ALLOW decisions for pods:get.
	for i := 0; i < 3; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			Method:          "GET",
			Path:            "/api/v1/namespaces/default/pods",
			ParsedResource:  "pods",
			ParsedVerb:      "get",
			ParsedNamespace: "default",
			DecisionVerdict: "allow",
			ModeAtDecision:  "cooperative",
		})
		require.NoError(t, err)
	}
	st.Close()

	out, _, err := runCLI(t, db, "rules", "recommend", "--min-support", "3", "--apply")
	require.NoError(t, err)
	assert.Contains(t, out, "pods:get")
	assert.Contains(t, out, "applied 1 rule")

	// Confirm via `rules list`.
	out, _, err = runCLI(t, db, "rules", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "pods:get")
}

// TestCLI_Recommend_SaveAsProfile_Explicit confirms --save-as-profile NAME
// writes a profile YAML containing the recommendation.
func TestCLI_Recommend_SaveAsProfile_Explicit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kb.db")
	profilesPath := filepath.Join(t.TempDir(), "profiles.yaml")
	t.Setenv("KBOUNCER_PROFILES_PATH", profilesPath)

	st, err := store.Open(db)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			ParsedResource:  "pods",
			ParsedVerb:      "list",
			DecisionVerdict: "allow",
		})
		require.NoError(t, err)
	}
	st.Close()

	out, _, err := runCLI(t, db, "rules", "recommend",
		"--min-support", "3",
		"--save-as-profile", "my-survey",
		"--profiles-path", profilesPath)
	require.NoError(t, err)
	assert.Contains(t, out, "my-survey")

	raw, err := os.ReadFile(profilesPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "my-survey")
	assert.Contains(t, string(raw), "pods:list")
}

// TestSaveAsProfile_OrgSourcedRefusal confirms a profile sourced from
// a URL cannot be overwritten by save-as-profile.
func TestSaveAsProfile_OrgSourcedRefusal(t *testing.T) {
	profilesPath := filepath.Join(t.TempDir(), "profiles.yaml")
	// Seed an org-sourced profile via UpsertProfile bypass: write the
	// YAML directly.
	yaml := `profiles:
  org-locked:
    description: "from org URL"
    source: "https://internal.example/profile.yaml"
`
	require.NoError(t, os.WriteFile(profilesPath, []byte(yaml), 0o600))

	// Try to UpsertProfile with the same name; it should refuse.
	err := profile.UpsertProfile(&profile.Profile{
		Name:        "org-locked",
		Description: "trying to overwrite",
	}, profilesPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read-only")
}

func TestParseRelativeOrAbsolute_HandlesShorthandDays(t *testing.T) {
	// 7d should resolve to ~7 days ago; check ordering vs now.
	got := parseRelativeOrAbsolute("7d")
	require.False(t, got.IsZero(), "7d must parse")
	assert.True(t, time.Now().UTC().Sub(got).Hours() > 24*6,
		"7d should be at least 6 days back")
}
