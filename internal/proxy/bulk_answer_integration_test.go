// Integration test: the proxy's profile-reload watcher hot-swaps the
// active profile when the bulk-answer flow writes a profile_reload_signal
// row. Tests the cross-process channel end-to-end without spinning up
// a second process — same DB file + same proxy goroutine.

package proxy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/profile"
	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

func TestProfileReloadWatcher_HotSwapsOnSignal(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rw.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	// Point the package's DefaultProfilesPath() at our test fixture.
	t.Setenv("KBOUNCER_PROFILES_PATH", profilesPath)

	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()

	// Write a minimal profiles.yaml with two locally-defined profiles
	// so Active() resolves either name.
	require.NoError(t, profile.UpsertProfile(&profile.Profile{
		Name:        "narrow-profile",
		Description: "test",
		Source:      "local",
		DenyVerbs:   []string{"delete"},
	}, profilesPath))
	require.NoError(t, profile.UpsertProfile(&profile.Profile{
		Name:        "broad-profile",
		Description: "test",
		Source:      "local",
	}, profilesPath))

	profiles, err := profile.LoadProfiles(profilesPath)
	require.NoError(t, err)
	startProfile, err := profiles.Active("narrow-profile")
	require.NoError(t, err)

	s := NewServer(Config{
		Host:          "127.0.0.1",
		Port:          0,
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyDeny,
		ActiveProfile: startProfile,
	}, st)
	require.Equal(t, "narrow-profile", s.ActiveProfile().Name)

	// Operator (CLI / MCP) writes the signal.
	require.NoError(t, st.SetProfileReloadSignal("broad-profile", "test-actor"))

	// Drive a single watcher tick manually so the test doesn't depend
	// on the real ticker.
	s.pollProfileReloadOnce()
	assert.Equal(t, "broad-profile", s.ActiveProfile().Name,
		"profile-reload watcher must hot-swap to the requested profile")

	// Signal is acked → second poll is a no-op.
	sig, err := st.GetProfileReloadSignal()
	require.NoError(t, err)
	assert.NotEmpty(t, sig.AppliedAt)
}

func TestProfileReloadWatcher_IgnoresUnknownProfile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rw.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	t.Setenv("KBOUNCER_PROFILES_PATH", profilesPath)

	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, profile.UpsertProfile(&profile.Profile{
		Name:   "narrow-profile",
		Source: "local",
	}, profilesPath))

	profiles, err := profile.LoadProfiles(profilesPath)
	require.NoError(t, err)
	startProfile, err := profiles.Active("narrow-profile")
	require.NoError(t, err)

	s := NewServer(Config{
		Mode:          ModeCooperative,
		ActiveProfile: startProfile,
	}, st)

	// Write a signal pointing at a profile that doesn't exist.
	require.NoError(t, st.SetProfileReloadSignal("nope-not-real", "test-actor"))
	s.pollProfileReloadOnce()
	assert.Equal(t, "narrow-profile", s.ActiveProfile().Name,
		"unknown profile name → watcher logs + acks, keeps current profile")

	// Signal must be acked so it doesn't re-fire forever.
	sig, err := st.GetProfileReloadSignal()
	require.NoError(t, err)
	assert.NotEmpty(t, sig.AppliedAt)
}

func TestExpiredRulesCount_Reflects(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "exp.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()

	// Seed: 2 permanent rules, 3 expired bulk-answer rules.
	past := time.Now().UTC().Add(-1 * time.Hour)
	for _, p := range []string{"pods:get", "pods:list"} {
		_, err := st.AddRule(makeAllowRule(p))
		require.NoError(t, err)
	}
	for _, p := range []string{"secrets:get", "configmaps:get", "services:get"} {
		_, err := st.AddTimeBoundedRule(makeAllowRule(p), past, "bulk-answer")
		require.NoError(t, err)
	}
	n, err := st.CountExpiredRules(time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

// Build a server (without serving) to confirm the burst detector is
// constructed and the active profile is wired into the hot-swap-aware
// field.
func TestNewServer_ConstructsBurstDetector(t *testing.T) {
	st := bdStore(t)
	s := NewServer(Config{
		Mode:                ModeCooperative,
		BulkAnswerThreshold: 7,
		BulkAnswerWindow:    30 * time.Second,
		BulkAnswerCooldown:  2 * time.Minute,
	}, st)
	require.NotNil(t, s.BurstDetector())
	snap := s.BurstDetector().Snapshot()
	assert.Equal(t, 7, snap.Threshold)
	assert.Equal(t, 30, snap.WindowSeconds)
}

func TestServerSetActiveProfile_HotSwaps(t *testing.T) {
	s := NewServer(Config{Mode: ModeCooperative}, nil)
	s.SetActiveProfile(&profile.Profile{Name: "alpha"})
	assert.Equal(t, "alpha", s.ActiveProfile().Name)
	s.SetActiveProfile(&profile.Profile{Name: "beta"})
	assert.Equal(t, "beta", s.ActiveProfile().Name)
}

func makeAllowRule(pattern string) rules.ProxyRule {
	return rules.ProxyRule{
		Pattern: pattern,
		Effect:  rules.EffectAllow,
		Origin:  rules.OriginUser,
	}
}
