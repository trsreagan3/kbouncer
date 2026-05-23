// profileallow_test.go — #386 / §A25 Phase 2 test suite. Mirrors the
// iam-jit Python tests/cli/test_profile_allow.py coverage so the
// cross-product invariants stay parity-aligned.

package profileallow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/kbouncer/internal/profile"
)

// writeProfilesYAML writes a minimal profiles.yaml with the
// named profile in local source so AddProfileAllowRule has a
// target to mutate.
func writeProfilesYAML(t *testing.T, dir string, profileName, source string) string {
	t.Helper()
	path := filepath.Join(dir, "profiles.yaml")
	body := map[string]any{
		"profiles": map[string]any{
			profileName: map[string]any{
				"description": "test profile",
			},
		},
	}
	if source != "" {
		body["profiles"].(map[string]any)[profileName].(map[string]any)["source"] = source
	}
	raw, err := yaml.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// setupQueuePath returns a tempdir + cleanup, plus sets
// IAM_JIT_PROFILE_ALLOW_PENDING_PATH to a unique file under that
// dir so concurrent tests don't bleed into the home pending queue.
func setupQueuePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	qp := filepath.Join(dir, "profile-allow-pending.jsonl")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", qp)
	return qp
}

func TestProfileAllow_AppendsRule(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	res, err := AddProfileAllowRule(Options{
		Target:       "namespaces/staging",
		Actions:      []string{"apps/deployments:get"},
		Reason:       "agent reads staging deployments",
		ProfileName:  "full-user",
		ProfilesPath: path,
		Source:       SourceCLI,
		Actor:        "test-actor",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != "applied" {
		t.Fatalf("status: got %q want %q", res.Status, "applied")
	}
	if res.RuleCountAfter != 1 {
		t.Fatalf("rule_count_after: got %d want 1", res.RuleCountAfter)
	}

	// Reload + assert the new rule survived the write.
	ps, lerr := profile.LoadProfiles(path)
	if lerr != nil {
		t.Fatal(lerr)
	}
	p, _ := ps.Active("full-user")
	if len(p.AllowRules) != 1 {
		t.Fatalf("on-disk allow rules: got %d want 1", len(p.AllowRules))
	}
	rule := p.AllowRules[0]
	if rule.Pattern != "apps/deployments:get" {
		t.Errorf("pattern: got %q", rule.Pattern)
	}
	if rule.ArnScope != "namespaces/staging" {
		t.Errorf("arn_scope: got %q", rule.ArnScope)
	}
	if !strings.Contains(rule.Note, EasyAllowOriginTag) {
		t.Errorf("note missing easy_allow tag: %q", rule.Note)
	}
	if !strings.Contains(rule.Note, "by=test-actor") {
		t.Errorf("note missing actor: %q", rule.Note)
	}
	if !strings.Contains(rule.Note, "via=cli") {
		t.Errorf("note missing source: %q", rule.Note)
	}
}

func TestProfileAllow_RefusesWildcardTarget(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	_, err := AddProfileAllowRule(Options{
		Target:       "*",
		Actions:      []string{"apps/deployments:get"},
		Reason:       "would loosen everything",
		ProfilesPath: path,
		ProfileName:  "full-user",
	})
	if err == nil {
		t.Fatal("expected target_too_broad error")
	}
	perr, ok := err.(*Error)
	if !ok || perr.Code != "target_too_broad" {
		t.Fatalf("error code: got %v", err)
	}
}

func TestProfileAllow_RefusesActionWithoutColon(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	_, err := AddProfileAllowRule(Options{
		Target:       "namespaces/staging",
		Actions:      []string{"badaction"},
		Reason:       "wrong shape",
		ProfileName:  "full-user",
		ProfilesPath: path,
	})
	if err == nil {
		t.Fatal("expected bad_action error")
	}
	perr, ok := err.(*Error)
	if !ok || perr.Code != "bad_action" {
		t.Fatalf("error code: got %v", err)
	}
}

func TestProfileAllow_RefusesOrgDistributedProfile(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "org-floor", "https://corp.example.com/profiles.yaml")

	_, err := AddProfileAllowRule(Options{
		Target:       "namespaces/staging",
		Actions:      []string{"apps/deployments:get"},
		Reason:       "agent reads",
		ProfileName:  "org-floor",
		ProfilesPath: path,
	})
	if err == nil {
		t.Fatal("expected org_distributed error")
	}
	perr, ok := err.(*Error)
	if !ok || perr.Code != "org_distributed" {
		t.Fatalf("error code: got %v want org_distributed", err)
	}
}

func TestProfileAllow_RefusesMissingReason(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")
	_, err := AddProfileAllowRule(Options{
		Target:       "namespaces/staging",
		Actions:      []string{"apps/deployments:get"},
		Reason:       "  ",
		ProfileName:  "full-user",
		ProfilesPath: path,
	})
	if err == nil {
		t.Fatal("expected missing_reason error")
	}
	if perr, ok := err.(*Error); !ok || perr.Code != "missing_reason" {
		t.Fatalf("error code: got %v", err)
	}
}

func TestProfileAllow_AgentSelfGrantDefaultOff_QueuesPending(t *testing.T) {
	qp := setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	res, err := AddProfileAllowRule(Options{
		Target:       "namespaces/staging",
		Actions:      []string{"apps/deployments:get"},
		Reason:       "agent suggests",
		ProfileName:  "full-user",
		ProfilesPath: path,
		Source:       SourceMCP,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("status: got %q want pending_approval", res.Status)
	}
	if res.PendingEntry == nil {
		t.Fatal("expected pending_entry")
	}

	// The profile must NOT have been mutated.
	ps, _ := profile.LoadProfiles(path)
	p, _ := ps.Active("full-user")
	if len(p.AllowRules) != 0 {
		t.Fatalf("profile was mutated despite default-off self-grant: got %d rules",
			len(p.AllowRules))
	}

	// Pending queue should have one entry.
	raw, rerr := os.ReadFile(qp)
	if rerr != nil {
		t.Fatal(rerr)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("pending queue lines: got %d want 1; raw=%q", len(lines), string(raw))
	}
	var entry map[string]any
	if jerr := json.Unmarshal([]byte(lines[0]), &entry); jerr != nil {
		t.Fatal(jerr)
	}
	if id, _ := entry["id"].(string); !strings.HasPrefix(id, "pa_") {
		t.Errorf("pending id missing pa_ prefix: %q", id)
	}
	if b, _ := entry["bouncer"].(string); b != "kbounce" {
		t.Errorf("pending entry bouncer: got %q want kbounce", b)
	}
	if src, _ := entry["source"].(string); src != SourceMCP {
		t.Errorf("pending entry source: got %q", src)
	}
}

func TestProfileAllow_AgentSelfGrantOptIn_AppliesImmediately(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	trueVal := true
	res, err := AddProfileAllowRule(Options{
		Target:              "namespaces/staging",
		Actions:             []string{"apps/deployments:get"},
		Reason:              "agent suggests; operator opted in",
		ProfileName:         "full-user",
		ProfilesPath:        path,
		Source:              SourceMCP,
		AllowAgentSelfGrant: &trueVal,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != "applied" {
		t.Fatalf("status: got %q want applied", res.Status)
	}
}

func TestProfileAllow_DurationExpiresMetadata(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	res, err := AddProfileAllowRule(Options{
		Target:       "namespaces/staging",
		Actions:      []string{"apps/deployments:get"},
		Reason:       "tmp",
		Duration:     "1h",
		ProfileName:  "full-user",
		ProfilesPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpiresAt == "" {
		t.Fatal("expected ExpiresAt set for non-permanent duration")
	}
}

func TestClassifyDenySource(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{"matched dynamic deny: dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C", DenySourceDynamicDeny},
		{"profile 'safe-default': verb 'delete' in deny_verbs", DenySourceSafeDefault},
		{"profile 'staging-work': cluster mismatch", DenySourceStaticProfile},
		{"task deny: scope exceeded", DenySourceTaskDeny},
		{"rule 42 blocked", DenySourceGlobalDeny},
		{"profile_only_account_ids missing", DenySourceProfileOnlyAccountIDs},
		{"no idea", DenySourceUnknown},
	}
	for _, tc := range cases {
		got, _ := ClassifyDenySource(tc.reason)
		if got != tc.want {
			t.Errorf("ClassifyDenySource(%q) = %q want %q", tc.reason, got, tc.want)
		}
	}
}

func TestSynthSuggestedAllowCommand_Dynamic(t *testing.T) {
	out := SynthSuggestedAllowCommand("namespaces/staging", "apps/deployments:get", DenySourceDynamicDeny)
	if !strings.Contains(out, "iam-jit deny remove") {
		t.Errorf("expected dynamic-deny suggestion, got %q", out)
	}
}

func TestSynthSuggestedAllowCommand_Allow(t *testing.T) {
	out := SynthSuggestedAllowCommand("namespaces/staging", "apps/deployments:get", DenySourceSafeDefault)
	if !strings.Contains(out, "kbounce profile allow") {
		t.Errorf("expected kbounce profile allow suggestion, got %q", out)
	}
}

func TestPendingQueueIDFormat(t *testing.T) {
	id := newPendingID()
	if !strings.HasPrefix(id, "pa_") {
		t.Errorf("id missing pa_ prefix: %q", id)
	}
	if len(id) != 3+26 {
		t.Errorf("id length: got %d want 29", len(id))
	}
}
