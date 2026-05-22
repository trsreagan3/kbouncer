// loader_test.go — #324b loader regression suite.
//
// Covers:
//   - happy-path YAML load + filter to kbouncer-applicable entries
//   - schema-violation rejection (missing required field, bad rule-id
//     shape, bad duration shape, bad applied_to bouncer)
//   - filter: ARN-targeted + URL-glob-targeted rules are skipped;
//     namespace + cluster + resource-triple targets are retained.
//   - glob matching: leading `*.` + trailing `prod-*` patterns
//   - resource triple matching: `core/v1/secrets` matches the
//     parser-emitted empty-group canonical shape.
//   - expired rules are skipped at load time

package dynamicdeny

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// validRuleID is a stable rule id used across the suite. ULID body
// "01HZ8VKJ6Y2BJTPVZ3PNX97A2C" matches the schema's Crockford base32
// shape (rejects I/L/O/U).
const validRuleID = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
const validRuleID2 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2D"
const validRuleID3 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2E"
const validRuleID4 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2F"

// goldenYAML builds a single-rule YAML payload targeting kbouncer.
func goldenYAML(t *testing.T) string {
	t.Helper()
	added := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(3 * time.Hour).Format(time.RFC3339)
	return strings.Join([]string{
		`schema_version: "1.0"`,
		`product: iam-jit-dynamic-denies`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets:`,
		`      - "namespace:prod"`,
		`    reason: "operator: lockout prod namespace during incident #4711"`,
		`    duration: "3h"`,
		`    added_by: "operator@org.com"`,
		`    added_at: "` + added + `"`,
		`    expires_at: "` + expires + `"`,
		`    applied_to:`,
		`      - kbouncer`,
		`    applies_to_recommender: false`,
		`    source: "cli"`,
	}, "\n")
}

func TestLoader_LoadsValidYAML(t *testing.T) {
	rs, err := LoadBytes([]byte(goldenYAML(t)), "test.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if rs == nil || len(rs.Rules) != 1 {
		t.Fatalf("Rules = %v; want 1", rs)
	}
	r := rs.Rules[0]
	if r.ID != validRuleID {
		t.Errorf("ID = %q; want %q", r.ID, validRuleID)
	}
	if len(r.Targets) != 1 || r.Targets[0] != "namespace:prod" {
		t.Errorf("Targets = %v; want [namespace:prod]", r.Targets)
	}
	if r.Duration != "3h" {
		t.Errorf("Duration = %q; want 3h", r.Duration)
	}
	if r.Source != "cli" {
		t.Errorf("Source = %q; want cli", r.Source)
	}
	if rs.SourcePath != "test.yaml" {
		t.Errorf("SourcePath = %q; want test.yaml", rs.SourcePath)
	}
	if len(rs.Patterns) != 1 {
		t.Fatalf("Patterns = %d; want 1", len(rs.Patterns))
	}
	if rs.Patterns[0].Kind != PatternKindNamespace || rs.Patterns[0].Body != "prod" {
		t.Errorf("Patterns[0] = %+v; want namespace=prod", rs.Patterns[0])
	}
}

func TestLoader_LoadFile_MissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	rs, err := LoadFile(filepath.Join(dir, "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadFile on missing path should not error; got %v", err)
	}
	if rs == nil || len(rs.Rules) != 0 {
		t.Errorf("Rules = %v; want empty", rs)
	}
}

func TestLoader_LoadFile_RealFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(goldenYAML(t)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rs, err := LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Errorf("Rules = %d; want 1", len(rs.Rules))
	}
}

func TestLoader_RejectsSchemaViolation(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantSubstr string
	}{
		{
			name: "missing_schema_version",
			body: strings.Join([]string{
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: ["namespace:prod"]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [kbouncer]`,
			}, "\n"),
			wantSubstr: "schema_version",
		},
		{
			name: "bad_rule_id",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: not-a-valid-id`,
				`    targets: ["namespace:prod"]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [kbouncer]`,
			}, "\n"),
			wantSubstr: "dd_",
		},
		{
			name: "bad_duration",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: ["namespace:prod"]`,
				`    reason: "test"`,
				`    duration: "not-a-duration"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [kbouncer]`,
			}, "\n"),
			wantSubstr: "duration",
		},
		{
			name: "unknown_bouncer",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: ["namespace:prod"]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [made-up-bouncer]`,
			}, "\n"),
			wantSubstr: "made-up-bouncer",
		},
		{
			name: "duplicate_rule_id",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: ["namespace:prod"]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [kbouncer]`,
				`  - id: ` + validRuleID,
				`    targets: ["namespace:stage"]`,
				`    reason: "dup"`,
				`    duration: "1h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [kbouncer]`,
			}, "\n"),
			wantSubstr: "duplicate",
		},
		{
			name: "bad_product_magic",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`product: kbouncer-config`,
				`denies: []`,
			}, "\n"),
			wantSubstr: "product",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tc.body), "x.yaml")
			if err == nil {
				t.Fatal("expected schema rejection; got no error")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q should mention %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

func TestLoader_FiltersNonKbouncerTargets(t *testing.T) {
	// 4 rules — only the namespace + resource-triple targets land on
	// kbouncer. The ARN-only + URL-glob-only rules get filtered out at
	// the `applied_to` step (the iam-jit cross-protocol resolver in
	// #324e writes `applied_to: [ibounce]` for an ARN target +
	// `applied_to: [gbounce]` for a URL target).
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["namespace:prod"]`,
		`    reason: "namespace-target -> kbouncer"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
		`  - id: ` + validRuleID2,
		`    targets: ["arn:aws:s3:::prod-*"]`,
		`    reason: "arn-target -> ibounce; should be filtered out"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [ibounce]`,
		`  - id: ` + validRuleID3,
		`    targets: ["*.openai.com"]`,
		`    reason: "url-glob-target -> gbounce; should be filtered out"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
		`  - id: ` + validRuleID4,
		`    targets: ["apps/v1/deployments", "core/v1/secrets"]`,
		`    reason: "k8s-resource-triple -> kbouncer"`,
		`    duration: "45m"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	// Only the rules whose applied_to includes "kbouncer" survive.
	if len(rs.Rules) != 2 {
		t.Fatalf("Rules = %d; want 2 (namespace + resource-triple); got %v", len(rs.Rules), rs.Rules)
	}
	for _, r := range rs.Rules {
		if r.ID == validRuleID2 || r.ID == validRuleID3 {
			t.Errorf("Rule %q should have been filtered out (applied_to does not include kbouncer)", r.ID)
		}
	}
	// Patterns: 1 from rule1 (namespace:prod) + 2 from rule4 (two
	// resource triples) = 3 total.
	if len(rs.Patterns) != 3 {
		t.Errorf("Patterns = %d; want 3", len(rs.Patterns))
	}
	// Globs() round-trip: should produce 3 unique targets (one per
	// kept rule's targets list).
	globs := rs.Globs()
	if len(globs) != 3 {
		t.Errorf("Globs() = %d; want 3 (one per kept-rule target)", len(globs))
	}
}

func TestLoader_NamespaceGlobMatches(t *testing.T) {
	// Three patterns covering exact + leading-`*.` + trailing-`*`
	// glob shapes. Each should fire only on the matching input.
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets:`,
		`      - "namespace:prod"`,
		`      - "namespace:prod-*"`,
		`      - "namespace:*.svc"`,
		`    reason: "namespace glob test"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Patterns) != 3 {
		t.Fatalf("Patterns = %d; want 3", len(rs.Patterns))
	}
	cases := []struct {
		ns   string
		want bool
	}{
		{"prod", true},        // exact
		{"prod-east", true},   // trailing-* glob
		{"prod-west-1", true}, // trailing-* glob
		{"stage", false},      // no match
		{"my.svc", true},      // leading-*. glob
		{"svc", true},         // leading-*. matches bare suffix too
		{"non-prod", false},   // doesn't start with prod-
	}
	for _, tc := range cases {
		got := rs.Match(MatchInput{Namespace: tc.ns}) != nil
		if got != tc.want {
			t.Errorf("Match(ns=%q) = %v; want %v", tc.ns, got, tc.want)
		}
	}
}

func TestLoader_ClusterMatches(t *testing.T) {
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets:`,
		`      - "cluster:prod-east"`,
		`      - "cluster:prod-*"`,
		`    reason: "cluster lockout"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	cases := []struct {
		cluster string
		want    bool
	}{
		{"prod-east", true},
		{"prod-west", true},
		{"stage-east", false},
		{"", false},
	}
	for _, tc := range cases {
		got := rs.Match(MatchInput{Cluster: tc.cluster}) != nil
		if got != tc.want {
			t.Errorf("Match(cluster=%q) = %v; want %v", tc.cluster, got, tc.want)
		}
	}
}

func TestLoader_ResourceTripleMatches(t *testing.T) {
	// core/v1/secrets should match the parser's empty-group canonical
	// shape (parser emits Group="" for core API requests).
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets:`,
		`      - "core/v1/secrets"`,
		`      - "apps/v1/deployments"`,
		`    reason: "block secrets + deployments"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Patterns) != 2 {
		t.Fatalf("Patterns = %d; want 2", len(rs.Patterns))
	}
	cases := []struct {
		group, version, resource string
		want                     bool
	}{
		// Core API request from parser: Group="", Version="v1",
		// Resource="secrets". Must match `core/v1/secrets`.
		{"", "v1", "secrets", true},
		// Core API with the explicit `core` group alias works too.
		{"core", "v1", "secrets", true},
		// Named-group request from parser: Group="apps", Version="v1",
		// Resource="deployments".
		{"apps", "v1", "deployments", true},
		// Wrong resource.
		{"apps", "v1", "configmaps", false},
		// Wrong version.
		{"apps", "v2", "deployments", false},
	}
	for _, tc := range cases {
		got := rs.Match(MatchInput{Group: tc.group, Version: tc.version, Resource: tc.resource}) != nil
		if got != tc.want {
			t.Errorf("Match(%s/%s/%s) = %v; want %v",
				tc.group, tc.version, tc.resource, got, tc.want)
		}
	}
}

func TestLoader_ExpiredRulesFiltered(t *testing.T) {
	expired := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["namespace:prod"]`,
		`    reason: "already expired"`,
		`    duration: "1h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T15:13:48Z"`,
		`    expires_at: "` + expired + `"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Errorf("expired rule should be skipped; got %d rule(s)", len(rs.Rules))
	}
	if len(rs.Patterns) != 0 {
		t.Errorf("expired rule should produce no patterns; got %d", len(rs.Patterns))
	}
}

func TestLoader_SilentlySkipsUnrecognizedTargets(t *testing.T) {
	// A rule whose applied_to claims kbouncer but whose targets are
	// ARN-shaped (an applied_to bug in the resolver) should load the
	// rule but produce zero patterns — the matcher never fires + the
	// proxy is unaffected.
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["arn:aws:s3:::prod-*", "https://api.openai.com/v1/*"]`,
		`    reason: "applied_to bug — these aren't kbouncer-shape"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Errorf("Rules = %d; want 1 (rule is kept even when no targets compile)", len(rs.Rules))
	}
	if len(rs.Patterns) != 0 {
		t.Errorf("Patterns = %d; want 0 (no kbouncer-shape targets)", len(rs.Patterns))
	}
}

func TestLoader_AcceptsKbounceAlias(t *testing.T) {
	// A hand-edited file may use the historical `kbounce` alias rather
	// than the canonical `kbouncer` token. The loader accepts both.
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["namespace:prod"]`,
		`    reason: "alias compat"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbounce]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Errorf("Rules = %d; want 1 (kbounce alias should be accepted)", len(rs.Rules))
	}
}

func TestLoader_RoundTripJSONShape(t *testing.T) {
	rs, err := LoadBytes([]byte(goldenYAML(t)), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("Rules = %d; want 1", len(rs.Rules))
	}
	jb, err := json.Marshal(rs.Rules[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, want := range []string{
		`"id"`, `"targets"`, `"reason"`, `"duration"`,
		`"added_by"`, `"added_at"`, `"applied_to"`,
	} {
		if !strings.Contains(string(jb), want) {
			t.Errorf("JSON round-trip missing field %s: %s", want, string(jb))
		}
	}
	yb, err := yaml.Marshal(rs.Rules[0])
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if !strings.Contains(string(yb), validRuleID) {
		t.Errorf("YAML round-trip lost rule id: %s", string(yb))
	}
}

func TestLoader_ResolveDefaultPath(t *testing.T) {
	t.Setenv(DefaultPathEnv, "/tmp/iam-jit-test-override.yaml")
	got := ResolveDefaultPath()
	if got != "/tmp/iam-jit-test-override.yaml" {
		t.Errorf("ResolveDefaultPath = %q; want override", got)
	}
}
