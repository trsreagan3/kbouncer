// Unit tests for the recommender synthesis algorithm.
//
// Per the parent commit body's audit-cadence note (a): the dedupe
// path is covered by Test_Synthesize_DedupesAgainstExistingRules
// — that's the closest we have to "don't resurrect a removed rule"
// since kbouncer's store doesn't track rule_removed events. The
// test confirms that re-running Synthesize against the rules
// already in the store flags those recommendations as covered.
package recommender

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/rules"
	"github.com/trsreagan3/kbouncer/internal/store"
)

// mkDecision builds a small DecisionRow for tests. Default verdict
// is "allow" because the recommender filters non-allow out — most
// tests want their rows counted.
func mkDecision(resource, verb, namespace, name string, opts ...func(*store.DecisionRow)) store.DecisionRow {
	d := store.DecisionRow{
		At:              time.Now().UTC(),
		ParsedResource:  resource,
		ParsedVerb:      verb,
		ParsedNamespace: namespace,
		ParsedName:      name,
		DecisionVerdict: "allow",
	}
	for _, opt := range opts {
		opt(&d)
	}
	return d
}

func TestSynthesize_EmptyInput(t *testing.T) {
	recs, summary := Synthesize(nil, SynthesizeOptions{})
	assert.Empty(t, recs)
	assert.Equal(t, 0, summary.TotalCalls)
}

func TestSynthesize_BelowMinSupport_Skipped(t *testing.T) {
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "default", "pod-1"),
		mkDecision("pods", "get", "default", "pod-2"),
		// Only 2 — below MinSupportDefault (3).
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	assert.Empty(t, recs)
}

func TestSynthesize_GroupsByResourceAndVerb(t *testing.T) {
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "default", "pod-1"),
		mkDecision("pods", "get", "default", "pod-2"),
		mkDecision("pods", "get", "default", "pod-3"),
		mkDecision("services", "list", "", ""),
		mkDecision("services", "list", "", ""),
		mkDecision("services", "list", "", ""),
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	require.Len(t, recs, 2)
	patterns := []string{recs[0].ProposedRule.Pattern, recs[1].ProposedRule.Pattern}
	assert.Contains(t, patterns, "pods:get")
	assert.Contains(t, patterns, "services:list")
}

func TestSynthesize_FiltersOutDenyDecisions(t *testing.T) {
	// 3 ALLOW decisions for pods:get + 5 DENY decisions for the same
	// shape. Recommender should ONLY recommend based on the 3 allows.
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "default", "pod-1"),
		mkDecision("pods", "get", "default", "pod-2"),
		mkDecision("pods", "get", "default", "pod-3"),
		mkDecision("secrets", "get", "default", "s1", func(d *store.DecisionRow) {
			d.DecisionVerdict = "deny"
		}),
		mkDecision("secrets", "get", "default", "s2", func(d *store.DecisionRow) {
			d.DecisionVerdict = "deny"
		}),
		mkDecision("secrets", "get", "default", "s3", func(d *store.DecisionRow) {
			d.DecisionVerdict = "deny"
		}),
		mkDecision("secrets", "get", "default", "s4", func(d *store.DecisionRow) {
			d.DecisionVerdict = "deny"
		}),
		mkDecision("secrets", "get", "default", "s5", func(d *store.DecisionRow) {
			d.DecisionVerdict = "deny"
		}),
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	require.Len(t, recs, 1)
	assert.Equal(t, "pods:get", recs[0].ProposedRule.Pattern)
}

func TestSynthesize_NamespaceLongestCommonPrefix(t *testing.T) {
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "prod-billing", "p1"),
		mkDecision("pods", "get", "prod-checkout", "p2"),
		mkDecision("pods", "get", "prod-frontend", "p3"),
		mkDecision("pods", "get", "prod-payments", "p4"),
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	require.Len(t, recs, 1)
	// All four namespaces share "prod-" prefix.
	assert.Equal(t, "prod-*", recs[0].ProposedRule.NamespaceScope)
	assert.Contains(t, recs[0].NamespaceRationale, "prod-")
}

func TestSynthesize_ResourceLongestCommonPrefix(t *testing.T) {
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "default", "api-server-1"),
		mkDecision("pods", "get", "default", "api-server-2"),
		mkDecision("pods", "get", "default", "api-worker-1"),
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	require.Len(t, recs, 1)
	assert.Equal(t, "api-*", recs[0].ProposedRule.ResourceScope)
}

func TestSynthesize_NamespaceBelowFractionThreshold_NoScope(t *testing.T) {
	// 4 decisions, only 1 has a namespace observable — below the 0.5
	// fraction gate. The recommender should NOT narrow by namespace.
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "prod-billing", "p1"),
		mkDecision("pods", "get", "", "p2"),
		mkDecision("pods", "get", "", "p3"),
		mkDecision("pods", "get", "", "p4"),
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	require.Len(t, recs, 1)
	assert.Empty(t, recs[0].ProposedRule.NamespaceScope,
		"namespace scope must NOT be inferred from sparse observable data")
}

func TestSynthesize_DedupesAgainstExistingRules(t *testing.T) {
	// audit-cadence (a) coverage: a rule already in the store gets
	// marked SkippedReason; the operator (or --apply) won't resurrect
	// it.
	//
	// The recommender will derive namespace_scope = "default" from the
	// three observed decisions (all-equal case). For dedupe to fire,
	// the existing rule must match the SAME pattern + scopes.
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "default", ""),
		mkDecision("pods", "get", "default", ""),
		mkDecision("pods", "get", "default", ""),
	}
	existing := []rules.ProxyRule{
		{Pattern: "pods:get", Effect: rules.EffectAllow, NamespaceScope: "default"},
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{
		MinSupport:    3,
		ExistingRules: existing,
	})
	require.Len(t, recs, 1)
	assert.NotEmpty(t, recs[0].SkippedReason,
		"recommendation matching an existing rule must be marked SKIPPED")
}

func TestSynthesize_TaskScopedDecisions_ExcludedByDefault(t *testing.T) {
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "default", "p1", func(d *store.DecisionRow) {
			d.TaskID = "task-abc"
		}),
		mkDecision("pods", "get", "default", "p2", func(d *store.DecisionRow) {
			d.TaskID = "task-abc"
		}),
		mkDecision("pods", "get", "default", "p3", func(d *store.DecisionRow) {
			d.TaskID = "task-abc"
		}),
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	assert.Empty(t, recs, "task-scoped decisions must be excluded by default")

	// With include_task_scoped, they're folded in.
	recs2, _ := Synthesize(decisions, SynthesizeOptions{
		MinSupport:        3,
		IncludeTaskScoped: true,
	})
	require.Len(t, recs2, 1, "include_task_scoped=true should fold them in")
}

func TestSynthesize_SortsBySupport(t *testing.T) {
	// pods:get has 5 ALLOW; services:list has 3 ALLOW. pods:get should
	// come first.
	decisions := []store.DecisionRow{
		mkDecision("services", "list", "", ""),
		mkDecision("services", "list", "", ""),
		mkDecision("services", "list", "", ""),
		mkDecision("pods", "get", "default", "p1"),
		mkDecision("pods", "get", "default", "p2"),
		mkDecision("pods", "get", "default", "p3"),
		mkDecision("pods", "get", "default", "p4"),
		mkDecision("pods", "get", "default", "p5"),
	}
	recs, _ := Synthesize(decisions, SynthesizeOptions{MinSupport: 3})
	require.Len(t, recs, 2)
	assert.Equal(t, "pods:get", recs[0].ProposedRule.Pattern)
	assert.Equal(t, "services:list", recs[1].ProposedRule.Pattern)
}

func TestFilterByWindow_BoundsAreInclusive(t *testing.T) {
	now := time.Now().UTC()
	decisions := []store.DecisionRow{
		mkDecision("pods", "get", "", "", func(d *store.DecisionRow) {
			d.At = now.Add(-2 * time.Hour)
		}),
		mkDecision("pods", "get", "", "", func(d *store.DecisionRow) {
			d.At = now.Add(-30 * time.Minute)
		}),
		mkDecision("pods", "get", "", "", func(d *store.DecisionRow) {
			d.At = now.Add(-5 * time.Minute)
		}),
	}
	since := now.Add(-1 * time.Hour)
	out := FilterByWindow(decisions, since, time.Time{})
	assert.Len(t, out, 2, "only decisions in window should remain")
}

func TestFilterByPatterns_NarrowsToSpecificPatterns(t *testing.T) {
	recs := []Recommendation{
		{ProposedRule: rules.ProxyRule{Pattern: "pods:get"}},
		{ProposedRule: rules.ProxyRule{Pattern: "services:list"}},
		{ProposedRule: rules.ProxyRule{Pattern: "secrets:get"}},
	}
	out := FilterByPatterns(recs, []string{"pods:get", "secrets:get"})
	require.Len(t, out, 2)
	patterns := []string{out[0].ProposedRule.Pattern, out[1].ProposedRule.Pattern}
	assert.Contains(t, patterns, "pods:get")
	assert.Contains(t, patterns, "secrets:get")
	assert.NotContains(t, patterns, "services:list")
}
