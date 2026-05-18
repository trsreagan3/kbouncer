// Burst detector tests. Use deterministic clock injection
// (onPromptAt) so the tests don't rely on real wall-clock.

package proxy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

func bdStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "bd.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBurstDetector_FiresAtThreshold(t *testing.T) {
	st := bdStore(t)
	d := NewBurstDetector(st, BurstDetectorOptions{
		Threshold: 3,
		Window:    10 * time.Second,
		Cooldown:  1 * time.Minute,
	})
	base := time.Unix(1700000000, 0).UTC()
	id1 := d.onPromptAt(base.Add(0))
	id2 := d.onPromptAt(base.Add(1 * time.Second))
	id3 := d.onPromptAt(base.Add(2 * time.Second))
	assert.Zero(t, id1, "first prompt below threshold")
	assert.Zero(t, id2, "second prompt below threshold")
	assert.Positive(t, id3, "threshold crossed at the 3rd prompt")

	b, err := st.LatestUnresolvedBurst()
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, id3, b.ID)
}

func TestBurstDetector_CooldownPreventsRefire(t *testing.T) {
	st := bdStore(t)
	d := NewBurstDetector(st, BurstDetectorOptions{
		Threshold: 2,
		Window:    10 * time.Second,
		Cooldown:  60 * time.Second,
	})
	base := time.Unix(1700000000, 0).UTC()
	d.onPromptAt(base.Add(0))
	id := d.onPromptAt(base.Add(1 * time.Second))
	require.Positive(t, id, "burst fires on 2nd prompt")

	// Within the cool-down: more prompts must not emit another event.
	id2 := d.onPromptAt(base.Add(5 * time.Second))
	id3 := d.onPromptAt(base.Add(30 * time.Second))
	assert.Zero(t, id2)
	assert.Zero(t, id3)
}

func TestBurstDetector_ReArmsAfterCooldown(t *testing.T) {
	st := bdStore(t)
	d := NewBurstDetector(st, BurstDetectorOptions{
		Threshold: 2,
		Window:    10 * time.Second,
		Cooldown:  60 * time.Second,
	})
	base := time.Unix(1700000000, 0).UTC()
	d.onPromptAt(base.Add(0))
	require.Positive(t, d.onPromptAt(base.Add(1*time.Second)))

	// After cool-down + window elapse, the next burst-shaped sequence
	// fires again.
	afterCD := base.Add(120 * time.Second)
	id1 := d.onPromptAt(afterCD)
	id2 := d.onPromptAt(afterCD.Add(1 * time.Second))
	assert.Zero(t, id1, "re-armed; first post-cooldown prompt is below threshold")
	assert.Positive(t, id2, "second post-cooldown prompt re-fires")
}

func TestBurstDetector_SlidingWindowPrunes(t *testing.T) {
	st := bdStore(t)
	d := NewBurstDetector(st, BurstDetectorOptions{
		Threshold: 3,
		Window:    10 * time.Second,
		Cooldown:  60 * time.Second,
	})
	base := time.Unix(1700000000, 0).UTC()
	// Two prompts far in the past — should age out of the window.
	d.onPromptAt(base.Add(0))
	d.onPromptAt(base.Add(1 * time.Second))
	// 30s later: the two old prompts are outside the 10s window. A
	// new pair shouldn't trip the threshold.
	id := d.onPromptAt(base.Add(30 * time.Second))
	assert.Zero(t, id, "stale prompts must not count toward threshold")
	id = d.onPromptAt(base.Add(31 * time.Second))
	assert.Zero(t, id)
	id = d.onPromptAt(base.Add(32 * time.Second))
	assert.Positive(t, id, "three prompts within the window do trip")
}

func TestBurstDetector_NilStoreDoesntPanic(t *testing.T) {
	d := NewBurstDetector(nil, BurstDetectorOptions{Threshold: 2})
	base := time.Unix(1700000000, 0).UTC()
	d.onPromptAt(base)
	id := d.onPromptAt(base.Add(1 * time.Second))
	assert.Zero(t, id, "nil store → record returns 0 (no emission); no panic")
}

func TestBurstDetector_ResetForResolution(t *testing.T) {
	st := bdStore(t)
	d := NewBurstDetector(st, BurstDetectorOptions{
		Threshold: 2,
		Window:    60 * time.Second,
		Cooldown:  60 * time.Second,
	})
	base := time.Unix(1700000000, 0).UTC()
	d.onPromptAt(base)
	require.Positive(t, d.onPromptAt(base.Add(1*time.Second)))
	d.ResetForResolution()
	snap := d.Snapshot()
	assert.Zero(t, snap.WindowCount, "post-resolution window is empty")
	assert.False(t, snap.Cooldown, "post-resolution cooldown is cleared")
}

func TestBurstDetector_SnapshotReflectsState(t *testing.T) {
	st := bdStore(t)
	d := NewBurstDetector(st, BurstDetectorOptions{
		Threshold: 5,
		Window:    60 * time.Second,
		Cooldown:  60 * time.Second,
	})
	snap := d.Snapshot()
	assert.Equal(t, 0, snap.WindowCount)
	assert.Equal(t, 5, snap.Threshold)
	assert.Equal(t, 60, snap.WindowSeconds)

	// Use real wall-clock so Snapshot's pruning doesn't drop the
	// entries (Snapshot uses time.Now; tests that need to assert
	// post-snapshot state rely on real time within the 60s window).
	d.OnPromptEnqueued()
	d.OnPromptEnqueued()
	snap = d.Snapshot()
	assert.GreaterOrEqual(t, snap.WindowCount, 2)
}

func TestBurstDetector_NilReceiverSafe(t *testing.T) {
	var d *BurstDetector
	assert.NotPanics(t, func() { d.OnPromptEnqueued() })
	assert.NotPanics(t, func() { d.ResetForResolution() })
	snap := d.Snapshot()
	assert.Zero(t, snap.WindowCount)
}
