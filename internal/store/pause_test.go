// Pause-event store tests (#6a — timed bypass / escape hatch).
//
// Mirrors the Python tests/bouncer/test_pause_for.py store-level
// section so cross-product audits can compare invariants. Covered
// here:
//
//   - StartPause writes a row + returns id + sets ends_at = now + duration
//   - StartPause rejects duration <= 0
//   - StartPause rejects duration > 24h
//   - StartPause refuses if another pause is already active
//   - GetActivePause returns the live row, nil when none
//   - GetActivePause auto-expires past-its-end pauses (no daemon needed)
//   - EndPause marks ended_at_actual + end_kind=resumed_early
//   - EndPause returns nil when no pause was active
//   - RecordDecision threads pause_id correctly + RecentDecisions reads it back
//   - ListRecentPauses returns history (newest first)
package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartPause_WritesRowWithCorrectEndsAt(t *testing.T) {
	s := freshDB(t)
	before := time.Now().UTC().Truncate(time.Second)
	pid, err := s.StartPause(600, "test", "me")
	require.NoError(t, err)
	after := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	assert.Positive(t, pid)

	active, err := s.GetActivePause()
	require.NoError(t, err)
	require.NotNil(t, active)

	ends, err := time.Parse("2006-01-02T15:04:05Z", active.EndsAt)
	require.NoError(t, err)

	expectedLo := before.Add(600 * time.Second)
	expectedHi := after.Add(600 * time.Second)
	assert.True(t, !ends.Before(expectedLo) && !ends.After(expectedHi),
		"ends=%s not in [%s, %s]", ends, expectedLo, expectedHi)
	assert.Equal(t, "test", active.Reason)
	assert.Equal(t, "me", active.StartedBy)
}

func TestStartPause_RejectsZeroAndNegative(t *testing.T) {
	s := freshDB(t)
	_, err := s.StartPause(0, "", "me")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "> 0")

	_, err = s.StartPause(-1, "", "me")
	require.Error(t, err)
}

func TestStartPause_RejectsOver24h(t *testing.T) {
	s := freshDB(t)
	_, err := s.StartPause(24*3600+1, "", "me")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "24h")
}

func TestStartPause_RefusesOverlapping(t *testing.T) {
	s := freshDB(t)
	_, err := s.StartPause(600, "", "me")
	require.NoError(t, err)

	_, err = s.StartPause(300, "", "me")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already active")
}

func TestGetActivePause_AutoExpiresPastPauses(t *testing.T) {
	// The lazy-GC in GetActivePause is the auto-revert mechanism — no
	// daemon thread, works in tests/serverless/anywhere.
	s := freshDB(t)
	_, err := s.StartPause(1, "", "me")
	require.NoError(t, err)

	// Sleep past the window; the next GetActivePause call should mark
	// the row expired and return nil.
	time.Sleep(1100 * time.Millisecond)

	active, err := s.GetActivePause()
	require.NoError(t, err)
	assert.Nil(t, active)

	rows, err := s.ListRecentPauses(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "expired", rows[0].EndKind)
	assert.NotEmpty(t, rows[0].EndedAtActual)
}

func TestEndPause_MarksResumedEarly(t *testing.T) {
	s := freshDB(t)
	pid, err := s.StartPause(600, "", "me")
	require.NoError(t, err)

	ended, err := s.EndPause("me")
	require.NoError(t, err)
	require.NotNil(t, ended)
	assert.Equal(t, pid, *ended)

	active, err := s.GetActivePause()
	require.NoError(t, err)
	assert.Nil(t, active)

	rows, err := s.ListRecentPauses(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "resumed_early", rows[0].EndKind)
	assert.NotEmpty(t, rows[0].EndedAtActual)
}

func TestEndPause_ReturnsNilWhenNoPause(t *testing.T) {
	s := freshDB(t)
	ended, err := s.EndPause("me")
	require.NoError(t, err)
	assert.Nil(t, ended)
}

func TestRecordDecision_LinksPauseID(t *testing.T) {
	s := freshDB(t)
	pid, err := s.StartPause(600, "", "me")
	require.NoError(t, err)

	_, err = s.RecordDecision(DecisionRow{
		Method:          "GET",
		Path:            "/api/v1/pods",
		ParsedVerb:      "list",
		ParsedResource:  "pods",
		DecisionVerdict: "deny",
		DecisionReason:  "test",
		ModeAtDecision:  "cooperative",
		PauseID:         &pid,
	})
	require.NoError(t, err)

	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].PauseID)
	assert.Equal(t, pid, *rows[0].PauseID)
}

func TestListRecentPauses_NewestFirst(t *testing.T) {
	s := freshDB(t)
	first, err := s.StartPause(600, "first", "a")
	require.NoError(t, err)
	_, err = s.EndPause("a")
	require.NoError(t, err)

	second, err := s.StartPause(600, "second", "b")
	require.NoError(t, err)

	rows, err := s.ListRecentPauses(20)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	// Newest-first ordering puts the still-active second pause at the
	// top of the list so `pause history` shows it without scrolling.
	assert.Equal(t, second, rows[0].ID)
	assert.Equal(t, first, rows[1].ID)
}
