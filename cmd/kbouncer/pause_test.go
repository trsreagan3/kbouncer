// CLI-layer tests for the pause duration parser.
//
// Symmetric to the Python tests/bouncer/test_pause_for.py::
// test_parse_duration_* cases — keeps suffix-based input shape stable
// across both products.
package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDuration_AcceptsCanonicalForms(t *testing.T) {
	cases := map[string]int64{
		"30s":   30,
		"30m":   30 * 60,
		"2h":    2 * 3600,
		" 90s ": 90,
	}
	for input, want := range cases {
		got, err := parseDuration(input)
		require.NoError(t, err, "input=%q", input)
		assert.Equal(t, want, got, "input=%q", input)
	}
}

func TestParseDuration_RejectsGarbage(t *testing.T) {
	// Same set of rejection cases the Python suffix parser rejects
	// (test_parse_duration_rejects_garbage), keeping cross-product
	// CLI surface symmetric.
	bad := []string{
		"30",  // missing suffix
		"xx",  // no integer prefix
		"30d", // day not supported (cap is 24h via h suffix)
		"0m",  // non-positive
		"-5m", // non-positive
		"",    // empty
	}
	for _, input := range bad {
		_, err := parseDuration(input)
		require.Error(t, err, "input=%q should be rejected", input)
	}
}

func TestParseDuration_RejectsAbove24h(t *testing.T) {
	_, err := parseDuration("25h")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "24h")
}
