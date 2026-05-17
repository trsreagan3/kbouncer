package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/kbouncer/internal/store"
)

// TestHealthz_IncludesLookupErrorsCounter closes UAT-K2 MED-K2-06:
// /healthz now exposes a `lookup_errors_counter` field mirroring the
// Python iam-jit-bouncer healthz shape. Confirms the field is present
// + reflects the package-level counter.
func TestHealthz_IncludesLookupErrorsCounter(t *testing.T) {
	ResetLookupErrorsCount()
	t.Cleanup(ResetLookupErrorsCount)

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })

	srv := NewServer(Config{
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
	}, st)

	// Manually trip the counter so we can observe a non-zero value.
	recordLookupError(assertErr{}, "kbounce: synthetic lookup error for test")
	recordLookupError(assertErr{}, "kbounce: synthetic lookup error for test")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.healthz(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	body, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(body, &payload))
	got, ok := payload["lookup_errors_counter"]
	require.True(t, ok, "healthz payload must include lookup_errors_counter")
	// JSON numbers decode as float64.
	gotF, ok := got.(float64)
	require.True(t, ok, "lookup_errors_counter must be numeric, got %T", got)
	assert.EqualValues(t, 2, int64(gotF),
		"lookup_errors_counter must reflect the package-level counter")
}

// TestLookupErrorsCounter_NoIncrementOnNil pins that recordLookupError
// is a no-op when the error is nil (cheap pre-check at the call site
// would otherwise be required everywhere).
func TestLookupErrorsCounter_NoIncrementOnNil(t *testing.T) {
	ResetLookupErrorsCount()
	t.Cleanup(ResetLookupErrorsCount)
	recordLookupError(nil, "kbounce: should not count")
	assert.Equal(t, int64(0), LookupErrorsCount())
}

// assertErr is a minimal error implementation for the synthetic
// counter-increment in the test above. Avoids pulling errors.New into
// the test file just for one string.
type assertErr struct{}

func (assertErr) Error() string { return "synthetic test error" }
