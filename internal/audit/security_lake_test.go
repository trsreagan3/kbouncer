package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/parquet-go/parquet-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock S3 client
// ---------------------------------------------------------------------------

type mockS3PutObject struct {
	Bucket string
	Key    string
	Body   []byte
}

type mockS3Client struct {
	mu      sync.Mutex
	puts    []mockS3PutObject
	putErr  error
}

func (m *mockS3Client) PutObject(
	ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	body := bytes.Buffer{}
	if in.Body != nil {
		body.ReadFrom(in.Body)
	}
	m.mu.Lock()
	m.puts = append(m.puts, mockS3PutObject{
		Bucket: aws.ToString(in.Bucket),
		Key:    aws.ToString(in.Key),
		Body:   append([]byte{}, body.Bytes()...),
	})
	m.mu.Unlock()
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) Puts() []mockS3PutObject {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockS3PutObject, len(m.puts))
	copy(out, m.puts)
	return out
}

// ---------------------------------------------------------------------------
// Schema + helpers
// ---------------------------------------------------------------------------

func TestSecurityLakeColumnNamesAreLockedIn(t *testing.T) {
	// Cross-product contract per [[cross-product-agent-parity]]: the
	// column set + order are byte-stable. ibounce + dbounce assert
	// the same list in their own tests.
	require.Equal(t, "metadata_version", SecurityLakeColumnNames[0])
	require.Contains(t, SecurityLakeColumnNames, "class_uid")
	require.Contains(t, SecurityLakeColumnNames, "activity_id")
	require.Contains(t, SecurityLakeColumnNames, "unmapped_iam_jit_verdict")
	require.Contains(t, SecurityLakeColumnNames, "unmapped_iam_jit_decision_id")
	require.Contains(t, SecurityLakeColumnNames, "unmapped_iam_jit_ext_json")
	require.Contains(t, SecurityLakeColumnNames, "resources_json")
	// Lock the count so a stray addition fails the test (forces the
	// author to update ibounce + dbounce together).
	require.Equal(t, 39, len(SecurityLakeColumnNames),
		"cross-product invariant: 39 columns; update ibounce + dbounce + this test together")
}

func TestSecurityLakePartitionPath(t *testing.T) {
	when := time.Date(2026, 5, 19, 14, 7, 33, 0, time.UTC)
	got := securityLakePartitionPath("us-east-1", when, 6003, 1747667253000)
	require.Equal(t,
		"region=us-east-1/eventday=20260519/eventhour=14/api_activity-1747667253000.parquet",
		got)
}

func TestSecurityLakePartitionPathUnknownClassFallback(t *testing.T) {
	when := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	got := securityLakePartitionPath("us-west-2", when, 7777, 123)
	require.Equal(t,
		"region=us-west-2/eventday=20260519/eventhour=14/class-7777-123.parquet",
		got)
}

func TestSecurityLakeRowFromEvent(t *testing.T) {
	ev := FromDecision(DecisionInput{
		At:            time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC),
		DecisionID:    42,
		Mode:          "transparent",
		Profile:       "safe-default",
		Verdict:       "deny",
		Reason:        "explicit-deny rule",
		Enforced:      true,
		Host:          "kubernetes.example.com",
		Method:        "DELETE",
		Path:          "/api/v1/namespaces/prod/pods/critical-db",
		ParsedVerb:    "delete",
		ParsedGroup:   "",
		ParsedVersion: "v1",
		ParsedResource: "pods",
		ParsedNamespace: "prod",
		ParsedName:     "critical-db",
		PrincipalName:  "agent@example.com",
		PrincipalUID:   "u-123",
	})
	row := securityLakeRowFromEvent(ev)

	require.Equal(t, "1.1.0", row.MetadataVersion)
	require.Equal(t, "kbounce", row.MetadataProductName)
	require.Equal(t, "iam-jit", row.MetadataProductVendorName)
	require.Equal(t, int32(6003), row.ClassUID)
	// kbounce uppercases verdicts in IAMJITExt.Verdict (matches the
	// existing FromDecision behaviour).
	require.Equal(t, "DENY", row.UnmappedIAMJITVerdict)
	require.Equal(t, int64(42), row.UnmappedIAMJITDecisionID)
	require.True(t, row.UnmappedIAMJITEnforced)
	require.Equal(t, "agent@example.com", row.ActorUserName)
	require.NotEmpty(t, row.ResourcesJSON)
	require.NotEmpty(t, row.UnmappedIAMJITExtJSON)
}

func TestEncodeSecurityLakeRowsRoundTrip(t *testing.T) {
	// Build two rows + encode + read back via parquet-go.
	row1 := SecurityLakeRow{
		MetadataVersion:           "1.1.0",
		MetadataProductName:       "kbounce",
		MetadataProductVendorName: "iam-jit",
		ClassUID:                  6003,
		ActivityID:                2,
		APIOperation:              "GET pods",
		UnmappedIAMJITVerdict:     "allow",
		UnmappedIAMJITDecisionID:  101,
	}
	row2 := SecurityLakeRow{
		MetadataVersion:           "1.1.0",
		MetadataProductName:       "kbounce",
		MetadataProductVendorName: "iam-jit",
		ClassUID:                  6003,
		ActivityID:                4,
		APIOperation:              "DELETE pods",
		UnmappedIAMJITVerdict:     "deny",
		UnmappedIAMJITDecisionID:  102,
		UnmappedIAMJITEnforced:    true,
	}
	payload, err := encodeSecurityLakeRows([]SecurityLakeRow{row1, row2})
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	// Read back. parquet.GenericReader.Read returns io.EOF as the
	// second return value when the buffer is exhausted (mirrors the
	// standard io.Reader contract); rows are still populated.
	reader := parquet.NewGenericReader[SecurityLakeRow](bytes.NewReader(payload))
	got := make([]SecurityLakeRow, 2)
	n, err := reader.Read(got)
	require.Equal(t, 2, n)
	if err != nil {
		// EOF is expected when all rows are drained.
		require.ErrorIs(t, err, io.EOF)
	}
	require.Equal(t, "allow", got[0].UnmappedIAMJITVerdict)
	require.Equal(t, int64(101), got[0].UnmappedIAMJITDecisionID)
	require.Equal(t, "deny", got[1].UnmappedIAMJITVerdict)
	require.True(t, got[1].UnmappedIAMJITEnforced)

	// Schema verification: every canonical column is present in the
	// parquet schema.
	schema := reader.Schema()
	fields := schema.Fields()
	got_names := make(map[string]bool)
	for _, f := range fields {
		got_names[f.Name()] = true
	}
	for _, name := range SecurityLakeColumnNames {
		require.True(t, got_names[name],
			"column %q missing from parquet schema", name)
	}
}

// ---------------------------------------------------------------------------
// Construction / refusal-to-start
// ---------------------------------------------------------------------------

func TestNewSecurityLakeWriterRequiresBucket(t *testing.T) {
	_, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "", Region: "us-east-1",
	})
	require.Error(t, err)
}

func TestNewSecurityLakeWriterRequiresRegion(t *testing.T) {
	_, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "b", Region: "",
	})
	require.Error(t, err)
}

func TestNewSecurityLakeWriterAppliesDefaults(t *testing.T) {
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "b", Region: "r",
	})
	require.NoError(t, err)
	require.Equal(t, SecurityLakeDefaultRotationSeconds, w.rotationSeconds)
	require.Equal(t, SecurityLakeDefaultMaxBatchBytes, w.maxBatchBytes)
	require.Equal(t, SecurityLakeDefaultMaxPendingRows, w.maxPendingRows)
}

// ---------------------------------------------------------------------------
// End-to-end with mock S3
// ---------------------------------------------------------------------------

func TestSecurityLakeWriterFlushesOnClose(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600, // won't fire during the test
		S3Client:        mock,
		AccountID:       "111111111111",
		CallerARN:       "arn:aws:iam::111111111111:role/test",
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	for i := 0; i < 3; i++ {
		ev := FromDecision(DecisionInput{
			DecisionID: int64(i), Mode: "cooperative", Verdict: "allow",
			Reason: "rule#1", Host: "kubernetes.example.com",
			ParsedVerb: "get", ParsedResource: "pods",
		})
		w.Write(context.Background(), ev)
	}

	// Nothing in S3 yet.
	require.Empty(t, mock.Puts(), "no rotation should have fired yet")

	w.Close()

	puts := mock.Puts()
	require.Equal(t, 1, len(puts))
	require.Equal(t, "test-bucket", puts[0].Bucket)
	require.Contains(t, puts[0].Key, "region=us-east-1/eventday=")
	require.Contains(t, puts[0].Key, "/eventhour=")
	require.Contains(t, puts[0].Key, "/api_activity-")
	require.Contains(t, puts[0].Key, ".parquet")
	require.NotEmpty(t, puts[0].Body)

	st := w.Status()
	require.True(t, st.WritesOK)
	require.Equal(t, int64(3), st.TotalEvents)
	require.Equal(t, int64(1), st.TotalFilesWritten)
	require.Greater(t, st.TotalBytesWritten, int64(0))
}

func TestSecurityLakeWriterPartitionsByClassUID(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	// One normal decision event (class 6003) + one synthetic with
	// class 7777 to exercise the per-class bucketing path.
	w.Write(context.Background(), FromDecision(DecisionInput{
		DecisionID: 1, Mode: "transparent", Verdict: "allow",
		Host: "kubernetes.example.com", ParsedVerb: "get",
	}))
	syn := Event{
		Metadata: OCSFMetadata{
			Version: "1.1.0",
			Product: OCSFProduct{Name: "kbounce", VendorName: "iam-jit",
				Version: "dev"},
		},
		Time:         time.Now().Unix(),
		ClassUID:     7777,
		ClassName:    "Synthetic",
		CategoryUID:  6,
		CategoryName: "Application Activity",
		ActivityID:   99,
		ActivityName: "synthetic",
		TypeUID:      777799,
		TypeName:     "Synthetic: Other",
		SeverityID:   1, Severity: "Informational",
		StatusID:  1, Status: "Success",
		API:       OCSFAPI{Service: OCSFAPIService{}, Request: OCSFAPIRequest{}},
		Resources: []OCSFResource{},
		Unmapped:  OCSFUnmapped{IAMJIT: IAMJITExt{EventType: "SYNTHETIC"}},
	}
	w.Write(context.Background(), syn)

	w.Close()
	puts := mock.Puts()
	require.Equal(t, 2, len(puts))
	prefixes := make(map[string]bool)
	for _, p := range puts {
		if contains(p.Key, "/api_activity-") {
			prefixes["api_activity"] = true
		}
		if contains(p.Key, "/class-7777-") {
			prefixes["class-7777"] = true
		}
	}
	require.True(t, prefixes["api_activity"])
	require.True(t, prefixes["class-7777"])
}

func TestSecurityLakeWriterFlushesOnSizeCap(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		MaxBatchBytes:   2048, // 2KB cap -> 2 rows trip the size flush
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	for i := 0; i < 3; i++ {
		w.Write(context.Background(), FromDecision(DecisionInput{
			DecisionID: int64(i), Mode: "transparent", Verdict: "allow",
			Host: "kubernetes.example.com", ParsedVerb: "get",
		}))
	}
	w.Close()
	// 2 files: one size-triggered (2 rows) + one close-triggered (1 row).
	require.Equal(t, 2, len(mock.Puts()))
}

func TestSecurityLakeWriterFlushesOnRotationTimer(t *testing.T) {
	mock := &mockS3Client{}
	now := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	clockMu := sync.Mutex{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 1,
		S3Client:        mock,
		Now: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		},
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))
	defer w.Close()

	w.Write(context.Background(), FromDecision(DecisionInput{
		DecisionID: 1, Mode: "transparent", Verdict: "allow",
		Host: "kubernetes.example.com", ParsedVerb: "get",
	}))

	// Advance fake clock past the deadline.
	clockMu.Lock()
	now = now.Add(5 * time.Second)
	clockMu.Unlock()

	// Wait for the ticker to observe + flush.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(mock.Puts()) >= 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("rotation timer did not fire within 5s")
}

func TestSecurityLakeWriterDroppedOnOverflow(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		MaxPendingRows:  2,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	for i := 0; i < 4; i++ {
		w.Write(context.Background(), FromDecision(DecisionInput{
			DecisionID: int64(i), Mode: "transparent", Verdict: "allow",
			Host: "kubernetes.example.com", ParsedVerb: "get",
		}))
	}
	st := w.Status()
	require.Equal(t, int64(2), st.DroppedEvents)
	require.Equal(t, 2, st.PendingRows)
	w.Close()
}

func TestSecurityLakeWriterStatusForMCP(t *testing.T) {
	mock := &mockS3Client{}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
		AccountID:       "111111111111",
		CallerARN:       "arn:aws:iam::111111111111:role/test",
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))
	defer w.Close()

	st := w.Status()
	require.True(t, st.Configured)
	require.Equal(t, "test-bucket", st.Bucket)
	require.Equal(t, "us-east-1", st.Region)
	require.Equal(t, "111111111111", st.AccountID)
	require.Equal(t, 600, st.RotationSeconds)
	require.True(t, st.WritesOK)
	require.Equal(t, int64(0), st.DroppedEvents)
}

func TestSecurityLakeWriterRecordsErrorOnPutObjectFailure(t *testing.T) {
	mock := &mockS3Client{putErr: errors.New("AccessDenied: simulated")}
	w, err := NewSecurityLakeWriter(SecurityLakeWriterOptions{
		Bucket: "test-bucket", Region: "us-east-1",
		RotationSeconds: 600,
		S3Client:        mock,
	})
	require.NoError(t, err)
	require.NoError(t, w.Start(context.Background()))

	w.Write(context.Background(), FromDecision(DecisionInput{
		DecisionID: 1, Mode: "transparent", Verdict: "allow",
		Host: "kubernetes.example.com", ParsedVerb: "get",
	}))
	w.Close()

	st := w.Status()
	assert.False(t, st.WritesOK)
	assert.Contains(t, st.LastError, "s3 put_object failed")
}

func TestSecurityLakeWriterDefaultsMatchSpec(t *testing.T) {
	require.Equal(t, 300, SecurityLakeDefaultRotationSeconds)
	require.Equal(t, 10*1024*1024, SecurityLakeDefaultMaxBatchBytes)
}

// JSON round-trip verifies the resources_json column carries valid JSON
// the operator can json_extract in Athena.
func TestSecurityLakeRowResourcesJSONIsValid(t *testing.T) {
	row := securityLakeRowFromEvent(Event{
		Resources: []OCSFResource{
			{Name: "pods/critical-db", UID: "pod-uid-1", Type: "pod"},
		},
		Unmapped: OCSFUnmapped{IAMJIT: IAMJITExt{Ext: map[string]any{
			"namespace": "prod", "watch": false,
		}}},
	})
	var resources []OCSFResource
	require.NoError(t, json.Unmarshal([]byte(row.ResourcesJSON), &resources))
	require.Equal(t, 1, len(resources))
	require.Equal(t, "pods/critical-db", resources[0].Name)
	require.Equal(t, "pod-uid-1", resources[0].UID)

	var ext map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.UnmappedIAMJITExtJSON), &ext))
	require.Equal(t, "prod", ext["namespace"])
}

// Helper: substring check that handles the assertion message format
// in older versions of testify without dragging in a regex.
func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

// Ensures the partition path's hour component is always 2-digits.
func TestSecurityLakePartitionPathTwoDigitHour(t *testing.T) {
	when := time.Date(2026, 5, 19, 4, 0, 0, 0, time.UTC)
	got := securityLakePartitionPath("eu-west-1", when, 6003, 1)
	require.Equal(t,
		"region=eu-west-1/eventday=20260519/eventhour=04/api_activity-1.parquet",
		got, fmt.Sprintf("got=%s", got))
}
