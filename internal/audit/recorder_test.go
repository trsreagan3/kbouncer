// Tests for the per-session recorder (#285).
//
// Mirrors the iam-roles Python recorder tests so cross-product
// regressions surface in CI. Per [[cross-product-agent-parity]] the
// on-disk shape must stay identical; any drift here is the failure
// signal the shared tests catch.

package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testSIDA = "01956c44-c5c1-7c31-9bca-7c0aaa000001"
	testSIDB = "01956c44-c5c1-7c31-9bca-7c0aaa000099"
)

func makeTestEvent(sid, op, verdict, agent string) Event {
	return Event{
		Time:         time.Now().UnixMilli(),
		ClassUID:     6003,
		ClassName:    "API Activity",
		ActivityID:   1,
		ActivityName: op,
		API: OCSFAPI{
			Operation: op,
			Service:   OCSFAPIService{Name: strings.SplitN(op, ":", 2)[0]},
		},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				Verdict: verdict,
				Profile: "safe-default",
				Agent: &OCSFAgent{
					Name:         agent,
					SessionID:    sid,
					DetectedFrom: "mcp_clientinfo",
				},
			},
		},
	}
}

func TestIsValidSessionID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{testSIDA, true},
		{"../../etc/passwd", false},
		{"a/b", false},
		{"", false},
		{strings.Repeat("a", 129), false},
	}
	for _, c := range cases {
		if got := IsValidSessionID(c.in); got != c.want {
			t.Errorf("IsValidSessionID(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestExtractSessionID(t *testing.T) {
	ev := makeTestEvent(testSIDA, "s3:GetObject", "allow", "claude-code")
	if got := ExtractSessionID(ev); got != testSIDA {
		t.Errorf("ExtractSessionID = %q want %q", got, testSIDA)
	}
	ev.Unmapped.IAMJIT.Agent = nil
	if got := ExtractSessionID(ev); got != "" {
		t.Errorf("ExtractSessionID with no agent = %q want empty", got)
	}
}

func TestRecorderMultipleSessionsMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	if err != nil {
		t.Fatalf("NewSessionRecorder: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.Record(makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	r.Record(makeTestEvent(testSIDB, "s3:Get", "allow", "cursor"))
	r.Record(makeTestEvent(testSIDA, "s3:List", "allow", "claude-code"))
	r.Stop()

	for _, sid := range []string{testSIDA, testSIDB} {
		if _, err := os.Stat(filepath.Join(dir, sid+".ndjson")); err != nil {
			t.Errorf("expected %s.ndjson to exist: %v", sid, err)
		}
	}
}

func TestRecorderMetaHeader(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	r.Stop()

	data, err := os.ReadFile(filepath.Join(dir, testSIDA+".ndjson"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 1 {
		t.Fatalf("recording is empty")
	}
	var header recordingMetaWrapper
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header unmarshal: %v", err)
	}
	if header.Meta.RecordingSchemaVersion != RecordingSchemaVersion {
		t.Errorf("schema_version = %q want %q",
			header.Meta.RecordingSchemaVersion, RecordingSchemaVersion)
	}
	if header.Meta.SessionID != testSIDA {
		t.Errorf("header session_id = %q want %q", header.Meta.SessionID, testSIDA)
	}
	if header.Meta.BouncerProduct != "kbouncer" {
		t.Errorf("header bouncer_product = %q want kbouncer",
			header.Meta.BouncerProduct)
	}
	if header.Meta.AgentName != "claude-code" {
		t.Errorf("header agent_name = %q want claude-code", header.Meta.AgentName)
	}
}

func TestRecorderFileMode(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	r.Stop()

	info, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != RecordingFileMode {
		t.Errorf("file mode = %o want %o", got, RecordingFileMode)
	}
}

func TestRecorderDropsEventWithoutSessionID(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	ev := makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code")
	ev.Unmapped.IAMJIT.Agent = nil
	r.Record(ev)
	r.Stop()

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ndjson") {
			t.Errorf("unexpected recording file %q", e.Name())
		}
	}
	if got := r.Status().DroppedEvents; got != 1 {
		t.Errorf("dropped count = %d want 1", got)
	}
}

func TestRecorderNoCrossSessionLeakage(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	evA := makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code")
	evA.StatusDetail = "sentinel-AAA-only-in-A"
	r.Record(evA)
	evB := makeTestEvent(testSIDB, "s3:Get", "allow", "cursor")
	evB.StatusDetail = "sentinel-BBB-only-in-B"
	r.Record(evB)
	r.Stop()

	a, _ := os.ReadFile(filepath.Join(dir, testSIDA+".ndjson"))
	b, _ := os.ReadFile(filepath.Join(dir, testSIDB+".ndjson"))
	if !strings.Contains(string(a), "sentinel-AAA-only-in-A") {
		t.Error("expected sentinel-AAA in session A's file")
	}
	if strings.Contains(string(a), "sentinel-BBB-only-in-B") {
		t.Error("sentinel-BBB leaked into session A's file")
	}
	if !strings.Contains(string(b), "sentinel-BBB-only-in-B") {
		t.Error("expected sentinel-BBB in session B's file")
	}
	if strings.Contains(string(b), "sentinel-AAA-only-in-A") {
		t.Error("sentinel-AAA leaked into session B's file")
	}
}

func TestRecorderSentinelGrep(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	ev := makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code")
	ev.Resources = []OCSFResource{
		{UID: "arn:aws:s3:::bucket/sentinel-XYZ"},
	}
	r.Record(ev)
	r.Stop()

	data, _ := os.ReadFile(filepath.Join(dir, testSIDA+".ndjson"))
	if !strings.Contains(string(data), "sentinel-XYZ") {
		t.Error("sentinel-XYZ should appear in recording (unredacted source of truth)")
	}
}

func TestRecorderPartialSuffixBeforeStop(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson.partial")); err != nil {
		t.Errorf("expected .partial file mid-session: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson")); !os.IsNotExist(err) {
		t.Errorf("final file should not exist mid-session; got err=%v", err)
	}
	r.Stop()
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson.partial")); !os.IsNotExist(err) {
		t.Errorf(".partial should be gone after Stop; got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson")); err != nil {
		t.Errorf("final file should exist after Stop: %v", err)
	}
}

func TestRecorderFinaliseIdle(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir:              dir,
		BouncerProduct:   "kbouncer",
		HeartbeatTimeout: time.Minute,
	})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	stale := r.FinaliseIdle(time.Now().Add(2 * time.Minute))
	if len(stale) != 1 || stale[0] != testSIDA {
		t.Errorf("FinaliseIdle = %v want [%s]", stale, testSIDA)
	}
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson")); err != nil {
		t.Errorf("expected final file: %v", err)
	}
	r.Stop()
}

func TestRecorderStartupFinalisesStalePartials(t *testing.T) {
	dir := t.TempDir()
	// Hand-craft a stale .partial.
	stale := filepath.Join(dir, testSIDA+".ndjson.partial")
	if err := os.WriteFile(stale, []byte(`{"_meta":{"session_id":"`+testSIDA+`"}}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir:              dir,
		BouncerProduct:   "kbouncer",
		HeartbeatTimeout: time.Minute,
	})
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson.partial")); !os.IsNotExist(err) {
		t.Errorf("stale .partial should be finalised on Start; err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson")); err != nil {
		t.Errorf("expected final file after Start finalisation: %v", err)
	}
}

func TestListSessionsEmpty(t *testing.T) {
	rows, err := ListSessions(t.TempDir())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for empty dir; got %d", len(rows))
	}
}

func TestListSessionsCountsEvents(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	for i := 0; i < 3; i++ {
		r.Record(makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	}
	r.Record(makeTestEvent(testSIDB, "s3:Get", "allow", "cursor"))
	r.Stop()

	rows, err := ListSessions(dir)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	counts := map[string]int64{}
	for _, row := range rows {
		counts[row.SessionID] = row.EventCount
	}
	if counts[testSIDA] != 3 {
		t.Errorf("session A event count = %d want 3", counts[testSIDA])
	}
	if counts[testSIDB] != 1 {
		t.Errorf("session B event count = %d want 1", counts[testSIDB])
	}
}

func TestReadSessionRoundTrips(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	r.Record(makeTestEvent(testSIDA, "s3:List", "allow", "claude-code"))
	r.Stop()

	meta, events, err := ReadSession(dir, testSIDA)
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	if meta.SessionID != testSIDA {
		t.Errorf("meta session_id = %q want %q", meta.SessionID, testSIDA)
	}
	if meta.BouncerProduct != "kbouncer" {
		t.Errorf("meta bouncer_product = %q want kbouncer", meta.BouncerProduct)
	}
	if len(events) != 2 {
		t.Errorf("event count = %d want 2", len(events))
	}
}

func TestReadSessionRejectsTraversal(t *testing.T) {
	if _, _, err := ReadSession(t.TempDir(), "../etc/passwd"); err == nil {
		t.Error("expected ReadSession to refuse traversal id")
	}
}

func TestDetectionFindingFromSession(t *testing.T) {
	events := []Event{
		{Time: 1_700_000_000_000, ActivityName: "s3:Get"},
		{Time: 1_700_000_010_000, ActivityName: "s3:List"},
	}
	meta := RecordingMeta{
		SessionID:      testSIDA,
		AgentName:      "claude-code",
		BouncerProduct: "kbouncer",
	}
	f := DetectionFindingFromSession(meta, events)
	if f.ClassUID != 2004 {
		t.Errorf("class_uid = %d want 2004", f.ClassUID)
	}
	if f.StartTime != 1_700_000_000_000 || f.EndTime != 1_700_000_010_000 {
		t.Errorf("time window wrong: start=%d end=%d", f.StartTime, f.EndTime)
	}
	if f.Unmapped.IAMJIT.Session.SessionID != testSIDA {
		t.Errorf("session id = %q want %q",
			f.Unmapped.IAMJIT.Session.SessionID, testSIDA)
	}
	if len(f.Unmapped.IAMJIT.Session.Events) != 2 {
		t.Errorf("expected 2 events in finding")
	}
}

func TestPurgeOlderThanRemovesOnlyOld(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, testSIDA+".ndjson")
	if err := os.WriteFile(old, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	new := filepath.Join(dir, testSIDB+".ndjson")
	if err := os.WriteFile(new, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	oldMtime := time.Now().Add(-40 * 24 * time.Hour)
	_ = os.Chtimes(old, oldMtime, oldMtime)

	removed, err := PurgeOlderThan(dir, 30*24*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if len(removed) != 1 || removed[0] != old {
		t.Errorf("removed = %v want [%s]", removed, old)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old file should be gone; err=%v", err)
	}
	if _, err := os.Stat(new); err != nil {
		t.Errorf("new file should survive: %v", err)
	}
}

func TestPurgeSkipsPartialFiles(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, testSIDA+".ndjson.partial")
	if err := os.WriteFile(partial, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	old := time.Now().Add(-90 * 24 * time.Hour)
	_ = os.Chtimes(partial, old, old)

	removed, _ := PurgeOlderThan(dir, 30*24*time.Hour, time.Now())
	if len(removed) != 0 {
		t.Errorf("expected purge to skip .partial files; got %v", removed)
	}
	if _, err := os.Stat(partial); err != nil {
		t.Errorf(".partial should survive purge: %v", err)
	}
}

// Manager-level wiring test — exercises the tee path through Emit so a
// future refactor that drops the recorder hook fails this test.
func TestManagerEmitTeesToRecorder(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "kbouncer",
	})
	if err != nil {
		t.Fatalf("NewSessionRecorder: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m := NewManager(ManagerOptions{SessionRecorder: r})
	defer m.Close()
	m.Emit(context.Background(), makeTestEvent(testSIDA, "s3:Get", "allow", "claude-code"))
	// Force finalisation so we can read the file.
	r.Stop()

	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson")); err != nil {
		t.Errorf("Manager.Emit should tee to recorder; file missing: %v", err)
	}
}
