package observ

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewLoggerDefaults(t *testing.T) {
	l := NewLogger(LogOptions{})
	if l.core.out == nil || l.core.now == nil {
		t.Fatal("NewLogger must fill in a sink and a clock")
	}
	if l.Level() != LevelInfo {
		t.Errorf("default level = %v, want info", l.Level())
	}
}

func TestEventLogWritesNDJSON(t *testing.T) {
	dir := t.TempDir()
	path := EventLogPathFor(dir)

	e, err := OpenEventLog(EventLogOptions{Path: path, Now: fixedClock()})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	if err := e.Write(Record{Kind: KindConn, Fields: map[string]any{"host": "discord.com", "rung": 2}}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := e.Write(Record{Kind: KindState, Time: time.Unix(0, 0).UTC(), Fields: map[string]any{"op": "proxy.pac"}}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	recs := readNDJSON(t, path)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0]["kind"] != KindConn || recs[0]["host"] != "discord.com" {
		t.Errorf("record 0 = %v", recs[0])
	}
	// Fields are flattened, not nested, so `jq 'select(.host=="x")'` works.
	if _, nested := recs[0]["fields"]; nested {
		t.Errorf("fields must be flattened into the object: %v", recs[0])
	}
	if recs[0]["ts"] != "2026-09-02T11:22:33.456Z" {
		t.Errorf("ts = %v, want the injected clock", recs[0]["ts"])
	}
	if recs[1]["ts"] != "1970-01-01T00:00:00Z" {
		t.Errorf("an explicit Time must be preserved, got %v", recs[1]["ts"])
	}
}

// Reserved keys must win: a caller field named "kind" cannot be allowed to
// make the log unreadable by the tools that key on it.
func TestEventLogReservedKeysWin(t *testing.T) {
	dir := t.TempDir()
	path := EventLogPathFor(dir)
	e, err := OpenEventLog(EventLogOptions{Path: path, Now: fixedClock()})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	defer e.Close()

	if err := e.Write(Record{Kind: KindDrift, Fields: map[string]any{"kind": "spoofed", "ts": "spoofed"}}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rec := readNDJSON(t, path)[0]
	if rec["kind"] != KindDrift || rec["ts"] == "spoofed" {
		t.Errorf("caller fields overrode reserved keys: %v", rec)
	}
}

func TestEventLogRotatesBySize(t *testing.T) {
	dir := t.TempDir()
	path := EventLogPathFor(dir)

	e, err := OpenEventLog(EventLogOptions{Path: path, MaxBytes: 200, Keep: 2, Now: fixedClock()})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	defer e.Close()

	for i := 0; i < 30; i++ {
		if err := e.Write(Record{Kind: KindConn, Fields: map[string]any{"i": i, "pad": strings.Repeat("x", 40)}}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	if got := e.Size(); got > 200 {
		t.Errorf("active file is %d bytes, above the %d cap", got, 200)
	}
	files := e.Files()
	if len(files) != 3 { // active + .1 + .2
		t.Fatalf("Files() = %v, want the active file and 2 rotations", files)
	}
	// Keep=2 must actually bound the generations kept.
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("a third generation survived; Keep is not bounding rotation")
	}
	// Every surviving generation must still be readable NDJSON.
	for _, f := range files {
		readNDJSON(t, f)
	}
}

func TestEventLogNegativeMaxBytesDisablesRotation(t *testing.T) {
	dir := t.TempDir()
	path := EventLogPathFor(dir)
	e, err := OpenEventLog(EventLogOptions{Path: path, MaxBytes: -1, Now: fixedClock()})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	defer e.Close()

	for i := 0; i < 50; i++ {
		if err := e.Write(Record{Kind: KindConn, Fields: map[string]any{"pad": strings.Repeat("y", 100)}}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if got := e.Files(); len(got) != 1 {
		t.Errorf("rotation happened despite MaxBytes<0: %v", got)
	}
}

// A run under sudo must not leave logs the user cannot read. The hook is the
// seam paths.Layout.Chown plugs into; here we only assert it is called for the
// active file and for each rotation.
func TestEventLogChownsWhatItCreates(t *testing.T) {
	dir := t.TempDir()
	path := EventLogPathFor(dir)

	var mu sync.Mutex
	var chowned []string
	e, err := OpenEventLog(EventLogOptions{
		Path: path, MaxBytes: 120, Keep: 2, Now: fixedClock(),
		Chown: func(p string) error {
			mu.Lock()
			defer mu.Unlock()
			chowned = append(chowned, filepath.Base(p))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	defer e.Close()

	for i := 0; i < 10; i++ {
		if err := e.Write(Record{Kind: KindConn, Fields: map[string]any{"pad": strings.Repeat("z", 60)}}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(chowned) < 3 {
		t.Fatalf("chown hook called %d times (%v); want the active file plus each rotation", len(chowned), chowned)
	}
	if chowned[0] != "events.ndjson" {
		t.Errorf("first chown was %q, want the active file", chowned[0])
	}
}

func TestEventLogWriteAfterCloseFails(t *testing.T) {
	dir := t.TempDir()
	e, err := OpenEventLog(EventLogOptions{Path: EventLogPathFor(dir), Now: fixedClock()})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close must be idempotent, got %v", err)
	}
	if err := e.Write(Record{Kind: KindConn}); err == nil {
		t.Error("Write after Close must report an error rather than silently drop the event")
	}
}

func TestOpenEventLogErrors(t *testing.T) {
	if _, err := OpenEventLog(EventLogOptions{}); err == nil {
		t.Error("an empty path must be rejected")
	}
	// A path whose parent does not exist: the caller (paths.EnsureDirs) is
	// responsible for the directory, so this must surface, not be papered over.
	if _, err := OpenEventLog(EventLogOptions{Path: filepath.Join(t.TempDir(), "missing", "e.ndjson")}); err == nil {
		t.Error("a missing parent directory must be reported")
	}
}

func TestMarshalRecordRejectsUnmarshalableFields(t *testing.T) {
	if _, err := marshalRecord(Record{Kind: KindConn, Fields: map[string]any{"c": make(chan int)}}); err == nil {
		t.Error("an unmarshalable field must produce an error the caller can report")
	}
}

func TestEventLogConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := EventLogPathFor(dir)
	e, err := OpenEventLog(EventLogOptions{Path: path, MaxBytes: -1, Now: fixedClock()})
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	defer e.Close()

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := e.Write(Record{Kind: KindConn, Fields: map[string]any{"i": i}}); err != nil {
				t.Errorf("Write: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if got := len(readNDJSON(t, path)); got != 24 {
		t.Fatalf("got %d records, want 24", got)
	}
}

func readNDJSON(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("%s: line is not valid json: %v (%q)", path, err, line)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}
