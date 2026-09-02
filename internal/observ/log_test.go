package observ

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 2, 11, 22, 33, 456000000, time.UTC)
	return func() time.Time { return t }
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"error": LevelError, "ERR": LevelError, "e": LevelError,
		"warn": LevelWarn, "Warning": LevelWarn,
		"": LevelInfo, "info": LevelInfo, " INFO ": LevelInfo,
		"debug": LevelDebug, "trace": LevelTrace,
	}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil {
			t.Errorf("ParseLevel(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("ParseLevel(\"loud\") must reject an unknown level rather than guess")
	}
}

func TestLevelString(t *testing.T) {
	if got := LevelTrace.String(); got != "trace" {
		t.Errorf("LevelTrace.String() = %q", got)
	}
	if got := Level(99).String(); got != "invalid" {
		t.Errorf("out-of-range level = %q, want invalid", got)
	}
}

func TestVerbosityLevel(t *testing.T) {
	for v, want := range map[int]Level{-1: LevelInfo, 0: LevelInfo, 1: LevelDebug, 2: LevelTrace, 7: LevelTrace} {
		if got := VerbosityLevel(v); got != want {
			t.Errorf("VerbosityLevel(%d) = %v, want %v", v, got, want)
		}
	}
}

func TestLoggerFiltersByLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogOptions{Level: LevelWarn, Out: &buf, Now: fixedClock()})

	l.Debugf("invisible")
	l.Infof("also invisible")
	if buf.Len() != 0 {
		t.Fatalf("messages below the threshold were emitted: %q", buf.String())
	}
	if l.Enabled(LevelInfo) {
		t.Error("Enabled(LevelInfo) must be false at warn")
	}

	l.Errorf("visible %d", 1)
	if !strings.Contains(buf.String(), "visible 1") {
		t.Fatalf("error message missing: %q", buf.String())
	}
}

// A warning without a remediation is noise, and noise is how the warning that
// mattered gets ignored. The signature forces one; this pins that it is
// actually emitted in both formats.
func TestWarnCarriesRemediation(t *testing.T) {
	var text, jsonBuf bytes.Buffer
	txt := NewLogger(LogOptions{Level: LevelWarn, Out: &text, Now: fixedClock()})
	js := NewLogger(LogOptions{Level: LevelWarn, JSON: true, Out: &jsonBuf, Now: fixedClock()})

	const remedy = "run `dpb tune` (~3 min)"
	txt.Warn(remedy, "escalation rate is %d%%", 71)
	js.Warn(remedy, "escalation rate is %d%%", 71)

	if !strings.Contains(text.String(), remedy) {
		t.Errorf("text warning lost its remediation: %q", text.String())
	}
	var rec map[string]any
	if err := json.Unmarshal(jsonBuf.Bytes(), &rec); err != nil {
		t.Fatalf("json warning is not one object per line: %v (%q)", err, jsonBuf.String())
	}
	if rec["remedy"] != remedy {
		t.Errorf("json remedy = %v, want %q", rec["remedy"], remedy)
	}
	if rec["level"] != "warn" || rec["msg"] != "escalation rate is 71%" {
		t.Errorf("json record = %v", rec)
	}
}

func TestWarnWithEmptyRemedySurfacesTheDefect(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogOptions{Level: LevelWarn, Out: &buf, Now: fixedClock()})
	l.Warn("   ", "something happened")

	out := buf.String()
	if !strings.Contains(out, "something happened") {
		t.Fatalf("the warning itself was dropped: %q", out)
	}
	if !strings.Contains(out, "bug in dpb") {
		t.Errorf("a missing remediation must be reported, not hidden: %q", out)
	}
}

func TestWithFieldsAndInheritedLevel(t *testing.T) {
	var buf bytes.Buffer
	root := NewLogger(LogOptions{Level: LevelInfo, JSON: true, Out: &buf, Now: fixedClock()})
	conn := root.With("host", "discord.com", "id", 42)

	conn.Debugf("hidden")
	if buf.Len() != 0 {
		t.Fatalf("derived logger ignored the parent's level: %q", buf.String())
	}

	// Raising verbosity on a live process must reach loggers derived earlier.
	root.SetLevel(LevelDebug)
	conn.Debugf("now visible")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("bad json: %v (%q)", err, buf.String())
	}
	if rec["host"] != "discord.com" || rec["id"] != float64(42) {
		t.Errorf("fields missing from record: %v", rec)
	}
	if conn.Level() != LevelDebug {
		t.Errorf("derived level = %v, want debug", conn.Level())
	}
}

func TestWithOddPairKeepsTheKey(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogOptions{Level: LevelInfo, JSON: true, Out: &buf, Now: fixedClock()}).With("host")
	l.Infof("x")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if rec["host"] != "(missing)" {
		t.Errorf("a miscounted With call must still show the key: %v", rec)
	}
}

func TestWithNoPairsReturnsSameLogger(t *testing.T) {
	l := Discard()
	if l.With() != l {
		t.Error("With() with no pairs should not allocate a new logger")
	}
}

func TestTextLineShape(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogOptions{Level: LevelTrace, Out: &buf, Now: fixedClock()}).With("host", "x.tr")
	l.Tracef("dialling")

	got := buf.String()
	for _, want := range []string{"11:22:33.456", "TRACE", "dialling", "host=x.tr"} {
		if !strings.Contains(got, want) {
			t.Errorf("text line %q is missing %q", got, want)
		}
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("text line is not newline terminated: %q", got)
	}
}

func TestJSONFieldErrorKeepsTheMessage(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogOptions{Level: LevelInfo, JSON: true, Out: &buf, Now: fixedClock()}).
		With("bad", make(chan int)) // channels cannot be marshalled
	l.Infof("still important")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("fallback line is not valid json: %v (%q)", err, buf.String())
	}
	if rec["msg"] != "still important" {
		t.Errorf("message lost to a bad field: %v", rec)
	}
	if rec["field_error"] == nil {
		t.Errorf("the field failure was hidden: %v", rec)
	}
}

func TestLoggerIsConcurrencySafe(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(LogOptions{Level: LevelInfo, JSON: true, Out: &buf, Now: fixedClock()})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.With("i", i).Infof("line")
			l.SetLevel(LevelInfo)
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 32 {
		t.Fatalf("got %d lines, want 32 (interleaved writes)", len(lines))
	}
	for _, ln := range lines {
		if !json.Valid([]byte(ln)) {
			t.Fatalf("interleaved write corrupted a line: %q", ln)
		}
	}
}

func TestDiscardWritesNothing(t *testing.T) {
	l := Discard()
	l.Errorf("nope")
	if l.Level() != LevelError {
		t.Errorf("Discard level = %v", l.Level())
	}
}
