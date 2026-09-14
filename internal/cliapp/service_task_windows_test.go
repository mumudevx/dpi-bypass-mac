//go:build windows

// This file tests service_task_windows.go's decision logic the same way
// service_windows_test.go tests service_windows.go's: the pure computations a
// mistake in would misinform an install or a status read, kept apart from the
// filesystem, schtasks and process-snapshot calls that surround them and
// cannot run without a real Windows machine.
//
// Nothing here can be executed in this environment — there is no Windows
// machine to run it on — but `GOOS=windows go test -c ./internal/cliapp/`
// links it and `GOOS=windows go vet ./...` type-checks it, which is what a
// change to this logic gets checked against until a Windows CI runner exists.
// The expected strings in TestLogonTaskArgumentsMatchesWhatCreateProcessParses
// were produced the same way service_windows_test.go's comment describes for
// winServiceImagePath: by running syscall.EscapeArg's published algorithm
// (GOROOT/src/syscall/exec_windows.go) standalone on darwin, since a wrong
// "want" in an unrunnable test is a defect wearing a passing test's clothes.

package cliapp

import (
	"strings"
	"testing"
)

// TestLogonTaskNameIsTheServiceName locks down the identity logonTaskName's
// own comment states: the two mechanisms share dpb's name on purpose, in two
// namespaces that cannot collide.
func TestLogonTaskNameIsTheServiceName(t *testing.T) {
	t.Parallel()
	if logonTaskName != serviceName {
		t.Errorf("logonTaskName = %q, want it to equal serviceName (%q)", logonTaskName, serviceName)
	}
	if logonTaskName != "dpb" {
		t.Errorf(`logonTaskName = %q, want "dpb" — a rename orphans the task an older dpb installed`, logonTaskName)
	}
}

// TestLogonTaskArgumentsMatchesWhatCreateProcessParses is
// logonTaskArguments' own comment made executable: verifyLogonTask's
// read-back check is only as good as this reproducing CreateProcess's
// argument escaping exactly, not approximately — the identical concern
// service_windows_test.go states for winServiceImagePath, applied to the
// Arguments half of a Task Scheduler action (Command is never escaped this
// way; see TestLogonTaskXMLGeneration).
func TestLogonTaskArgumentsMatchesWhatCreateProcessParses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "a single plain argument needs no escaping",
			args: []string{"run"},
			want: "run",
		},
		{
			name: "an argument with a space is quoted on its own",
			args: []string{"run", "--profile", "turkey line"},
			want: `run --profile "turkey line"`,
		},
		{
			name: "an embedded quote is backslash-escaped",
			args: []string{"run", `a"b`},
			want: `run a\"b`,
		},
		{
			name: "a trailing backslash is doubled before the closing quote",
			args: []string{"run", `C:\some dir\`},
			want: `run "C:\some dir\\"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := logonTaskArguments(tc.args); got != tc.want {
				t.Errorf("logonTaskArguments(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// TestLogonTaskXMLGeneration checks the task definition schtasks /create /xml
// consumes carries every setting whose absence is a silent trap for a
// long-running process — see logonTaskXML's own comment for what each one
// defaults to when omitted and why that default is wrong here. This is a
// plain string generation function, so the check is textual, the same way a
// mistyped plist key would only be caught by grepping servicePlist's output
// on darwin.
func TestLogonTaskXMLGeneration(t *testing.T) {
	t.Parallel()
	doc := logonTaskXML("S-1-5-21-1-2-3-1001", `C:\Program Files\dpb\dpb.exe`, []string{"run", "--profile", "turkey"})

	for _, want := range []string{
		// Traps for a long-running process that Task Scheduler applies
		// silently when the element is absent.
		"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
		// Proxy mode does not need, and must not ask for, elevation.
		"<RunLevel>LeastPrivilege</RunLevel>",
		// Runs only in a real interactive logon — the whole reason this
		// mechanism exists rather than a Windows service.
		"<LogonType>InteractiveToken</LogonType>",
		// A second logon must not start a second copy of the proxy.
		"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
		// The trigger this mechanism is named for.
		"<LogonTrigger>",
		// The account the task's Principal and LogonTrigger run as.
		"<UserId>S-1-5-21-1-2-3-1001</UserId>",
		// The command and its arguments, Task Scheduler's own way (a
		// separate Arguments element, not one escaped command line).
		`<Command>C:\Program Files\dpb\dpb.exe</Command>`,
		"<Arguments>run --profile turkey</Arguments>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("logonTaskXML(...) does not contain %q\ngot:\n%s", want, doc)
		}
	}

	// RestartOnFailure is deliberately absent — see the package comment on
	// why enabling it would restart into a network `dpb run` deliberately
	// refused to touch (exit 5). Its presence here would be a silent
	// regression back to a hot loop this project has designed around on
	// every other platform.
	if strings.Contains(doc, "RestartOnFailure") {
		t.Error("logonTaskXML(...) contains RestartOnFailure, which cannot tell a deliberate " +
			"refusal (dpb run exit 5) from a crash and must not be enabled")
	}
}

// TestLogonTaskXMLEscapesSpecialCharacters checks a SID or path containing a
// character with XML meaning does not produce invalid XML. An ampersand in a
// home directory is the case service_darwin.go's plistText comment names for
// the plist; this is the same hazard for the task definition.
func TestLogonTaskXMLEscapesSpecialCharacters(t *testing.T) {
	t.Parallel()
	doc := logonTaskXML("S-1-5-21-1-2-3-1001", `C:\Users\A & B\dpb.exe`, []string{"run"})
	if strings.Contains(doc, `C:\Users\A & B\dpb.exe`) {
		t.Error("logonTaskXML(...) wrote an unescaped ampersand into the Command element")
	}
	if !strings.Contains(doc, `C:\Users\A &amp; B\dpb.exe`) {
		t.Errorf("logonTaskXML(...) did not escape the ampersand as &amp;\ngot:\n%s", doc)
	}
}

// TestDecodeTaskXMLHandlesTheEncodingTaskSchedulerPersistsWith round-trips
// through the UTF-16LE-with-BOM encoding every Task Scheduler file this
// project has observed uses, plus the two fallback/error cases: bytes that
// are already UTF-8 (what dpb itself writes to the staging file), and a
// truncated UTF-16 sequence.
func TestDecodeTaskXMLHandlesTheEncodingTaskSchedulerPersistsWith(t *testing.T) {
	t.Parallel()
	t.Run("UTF-16LE with a byte-order mark decodes to the original text", func(t *testing.T) {
		t.Parallel()
		want := `<?xml version="1.0" encoding="UTF-16"?><Task>ok</Task>`
		b := []byte{0xFF, 0xFE}
		for _, r := range want {
			lo := byte(r)
			hi := byte(r >> 8)
			b = append(b, lo, hi)
		}
		got, err := decodeTaskXML(b)
		if err != nil {
			t.Fatalf("decodeTaskXML: %v", err)
		}
		if got != want {
			t.Errorf("decodeTaskXML(...) = %q, want %q", got, want)
		}
	})

	t.Run("no byte-order mark is assumed already UTF-8", func(t *testing.T) {
		t.Parallel()
		want := `<?xml version="1.0" encoding="UTF-8"?><Task>ok</Task>`
		got, err := decodeTaskXML([]byte(want))
		if err != nil {
			t.Fatalf("decodeTaskXML: %v", err)
		}
		if got != want {
			t.Errorf("decodeTaskXML(...) = %q, want %q", got, want)
		}
	})

	t.Run("a truncated UTF-16 sequence after the BOM is an error, not mojibake", func(t *testing.T) {
		t.Parallel()
		b := []byte{0xFF, 0xFE, 0x3C, 0x00, 0x3F} // one whole code unit plus one stray byte
		if _, err := decodeTaskXML(b); err == nil {
			t.Error("decodeTaskXML(...) = nil error for an odd byte count after the BOM, want an error")
		}
	})
}

// TestStripXMLProlog checks the declaration-stripping helper that lets
// parseTaskXML hand encoding/xml.Unmarshal a document with no encoding
// attribute for it to refuse — see stripXMLProlog's own comment for why
// Unmarshal cannot be handed encoding="UTF-16" text directly even after it
// has already been decoded to native UTF-8.
func TestStripXMLProlog(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{
			name: "a UTF-16 declaration is removed",
			in:   `<?xml version="1.0" encoding="UTF-16"?><Task>x</Task>`,
			want: `<Task>x</Task>`,
		},
		{
			name: "leading whitespace before the declaration is tolerated",
			in:   "\n\t <?xml version=\"1.0\" encoding=\"UTF-16\"?><Task>x</Task>",
			want: `<Task>x</Task>`,
		},
		{
			name: "text with no declaration is returned unchanged",
			in:   `<Task>x</Task>`,
			want: `<Task>x</Task>`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := stripXMLProlog(tc.in); got != tc.want {
				t.Errorf("stripXMLProlog(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseTaskXMLRoundTripsThroughWhatTaskSchedulerWouldPersist is
// verifyLogonTask's own check made a unit test: it generates a definition
// with logonTaskXML exactly as installLogonTask would, re-encodes it as
// UTF-16LE with a byte-order mark exactly as Task Scheduler persists a task
// (see decodeTaskXML's comment), and confirms parseTaskXML recovers the same
// Command, Arguments and LogonTrigger presence that were asked for. This is
// the one test in this file that exercises the full write-then-read-back
// pipeline without a real Windows machine.
func TestParseTaskXMLRoundTripsThroughWhatTaskSchedulerWouldPersist(t *testing.T) {
	t.Parallel()
	const exe = `C:\dpb\dpb.exe`
	runArgs := []string{"run", "--profile", "turkey"}
	doc := logonTaskXML("S-1-5-21-1-2-3-1001", exe, runArgs)

	persisted := utf16LEWithBOM(t, doc)
	def, err := parseTaskXML(persisted)
	if err != nil {
		t.Fatalf("parseTaskXML: %v", err)
	}
	if def.command != exe {
		t.Errorf("def.command = %q, want %q", def.command, exe)
	}
	wantArgs := logonTaskArguments(runArgs)
	if def.arguments != wantArgs {
		t.Errorf("def.arguments = %q, want %q", def.arguments, wantArgs)
	}
	if !def.hasLogonTrigger {
		t.Error("def.hasLogonTrigger = false for a document logonTaskXML always gives a LogonTrigger")
	}
}

// TestParseTaskXMLReportsAMissingLogonTrigger checks the one field
// parseTaskXML derives rather than copies verbatim: a definition with no
// LogonTrigger at all (never produced by logonTaskXML, but exactly what a
// hand-edited or corrupted persisted file could contain) must not be reported
// as having one.
func TestParseTaskXMLReportsAMissingLogonTrigger(t *testing.T) {
	t.Parallel()
	const noTrigger = `<Task><Triggers></Triggers><Actions><Exec><Command>C:\dpb\dpb.exe</Command></Exec></Actions></Task>`
	def, err := parseTaskXML(utf16LEWithBOM(t, noTrigger))
	if err != nil {
		t.Fatalf("parseTaskXML: %v", err)
	}
	if def.hasLogonTrigger {
		t.Error("def.hasLogonTrigger = true for a document with no <LogonTrigger> element")
	}
}

// utf16LEWithBOM encodes s the way every Task Scheduler file this project has
// observed is encoded on disk, for tests that need to simulate "what got
// persisted" without a real Windows machine to persist it.
func utf16LEWithBOM(t *testing.T, s string) []byte {
	t.Helper()
	b := []byte{0xFF, 0xFE}
	for _, r := range s {
		if r > 0xFFFF {
			t.Fatalf("utf16LEWithBOM: %q needs surrogate pairs, which this test helper does not encode", s)
		}
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

// ── logonTaskFound: the "not installed" vs. "cannot tell" combinator ───────

// TestLogonTaskFound is the "no" vs. "I cannot tell" distinction made
// directly testable — see logonTaskFound's own comment for why it was
// factored out of statusLogonTask. Table-driven over every combination of
// the two observers' answers this project's rule (service.go's serviceStatus
// comment on the two real defects it already cost) cares about.
func TestLogonTaskFound(t *testing.T) {
	t.Parallel()
	sentinel := errDecodeSentinel{}
	for _, tc := range []struct {
		name          string
		fileFound     bool
		fileErr       error
		schtasksKnows bool
		wantFound     bool
		wantErr       error
	}{
		{
			name:      "neither observer knows it and neither failed: genuinely not installed",
			wantFound: false,
			wantErr:   nil,
		},
		{
			name:      "the file says yes even though schtasks does not",
			fileFound: true,
			wantFound: true,
			wantErr:   nil,
		},
		{
			name:          "schtasks says yes even though the file is missing",
			schtasksKnows: true,
			wantFound:     true,
			wantErr:       nil,
		},
		{
			name:          "both observers say yes",
			fileFound:     true,
			schtasksKnows: true,
			wantFound:     true,
			wantErr:       nil,
		},
		{
			name:      "the file observer failed outright and schtasks also says no: cannot tell, not not-installed",
			fileErr:   sentinel,
			wantFound: false,
			wantErr:   sentinel,
		},
		{
			name:          "the file observer failed but schtasks says yes anyway: found wins over the failure",
			fileErr:       sentinel,
			schtasksKnows: true,
			wantFound:     true,
			wantErr:       nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			found, err := logonTaskFound(tc.fileFound, tc.fileErr, tc.schtasksKnows)
			if found != tc.wantFound {
				t.Errorf("logonTaskFound(%v, %v, %v) found = %v, want %v",
					tc.fileFound, tc.fileErr, tc.schtasksKnows, found, tc.wantFound)
			}
			if err != tc.wantErr {
				t.Errorf("logonTaskFound(%v, %v, %v) err = %v, want %v",
					tc.fileFound, tc.fileErr, tc.schtasksKnows, err, tc.wantErr)
			}
		})
	}
}

// errDecodeSentinel is a comparable error value so TestLogonTaskFound's table
// can assert exactly which error came back with ==, rather than settling for
// "an error came back".
type errDecodeSentinel struct{}

func (errDecodeSentinel) Error() string { return "sentinel: an observer could not be consulted" }
