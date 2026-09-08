package sysport

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Result is the outcome of one external command. Combined holds stdout and
// stderr interleaved, because macOS tools are inconsistent about which stream
// they report failure on and the liar table has to see both.
type Result struct {
	Argv     []string
	Combined string
	Code     int
	Err      error
	Duration time.Duration
}

// liars maps a command's base name to patterns that indicate failure regardless
// of exit status. The route entries are the load-bearing ones; the rest are
// defence in depth against tools that report errors on stdout with a zero exit.
var liars = map[string][]*regexp.Regexp{
	"route": {
		regexp.MustCompile(`writing to routing socket`),
		regexp.MustCompile(`not in table`),
		regexp.MustCompile(`File exists`),
		regexp.MustCompile(`Network is unreachable`),
		regexp.MustCompile(`No such process`),
	},
	"networksetup": {
		regexp.MustCompile(`(?im)^\s*\*\*\s*Error`),
		regexp.MustCompile(`is not a recognized network service`),
		regexp.MustCompile(`(?im)^Error:`),
	},
	"ifconfig": {
		regexp.MustCompile(`(?i)ioctl \(SIOC`),
		regexp.MustCompile(`(?i)does not exist`),
		regexp.MustCompile(`(?i)Invalid argument`),
	},
	"launchctl": {
		regexp.MustCompile(`(?im)^Bootstrap failed`),
		regexp.MustCompile(`(?im)^Load failed`),
		regexp.MustCompile(`(?i)Operation not permitted`),
	},
}

// Failed reports whether the command failed, by exit status, exec error, or a
// match in the known-liar table. Callers must use this and never compare Code
// against zero themselves.
func (r Result) Failed() bool {
	if r.Err != nil || r.Code != 0 {
		return true
	}
	return r.liar() != ""
}

// liar returns the matched failure text, or "" if the output looks clean.
func (r Result) liar() string {
	if len(r.Argv) == 0 {
		return ""
	}
	for _, re := range liars[filepath.Base(r.Argv[0])] {
		if m := re.FindString(r.Combined); m != "" {
			return m
		}
	}
	return ""
}

// Reason explains a failure in terms a user can act on. It is "" when the
// command succeeded.
func (r Result) Reason() string {
	switch {
	case r.Err != nil:
		return fmt.Sprintf("%s: could not run: %v", r.cmdline(), r.Err)
	case r.Code != 0:
		return fmt.Sprintf("%s: exit status %d: %s", r.cmdline(), r.Code, firstLine(r.Combined))
	default:
		if m := r.liar(); m != "" {
			// The whole point of the table: exit 0 is not success here.
			return fmt.Sprintf("%s: exited 0 but reported a failure (%q): %s",
				r.cmdline(), m, firstLine(r.Combined))
		}
	}
	return ""
}

// Error turns a failed Result into an error, or nil if it succeeded.
func (r Result) Error() error {
	if !r.Failed() {
		return nil
	}
	return errors.New(r.Reason())
}

func (r Result) cmdline() string { return strings.Join(r.Argv, " ") }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(no output)"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Runner executes external commands. It is an interface so every Op can be
// driven by a scripted fake in tests, which is the only way the failure paths
// that matter get exercised.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) Result
}
