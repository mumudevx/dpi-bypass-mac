// Package netstate owns every mutation dpb makes to macOS system state.
//
// Two rules govern the whole package, and both exist because the tools macOS
// gives us are not trustworthy:
//
//  1. An exit status is evidence, not proof. macOS route(8) has no failure exit
//     path at all — Apple's route.c declares newroute() as void and main() does
//     `newroute(argc, argv); exit(0)`, while rtmsg() only warnx()es. Verified on
//     this machine 2026-09-02: `route -n get -inet6 2001:db8::1` prints
//     "route: writing to routing socket: not in table" and exits 0. So Result
//     also matches the combined output against a per-command table of known
//     liars.
//
//  2. Verification never uses the subsystem that applied the change. Routes are
//     written with route(8) and verified by reading the kernel RIB through an
//     AF_ROUTE socket; proxy settings are written with networksetup and verified
//     with `scutil --proxy`; DNS likewise with `scutil --dns`; interfaces with
//     net.Interfaces(). Parsing a tool's own stderr still trusts the tool.
package netstate

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
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

type execRunner struct {
	logf func(string, ...any)
}

// NewExecRunner returns a Runner backed by os/exec. logf may be nil.
func NewExecRunner(logf func(string, ...any)) Runner {
	return &execRunner{logf: logf}
}

func (x *execRunner) Run(ctx context.Context, name string, args ...string) Result {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()

	res := Result{
		Argv:     append([]string{name}, args...),
		Combined: strings.TrimRight(string(out), "\n"),
		Duration: time.Since(start),
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		res.Code = ee.ExitCode()
	case err != nil:
		res.Err = err
	}
	// A killed-by-context command can exit non-zero with no useful output; say
	// so, otherwise the caller reports a mysterious "exit status -1".
	if ctxErr := ctx.Err(); ctxErr != nil && res.Err == nil && res.Code != 0 {
		res.Err = ctxErr
	}
	if x.logf != nil {
		if reason := res.Reason(); reason != "" {
			x.logf("netstate: %s", reason)
		} else {
			x.logf("netstate: ok (%s) in %s", res.cmdline(), res.Duration.Round(time.Millisecond))
		}
	}
	return res
}
