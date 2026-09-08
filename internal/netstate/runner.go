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
//     The single documented exception is `launchctl setenv`/`getenv` — launchd's
//     store has no second observer; see the Op interface's doc comment.
//
// A third rule earned by a Turkish-language Mac: every external tool whose
// output we parse runs with LC_ALL=C. exec inherits os.Environ(), Terminal.app
// exports LANG from the region, and `ps -o lstart=` reorders its fields in
// tr_TR — which made a live dpb look dead. See lock.go.
package netstate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

type execRunner struct {
	logf func(string, ...any)
	// env is appended to the inherited environment. Go's exec keeps the LAST
	// occurrence of a duplicated key, so an entry here overrides what the user's
	// shell exported. It exists for LC_ALL=C: exec.Command inherits os.Environ(),
	// Terminal.app exports LANG from the region, and a tool whose output we parse
	// must not change shape with the user's language.
	env []string
}

// NewExecRunner returns a Runner backed by os/exec. logf may be nil.
func NewExecRunner(logf func(string, ...any)) Runner {
	return &execRunner{logf: logf}
}

// newExecRunnerEnv returns a Runner that runs commands with extra environment
// entries layered over the inherited one.
func newExecRunnerEnv(logf func(string, ...any), env []string) Runner {
	return &execRunner{logf: logf, env: append([]string(nil), env...)}
}

// cmdline duplicates the unexported helper of the same name in sysport.
// Result's move there exported only Failed, Reason and Error — the three
// methods sysport.Runner's callers need — so this file's own log line keeps a
// small private copy instead of growing sysport's surface for one call site.
//
// firstLine used to sit beside it for the same reason. Its one caller was
// ListServices's error message, which left with the tool it was reading, so the
// copy left too rather than staying behind as an unreachable helper.
func cmdline(argv []string) string { return strings.Join(argv, " ") }

func (x *execRunner) Run(ctx context.Context, name string, args ...string) Result {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	if len(x.env) > 0 {
		cmd.Env = append(os.Environ(), x.env...)
	}
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
			x.logf("netstate: ok (%s) in %s", cmdline(res.Argv), res.Duration.Round(time.Millisecond))
		}
	}
	return res
}
