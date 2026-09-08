//go:build darwin

package scdarwin

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mumudevx/dpb/internal/sysport"
)

// The scutil parsers in this file and dns.go are the independent verifiers.
// Everything the proxy and DNS ops write goes in through networksetup(8) and
// comes back out through scutil(8), which reads the dynamic store the system
// actually consults rather than the preferences plist networksetup wrote.

type proxyCtl struct{ p *port }

var _ sysport.ProxyController = proxyCtl{}

// Services lists the enabled network services, which is what every
// networksetup verb takes as its second argument.
func (c proxyCtl) Services(ctx context.Context) ([]string, error) {
	svcs, err := ListServices(ctx, c.p.env())
	if err != nil {
		return nil, err
	}
	return serviceNames(svcs), nil
}

// Configured reads svc's stored proxy configuration through networksetup — the
// same subsystem the setters write to. It is for CAPTURE, never for
// verification; Live is the verifier.
//
// One networksetup getter runs per requested kind, and no more. Reading a kind
// the caller does not need is not merely slow: each getter is a separate
// invocation with its own failure, so a `-getsocksfirewallproxy` that errors on
// a service would abort a PAC capture that has nothing to do with SOCKS. The
// returned value records which kinds it describes, so Restore puts back exactly
// what was read and leaves the rest of the service alone.
func (c proxyCtl) Configured(ctx context.Context, svc string, kinds ...sysport.ProxyKind) (sysport.ProxySettings, error) {
	if len(kinds) == 0 {
		kinds = allProxyKinds
	}
	p := sysport.ProxySettings{Kinds: append([]sysport.ProxyKind(nil), kinds...)}
	r := c.p.run

	if wants(p, sysport.ProxyAuto) {
		kv, err := networksetupKV(ctx, r, "-getautoproxyurl", svc)
		if err != nil {
			return p, err
		}
		p.AutoURL = nullToEmpty(kv["URL"])
		p.AutoOn = yes(kv["Enabled"])
	}

	// Web and secure are one kind: macOS treats them as separate settings but
	// they are never useful apart, and Restore puts both back together.
	if wants(p, sysport.ProxyWeb) {
		kv, err := networksetupKV(ctx, r, "-getwebproxy", svc)
		if err != nil {
			return p, err
		}
		p.WebPort = atoi(kv["Port"])
		p.WebHost = nullToEmpty(kv["Server"])
		p.WebOn = yes(kv["Enabled"])

		kv, err = networksetupKV(ctx, r, "-getsecurewebproxy", svc)
		if err != nil {
			return p, err
		}
		p.SecurePort = atoi(kv["Port"])
		p.SecureHost = nullToEmpty(kv["Server"])
		p.SecureOn = yes(kv["Enabled"])
	}

	if wants(p, sysport.ProxySOCKS) {
		kv, err := networksetupKV(ctx, r, "-getsocksfirewallproxy", svc)
		if err != nil {
			return p, err
		}
		p.SOCKSPort = atoi(kv["Port"])
		p.SOCKSHost = nullToEmpty(kv["Server"])
		p.SOCKSOn = yes(kv["Enabled"])
	}

	return p, nil
}

func (c proxyCtl) SetAuto(ctx context.Context, svc, url string) error {
	cmds := [][]string{
		{"-setautoproxyurl", svc, url},
		{"-setautoproxystate", svc, "on"},
	}
	return c.runAll(ctx, cmds)
}

func (c proxyCtl) SetManual(ctx context.Context, svc string, kind sysport.ProxyKind, host string, port int) error {
	var cmds [][]string
	switch kind {
	case sysport.ProxyWeb:
		p := strconv.Itoa(port)
		cmds = [][]string{
			{"-setwebproxy", svc, host, p},
			{"-setsecurewebproxy", svc, host, p},
			{"-setwebproxystate", svc, "on"},
			{"-setsecurewebproxystate", svc, "on"},
		}
	case sysport.ProxySOCKS:
		cmds = [][]string{
			{"-setsocksfirewallproxy", svc, host, strconv.Itoa(port)},
			{"-setsocksfirewallproxystate", svc, "on"},
		}
	default:
		// Refused by name with a reason, never skipped quietly: a PAC URL is not
		// a host:port and SetAuto is the verb that installs one.
		return fmt.Errorf("netstate: SetManual cannot install an auto-proxy (PAC) setting on %s; use SetAuto", svc)
	}
	return c.runAll(ctx, cmds)
}

func (c proxyCtl) runAll(ctx context.Context, cmds [][]string) error {
	for _, args := range cmds {
		if err := c.p.run.Run(ctx, "networksetup", args...).Error(); err != nil {
			return err
		}
	}
	return nil
}

// Restore puts a service's captured configuration back. It is idempotent: the
// commands it issues set an absolute state rather than toggling one.
func (c proxyCtl) Restore(ctx context.Context, svc string, prev sysport.ProxySettings) error {
	var firstErr error
	for _, cmd := range restoreCmds(svc, prev) {
		err := c.p.run.Run(ctx, "networksetup", cmd.args...).Error()
		if err == nil {
			continue
		}
		// soft: clearing a stored proxy field is tidying, and what the user
		// actually needs is the setting switched off. A networksetup that
		// refuses an empty server must not fail the whole restore — but it is
		// still said out loud, because a silently absent tidy-up is how a
		// stale Server behind a disabled toggle survives a clean exit.
		if cmd.soft {
			c.p.env().logf("netstate: %v (tidying only; the state command decides)", err)
			continue
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// restoreCmd is one networksetup invocation. soft marks a command whose failure
// must not fail the revert: clearing a stored proxy field is tidying, and what
// the user actually needs is the setting switched off. A networksetup that
// refuses an empty server must not leave the journal entry pending forever.
type restoreCmd struct {
	args []string
	soft bool
}

// allProxyKinds is what a whole-service capture describes.
var allProxyKinds = []sysport.ProxyKind{sysport.ProxyAuto, sysport.ProxyWeb, sysport.ProxySOCKS}

// wants reports whether p describes kind. A nil Kinds means the capture was
// whole-service, which is what Configured returns.
func wants(p sysport.ProxySettings, kind sysport.ProxyKind) bool {
	if p.Kinds == nil {
		return true
	}
	for _, k := range p.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// restoreCmds builds the absolute state to restore. It is idempotent by
// construction: every command sets a value rather than toggling one.
//
// The empty-previous case does NOT just switch the setting off. macOS keeps a
// disabled proxy's Server and Port — confirmed live on this machine:
// `networksetup -getwebproxy Wi-Fi` reports "Enabled: No, Server: 127.0.0.1,
// Port: 8080" from an earlier run — so switching off alone abandons the fields
// pointing at our dead port, and the next time the user ticks the box in System
// Settings they get a total HTTP/HTTPS outage. Clearing the fields first
// restores what was there before us.
//
// Only the kinds p claims to describe are emitted. A zero field in a group the
// capture never read is not "there was nothing here" — see ProxySettings.Kinds.
func restoreCmds(svc string, p sysport.ProxySettings) []restoreCmd {
	var cmds []restoreCmd

	if wants(p, sysport.ProxyAuto) {
		if p.AutoURL == "" {
			// Either there was nothing here, or what was here was ours. Both mean
			// "off": pinning the user to a dead PAC URL is worse than no PAC.
			cmds = append(cmds,
				restoreCmd{args: []string{"-setautoproxyurl", svc, ""}, soft: true},
				restoreCmd{args: []string{"-setautoproxystate", svc, "off"}})
		} else {
			cmds = append(cmds,
				restoreCmd{args: []string{"-setautoproxyurl", svc, p.AutoURL}},
				restoreCmd{args: []string{"-setautoproxystate", svc, onOff(p.AutoOn)}})
		}
	}

	// Web and secure are one kind: macOS treats them as separate settings but
	// they are never useful apart, so a capture that named ProxyWeb captured
	// both and a restore puts both back.
	if wants(p, sysport.ProxyWeb) {
		if p.WebHost == "" {
			cmds = append(cmds,
				restoreCmd{args: []string{"-setwebproxy", svc, "", "0"}, soft: true},
				restoreCmd{args: []string{"-setwebproxystate", svc, "off"}})
		} else {
			cmds = append(cmds,
				restoreCmd{args: []string{"-setwebproxy", svc, p.WebHost, strconv.Itoa(p.WebPort)}},
				restoreCmd{args: []string{"-setwebproxystate", svc, onOff(p.WebOn)}})
		}

		if p.SecureHost == "" {
			cmds = append(cmds,
				restoreCmd{args: []string{"-setsecurewebproxy", svc, "", "0"}, soft: true},
				restoreCmd{args: []string{"-setsecurewebproxystate", svc, "off"}})
		} else {
			cmds = append(cmds,
				restoreCmd{args: []string{"-setsecurewebproxy", svc, p.SecureHost, strconv.Itoa(p.SecurePort)}},
				restoreCmd{args: []string{"-setsecurewebproxystate", svc, onOff(p.SecureOn)}})
		}
	}

	if wants(p, sysport.ProxySOCKS) {
		if p.SOCKSHost == "" {
			cmds = append(cmds,
				restoreCmd{args: []string{"-setsocksfirewallproxy", svc, "", "0"}, soft: true},
				restoreCmd{args: []string{"-setsocksfirewallproxystate", svc, "off"}})
		} else {
			cmds = append(cmds,
				restoreCmd{args: []string{"-setsocksfirewallproxy", svc, p.SOCKSHost, strconv.Itoa(p.SOCKSPort)}},
				restoreCmd{args: []string{"-setsocksfirewallproxystate", svc, onOff(p.SOCKSOn)}})
		}
	}

	return cmds
}

// Live reads the RESOLVED proxy configuration out of the dynamic store with
// `scutil --proxy`. networksetup wrote the preference; this reads what the
// system will actually do, which is why it is the verifier.
func (c proxyCtl) Live(ctx context.Context) (sysport.ProxyState, error) {
	return readProxyState(ctx, c.p.env())
}

var scutilKV = regexp.MustCompile(`^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$`)
var scutilArrayEntry = regexp.MustCompile(`^\s*\d+\s*:\s*(.*)$`)

// parseProxyState parses `scutil --proxy`. Nested arrays other than
// ExceptionsList are ignored rather than flattened, because flattening them
// would silently merge keys from different scopes.
func parseProxyState(out string) sysport.ProxyState {
	st := sysport.ProxyState{Keys: map[string]string{}}
	inArray := ""
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "}" {
			inArray = ""
			continue
		}
		if inArray != "" {
			if m := scutilArrayEntry.FindStringSubmatch(line); m != nil {
				if inArray == "ExceptionsList" {
					st.Exceptions = append(st.Exceptions, strings.TrimSpace(m[1]))
				}
			}
			continue
		}
		m := scutilKV.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		if strings.HasPrefix(val, "<array>") || strings.HasPrefix(val, "<dictionary>") {
			inArray = key
			continue
		}
		st.Keys[key] = val
	}
	return st
}

// readProxyState runs `scutil --proxy` and parses it.
func readProxyState(ctx context.Context, e Env) (sysport.ProxyState, error) {
	res := e.runner().Run(ctx, "scutil", "--proxy")
	if err := res.Error(); err != nil {
		return sysport.ProxyState{}, fmt.Errorf("netstate: read proxy state: %w", err)
	}
	return parseProxyState(res.Combined), nil
}

// The exported read-only observers.
//
// The scutil and launchctl readers in this package are the independent
// verifiers Op.Verify uses, and they were unexported because nothing outside
// netstate needed them. `dpb doctor` and `dpb coverage` do: both answer
// questions about the state macOS is ACTUALLY in — is an auto-proxy URL still
// pointing at a port nobody is listening on, did the environment variables
// Discord's updater reads survive — and answering them with a second parser
// written in the CLI would mean the tool verifies its own mutations with one
// reader and diagnoses them with another.
//
// These are wrappers, not new logic, and every one of them is read-only.
// ReadDNSResolvers and PrimaryNameservers are in dns.go, ReadLaunchEnv in
// env.go, beside the parsers they wrap.

// ReadProxyState runs `scutil --proxy` and parses it. It reads the dynamic
// store the system actually consults, not the preferences plist networksetup
// wrote, which is why it is the verifier for every proxy Op.
func ReadProxyState(ctx context.Context, e Env) (sysport.ProxyState, error) {
	return readProxyState(ctx, e)
}

// ParseProxyState parses `scutil --proxy` output that a caller already has.
//
// It is exported for one reason: netstate decides whether a ProxyState
// satisfies a request (checkProxyPair), that decision stayed behind when the
// parser moved here, and the assertions that pin it need a real capture to run
// against rather than a hand-built map. Parsing is the only thing it does.
func ParseProxyState(out string) sysport.ProxyState { return parseProxyState(out) }

// networksetupKV runs a networksetup getter and parses its "Key: value" output.
func networksetupKV(ctx context.Context, r sysport.Runner, args ...string) (map[string]string, error) {
	res := r.Run(ctx, "networksetup", args...)
	if err := res.Error(); err != nil {
		return nil, err
	}
	return parseColonKV(res.Combined), nil
}

func parseColonKV(out string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return kv
}

func nullToEmpty(s string) string {
	if s == "(null)" {
		return ""
	}
	return s
}

func yes(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "yes") }

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
