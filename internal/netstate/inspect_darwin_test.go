package netstate

import (
	"context"
	"strings"
	"testing"
)

// scriptedRunner answers a fixed script keyed on the joined argv, so these
// tests assert the wrappers read through the subsystem they claim to and parse
// what it actually prints.
type scriptedRunner struct {
	out  map[string]string
	code map[string]int
}

func (r scriptedRunner) Run(_ context.Context, name string, args ...string) Result {
	key := strings.Join(append([]string{name}, args...), " ")
	res := Result{Argv: append([]string{name}, args...)}
	out, ok := r.out[key]
	if !ok {
		res.Combined, res.Code = key+": not in the script", 127
		return res
	}
	res.Combined, res.Code = out, r.code[key]
	return res
}

// A capture from this machine: the shape `scutil --proxy` prints with an
// auto-proxy URL in force.
const proxyStateCapture = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://127.0.0.1:8080/dpb.pac
  SOCKSEnable : 0
}`

func TestReadProxyStateParsesTheDynamicStore(t *testing.T) {
	e := Env{Runner: scriptedRunner{out: map[string]string{"scutil --proxy": proxyStateCapture}}}
	st, err := ReadProxyState(context.Background(), e)
	if err != nil {
		t.Fatalf("ReadProxyState: %v", err)
	}
	if !st.On("ProxyAutoConfigEnable") {
		t.Error("ProxyAutoConfigEnable did not read as on")
	}
	if got := st.Str("ProxyAutoConfigURLString"); got != "http://127.0.0.1:8080/dpb.pac" {
		t.Errorf("auto-proxy URL = %q", got)
	}
	if len(st.Exceptions) != 2 || st.Exceptions[0] != "*.local" {
		t.Errorf("exceptions = %v", st.Exceptions)
	}
}

func TestReadProxyStateReportsAFailure(t *testing.T) {
	e := Env{Runner: scriptedRunner{
		out:  map[string]string{"scutil --proxy": "scutil: cannot open"},
		code: map[string]int{"scutil --proxy": 1},
	}}
	if _, err := ReadProxyState(context.Background(), e); err == nil {
		t.Fatal("a failing scutil produced no error")
	}
}

const dnsCapture = `DNS configuration

resolver #1
  nameserver[0] : 192.168.0.1
  if_index : 14 (en0)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 10.0.0.1
  if_index : 14 (en0)
`

func TestReadDNSResolversAndPrimary(t *testing.T) {
	e := Env{Runner: scriptedRunner{out: map[string]string{"scutil --dns": dnsCapture}}}
	rs, err := ReadDNSResolvers(context.Background(), e)
	if err != nil {
		t.Fatalf("ReadDNSResolvers: %v", err)
	}
	if len(rs) < 2 {
		t.Fatalf("got %d resolver blocks, want the unscoped and the scoped one", len(rs))
	}
	ns := PrimaryNameservers(rs)
	if len(ns) != 1 || ns[0] != "192.168.0.1" {
		t.Fatalf("primary nameservers = %v, want only the unscoped 192.168.0.1", ns)
	}
}

func TestReadLaunchEnv(t *testing.T) {
	e := Env{Runner: scriptedRunner{out: map[string]string{
		"launchctl getenv HTTPS_PROXY": "http://127.0.0.1:8080\n",
	}}}
	got, err := ReadLaunchEnv(context.Background(), e, "HTTPS_PROXY")
	if err != nil {
		t.Fatalf("ReadLaunchEnv: %v", err)
	}
	if got != "http://127.0.0.1:8080" {
		t.Errorf("HTTPS_PROXY = %q", got)
	}
}

// An unset variable is answered "no", never "could not tell": some launchd
// builds exit non-zero with no output for a variable that is simply not set,
// and a doctor line that says "unknown" where it could say "not set" is a line
// nobody can act on.
func TestReadLaunchEnvTreatsSilentFailureAsUnset(t *testing.T) {
	e := Env{Runner: scriptedRunner{
		out:  map[string]string{"launchctl getenv NO_PROXY": ""},
		code: map[string]int{"launchctl getenv NO_PROXY": 1},
	}}
	got, err := ReadLaunchEnv(context.Background(), e, "NO_PROXY")
	if err != nil {
		t.Fatalf("ReadLaunchEnv on an unset variable: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want the empty string", got)
	}
}

func TestReadLaunchEnvReportsARealFailure(t *testing.T) {
	e := Env{Runner: scriptedRunner{
		out:  map[string]string{"launchctl getenv X": "Could not connect to the bootstrap server"},
		code: map[string]int{"launchctl getenv X": 5},
	}}
	if _, err := ReadLaunchEnv(context.Background(), e, "X"); err == nil {
		t.Fatal("a launchctl that said why it failed produced no error")
	}
}

func TestReadLaunchEnvNeedsAName(t *testing.T) {
	if _, err := ReadLaunchEnv(context.Background(), Env{}, ""); err == nil {
		t.Fatal("an empty variable name produced no error")
	}
}

// The wrappers must fail loudly on a zero Env rather than nil-panicking, which
// is netstate's noRunner contract.
func TestInspectorsOnAZeroEnv(t *testing.T) {
	ctx := context.Background()
	if _, err := ReadProxyState(ctx, Env{}); err == nil {
		t.Error("ReadProxyState on a zero Env produced no error")
	}
	if _, err := ReadDNSResolvers(ctx, Env{}); err == nil {
		t.Error("ReadDNSResolvers on a zero Env produced no error")
	}
	// "Could not run launchctl" must not be reported as "the variable is not
	// set": that would answer a question we never asked the system.
	if _, err := ReadLaunchEnv(ctx, Env{}, "HTTPS_PROXY"); err == nil {
		t.Error("ReadLaunchEnv on a zero Env produced no error")
	}
}
