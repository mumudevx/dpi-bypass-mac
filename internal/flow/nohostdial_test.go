package flow_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These two tests are build gates. They walk the whole module's source and fail
// the build on a construct that is always a defect here, regardless of whether
// any behavioural test happens to exercise it.
//
// They live in internal/flow because flow is the package whose promises they
// protect, and they run in the default `go test` invocation on purpose: a gate
// behind a build tag is a gate that is off.

// resolvePkg is the one package allowed to turn a name into an address.
//
// MEASUREMENTS.md §5.4: the compatibility matrix's first run scored every
// emitter 0/6 because Go's own resolver returned the BTK sinkhole address, so
// every emitter was measured against a blackhole rather than against the
// origin. "Every outbound dial in the implementation must resolve through the
// tool's own chain" is the conclusion, and this test is that conclusion made
// mechanical.
const resolvePkg = "internal/resolve"

// The bare-goroutine gate is INCLUSIVE BY DEFAULT: every non-test file in this
// module is in scope, and a package is covered on the day it is created.
//
// It used to be scoped by a hand-maintained list of three directories
// (internal/front, internal/flow, internal/resolve). internal/netwatch was
// added afterwards — it runs a routing-socket reader and a sleep watcher, and
// it ships in the binary — and the list was not updated, so a bare `go func(){}()`
// injected into netwatch left the gate green. A gate whose scope is a list
// falls behind the tree by construction; the only scope that cannot is "all of
// it, minus what somebody wrote down a reason for".
//
// Go runs only the panicking goroutine's deferred functions, so an unguarded
// goroutine in a connection or watcher path turns one malformed input into a
// process death that strands the system's proxy settings. flow.Safe is the
// sanctioned spawn.
//
// goStmtExemptFiles is that written-down list. The key is a file path relative
// to the module root and the value is why a bare `go` is correct THERE.
// TestGoStmtExemptionsAreLive fails on an entry that no longer matches a file
// holding a bare `go` (a stale licence) and on one whose reason is too thin to
// have been thought about, so every entry costs a review and expires on its own.
//
// Exempting a file turns the rule off for the whole file, including a goroutine
// added to it later. Prefer flow.Safe; reach for this only when the reason
// below is genuinely true of every spawn in the file.
var goStmtExemptFiles = map[string]string{
	safeGoFile: "flow.Safe IS the sanctioned spawn: this is the one recover barrier every " +
		"other goroutine in the tree is required to go through, so the bare `go` here is " +
		"the implementation of the rule rather than an exception to it.",

	"cmd/dpb/main.go": "watchSignals is the process's top-level signal handler, spawned " +
		"before any datapath exists and holding no connection. It parses nothing and reads " +
		"no untrusted input; its whole body is a select over a signal channel. A recover " +
		"barrier here would be actively wrong: the second-signal path exists to force an " +
		"immediate exit when teardown is wedged, and swallowing a panic in it would leave " +
		"the user with a process that answers no signal at all.",

	"internal/janitor/spawn_darwin.go": "the one goroutine is the child reaper inside Stop: " +
		"`defer close(done); c.cmd.Wait()`. It touches no network input and calls one " +
		"os/exec method, and janitor is deliberately a leaf package below internal/flow so " +
		"that the SIGKILL-residue janitor can be spawned from anywhere in the tree without " +
		"dragging the connection engine in.",

	"internal/observ/control.go": "the control socket's accept loop. The per-connection " +
		"handler already carries a written-out recover barrier at the spawn site — a panic " +
		"answering `dpb status` must not take down the proxy the user is browsing through — " +
		"and the second goroutine is a bare select that closes the listener on cancellation. " +
		"observ sits below internal/flow in the layering (flow, front and cliapp all import " +
		"observ), so flow.Safe is not reachable from here without inverting that.",

	"internal/testcensor/dns.go": "the censor simulator's fake DNS server. It is test " +
		"scaffolding: in the shipped binary it is reached only by `dpb selftest`, which " +
		"stands the fake up in-process on loopback. A panic in a fake must fail the " +
		"self-test loudly rather than be recovered into a passing run.",

	"internal/testcensor/origin.go": "the censor simulator's fake origin server, for the " +
		"same reason as dns.go: it is the thing a test drives, not a path a user's bytes " +
		"take, and a recovered panic in it would turn a broken fixture into a green test.",

	"internal/testnet/killfuzz.go": "the SIGKILL fuzz harness's `cmd.Wait()` reaper. " +
		"internal/testnet is imported only by _test.go files — it is in no build of the " +
		"binary — and the goroutine's entire body is one os/exec call.",
}

const safeGoFile = "internal/flow/safe.go"

// allowedDialFiles is the escape hatch for a file that genuinely must call a
// stdlib dial or lookup outside internal/resolve. It is empty, and adding to it
// needs a comment saying why the call cannot go through resolve.Chain.
//
// Prefer reviewedAddrExprs below: exempting a whole file turns off every rule
// in it, including the ones that would catch a hostname literal added later.
var allowedDialFiles = map[string]string{}

// reviewedAddrExprs records the non-literal address arguments that have been
// read and found to carry an address rather than a name.
//
// Rule A2 cannot type-check — the gate is an AST walk, and the module has no
// x/tools dependency to load types with — so it treats every non-literal
// address argument as suspect and requires the review to be written down here.
// The key is the argument's exact source spelling, so editing the call site
// re-opens the question instead of silently inheriting the exemption, and the
// value is why the expression cannot be a hostname.
var reviewedAddrExprs = map[string]map[string]string{
	"internal/flow/dialer.go": {
		"ap.String()": "ap is a netip.AddrPort produced by NetDialer.candidates, which " +
			"either unwraps Target.pinned() or calls the tool's own resolve chain and " +
			"converts the result to netip.AddrPort. netip.AddrPort.String() cannot " +
			"render a name, so Go's resolver is never consulted (MEASUREMENTS.md §5.4).",
	},
	"internal/flow/udpflow.go": {
		"dst.String()": "dst is the netip.AddrPort NetUDPDialer.DialUDP was handed. The " +
			"datagram path has no Target and no name at all: the destination comes off a " +
			"captured packet's IP header or out of a SOCKS5 UDP header, and a name in a " +
			"SOCKS5 header is resolved through the tool's own chain by the front end " +
			"before it reaches this dialer. netip.AddrPort.String() cannot render a name, " +
			"so Go's resolver is never consulted (MEASUREMENTS.md §5.4).",
	},
	"internal/observ/client.go": {
		"c.path": "the network argument is the literal \"unix\", so the address is a " +
			"filesystem path for an AF_UNIX socket and not a host at all: the kernel " +
			"never consults any resolver for it. c.path comes from " +
			"paths.Layout.ControlSocket(), which joins the process's own state directory " +
			"(MEASUREMENTS.md §5.4).",
	},
	"internal/cliapp/selftest.go": {
		"d.addr": "d.addr is censorLine.origin.Addr(), the Addr() of a net.Listener this " +
			"process bound itself on 127.0.0.1:0, so it is always an IP literal with a " +
			"port and can never be a name Go's resolver would be asked about " +
			"(MEASUREMENTS.md §5.4).",
	},
}

// dialSelectors are the selector names that denote "open a connection". The
// literal-argument check below applies to all of them wherever they appear,
// including in tests, because a hostname literal is a hostname literal.
var dialSelectors = map[string]bool{
	"Dial":           true,
	"DialContext":    true,
	"DialTimeout":    true,
	"DialTLS":        true,
	"DialTLSContext": true,
	"DialWithDialer": true,
}

// netPkgFuncs are package-level net.* calls that resolve a name using Go's
// resolver. In non-test code outside internal/resolve they are a defect no
// matter how the argument is spelled.
var netPkgFuncs = map[string]bool{
	"Dial":        true,
	"DialTimeout": true,
	"LookupHost":  true,
	"LookupIP":    true,
	"LookupAddr":  true,
	"LookupCNAME": true,
	"LookupMX":    true,
	"LookupNS":    true,
	"LookupSRV":   true,
	"LookupTXT":   true,
}

// tlsPkgFuncs are crypto/tls helpers that dial and handshake in one call. The
// sanctioned shape is tls.Client over a conn from the resolved dial path.
var tlsPkgFuncs = map[string]bool{
	"Dial":           true,
	"DialWithDialer": true,
}

// lookupSelectors are the resolver method names. They are checked as selectors
// (a method on some value) rather than as net.* package calls, because the hole
// this closes was `(&net.Resolver{}).LookupHost(ctx, name)`, which is a method
// call on a composite literal and matches no package-level rule at all.
var lookupSelectors = map[string]bool{
	"LookupHost":   true,
	"LookupIP":     true,
	"LookupIPAddr": true,
	"LookupNetIP":  true,
	"LookupAddr":   true,
	"LookupCNAME":  true,
	"LookupMX":     true,
	"LookupNS":     true,
	"LookupSRV":    true,
	"LookupTXT":    true,
	"LookupPort":   true,
}

// netPkgIdents are package-level identifiers whose mere use means Go's resolver
// is in the picture.
//
// "Resolver" is here because &net.Resolver{} is a composite literal, not a call:
// it matched nothing before, and a file holding one reaches Go's resolver with
// every rule in this gate green. Verified against this line: a file built from
// a clean tree with net.Resolver{}.LookupHost("discord.com") in it passes the
// whole suite and returns 195.175.254.2 — the BTK sinkhole, which is exactly the
// §5.4 failure that invalidated a measurement matrix. There is no sanctioned use
// of net.Resolver outside internal/resolve, so its mere mention is the defect.
var netPkgIdents = map[string]bool{
	"DefaultResolver": true,
	"Resolver":        true,
}

// httpPkgFuncs are net/http helpers that build a request on the default
// transport, which resolves through Go's resolver.
var httpPkgFuncs = map[string]bool{
	"Get": true, "Head": true, "Post": true, "PostForm": true,
}

// httpPkgIdents are the net/http types and values that own a dial. An
// http.Client outside internal/resolve cannot have a resolved dialer wired into
// it — internal/resolve is the only package that knows how to build one — so
// constructing one is the defect, and that also closes c.Get(url), which is a
// method call on a value this gate would otherwise never see.
var httpPkgIdents = map[string]bool{
	"Client": true, "Transport": true, "DefaultClient": true, "DefaultTransport": true,
}

// networkNames are the first argument to Dial and are never addresses.
var networkNames = map[string]bool{
	"tcp": true, "tcp4": true, "tcp6": true,
	"udp": true, "udp4": true, "udp6": true,
	"ip": true, "ip4": true, "ip6": true,
	"unix": true, "unixgram": true, "unixpacket": true,
}

func TestNoHostnameDial(t *testing.T) {
	root := moduleRoot(t)
	var findings []string
	forEachGoFile(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		findings = append(findings, checkHostnameDial(rel, fset, f)...)
	})
	report(t, findings, "hostname dial")
}

func checkHostnameDial(rel string, fset *token.FileSet, f *ast.File) []string {
	if rel == resolvePkg || strings.HasPrefix(rel, resolvePkg+"/") {
		return nil
	}
	if _, ok := allowedDialFiles[rel]; ok {
		return nil
	}
	isTest := strings.HasSuffix(rel, "_test.go")
	imports := importNames(f)

	var findings []string
	// called holds every selector that appears in call position. Rule C below
	// fires on the ones that do NOT, i.e. a dial captured as a function value.
	called := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			called[c.Fun] = true
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			pkg := pkgIdent(sel.X)

			// Rule A: a hostname spelled out as a literal, anywhere,
			// including in tests. A hostname literal is a hostname literal.
			if dialSelectors[name] || lookupSelectors[name] {
				for _, arg := range node.Args {
					if host, bad := literalHostname(arg); bad {
						findings = append(findings, at(fset, arg.Pos(), rel,
							"%s dials the hostname %q directly; resolve it through resolve.Chain and dial the address",
							name, host))
					}
				}
			}

			// Rule B: Go's own resolver in production code. The argument does
			// not matter: outside internal/resolve there is no sanctioned way
			// to reach it at all.
			if isTest {
				return true
			}
			switch {
			case imports[pkg] == "net" && netPkgFuncs[name]:
				findings = append(findings, at(fset, node.Pos(), rel,
					"net.%s uses Go's resolver; only %s may resolve names (MEASUREMENTS.md 5.4)", name, resolvePkg))
			case imports[pkg] == "crypto/tls" && tlsPkgFuncs[name]:
				findings = append(findings, at(fset, node.Pos(), rel,
					"tls.%s dials and resolves in one call; dial through resolve.Chain and wrap with tls.Client", name))
			case imports[pkg] == "net/http" && httpPkgFuncs[name]:
				findings = append(findings, at(fset, node.Pos(), rel,
					"http.%s dials through http.DefaultTransport, which uses Go's resolver; "+
						"build the request on a client whose dialer came from %s", name, resolvePkg))
			}

			// Rule D: a stream dial to port 53, anywhere in the module.
			//
			// MEASUREMENTS.md §2 measures plaintext DNS over TCP as
			// connection-reset at every port tested, so a TCP/53 dial fails for
			// exactly the names this tool exists to reach. internal/resolve has
			// its own structural gate, but it reads only its own directory: a
			// plaintext TCP/53 client added to any other package passed
			// everything. Listening on TCP/53 is a different act and stays
			// legal — the tunnel's in-process resolver does it — so this rule
			// keys on dial selectors, not on the port alone.
			if dialSelectors[name] {
				if streamNetworkArg(node) {
					if arg, ok := addressArg(node); ok {
						if lit, isLit := stringLit(arg); isLit && isDNSPort(lit) {
							findings = append(findings, at(fset, arg.Pos(), rel,
								"%s opens a TCP connection to %q; plaintext DNS over TCP is "+
									"reset at every port on the target network, so this fails for "+
									"exactly the blocked names (MEASUREMENTS.md 2)", name, lit))
						}
					}
				}
			}

			// Rule A2: an address argument that is not a literal at all.
			//
			// Rule A only ever looked at *ast.BasicLit, so
			// `(&net.Dialer{}).DialContext(ctx, "tcp", hostport)` — a variable
			// holding "discord.com:443" — passed every gate in this file while
			// reaching the BTK sinkhole on the live line (MEASUREMENTS.md §5.4).
			// The gate cannot tell an address variable from a name variable
			// without types, so outside internal/resolve every non-literal
			// address argument in production code must be reviewed and recorded
			// in reviewedAddrExprs.
			if dialSelectors[name] || lookupSelectors[name] {
				if arg, ok := addressArg(node); ok {
					if _, isLit := stringLit(arg); !isLit {
						expr := exprText(fset, arg)
						if _, reviewed := reviewedAddrExprs[rel][expr]; !reviewed {
							findings = append(findings, at(fset, arg.Pos(), rel,
								"%s takes the address from %s, which this gate cannot prove is an "+
									"address rather than a name; resolve through resolve.Chain and pass a "+
									"netip.AddrPort, or record the review in reviewedAddrExprs "+
									"(MEASUREMENTS.md 5.4)", name, expr))
						}
					}
				}
			}
		case *ast.SelectorExpr:
			if isTest {
				return true
			}
			// Rule C: `var sysDial = net.Dial` followed by `sysDial(...)`.
			// Every other rule here matches on call position, so capturing the
			// function as a value walked straight past all of them — verified
			// by injecting exactly that into internal/front/tunfe and watching
			// the gate stay green. The capture is the defect; where it is later
			// called is unknowable to an AST walk.
			if !called[node] {
				switch pkgOf := imports[pkgIdent(node.X)]; {
				case pkgOf == "net" && netPkgFuncs[node.Sel.Name],
					pkgOf == "crypto/tls" && tlsPkgFuncs[node.Sel.Name],
					pkgOf == "net/http" && httpPkgFuncs[node.Sel.Name]:
					findings = append(findings, at(fset, node.Pos(), rel,
						"%s.%s is captured as a value, which reaches Go's resolver wherever it is "+
							"later called; only %s may resolve names (MEASUREMENTS.md 5.4)",
						pkgIdent(node.X), node.Sel.Name, resolvePkg))
				}
			}
			switch pkgOf := imports[pkgIdent(node.X)]; {
			case pkgOf == "net" && netPkgIdents[node.Sel.Name]:
				findings = append(findings, at(fset, node.Pos(), rel,
					"net.%s is Go's resolver; only %s may resolve names (MEASUREMENTS.md 5.4)", node.Sel.Name, resolvePkg))
			case pkgOf == "net/http" && httpPkgIdents[node.Sel.Name]:
				findings = append(findings, at(fset, node.Pos(), rel,
					"http.%s owns a dial that resolves through Go's resolver; only %s may "+
						"build one (MEASUREMENTS.md 5.4)", node.Sel.Name, resolvePkg))
			}
		}
		return true
	})
	return findings
}

// addressArg picks the argument that carries the destination.
//
// The address is the argument after the network name ("tcp", "udp4", ...) when
// one is spelled out, which covers net.Dial, tls.Dial, tls.DialWithDialer and
// Dialer.DialContext alike without a per-function table. When the network is
// itself a variable — NetDialer computes it from the address family — the
// address is the last argument, which is true of every dial and lookup
// signature in the standard library.
func addressArg(call *ast.CallExpr) (ast.Expr, bool) {
	if len(call.Args) == 0 {
		return nil, false
	}
	for i, a := range call.Args {
		if s, ok := stringLit(a); ok && networkNames[s] && i+1 < len(call.Args) {
			return call.Args[i+1], true
		}
	}
	return call.Args[len(call.Args)-1], true
}

// exprText renders an argument exactly as it is written, so reviewedAddrExprs
// is keyed on source the reader can grep for.
func exprText(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return fmt.Sprintf("%T", e)
	}
	return buf.String()
}

func TestNoBareGoroutine(t *testing.T) {
	root := moduleRoot(t)
	var findings []string
	forEachGoFile(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		findings = append(findings, checkBareGoroutine(rel, fset, f)...)
	})
	report(t, findings, "bare goroutine")
}

func checkBareGoroutine(rel string, fset *token.FileSet, f *ast.File) []string {
	// Test harnesses legitimately run fakes on their own goroutines; the
	// promise this gate protects is about the shipped paths.
	if strings.HasSuffix(rel, "_test.go") {
		return nil
	}
	// Everything else is in scope. A file is out only if somebody wrote down
	// why, and TestGoStmtExemptionsAreLive keeps that reason honest.
	if _, exempt := goStmtExemptFiles[rel]; exempt {
		return nil
	}
	var findings []string
	ast.Inspect(f, func(n ast.Node) bool {
		if g, ok := n.(*ast.GoStmt); ok {
			findings = append(findings, at(fset, g.Pos(), rel,
				"bare `go` statement; spawn it with flow.Safe so a panic kills the connection and not the process"))
		}
		return true
	})
	return findings
}

func report(t *testing.T, findings []string, gate string) {
	t.Helper()
	if len(findings) == 0 {
		return
	}
	sort.Strings(findings)
	t.Errorf("%s gate: %d violation(s):\n  %s", gate, len(findings), strings.Join(findings, "\n  "))
}

// at formats one finding as "path:line:col: message" so an editor can jump to it.
func at(fset *token.FileSet, pos token.Pos, rel, format string, args ...any) string {
	p := fset.Position(pos)
	return fmt.Sprintf("%s:%d:%d: %s", rel, p.Line, p.Column, fmt.Sprintf(format, args...))
}

// literalHostname reports whether arg is a string literal naming a host that Go
// would have to resolve. It returns the offending host.
func literalHostname(arg ast.Expr) (string, bool) {
	s, ok := stringLit(arg)
	if !ok || s == "" {
		return "", false
	}
	if networkNames[s] {
		return "", false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	if host == "" {
		return "", false // a listen address like ":8080"
	}
	if strings.HasPrefix(host, "$") || strings.ContainsAny(host, "%{ ") {
		return "", false // a format template, judged where it is filled in
	}
	if net.ParseIP(host) != nil {
		return "", false
	}
	// localhost cannot be sinkholed by an ISP resolver; it is the address every
	// in-process test harness uses.
	if host == "localhost" {
		return "", false
	}
	// A bare token with no dot is not a public name (a unix socket path, a
	// scheme, a test fixture label).
	if !strings.Contains(host, ".") {
		return "", false
	}
	return host, true
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

func litString(e ast.Expr) string {
	s, _ := stringLit(e)
	return s
}

func pkgIdent(e ast.Expr) string {
	id, ok := e.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// importNames maps the local name of each import to its path.
func importNames(f *ast.File) map[string]string {
	m := make(map[string]string, len(f.Imports))
	for _, im := range f.Imports {
		path, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		name := path
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			name = path[i+1:]
		}
		if im.Name != nil {
			name = im.Name.Name
		}
		m[name] = path
	}
	return m
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}

// forEachGoFile parses every Go file belonging to THIS module. Directories with
// their own go.mod (docs/measurements/*, the first-hand measurement programs)
// are separate modules and are deliberately skipped.
func forEachGoFile(t *testing.T, root string, fn func(rel string, fset *token.FileSet, f *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	seen := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			switch {
			case rel == ".":
				return nil
			case strings.HasPrefix(d.Name(), "."), d.Name() == "testdata", d.Name() == "vendor":
				return fs.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return fs.SkipDir // a nested module
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("parse %s: %v", rel, err)
			return nil
		}
		seen++
		fn(rel, fset, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if seen == 0 {
		t.Fatalf("build gate walked %s and found no Go files; the gate is not actually checking anything", root)
	}
}

// TestGatesDetectViolations is the gates' own regression test. A build gate
// that has silently stopped matching is worse than no gate, because the tree
// then looks clean. Each case is parsed as if it were the named file.
func TestGatesDetectViolations(t *testing.T) {
	cases := []struct {
		name string
		rel  string
		src  string
		want int
		gate func(string, *token.FileSet, *ast.File) []string
	}{
		{
			name: "literal hostname passed to net.Dial",
			rel:  "internal/probe/trial.go",
			src:  "package p\nimport \"net\"\nfunc f() { net.Dial(\"tcp\", \"example.com:443\") }\n",
			want: 2, // rule A (the literal) and rule B (net.Dial at all)
			gate: checkHostnameDial,
		},
		{
			name: "literal hostname in a test file",
			rel:  "internal/probe/trial_test.go",
			src:  "package p\nimport \"crypto/tls\"\nfunc f() { tls.Dial(\"tcp\", \"discord.com:443\", nil) }\n",
			want: 1, // rule A only; rule B does not apply to tests
			gate: checkHostnameDial,
		},
		{
			name: "IP literal and network name are fine",
			rel:  "internal/front/proxyfe/server_test.go",
			src:  "package p\nfunc f(d dialer) { d.DialContext(nil, \"tcp\", \"127.0.0.1:8080\") }\n",
			want: 0,
			gate: checkHostnameDial,
		},
		{
			name: "a variable address in a test is fine",
			rel:  "internal/front/proxyfe/server_test.go",
			src:  "package p\nfunc f(d dialer, addr string) { d.DialContext(nil, \"tcp\", addr) }\n",
			want: 0,
			gate: checkHostnameDial,
		},
		{
			name: "stdlib lookup in production code",
			rel:  "internal/netwatch/portal.go",
			src:  "package p\nimport \"net\"\nfunc f(h string) { net.LookupHost(h) }\n",
			want: 2, // rule B (net.LookupHost at all) and rule A2 (h is not an address)
			gate: checkHostnameDial,
		},
		{
			name: "net.DefaultResolver in production code",
			rel:  "internal/netwatch/portal.go",
			src:  "package p\nimport \"net\"\nvar r = net.DefaultResolver\n",
			want: 1,
			gate: checkHostnameDial,
		},
		{
			// MF10's first hole. &net.Resolver{} is a composite literal, so no
			// rule keyed on a call or on net.DefaultResolver ever saw it.
			name: "net.Resolver composite literal in production code",
			rel:  "internal/netwatch/portal.go",
			src:  "package p\nimport (\"context\"\n\"net\")\nfunc f(ctx context.Context, h string) { (&net.Resolver{}).LookupHost(ctx, h) }\n",
			want: 2, // the net.Resolver mention, and the unproven address argument
			gate: checkHostnameDial,
		},
		{
			// MF10's second hole. The address is in a variable, so rule A's
			// *ast.BasicLit walk matched nothing.
			name: "a variable address in production code",
			rel:  "internal/front/proxyfe/connect.go",
			src:  "package p\nimport (\"context\"\n\"net\")\nfunc f(ctx context.Context, hostport string) { (&net.Dialer{}).DialContext(ctx, \"tcp\", hostport) }\n",
			want: 1,
			gate: checkHostnameDial,
		},
		{
			name: "an IP literal in production code is fine",
			rel:  "internal/front/proxyfe/connect.go",
			src:  "package p\nfunc f(d dialer) { d.DialContext(nil, \"tcp\", \"127.0.0.1:8080\") }\n",
			want: 0,
			gate: checkHostnameDial,
		},
		{
			// The address argument is picked as the one after the network name,
			// so a trailing *tls.Config is not mistaken for the destination.
			name: "tls.DialWithDialer picks the address, not the config",
			rel:  "internal/probe/trial.go",
			src:  "package p\nfunc f(d dialer, cfg *config, addr string) { d.DialWithDialer(nil, \"tcp\", addr, cfg) }\n",
			want: 1,
			gate: checkHostnameDial,
		},
		{
			name: "http.Get in production code",
			rel:  "internal/netwatch/portal.go",
			src:  "package p\nimport \"net/http\"\nfunc f(u string) { http.Get(u) }\n",
			want: 1,
			gate: checkHostnameDial,
		},
		{
			// An http.Client outside internal/resolve cannot have a resolved
			// dialer, and flagging the construction is what closes c.Get(url).
			name: "http.Client in production code",
			rel:  "internal/netwatch/portal.go",
			src:  "package p\nimport \"net/http\"\nfunc f(u string) { c := &http.Client{}; c.Get(u) }\n",
			want: 1,
			gate: checkHostnameDial,
		},
		{
			// The reviewed exemption is keyed on file AND on the argument's
			// exact spelling, so it cannot leak to another call site.
			name: "a reviewed address expression is exempt in its own file",
			rel:  "internal/flow/dialer.go",
			src:  "package p\nfunc f(nd dialer, ctx any, ap addrPort) { nd.DialContext(ctx, networkFor(ap.Addr()), ap.String()) }\n",
			want: 0,
			gate: checkHostnameDial,
		},
		{
			name: "the same expression in another file is not exempt",
			rel:  "internal/front/proxyfe/connect.go",
			src:  "package p\nfunc f(nd dialer, ctx any, ap addrPort) { nd.DialContext(ctx, networkFor(ap.Addr()), ap.String()) }\n",
			want: 1,
			gate: checkHostnameDial,
		},
		{
			name: "internal/resolve is exempt",
			rel:  "internal/resolve/udp.go",
			src:  "package p\nimport \"net\"\nfunc f() { net.Dial(\"tcp\", \"dns.quad9.net:853\") }\n",
			want: 0,
			gate: checkHostnameDial,
		},
		{
			name: "bare go in a connection path",
			rel:  "internal/front/proxyfe/connect.go",
			src:  "package p\nfunc f() { go func() {}() }\n",
			want: 1,
			gate: checkBareGoroutine,
		},
		{
			name: "safe.go holds the only sanctioned spawn",
			rel:  safeGoFile,
			src:  "package p\nfunc f() { go func() {}() }\n",
			want: 0,
			gate: checkBareGoroutine,
		},
		{
			// X2. internal/netwatch was created after the gate's directory
			// list was written, so this exact source passed the whole suite:
			// the verifier injected it, watched the build stay green, and the
			// package that runs the routing-socket reader was never covered.
			name: "bare go in a package the old directory list never named",
			rel:  "internal/netwatch/watcher.go",
			src:  "package p\nfunc f() { go func() {}() }\n",
			want: 1,
			gate: checkBareGoroutine,
		},
		{
			// Inclusion by default: a package that does not exist yet is
			// covered the moment its first file is written.
			name: "bare go in a package nobody has thought about yet",
			rel:  "internal/somethingnew/thing.go",
			src:  "package p\nfunc f() { go func() {}() }\n",
			want: 1,
			gate: checkBareGoroutine,
		},
		{
			name: "cmd is in scope too",
			rel:  "cmd/dpb/other.go",
			src:  "package main\nfunc f() { go func() {}() }\n",
			want: 1,
			gate: checkBareGoroutine,
		},
		{
			name: "a file with a written reason is out of scope",
			rel:  "internal/observ/control.go",
			src:  "package p\nfunc f() { go func() {}() }\n",
			want: 0, // exempt: see goStmtExemptFiles
			gate: checkBareGoroutine,
		},
		{
			name: "a test harness may spawn its own fakes",
			rel:  "internal/probe/runner_test.go",
			src:  "package p\nfunc f() { go func() {}() }\n",
			want: 0,
			gate: checkBareGoroutine,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, tc.rel, tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := tc.gate(tc.rel, fset, f)
			if len(got) != tc.want {
				t.Fatalf("got %d finding(s), want %d:\n  %s", len(got), tc.want, strings.Join(got, "\n  "))
			}
		})
	}
}

// TestGateWalkCoversTheTree pins the walk's scope: it must reach this module's
// own source and must not descend into the nested measurement modules, whose
// probes dial hostnames on purpose.
func TestGateWalkCoversTheTree(t *testing.T) {
	root := moduleRoot(t)
	var files []string
	forEachGoFile(t, root, func(rel string, _ *token.FileSet, _ *ast.File) {
		files = append(files, rel)
	})

	var sawOwn bool
	for _, rel := range files {
		if rel == safeGoFile {
			sawOwn = true
		}
		if strings.HasPrefix(rel, "docs/measurements/") {
			t.Errorf("walk descended into the nested module file %s", rel)
		}
	}
	if !sawOwn {
		t.Fatalf("walk did not reach %s; it is not checking this module", safeGoFile)
	}
}

// knownBadTree is the file MEASUREMENTS.md §5.4 is about, in the four shapes
// this gate was blind to. Run against the live Türk Telekom line from a clean
// copy of the tree, it resolves discord.com to 195.175.254.2 — the BTK sinkhole
// — and connects to it, while `go test ./internal/flow/` reports ok.
const knownBadTree = `package proxyfe

import (
	"context"
	"net"
	"net/http"
)

func lookup(ctx context.Context, host string) ([]string, error) {
	r := &net.Resolver{}
	return r.LookupHost(ctx, host)
}

func dial(ctx context.Context, hostport string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", hostport)
}

func fetch(u string) (*http.Response, error) { return http.Get(u) }

func fetch2(u string) (*http.Response, error) {
	c := &http.Client{}
	return c.Get(u)
}
`

// TestGateFailsOnAKnownBadTree is the gate's meta-test, and it exercises the
// WALK, not only the predicate: a gate that has quietly stopped visiting files
// reports a clean tree, which is the most dangerous state it can be in.
//
// Every construct below passed the gate as it was written. The whole point of
// the gate is that internal/resolve is the only package allowed to turn a name
// into an address, and seven milestones are still to be written by parallel
// authors against it.
func TestGateFailsOnAKnownBadTree(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "front", "proxyfe")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "leak.go"), []byte(knownBadTree), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var findings []string
	forEachGoFile(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		findings = append(findings, checkHostnameDial(rel, fset, f)...)
	})
	if len(findings) == 0 {
		t.Fatal("the gate walked a tree that reaches the BTK sinkhole and found nothing")
	}

	joined := strings.Join(findings, "\n")
	for _, want := range []string{
		"net.Resolver", // the composite literal
		"LookupHost",   // its unproven address argument
		"DialContext",  // a hostname in a variable
		"http.Get",     // the default transport
		"http.Client",  // and the client that owns one
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no finding mentions %q; the gate is blind to it again:\n%s", want, joined)
		}
	}
}

// goStmtFiles reports every non-test file in the tree that contains a bare `go`
// statement, and how many it contains.
func goStmtFiles(t *testing.T) map[string]int {
	t.Helper()
	root := moduleRoot(t)
	out := map[string]int{}
	forEachGoFile(t, root, func(rel string, _ *token.FileSet, f *ast.File) {
		if strings.HasSuffix(rel, "_test.go") {
			return
		}
		n := 0
		ast.Inspect(f, func(node ast.Node) bool {
			if _, ok := node.(*ast.GoStmt); ok {
				n++
			}
			return true
		})
		if n > 0 {
			out[rel] = n
		}
	})
	return out
}

// TestEveryGoroutineIsCoveredOrExplained is the meta-test the directory list
// could not have: it walks the REAL tree, finds every non-test file that spawns
// a goroutine, and requires each one to be either flagged by the gate or listed
// in goStmtExemptFiles with a reason. There is no third state — no package can
// be silently out of scope because nobody remembered to name it.
func TestEveryGoroutineIsCoveredOrExplained(t *testing.T) {
	root := moduleRoot(t)

	flagged := map[string]bool{}
	forEachGoFile(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		if len(checkBareGoroutine(rel, fset, f)) > 0 {
			flagged[rel] = true
		}
	})

	for rel := range goStmtFiles(t) {
		why, exempt := goStmtExemptFiles[rel]
		switch {
		case flagged[rel]:
			// The gate sees it; the build is red until somebody acts.
		case exempt && why != "":
			// Somebody wrote down why, and the entry is checked below.
		default:
			t.Errorf("%s spawns a goroutine but is neither flagged by the bare-goroutine "+
				"gate nor listed in goStmtExemptFiles with a reason; a package that is "+
				"silently out of scope is how internal/netwatch went uncovered", rel)
		}
	}
}

// TestGoStmtExemptionsAreLive keeps the exemption table from rotting. An entry
// that matches no file, or matches a file that no longer spawns anything, is a
// standing licence for a goroutine nobody reviewed — and a reason too short to
// have been thought about is the same thing with extra steps.
func TestGoStmtExemptionsAreLive(t *testing.T) {
	spawning := goStmtFiles(t)
	for rel, why := range goStmtExemptFiles {
		if spawning[rel] == 0 {
			t.Errorf("goStmtExemptFiles[%q] licenses a bare `go` in a file that no longer "+
				"has one (or no longer exists); delete the entry rather than leaving the "+
				"rule switched off for that file", rel)
		}
		if len(why) < 80 {
			t.Errorf("goStmtExemptFiles[%q] must say why a bare `go` is correct there and "+
				"why flow.Safe is not; got %q", rel, why)
		}
	}
}

// TestBareGoroutineGateFailsOnANewPackage exercises the WALK, not only the
// predicate, against the exact defect X2 reports: a goroutine in a package the
// old directory list never named.
//
// The verifier proved the hole by injecting `go func(){}()` into
// internal/netwatch and watching `go test ./...` stay green. This is that
// injection, made mechanical, plus a package that does not exist at all — the
// case a list can never cover in advance.
func TestBareGoroutineGateFailsOnANewPackage(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		// The package the list forgot.
		"internal/netwatch/watcher.go": "package netwatch\nfunc watch() { go func() {}() }\n",
		// A package invented after this gate was written.
		"internal/brandnew/pump.go": "package brandnew\nfunc pump() { go func() {}() }\n",
		// The binary's own main package.
		"cmd/dpb/extra.go": "package main\nfunc spawn() { go func() {}() }\n",
	}
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	var findings []string
	forEachGoFile(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		findings = append(findings, checkBareGoroutine(rel, fset, f)...)
	})

	joined := strings.Join(findings, "\n")
	for rel := range files {
		if !strings.Contains(joined, rel) {
			t.Errorf("the gate walked a tree with an unguarded goroutine in %s and did not "+
				"flag it; a package is only covered if somebody remembered to list it:\n%s",
				rel, joined)
		}
	}
}

// TestReviewedAddrExprsAreLive keeps the exemption table honest. An entry that
// no longer matches any call site is a stale licence sitting in the tree, and
// every entry must say why the expression cannot be a hostname.
func TestReviewedAddrExprsAreLive(t *testing.T) {
	root := moduleRoot(t)
	used := make(map[string]map[string]bool, len(reviewedAddrExprs))

	forEachGoFile(t, root, func(rel string, fset *token.FileSet, f *ast.File) {
		if _, ok := reviewedAddrExprs[rel]; !ok {
			return
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (!dialSelectors[sel.Sel.Name] && !lookupSelectors[sel.Sel.Name]) {
				return true
			}
			if arg, ok := addressArg(call); ok {
				if used[rel] == nil {
					used[rel] = map[string]bool{}
				}
				used[rel][exprText(fset, arg)] = true
			}
			return true
		})
	})

	for rel, exprs := range reviewedAddrExprs {
		for expr, why := range exprs {
			if !used[rel][expr] {
				t.Errorf("reviewedAddrExprs[%q][%q] matches no call site; delete it rather than "+
					"leaving a licence for a call that no longer exists", rel, expr)
			}
			if len(why) < 40 || !strings.Contains(why, "5.4") {
				t.Errorf("reviewedAddrExprs[%q][%q] must say why the expression cannot be a "+
					"hostname and cite MEASUREMENTS.md §5.4; got %q", rel, expr, why)
			}
		}
	}
}

// streamNetworkArg reports whether the call names a stream network.
func streamNetworkArg(call *ast.CallExpr) bool {
	for _, a := range call.Args {
		if v, ok := stringLit(a); ok {
			switch v {
			case "tcp", "tcp4", "tcp6":
				return true
			}
		}
	}
	return false
}

// isDNSPort reports whether an address literal names port 53.
func isDNSPort(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port == "53"
}
