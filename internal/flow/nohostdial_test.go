package flow_test

import (
	"fmt"
	"go/ast"
	"go/parser"
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

// noGoStmtDirs are the packages where a bare `go` statement is forbidden.
// Go runs only the panicking goroutine's deferred functions, so an unguarded
// goroutine in a connection path turns one malformed input into a process
// death that strands the system's proxy settings. flow.Safe is the sanctioned
// spawn; safe.go therefore holds the only bare `go` in the tree.
var noGoStmtDirs = []string{
	"internal/front",
	"internal/flow",
	"internal/resolve",
}

const safeGoFile = "internal/flow/safe.go"

// allowedDialFiles is the escape hatch for a file that genuinely must call a
// stdlib dial or lookup outside internal/resolve. It is empty, and adding to it
// needs a comment saying why the call cannot go through resolve.Chain.
var allowedDialFiles = map[string]string{}

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

// netPkgIdents are package-level identifiers whose mere use means Go's resolver
// is in the picture.
var netPkgIdents = map[string]bool{
	"DefaultResolver": true,
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
	ast.Inspect(f, func(n ast.Node) bool {
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
			if dialSelectors[name] {
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
			}
		case *ast.SelectorExpr:
			if isTest {
				return true
			}
			if imports[pkgIdent(node.X)] == "net" && netPkgIdents[node.Sel.Name] {
				findings = append(findings, at(fset, node.Pos(), rel,
					"net.%s is Go's resolver; only %s may resolve names (MEASUREMENTS.md 5.4)", node.Sel.Name, resolvePkg))
			}
		}
		return true
	})
	return findings
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
	if !inAnyDir(rel, noGoStmtDirs) {
		return nil
	}
	// Test harnesses legitimately run fakes on their own goroutines; the
	// promise this gate protects is about the shipped connection paths.
	if strings.HasSuffix(rel, "_test.go") || rel == safeGoFile {
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

func inAnyDir(rel string, dirs []string) bool {
	for _, d := range dirs {
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
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
			want: 1,
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
			name: "bare go outside the guarded packages",
			rel:  "internal/probe/runner.go",
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
