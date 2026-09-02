package strategy

import (
	"errors"
	"strings"
	"testing"
)

func trivialOp(d OpDoc) Op {
	return newStub(d, func(Args) (Step, error) {
		return StepFunc(d.Name, d.Caps, func(*Builder) error { return nil }), nil
	})
}

func mustPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("want a panic mentioning %q", want)
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, want) {
			t.Fatalf("panic = %v, want it to mention %q", r, want)
		}
	}()
	fn()
}

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	if got := r.Names(); len(got) != 0 {
		t.Fatalf("a fresh registry has %v", got)
	}
	// An empty spec parses against an empty registry: plain is always available.
	if s, err := r.Get(""); err != nil || !s.IsPlain() {
		t.Fatalf("Get(\"\") = %+v, %v", s, err)
	}
	// And an unknown op says so honestly rather than pretending.
	_, err := r.Get("tlsfrag:pos=snimid")
	if !errors.Is(err, ErrUnknownOp) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "(none registered)") {
		t.Errorf("an empty registry must say it has nothing: %v", err)
	}

	registerStubs(r)
	names := r.Names()
	if len(names) != 11 {
		t.Fatalf("Names = %v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Names must be sorted: %v", names)
		}
	}
	if _, err := r.Get("tlsfrag:pos=snimid"); err != nil {
		t.Fatalf("Get after Register: %v", err)
	}
}

func TestRegistryDocsAreInExecutionOrder(t *testing.T) {
	docs := Docs()
	if len(docs) == 0 {
		t.Fatal("no docs")
	}
	for i := 1; i < len(docs); i++ {
		a, b := docs[i-1], docs[i]
		if a.Kind > b.Kind || (a.Kind == b.Kind && a.Name >= b.Name) {
			t.Fatalf("Docs must be ordered by (Kind, Name): %s/%s then %s/%s", a.Kind, a.Name, b.Kind, b.Name)
		}
	}
	var frag OpDoc
	for _, d := range docs {
		if d.Name == "tlsfrag" {
			frag = d
		}
	}
	if frag.Source == "" || frag.Determinism != DetRuleBased {
		t.Fatalf("tlsfrag doc = %+v: the primary emitter must carry its citation", frag)
	}
	if _, ok := frag.Param("pos"); !ok {
		t.Error("tlsfrag must document its pos parameter")
	}
	if _, ok := frag.Param("nope"); ok {
		t.Error("Param must not invent parameters")
	}
	if got := frag.ParamNames(); len(got) != 1 || got[0] != "pos" {
		t.Errorf("ParamNames = %v", got)
	}
}

func TestRegisterPanicsOnABadOp(t *testing.T) {
	mustPanic(t, "Register(nil)", func() { NewRegistry().Register(nil) })

	mustPanic(t, "not an identifier", func() {
		NewRegistry().Register(trivialOp(OpDoc{Name: "TlsFrag"}))
	})
	mustPanic(t, "reserved", func() {
		NewRegistry().Register(trivialOp(OpDoc{Name: "plain"}))
	})
	mustPanic(t, "registered twice", func() {
		r := NewRegistry()
		r.Register(trivialOp(OpDoc{Name: "dup"}))
		r.Register(trivialOp(OpDoc{Name: "dup"}))
	})
	mustPanic(t, "parameter name", func() {
		NewRegistry().Register(trivialOp(OpDoc{Name: "x", Params: []ParamDoc{{Name: "Size"}}}))
	})
	mustPanic(t, "declared twice", func() {
		NewRegistry().Register(trivialOp(OpDoc{Name: "x", Params: []ParamDoc{{Name: "size"}, {Name: "size"}}}))
	})
	// A non-canonical default would make canonicalisation non-idempotent: the
	// elision compares a canonical value against the declared default.
	mustPanic(t, "not canonical", func() {
		NewRegistry().Register(trivialOp(OpDoc{Name: "x", Params: []ParamDoc{{Name: "size", Default: "012"}}}))
	})
}

// Doc() and the interface methods must agree, or `dpb strategy list` documents
// one op and the validator enforces another.
func TestRegisterPanicsWhenDocDisagreesWithTheMethods(t *testing.T) {
	mustPanic(t, "Doc().Name", func() {
		NewRegistry().Register(nameLiar{Base{D: OpDoc{Name: "real"}}})
	})
	mustPanic(t, "Doc().Kind", func() {
		NewRegistry().Register(kindLiar{Base{D: OpDoc{Name: "real", Kind: KindMutate}}})
	})
	mustPanic(t, "Doc().Caps", func() {
		NewRegistry().Register(capLiar{Base{D: OpDoc{Name: "real", Caps: CapStreamWrite}}})
	})
}

type nameLiar struct{ Base }

func (nameLiar) Name() string               { return "other" }
func (nameLiar) Compile(Args) (Step, error) { return nil, nil }

type kindLiar struct{ Base }

func (kindLiar) Kind() Kind                 { return KindSide }
func (kindLiar) Compile(Args) (Step, error) { return nil, nil }

type capLiar struct{ Base }

func (capLiar) Caps() Cap                  { return CapOOB }
func (capLiar) Compile(Args) (Step, error) { return nil, nil }

func TestBaseDerivesFromDoc(t *testing.T) {
	d := OpDoc{Name: "x", Kind: KindSide, Caps: CapUDPTTL}
	b := Base{D: d}
	if b.Name() != "x" || b.Kind() != KindSide || b.Caps() != CapUDPTTL || b.Doc().Name != d.Name {
		t.Fatalf("Base does not derive from its doc: %+v", b)
	}
}

func TestStepFunc(t *testing.T) {
	called := false
	s := StepFunc("x", CapOOB, func(*Builder) error { called = true; return nil })
	if s.Name() != "x" || s.Caps() != CapOOB {
		t.Fatalf("StepFunc = %+v", s)
	}
	if err := s.Apply(&Builder{}); err != nil || !called {
		t.Fatalf("Apply: %v, called=%v", err, called)
	}
}

func TestGetRejectsANilStep(t *testing.T) {
	r := NewRegistry()
	r.Register(newStub(OpDoc{Name: "broken"}, func(Args) (Step, error) { return nil, nil }))
	if _, err := r.Get("broken"); !errors.Is(err, ErrBadSpec) {
		t.Fatalf("got %v, want ErrBadSpec", err)
	}
}

func TestDefaultRegistryIsShared(t *testing.T) {
	if Default() != Default() {
		t.Fatal("Default must return the same registry every time")
	}
	if _, err := Parse("tlsfrag:pos=snimid"); err != nil {
		t.Fatalf("package-level Parse must consult the default registry: %v", err)
	}
}

func TestIsIdent(t *testing.T) {
	for _, s := range []string{"a", "tlsfrag", "host_pad", "chunk2"} {
		if !isIdent(s) {
			t.Errorf("isIdent(%q) = false", s)
		}
	}
	for _, s := range []string{"", "A", "2chunk", "_x", "tls-frag", "tls.frag", "tls frag"} {
		if isIdent(s) {
			t.Errorf("isIdent(%q) = true", s)
		}
	}
}

// internal/ops registers from init through the package-level helper, so that
// path is exercised here rather than only the method it delegates to.
//
// It runs the whole body TWICE in one process. `go test -count=N` re-runs every
// test inside the SAME process, and Default() is process-wide, so a test that
// registers into it and leaves the op behind panics its own duplicate check on
// the second run — which is exactly what `go test ./internal/strategy/ -count=3`
// did: "panic: strategy: op \"testonlynoop\" registered twice". Repeated runs
// are how a flaky test is found, so a package that cannot be run twice is a
// package whose flakes cannot be chased. The two rounds fail without the
// unregisterOp cleanup below and pass with it.
func TestPackageLevelRegister(t *testing.T) {
	for _, round := range []string{"first run", "second run in the same process"} {
		t.Run(round, checkPackageLevelRegister)
	}
}

// TestPackageLevelRegisterRejectsADuplicate pins the check the cleanup above
// must not be allowed to weaken. Withdrawing an op is a test-only rollback of
// the test's own side effect; while a name IS registered, taking it again is
// still a panic, and on the DEFAULT registry rather than only on a fresh one.
func TestPackageLevelRegisterRejectsADuplicate(t *testing.T) {
	const name = "testonlydup"
	op := trivialOp(OpDoc{
		Name: name, Kind: KindSide,
		Summary: "registered by the strategy package's own tests",
	})
	Register(op)
	t.Cleanup(func() { unregisterOp(t, name) })
	mustPanic(t, "registered twice", func() { Register(op) })
}

// unregisterOp removes an op from the default registry, restoring it to the
// state the test found it in.
//
// It deletes from the map directly rather than calling an exported Unregister:
// there must be no way for shipped code to withdraw an op, because the duplicate
// check in Register is only meaningful if a name, once taken, stays taken. This
// test is in package strategy, so it can reach r.ops without widening the API by
// one byte.
func unregisterOp(t *testing.T, name string) {
	t.Helper()
	r := Default()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.ops[name]; !ok {
		t.Fatalf("unregisterOp(%q): the op is not registered; the test that registered "+
			"it is no longer doing so, and this cleanup is now hiding a hole", name)
	}
	delete(r.ops, name)
}

func checkPackageLevelRegister(t *testing.T) {
	const name = "testonlynoop"
	Register(trivialOp(OpDoc{
		Name: name, Kind: KindSide,
		Summary: "registered by the strategy package's own tests",
	}))
	// Registered into a process-wide singleton, so it must come back out
	// however this test ends.
	t.Cleanup(func() { unregisterOp(t, name) })
	s, err := Parse(name)
	if err != nil {
		t.Fatalf("Parse(%q) after Register: %v", name, err)
	}
	if s.String() != name {
		t.Fatalf("String = %q", s.String())
	}
	found := false
	for _, d := range Docs() {
		if d.Name == name {
			found = true
		}
	}
	if !found {
		t.Fatal("Docs must list an op registered through the package-level helper")
	}
}
