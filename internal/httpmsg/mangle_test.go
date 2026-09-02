package httpmsg

import (
	"errors"
	"strings"
	"testing"
)

const req = "GET /a HTTP/1.1\r\nUser-Agent: x\r\nHost: example.com\r\nAccept: */*\r\n\r\n"

func TestHostCase(t *testing.T) {
	in := []byte(req)
	out, err := HostCase(in)
	if err != nil {
		t.Fatalf("HostCase: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, DefaultSpell+": example.com") {
		t.Fatalf("output does not carry the respelled header:\n%q", got)
	}
	if strings.Contains(got, "\r\nHost:") {
		t.Fatal("the original Host spelling survived")
	}
	if len(out) != len(req) {
		t.Fatalf("length changed: %d -> %d", len(req), len(out))
	}
	// The mutated request must still parse to the same hostname, because
	// Builder.Reparse runs after every KindMutate step.
	r, err := Parse(out)
	if err != nil || r.Host != "example.com" {
		t.Fatalf("reparse: %v, host %q", err, r.Host)
	}
	if string(in) != req {
		t.Fatal("HostCase mutated its input; the ladder still needs the original bytes for the next rung")
	}
}

func TestHostSpellRejects(t *testing.T) {
	for _, spell := range []string{"", "hos", "hosts", "xost"} {
		if _, err := HostSpell([]byte(req), spell); !errors.Is(err, ErrBadSpell) {
			t.Errorf("HostSpell(%q) err = %v, want ErrBadSpell", spell, err)
		}
	}
	// Respelling to the spelling already on the wire changes nothing, and a
	// mutator that silently returns its input is the inert-knob defect
	// MEASUREMENTS.md §3.5 records.
	if _, err := HostSpell([]byte(req), "Host"); !errors.Is(err, ErrBadSpell) {
		t.Errorf("err = %v, want ErrBadSpell for a no-op respelling", err)
	}
}

func TestHostDot(t *testing.T) {
	out, err := HostDot([]byte(req))
	if err != nil {
		t.Fatalf("HostDot: %v", err)
	}
	if !strings.Contains(string(out), "Host: example.com.\r\n") {
		t.Fatalf("output:\n%q", string(out))
	}
	if len(out) != len(req)+1 {
		t.Fatalf("length = %d, want %d", len(out), len(req)+1)
	}
	if _, err := HostDot(out); !errors.Is(err, ErrAlreadyDotted) {
		t.Fatalf("second HostDot err = %v, want ErrAlreadyDotted", err)
	}

	// With a port, the dot belongs to the hostname, not to the authority.
	withPort := "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
	out, err = HostDot([]byte(withPort))
	if err != nil {
		t.Fatalf("HostDot with port: %v", err)
	}
	if !strings.Contains(string(out), "Host: example.com.:8080\r\n") {
		t.Fatalf("output:\n%q", string(out))
	}
}

// TestHostDotRefusesIPLiterals pins that the mutator does not produce a broken
// authority. A trailing dot on "1.2.3.4" is not a name, and on "[::1]" it would
// land outside the brackets and change nothing at all.
func TestHostDotRefusesIPLiterals(t *testing.T) {
	for _, host := range []string{"1.2.3.4", "1.2.3.4:8080", "[2001:db8::1]", "[::1]:443"} {
		in := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		if _, err := HostDot([]byte(in)); !errors.Is(err, ErrHostIsLiteral) {
			t.Errorf("HostDot(%q) err = %v, want ErrHostIsLiteral", host, err)
		}
	}
}

func TestHostPad(t *testing.T) {
	for _, n := range []int{MinPad, MinPad + 1, 64, 512} {
		out, err := HostPad([]byte(req), n)
		if err != nil {
			t.Fatalf("HostPad(%d): %v", n, err)
		}
		if len(out) != len(req)+n {
			t.Fatalf("HostPad(%d): length = %d, want %d", n, len(out), len(req)+n)
		}
		r, err := Parse(out)
		if err != nil {
			t.Fatalf("HostPad(%d) produced an unparseable head: %v", n, err)
		}
		if !r.Complete || r.Host != "example.com" {
			t.Fatalf("HostPad(%d): complete=%v host=%q", n, r.Complete, r.Host)
		}
		// The point of the mutator: the hostname moved further into the request.
		base, _ := Parse([]byte(req))
		if r.HostStart != base.HostStart+n {
			t.Fatalf("HostPad(%d): host moved to %d, want %d", n, r.HostStart, base.HostStart+n)
		}
	}
	for _, n := range []int{0, MinPad - 1, -1, MaxPad + 1} {
		if _, err := HostPad([]byte(req), n); !errors.Is(err, ErrPadRange) {
			t.Errorf("HostPad(%d) err = %v, want ErrPadRange", n, err)
		}
	}
}

func TestMutatorPreconditions(t *testing.T) {
	mutators := map[string]func([]byte) ([]byte, error){
		"HostCase": HostCase,
		"HostDot":  HostDot,
		"HostPad":  func(b []byte) ([]byte, error) { return HostPad(b, 32) },
	}
	inputs := map[string]struct {
		in   string
		want error
	}{
		"not a request":    {"\x16\x03\x01\x00\x05", ErrNotRequest},
		"incomplete head":  {"GET / HTTP/1.1\r\nHost: example.com\r\n", ErrIncomplete},
		"no host header":   {"GET / HTTP/1.0\r\nAccept: */*\r\n\r\n", ErrNoHost},
		"host in the body": {"POST / HTTP/1.1\r\n\r\nHost: x\r\n", ErrNoHost},
	}
	for mn, fn := range mutators {
		for in, c := range inputs {
			t.Run(mn+"/"+in, func(t *testing.T) {
				out, err := fn([]byte(c.in))
				if !errors.Is(err, c.want) {
					t.Fatalf("err = %v, want %v", err, c.want)
				}
				if out != nil {
					t.Fatalf("output returned alongside an error: %q", out)
				}
			})
		}
	}
}

// TestMutatorsAreLive is the byte-diff sweep: every mutator, at every parameter
// it accepts, must actually change the bytes on the wire. MEASUREMENTS.md §3.5
// records the previous implementation shipping a knob that did nothing.
func TestMutatorsAreLive(t *testing.T) {
	base := []byte(req)
	seen := map[string]bool{string(base): true}
	add := func(name string, out []byte, err error) {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if seen[string(out)] {
			t.Fatalf("%s produced bytes already seen; the parameter is inert", name)
		}
		seen[string(out)] = true
	}
	out, err := HostCase(base)
	add("hostcase", out, err)
	out, err = HostDot(base)
	add("hostdot", out, err)
	for _, spell := range []string{"HOST", "hOSt", "HosT"} {
		out, err = HostSpell(base, spell)
		add("hostspell:"+spell, out, err)
	}
	for n := MinPad; n < MinPad+8; n++ {
		out, err = HostPad(base, n)
		add("hostpad:"+string(rune('0'+n-MinPad)), out, err)
	}
}
