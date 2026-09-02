package policy

import (
	"strings"
	"testing"
)

// FuzzMatchLabel is the guard on the one defect class this package exists to
// eliminate. The previous implementation matched exclusions with a bare
// strings.HasSuffix, so an entry for bank.com also covered evilbank.com; the
// four pinned cases below are the plan's acceptance criterion, and the
// property check afterwards generalises them to every input the fuzzer finds.
func FuzzMatchLabel(f *testing.F) {
	seeds := []string{
		"bank.com", "www.bank.com", "evilbank.com", "bank.com.evil.tld",
		"", ".", "..", "BANK.COM", "bank.com.", "xbank.com",
		"a.b.c.bank.com", "bank.co", "türkiye.gov.tr", "xn--trkiye-3ya.gov.tr",
		"1.2.3.4", "::1", "[::1]", strings.Repeat("a", 300),
		"\x00bank.com", "bank\x00.com", "-.bank.com", "bank..com",
	}
	patterns := []string{"bank.com", ".bank.com", "*.bank.com", "=bank.com", "", "*", "10.0.0.0/8"}
	for _, p := range patterns {
		for _, h := range seeds {
			f.Add(p, h)
		}
	}

	f.Fuzz(func(t *testing.T, pattern, host string) {
		// The pins. These must hold no matter what the fuzzer is exploring.
		if !MatchLabel("bank.com", "bank.com") {
			t.Fatal("bank.com must match itself")
		}
		if !MatchLabel("bank.com", "www.bank.com") {
			t.Fatal("bank.com must match www.bank.com")
		}
		if MatchLabel("bank.com", "evilbank.com") {
			t.Fatal("bank.com must NOT match evilbank.com")
		}
		if MatchLabel("bank.com", "bank.com.evil.tld") {
			t.Fatal("bank.com must NOT match bank.com.evil.tld")
		}

		got := MatchLabel(pattern, host)

		kind, base, err := parsePattern(pattern)
		if err != nil {
			if got {
				t.Fatalf("MatchLabel(%q, %q) matched on an unusable pattern", pattern, host)
			}
			return
		}
		name := Normalize(host)
		if got {
			// The anchor, stated as a property: a match is either the name
			// itself or a name whose suffix begins at a label boundary. Any
			// other true result is the HasSuffix bug returning.
			if name != base && !strings.HasSuffix(name, "."+base) {
				t.Fatalf("MatchLabel(%q, %q) matched but %q is neither %q nor a subdomain of it",
					pattern, host, name, base)
			}
			if kind == kindWildcard && name == base {
				t.Fatalf("MatchLabel(%q, %q) matched a wildcard against its own apex", pattern, host)
			}
			if kind == kindExact && name != base {
				t.Fatalf("MatchLabel(%q, %q) matched an exact rule against a subdomain", pattern, host)
			}
		} else if name != "" && name == base && kind != kindWildcard {
			t.Fatalf("MatchLabel(%q, %q) failed to match an identical name", pattern, host)
		}

		// Normalisation is idempotent; a second pass must not change the key
		// the store and the matcher agree on.
		if again := Normalize(name); name != "" && again != name {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q", host, name, again)
		}

		// Spelling must not steer the decision. The canonical name is ASCII
		// by construction, so upper-casing it and adding the root dot are
		// both no-ops that any correct matcher agrees on. (The raw input is
		// deliberately not re-cased here: Unicode folding is not a round trip
		// — Turkish dotless i is the classic counterexample — and a host with
		// trailing junk is a different string, not a different spelling.)
		if name != "" {
			if up := MatchLabel(pattern, strings.ToUpper(name)); up != got {
				t.Fatalf("MatchLabel(%q, %q)=%v but upper-case canonical form=%v", pattern, host, got, up)
			}
			if dot := MatchLabel(pattern, name+"."); dot != got {
				t.Fatalf("MatchLabel(%q, %q)=%v but rooted canonical form=%v", pattern, host, got, dot)
			}
		}
	})
}

// FuzzNormalize pins the invariants every other component leans on: the result
// is always a usable key or empty, and it never contains a byte that would
// make it ambiguous as a store key or a log field.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"", ".", "a.b", "A.B.", "1.2.3.4", "[::1]", "ü.com", "a\x00b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		got := Normalize(host)
		if got == "" {
			return
		}
		if len(got) > maxNameLen {
			t.Fatalf("Normalize(%q) = %q, longer than %d bytes", host, got, maxNameLen)
		}
		if strings.ContainsAny(got, " \t\r\n|") {
			// "|" matters: Key joins the network key and the host with it.
			t.Fatalf("Normalize(%q) = %q contains a separator byte", host, got)
		}
		if got != strings.ToLower(got) {
			t.Fatalf("Normalize(%q) = %q is not lower-case", host, got)
		}
		if strings.HasSuffix(got, ".") {
			t.Fatalf("Normalize(%q) = %q keeps a root dot", host, got)
		}
	})
}
