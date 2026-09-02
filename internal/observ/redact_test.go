package observ

import (
	"strings"
	"testing"
)

func TestRedactorHidesTheNameKeepsTheTLD(t *testing.T) {
	r := NewRedactorWithSalt([]byte("test-salt"))

	got := r.Host("www.isbank.com.tr")
	if strings.Contains(got, "isbank") {
		t.Fatalf("redacted host still contains the name: %q", got)
	}
	if !strings.HasSuffix(got, ".tr") {
		t.Errorf("redacted host lost the TLD, which is what makes a report triageable: %q", got)
	}
}

// Within one report the same host must map to one token, or the report becomes
// unreadable. Case and a trailing root dot are the same host.
func TestRedactorIsStableAndNormalising(t *testing.T) {
	r := NewRedactorWithSalt([]byte("test-salt"))
	a := r.Host("discord.com")
	for _, variant := range []string{"discord.com", "Discord.com", "DISCORD.COM.", " discord.com "} {
		if got := r.Host(variant); got != a {
			t.Errorf("Host(%q) = %q, want %q", variant, got, a)
		}
	}
	if r.Host("discord.gg") == a {
		t.Error("different hosts must not collide")
	}
}

// Two reports must not be joinable, so the salt has to change per Redactor.
func TestRedactorSaltSeparatesReports(t *testing.T) {
	a := NewRedactorWithSalt([]byte("salt-a")).Host("discord.com")
	b := NewRedactorWithSalt([]byte("salt-b")).Host("discord.com")
	if a == b {
		t.Error("the same host produced the same token under different salts")
	}
	if NewRedactor().Host("discord.com") == NewRedactor().Host("discord.com") {
		t.Error("NewRedactor must generate a fresh salt each time")
	}
}

func TestRedactorSingleLabelName(t *testing.T) {
	r := NewRedactorWithSalt([]byte("s"))
	got := r.Host("router")
	if !strings.HasSuffix(got, ".local") {
		t.Errorf("single-label name = %q, want a .local suffix", got)
	}
	if strings.Contains(got, "router") {
		t.Errorf("single-label name leaked: %q", got)
	}
}

func TestRedactorIPKeepsThePrefix(t *testing.T) {
	r := NewRedactorWithSalt([]byte("s"))
	cases := map[string]string{
		"162.159.128.233": "162.159.0.0/16",
		"2606:4700::1111": "2606:4700::/32",
		"127.0.0.1":       "127.0.0.1",
		"::1":             "::1",
		"0.0.0.0":         "0.0.0.0",
	}
	for in, want := range cases {
		if got := r.IP(in); got != want {
			t.Errorf("IP(%q) = %q, want %q", in, got, want)
		}
	}
	// An IP arriving through the hostname field must still be masked, not hashed.
	if got := r.Host("162.159.128.233"); got != "162.159.0.0/16" {
		t.Errorf("Host(ip literal) = %q, want the masked prefix", got)
	}
}

func TestRedactorHostPortKeepsThePort(t *testing.T) {
	r := NewRedactorWithSalt([]byte("s"))

	got := r.HostPort("discord.com:443")
	if !strings.HasSuffix(got, ":443") {
		t.Errorf("HostPort lost the port: %q", got)
	}
	if strings.Contains(got, "discord") {
		t.Errorf("HostPort leaked the name: %q", got)
	}
	if got := r.HostPort("[2606:4700::1111]:443"); got != "[2606:4700::/32]:443" {
		t.Errorf("HostPort(v6) = %q", got)
	}
	// Not a host:port at all: fall back to hostname redaction rather than
	// returning the input untouched.
	if got := r.HostPort("discord.com"); strings.Contains(got, "discord") {
		t.Errorf("HostPort(no port) leaked the name: %q", got)
	}
}

func TestRedactorOffIsPassThrough(t *testing.T) {
	r := Off()
	if r.Enabled() {
		t.Error("Off().Enabled() must be false")
	}
	for _, s := range []string{"discord.com", "1.2.3.4", "discord.com:443"} {
		if r.Host(s) != s || r.IP(s) != s || r.HostPort(s) != s {
			t.Errorf("Off() redacted %q", s)
		}
	}
	var nilR *Redactor
	if nilR.Enabled() {
		t.Error("a nil Redactor must report itself disabled rather than panic")
	}
	if nilR.Host("discord.com") != "discord.com" {
		t.Error("a nil Redactor must pass through")
	}
}

func TestRedactorEmptyInputs(t *testing.T) {
	r := NewRedactorWithSalt([]byte("s"))
	if r.Host("") != "" || r.IP("") != "" || r.HostPort("") != "" {
		t.Error("empty input must stay empty")
	}
	if got := r.Host("."); got != "." {
		t.Errorf("Host(\".\") = %q, want it unchanged", got)
	}
}
