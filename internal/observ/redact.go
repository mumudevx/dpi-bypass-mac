package observ

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
)

// Redactor turns hostnames and addresses into stable pseudonyms so a user in
// Turkey can paste `dpb tune --json` or `dpb doctor --json` output into a
// public issue without publishing their browsing history.
//
// The salt is generated per Redactor, so the same host maps to the same token
// within one report — which is what makes a report readable — and to a
// different token in the next one, so two reports cannot be joined and no
// offline dictionary attack against the short digest survives across runs.
//
// The last DNS label is kept in the clear. It is not identifying on its own and
// it is load-bearing for triage: ".tr" versus ".com" is usually the whole story
// about why a host behaved differently.
type Redactor struct {
	salt []byte
	off  bool
}

// NewRedactor returns a redactor with a fresh random salt.
func NewRedactor() *Redactor {
	salt := make([]byte, 16)
	// crypto/rand.Read never returns an error on darwin; if it somehow did,
	// a zero salt still redacts, it merely becomes joinable across reports.
	_, _ = rand.Read(salt)
	return &Redactor{salt: salt}
}

// NewRedactorWithSalt is the deterministic constructor used by tests.
func NewRedactorWithSalt(salt []byte) *Redactor {
	return &Redactor{salt: append([]byte(nil), salt...)}
}

// Off returns a pass-through redactor for local, non-shareable output. It is a
// real object rather than a nil check so no caller has to remember one.
func Off() *Redactor { return &Redactor{off: true} }

// Enabled reports whether this redactor actually redacts.
func (r *Redactor) Enabled() bool { return r != nil && !r.off }

const redactPrefix = "x"

// Host redacts a DNS name. An IP literal is routed to IP, because a hostname
// field very often holds one.
func (r *Redactor) Host(name string) string {
	if !r.Enabled() || name == "" {
		return name
	}
	// Normalise before hashing so "Discord.com." and "discord.com" collapse to
	// one token; otherwise the report shows two "different" hosts.
	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if norm == "" {
		return name
	}
	if addr, err := netip.ParseAddr(norm); err == nil {
		return r.ipAddr(addr)
	}

	tld := norm
	if i := strings.LastIndexByte(norm, '.'); i >= 0 {
		tld = norm[i+1:]
	} else {
		// A single-label name has no public part worth keeping.
		tld = "local"
	}
	return redactPrefix + r.digest(norm) + "." + tld
}

// HostPort redacts the host half of a "host:port" address, keeping the port.
func (r *Redactor) HostPort(addr string) string {
	if !r.Enabled() || addr == "" {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return r.Host(addr)
	}
	h := r.Host(host)
	if strings.ContainsRune(h, ':') { // a redacted IPv6 literal
		h = "[" + h + "]"
	}
	return h + ":" + port
}

// IP masks an address rather than hashing it. The network prefix is kept
// because "which ISP / which CDN" is exactly the question a shared diagnostic
// has to answer, while the host part is what identifies an individual flow.
func (r *Redactor) IP(s string) string {
	if !r.Enabled() || s == "" {
		return s
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return r.Host(s)
	}
	return r.ipAddr(addr)
}

func (r *Redactor) ipAddr(addr netip.Addr) string {
	// Loopback and the link-local ranges are not identifying and are often the
	// whole point of the line (a probe against 127.0.0.1 in testcensor).
	if addr.IsLoopback() || addr.IsUnspecified() {
		return addr.String()
	}
	bits := 16
	if addr.Is6() && !addr.Is4In6() {
		bits = 32
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return redactPrefix + r.digest(addr.String())
	}
	return p.String()
}

func (r *Redactor) digest(s string) string {
	h := sha256.New()
	h.Write(r.salt)
	h.Write([]byte{0}) // domain separation between salt and value
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil)[:4])
}
