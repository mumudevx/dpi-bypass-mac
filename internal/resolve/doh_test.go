package resolve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newTestDoH(t *testing.T, rt http.RoundTripper) *dohResolver {
	t.Helper()
	return &dohResolver{
		label:  "doh-test",
		url:    "https://cloudflare-dns.com/dns-query",
		host:   "cloudflare-dns.com",
		boot:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		client: &http.Client{Transport: rt},
	}
}

func httpResp(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{dohContentType}},
	}
}

// TestNewDoHDemandsBootstrap is the §5.4 guard for the encrypted transports: a
// DoH endpoint is a hostname, and the only safe way to reach a hostname on this
// network is an address we shipped in the binary.
func TestNewDoHDemandsBootstrap(t *testing.T) {
	if _, err := NewDoH("https://cloudflare-dns.com/dns-query", nil, nil); err == nil {
		t.Fatal("a DoH endpoint with no bootstrap address must be refused")
	} else if !strings.Contains(err.Error(), "5.4") {
		t.Fatalf("error must cite the measurement: %v", err)
	}
	if _, err := NewDoH("http://dns.example/dns-query", DefaultSinkholes, nil); err == nil {
		t.Fatal("plaintext http must be refused")
	}
	if _, err := NewDoH("https:///dns-query", DefaultSinkholes, nil); err == nil {
		t.Fatal("an endpoint with no host must be refused")
	}
	if _, err := NewDoH("://bad", nil, nil); err == nil {
		t.Fatal("an unparseable endpoint must be refused")
	}
	// An invalid address in the bootstrap list is dropped, not accepted.
	if _, err := NewDoH("https://dns.example/dns-query", []netip.Addr{{}}, nil); err == nil {
		t.Fatal("a bootstrap list of invalid addresses is no bootstrap at all")
	}
	r, err := NewDoH("https://dns.google/dns-query", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Label() != "doh-dns.google" || r.Transport() != "doh" {
		t.Fatalf("label = %q transport = %q", r.Label(), r.Transport())
	}
}

// TestDoHDialDiscardsTheHostname is the heart of §5.4: net/http hands the dial
// function "cloudflare-dns.com:443", and passing that to any dialer is exactly
// the fall-through that made the first compatibility run measure a sinkhole.
func TestDoHDialDiscardsTheHostname(t *testing.T) {
	var (
		mu     sync.Mutex
		dialed []string
	)
	r, err := NewDoH("https://cloudflare-dns.com/dns-query",
		[]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return nil, errors.New("no network in this test")
		})
	if err != nil {
		t.Fatal(err)
	}
	tr := r.(*dohResolver).client.Transport.(*http.Transport)
	if _, err := tr.DialContext(context.Background(), "tcp", "cloudflare-dns.com:443"); err == nil {
		t.Fatal("the test dialer always fails")
	}
	mu.Lock()
	got := append([]string(nil), dialed...)
	mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("both bootstrap addresses must be tried, got %v", got)
	}
	for _, a := range got {
		if strings.Contains(a, "cloudflare-dns.com") {
			t.Fatalf("the hostname reached the dialer: %v", got)
		}
		if _, err := netip.ParseAddrPort(a); err != nil {
			t.Fatalf("dialled %q, which is not a literal address: %v", a, err)
		}
	}
}

func TestDoHDialRotatesBootstrap(t *testing.T) {
	var (
		mu    sync.Mutex
		first []string
	)
	r, err := NewDoH("https://cloudflare-dns.com/dns-query",
		[]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			first = append(first, addr)
			mu.Unlock()
			return nil, errors.New("down")
		})
	if err != nil {
		t.Fatal(err)
	}
	tr := r.(*dohResolver).client.Transport.(*http.Transport)
	_, _ = tr.DialContext(context.Background(), "tcp", "cloudflare-dns.com:443")
	_, _ = tr.DialContext(context.Background(), "tcp", "cloudflare-dns.com:443")
	mu.Lock()
	defer mu.Unlock()
	if len(first) != 4 {
		t.Fatalf("two dials over two addresses = four attempts, got %v", first)
	}
	// A bootstrap address that has gone dark must cost one attempt, not every
	// attempt, so the second dial must not start where the first started.
	if first[0] == first[2] {
		t.Fatalf("the bootstrap list did not rotate: %v", first)
	}
}

func TestDoHDialRejectsABadPort(t *testing.T) {
	r, err := NewDoH("https://dns.example/dns-query", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := r.(*dohResolver).client.Transport.(*http.Transport)
	if _, err := tr.DialContext(context.Background(), "tcp", "dns.example:notaport"); err == nil {
		t.Fatal("a non-numeric port must fail")
	}
}

// TestDoHZeroesTheIDOnTheWire covers RFC 8484 §4.1 and the funnel's promise
// that the caller's own ID comes back regardless.
func TestDoHZeroesTheIDOnTheWire(t *testing.T) {
	var sent []byte
	r := newTestDoH(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		sent = b
		if req.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", req.Method)
		}
		if got := req.Header.Get("Content-Type"); got != dohContentType {
			t.Errorf("content-type = %q", got)
		}
		return httpResp(http.StatusOK, buildAnswer(t, b, 60, genuineAnswer[0])), nil
	}))

	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0xabcd); err != nil {
		t.Fatal(err)
	}
	ans, err := r.Exchange(context.Background(), q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id := binary.BigEndian.Uint16(sent[0:2]); id != 0 {
		t.Fatalf("the wire ID must be zero (RFC 8484 §4.1), got %#x", id)
	}
	id, err := MsgID(ans)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0xabcd {
		t.Fatalf("the caller's ID must be restored, got %#x", id)
	}
}

func TestDoHExchangeFailures(t *testing.T) {
	q := mustQuery(t, "discord.com", dns.TypeA)

	t.Run("short query", func(t *testing.T) {
		r := newTestDoH(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("a short query must never reach the network")
			return nil, nil
		}))
		if _, err := r.Exchange(context.Background(), []byte{1}); !errors.Is(err, ErrShortMessage) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		r := newTestDoH(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial refused")
		}))
		if _, err := r.Exchange(context.Background(), q); err == nil {
			t.Fatal("a transport error must surface")
		}
	})

	t.Run("non-200", func(t *testing.T) {
		r := newTestDoH(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return httpResp(http.StatusTooManyRequests, []byte("slow down")), nil
		}))
		if _, err := r.Exchange(context.Background(), q); err == nil || !strings.Contains(err.Error(), "429") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		r := newTestDoH(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return httpResp(http.StatusOK, bytes.Repeat([]byte{0}, dohBodyMax+1)), nil
		}))
		if _, err := r.Exchange(context.Background(), q); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("stub body", func(t *testing.T) {
		r := newTestDoH(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return httpResp(http.StatusOK, []byte{1, 2, 3}), nil
		}))
		if _, err := r.Exchange(context.Background(), q); !errors.Is(err, ErrShortMessage) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("answers a different question", func(t *testing.T) {
		other := mustQuery(t, "discord.gg", dns.TypeA)
		r := newTestDoH(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return httpResp(http.StatusOK, buildAnswer(t, other, 60, genuineAnswer[0])), nil
		}))
		if _, err := r.Exchange(context.Background(), q); err == nil ||
			!strings.Contains(err.Error(), "does not match") {
			t.Fatalf("err = %v", err)
		}
	})
}
