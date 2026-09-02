package resolve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestNewDoTRefusesAHostname: DoT is reached at a literal address for the same
// reason DoH carries bootstrap addresses — a hostname here would be handed to
// the system resolver (MEASUREMENTS.md §5.4).
func TestNewDoTRefusesAHostname(t *testing.T) {
	for _, addr := range []string{"dns.quad9.net:853", "9.9.9.9", "quad9"} {
		if _, err := NewDoT(addr, nil); err == nil {
			t.Fatalf("NewDoT(%q) must be refused", addr)
		}
	}
	if _, err := NewDoT("9.9.9.9:0", nil); err == nil {
		t.Fatal("port 0 must be refused")
	}
	if _, err := NewDoTServerName("9.9.9.9:853", "", nil); err == nil {
		t.Fatal("an empty ServerName must be refused")
	}
	if _, err := NewDoTServerName("nope", "x", nil); err == nil {
		t.Fatal("a non-literal address must be refused")
	}
	r, err := NewDoT("9.9.9.9:853", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Label() != "dot-9.9.9.9" || r.Transport() != "dot" {
		t.Fatalf("label = %q transport = %q", r.Label(), r.Transport())
	}
}

// dotServer runs an RFC 7858 endpoint on loopback with a throwaway certificate
// and returns its address plus a client config that trusts it.
func dotServer(t *testing.T, handle func(query []byte) []byte) (string, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dpb-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp := handle(q)
				if resp == nil {
					return
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}()
		}
	}()
	return l.Addr().String(), &tls.Config{ServerName: "127.0.0.1", RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func newTestDoT(t *testing.T, addr string, cfg *tls.Config) *dotResolver {
	t.Helper()
	r, err := NewDoTServerName(addr, "127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	d := r.(*dotResolver)
	d.tlsCfg = cfg
	return d
}

func TestDoTExchange(t *testing.T) {
	addr, cfg := dotServer(t, func(q []byte) []byte {
		return buildAnswer(t, q, 60, genuineAnswer...)
	})
	r := newTestDoT(t, addr, cfg)

	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0x7777); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ans, err := r.Exchange(ctx, q)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id, _ := MsgID(ans); id != 0x7777 {
		t.Fatalf("caller ID = %#x", id)
	}
	if got := addrStrings(AnswerAddrs(ans)); got != addrStrings(genuineAnswer) {
		t.Fatalf("answer = %s", got)
	}
}

func TestDoTUsesTheSuppliedDialer(t *testing.T) {
	addr, cfg := dotServer(t, func(q []byte) []byte { return buildAnswer(t, q, 60, genuineAnswer[0]) })
	var mu sync.Mutex
	var seen []string
	r, err := NewDoTServerName(addr, "127.0.0.1", func(ctx context.Context, network, a string) (net.Conn, error) {
		mu.Lock()
		seen = append(seen, network+"|"+a)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, a)
	})
	if err != nil {
		t.Fatal(err)
	}
	d := r.(*dotResolver)
	d.tlsCfg = cfg
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := d.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || !strings.HasPrefix(seen[0], "tcp|127.0.0.1:") {
		t.Fatalf("the desyncing dial path must carry the DoT connection, got %v", seen)
	}
}

func TestDoTExchangeFailures(t *testing.T) {
	t.Run("short query", func(t *testing.T) {
		r, err := NewDoT("9.9.9.9:853", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Exchange(context.Background(), []byte{1}); !errors.Is(err, ErrShortMessage) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("dial failure", func(t *testing.T) {
		// Port 1 on loopback has nothing listening.
		r, err := NewDoTServerName("127.0.0.1:1", "127.0.0.1", nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := r.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err == nil {
			t.Fatal("a refused dial must surface")
		}
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		addr, _ := dotServer(t, func(q []byte) []byte { return buildAnswer(t, q, 60, genuineAnswer[0]) })
		r, err := NewDoTServerName(addr, "127.0.0.1", nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := r.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err == nil ||
			!strings.Contains(err.Error(), "handshake") {
			t.Fatalf("an unverifiable resolver must be refused, got %v", err)
		}
	})

	t.Run("implausible length", func(t *testing.T) {
		addr, cfg := dotServer(t, func(q []byte) []byte { return []byte{1, 2, 3} })
		r := newTestDoT(t, addr, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := r.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err == nil ||
			!strings.Contains(err.Error(), "implausible") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("answers a different question", func(t *testing.T) {
		addr, cfg := dotServer(t, func(q []byte) []byte {
			other := mustQuery(t, "discord.gg", dns.TypeA)
			return buildAnswer(t, other, 60, genuineAnswer[0])
		})
		r := newTestDoT(t, addr, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := r.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err == nil ||
			!strings.Contains(err.Error(), "does not match") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("closed before answering", func(t *testing.T) {
		addr, cfg := dotServer(t, func(q []byte) []byte { return nil })
		r := newTestDoT(t, addr, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := r.Exchange(ctx, mustQuery(t, "discord.com", dns.TypeA)); err == nil {
			t.Fatal("a closed stream must surface as an error")
		}
	})
}

// TestDoTRefusesPort53 pins the distinction the whole transport rests on. DoT
// is a TLS stream on 853 (DOSSIER GT4: "DoT/853 connects"); a "dot" endpoint
// pointed at 53 is a TLS handshake attempted against the plaintext DNS port,
// which MEASUREMENTS.md §2 measures as connection-reset at every port on this
// ISP. Accepting it costs a full per-rung budget per query and answers nothing.
func TestDoTRefusesPort53(t *testing.T) {
	if _, err := NewDoT("8.8.8.8:53", nil); err == nil {
		t.Fatal("a DoT endpoint on port 53 must be refused")
	}
	if _, err := NewDoTServerName("8.8.8.8:53", "dns.google", nil); err == nil {
		t.Fatal("an explicit ServerName does not make port 53 DoT")
	}
	// The Endpoint form is the one a profile or a config layer would carry.
	if _, err := (Endpoint{Label: "bad", Transport: "dot", Target: "9.9.9.9:53"}).New(nil, nil); err == nil {
		t.Fatal("Endpoint.New must not build a DoT resolver on port 53")
	}
	// 853 is still fine.
	if _, err := NewDoT("9.9.9.9:853", nil); err != nil {
		t.Fatalf("DoT on 853 must still build: %v", err)
	}
}
