package testcensor

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// OriginConfig configures a simulated origin server.
type OriginConfig struct {
	// Names go into the certificate's SANs. Empty means "localhost".
	Names []string
	// Response is written after the first request line is read. Empty sends a
	// minimal 200.
	Response []byte
	// NextProtos offered in ALPN.
	NextProtos []string
	Logf       func(string, ...any)
}

// Origin is a real TLS server on loopback: a genuine ServerHello, a genuine
// certificate, a genuine handshake.
//
// It matters that it is real rather than an echo server. A record-reframing
// emitter is only correct if a conforming TLS implementation reconstructs the
// identical ClientHello from the records it receives, and the cheapest way to
// assert that is to hand the bytes to crypto/tls and require the handshake to
// complete. Origin also keeps every raw byte the client sent, so CheckIntegrity
// can compare what arrived against what was written.
type Origin struct {
	cfg   OriginConfig
	ln    net.Listener
	tlsc  *tls.Config
	pool  *x509.CertPool
	wg    sync.WaitGroup
	close sync.Once

	mu       sync.Mutex
	received [][]byte
	errs     []error
	conns    int
}

// NewOrigin builds and starts an origin on 127.0.0.1 with an ephemeral port.
func NewOrigin(cfg OriginConfig) (*Origin, error) {
	if len(cfg.Names) == 0 {
		cfg.Names = []string{"localhost"}
	}
	cert, pool, err := selfSigned(cfg.Names)
	if err != nil {
		return nil, fmt.Errorf("testcensor: origin certificate: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("testcensor: origin listen: %w", err)
	}
	o := &Origin{
		cfg:  cfg,
		ln:   ln,
		pool: pool,
		tlsc: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   cfg.NextProtos,
		},
	}
	o.wg.Add(1)
	go o.accept()
	return o, nil
}

// Addr is the origin's host:port.
func (o *Origin) Addr() string { return o.ln.Addr().String() }

// ClientConfig trusts the origin's self-signed certificate.
func (o *Origin) ClientConfig(serverName string) *tls.Config {
	return &tls.Config{RootCAs: o.pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
}

// Received returns the raw client-to-server bytes of connection i, in accept
// order. It is the input to CheckIntegrity.
func (o *Origin) Received(i int) []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	if i < 0 || i >= len(o.received) {
		return nil
	}
	return append([]byte(nil), o.received[i]...)
}

// Conns is the number of connections accepted.
func (o *Origin) Conns() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.conns
}

// Errs returns the handshake and I/O errors the origin saw. A fragile-terminator
// test asserts on these; a healthy test asserts they are empty.
func (o *Origin) Errs() []error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]error(nil), o.errs...)
}

// Close stops the listener and waits for in-flight connections.
func (o *Origin) Close() error {
	var err error
	o.close.Do(func() { err = o.ln.Close() })
	o.wg.Wait()
	return err
}

func (o *Origin) accept() {
	defer o.wg.Done()
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		o.mu.Lock()
		o.received = append(o.received, nil)
		idx := len(o.received) - 1
		o.conns++
		o.mu.Unlock()

		o.wg.Add(1)
		go func() {
			defer o.wg.Done()
			o.serve(c, idx)
		}()
	}
}

func (o *Origin) serve(raw net.Conn, idx int) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	rec := &recordConn{Conn: raw, o: o, idx: idx}

	tc := tls.Server(rec, o.tlsc)
	if err := tc.Handshake(); err != nil {
		o.note(fmt.Errorf("handshake from %s: %w", raw.RemoteAddr(), err))
		return
	}
	br := bufio.NewReader(tc)
	line, err := br.ReadString('\n')
	if err != nil {
		o.note(fmt.Errorf("read request: %w", err))
		return
	}
	// Drain the header block so the client's write completes before the reply.
	for {
		l, err := br.ReadString('\n')
		if err != nil || strings.TrimRight(l, "\r\n") == "" {
			break
		}
	}
	resp := o.cfg.Response
	if len(resp) == 0 {
		resp = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}
	if _, err := tc.Write(resp); err != nil {
		o.note(fmt.Errorf("write response to %q: %w", strings.TrimSpace(line), err))
	}
	_ = tc.Close()
}

func (o *Origin) note(err error) {
	o.mu.Lock()
	o.errs = append(o.errs, err)
	o.mu.Unlock()
	if o.cfg.Logf != nil {
		o.cfg.Logf("testcensor: origin: %v", err)
	}
}

// recordConn keeps every byte the client sent, before TLS sees it.
type recordConn struct {
	net.Conn
	o   *Origin
	idx int
}

func (r *recordConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.o.mu.Lock()
		r.o.received[r.idx] = append(r.o.received[r.idx], b[:n]...)
		r.o.mu.Unlock()
	}
	return n, err
}

// selfSigned mints a throwaway leaf that is its own CA, so a client can be
// pointed at it with a RootCAs pool and no InsecureSkipVerify anywhere — a test
// that disables verification is not testing a TLS handshake.
func selfSigned(names []string) (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              names,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, nil
}

// ErrNoOrigin is returned when a helper is asked about a connection the origin
// never accepted.
var ErrNoOrigin = errors.New("testcensor: no such origin connection")
