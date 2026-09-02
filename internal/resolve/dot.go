package resolve

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

const (
	dotTimeout = 8 * time.Second
	dotMsgMax  = 64 << 10
	// streamNetwork is the network name an encrypted DNS transport dials on.
	//
	// It is declared here because this file and doh.go are the only two the
	// package's own TestNoPlaintextTCPPathExists gate lets name a stream
	// network. Everything else that has to reason about one — Endpoint.New
	// deciding whether a configured transport is asking for plaintext DNS over
	// TCP — references this constant, so the gate stays exact rather than
	// being widened to let another file through.
	streamNetwork = "tcp"
)

type dotResolver struct {
	label      string
	addr       string
	serverName string
	dial       DialFunc
	// tlsCfg is the verification policy. It is a field rather than a literal
	// so a test can point it at a self-signed fixture; nothing in the shipped
	// binary sets it, so the default below is what ships.
	tlsCfg *tls.Config
}

// NewDoT builds a DNS-over-TLS resolver on a literal address.
//
// addr must be ip:port. The ServerName is the IP itself, which Go verifies
// against the certificate's IP SANs and — because it is not a DNS name — does
// not put on the wire as SNI. Use NewDoTServerName when a profile wants the
// operator's hostname in SNI instead.
//
// DoT is a TLS stream on 853 and is NOT the TCP/53 fallback ErrTCPForbidden
// exists to prevent: MEASUREMENTS.md §2 measures plaintext TCP/53 as
// connection-reset at every port tested, while DOSSIER GT4 records DoT/853 as
// connecting. The distinction is the reason this resolver may open a stream at
// all.
func NewDoT(addr string, dial DialFunc) (Resolver, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("resolve: DoT address %q must be a literal ip:port, "+
			"never a hostname (MEASUREMENTS.md §5.4): %w", addr, err)
	}
	return NewDoTServerName(addr, ap.Addr().String(), dial)
}

// NewDoTServerName is NewDoT with an explicit certificate name, for a resolver
// whose certificate carries no IP SAN.
func NewDoTServerName(addr, serverName string, dial DialFunc) (Resolver, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("resolve: DoT address %q must be a literal ip:port, "+
			"never a hostname (MEASUREMENTS.md §5.4): %w", addr, err)
	}
	if ap.Port() == 0 {
		return nil, fmt.Errorf("resolve: DoT address %q has port 0", addr)
	}
	// A "DoT" endpoint on port 53 is not DoT. It is a TLS handshake attempted
	// against the plaintext DNS port, and MEASUREMENTS.md §2 measures TCP/53 as
	// connection-reset at every port tested on this ISP, so it can only burn a
	// full per-rung budget per query before failing. DoT lives on 853
	// (DOSSIER GT4: "DoT/853 connects"); refusing 53 here is what stops a
	// profile or a config layer from spending the chain's budget on it.
	if ap.Port() == 53 {
		return nil, fmt.Errorf("resolve: DoT address %q uses port 53, which is the plaintext DNS port: "+
			"TCP/53 is connection-reset at every port on this ISP (MEASUREMENTS.md §2); DoT is 853", addr)
	}
	if serverName == "" {
		return nil, fmt.Errorf("resolve: DoT %q needs a ServerName to verify against", addr)
	}
	return &dotResolver{
		label:      "dot-" + ap.Addr().String(),
		addr:       ap.String(),
		serverName: serverName,
		dial:       dial,
		tlsCfg:     &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12},
	}, nil
}

func (r *dotResolver) Label() string     { return r.label }
func (r *dotResolver) Transport() string { return "dot" }

func (r *dotResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < headerLen {
		return nil, ErrShortMessage
	}
	if len(query) > dotMsgMax {
		return nil, fmt.Errorf("resolve: %s: query larger than %d bytes", r.label, dotMsgMax)
	}
	callerID := binary.BigEndian.Uint16(query[0:2])
	out := make([]byte, len(query))
	copy(out, query)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dotTimeout)
	}

	// The address is a literal, so this dial resolves nothing. When dial is the
	// uplink-bound desyncing path, the DoT handshake gets the same ladder every
	// other connection gets.
	var (
		conn net.Conn
		err  error
	)
	if r.dial != nil {
		conn, err = r.dial(ctx, streamNetwork, r.addr)
	} else {
		d := &net.Dialer{Deadline: deadline}
		conn, err = d.DialContext(ctx, streamNetwork, r.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve: %s: dial %s: %w", r.label, r.addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("resolve: %s: set deadline: %w", r.label, err)
	}

	tc := tls.Client(conn, r.tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("resolve: %s: TLS handshake: %w", r.label, err)
	}

	// RFC 7858 §3.3: length-prefixed, and the prefix and the message go in one
	// write so the query is not split across segments for free.
	framed := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(out)))
	copy(framed[2:], out)
	if _, err := tc.Write(framed); err != nil {
		return nil, fmt.Errorf("resolve: %s: write query: %w", r.label, err)
	}

	var hdr [2]byte
	if _, err := io.ReadFull(tc, hdr[:]); err != nil {
		return nil, fmt.Errorf("resolve: %s: read length for %s: %w", r.label, questionLabel(query), err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < headerLen || n > dotMsgMax {
		return nil, fmt.Errorf("resolve: %s: implausible answer length %d", r.label, n)
	}
	answer := make([]byte, n)
	if _, err := io.ReadFull(tc, answer); err != nil {
		return nil, fmt.Errorf("resolve: %s: read answer: %w", r.label, err)
	}
	if !IsResponse(answer) || !SameQuestion(out, answer) {
		return nil, fmt.Errorf("resolve: %s: answer does not match the question %s",
			r.label, questionLabel(query))
	}
	binary.BigEndian.PutUint16(answer[0:2], callerID)
	return answer, nil
}
