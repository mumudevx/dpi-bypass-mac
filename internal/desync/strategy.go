// Package desync implements the interception-independent DPI-bypass engine.
//
// The same strategies run whether traffic was intercepted by the no-sudo proxy
// front-end (internal/proxy) or the transparent TUN front-end (internal/tun).
// A front-end hands the engine an outbound Conn and the first client payload
// (a TLS ClientHello or an HTTP request); the engine rewrites/splits/injects
// that first payload, after which the front-end relays the rest verbatim.
//
// Composition rule: a chain is [0..n Transformer] + exactly one Emitter.
// Transformers mutate the byte stream (e.g. HTTP Host-header tricks); the
// Emitter owns the actual Write to the connection (split, record-fragment,
// fake-packet). This mirrors how GoodbyeDPI presets combine one fragmentation
// mode with a couple of header tweaks.
package desync

import (
	"context"
	"errors"
	"io"
)

// ErrUnsupported is returned by Conn methods a given interception layer cannot
// honour (e.g. SetTTL on a netstack conn, or RawInjector on a proxy conn).
var ErrUnsupported = errors.New("desync: operation not supported on this connection")

// Conn is the outbound connection abstraction the engine writes the first
// payload through. Both proxy dial-conns and TUN netstack-conns implement it.
type Conn interface {
	io.Writer

	// SetTTL sets the IP TTL on the underlying socket if supported. Proxy
	// conns implement this via setsockopt; conns that cannot return
	// ErrUnsupported.
	SetTTL(ttl int) error

	// RawInjector returns a non-nil injector only on the TUN path, where the
	// userspace netstack lets fake-packet emitters emit out-of-band crafted
	// TCP segments. Proxy conns return nil.
	RawInjector() RawInjector
}

// RawInjector emits a crafted TCP segment directly onto the wire, bypassing the
// netstack's own sequencing. Used by packet-level fake desync (TUN only).
type RawInjector interface {
	// InjectSegment writes an already-framed TCP segment (with chosen seq,
	// checksum and IP TTL) toward the server.
	InjectSegment(seg []byte) error
}

// Protocol classifies the first client payload.
type Protocol int

const (
	ProtoUnknown Protocol = iota
	ProtoTLS
	ProtoHTTP
)

func (p Protocol) String() string {
	switch p {
	case ProtoTLS:
		return "tls"
	case ProtoHTTP:
		return "http"
	default:
		return "unknown"
	}
}

// Meta carries everything strategies need about the first payload so each does
// not re-parse. Offsets are absolute byte indices into the payload.
type Meta struct {
	Protocol  Protocol
	DstPort   int
	SNI       string
	SNIOffset int // start of the SNI host-name value; -1 if none
	SNILen    int
	Host      string
	HostStart int // start of the HTTP Host header value; -1 if none
	HostLen   int
}

// Transformer mutates the payload (and may shift meta offsets). It must not
// write to the connection.
type Transformer interface {
	Name() string
	Transform(payload []byte, meta *Meta) ([]byte, error)
}

// Emitter owns writing the (possibly transformed) first payload to conn using
// whatever splitting/fragmentation/injection it implements. Exactly one emitter
// runs per chain.
type Emitter interface {
	Name() string
	Emit(ctx context.Context, conn Conn, payload []byte, meta *Meta) error
}
