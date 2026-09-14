package flow

// This file has no build tag, unlike dialer_windows.go which is the only
// caller of what is defined here. That split is deliberate: the arithmetic
// below is the byte-order trap described in dialer_windows.go's bindToInterface
// comment, and the only way to regression-test it on this development machine
// (which cannot run Windows) is to keep it in a file the darwin build also
// compiles, so unicastif_test.go actually executes instead of merely
// type-checking under `GOOS=windows go vet`.
//
// Background, confirmed against two independent sources: MSDN's Winsock
// option reference for IP_UNICAST_IF / IPV6_UNICAST_IF (ws2ipdef.h), and this
// module's own vendored golang.zx2c4.com/wireguard/conn/bind_windows.go
// (bindSocketToInterface4 / bindSocketToInterface6), which pins wireguard's
// UDP sockets on Windows for the identical reason. Both agree:
//
//   - IP_UNICAST_IF (IPPROTO_IP) wants the interface index in NETWORK byte
//     order (big-endian) -- as if it were an IPv4 address with leading zeros.
//   - IPV6_UNICAST_IF (IPPROTO_IPV6) wants the interface index in HOST byte
//     order, unchanged -- like every other integer setsockopt option.
//
// Getting either one wrong is silent: setsockopt still succeeds, it just pins
// the socket to whatever interface the wrong-endian value happens to name, or
// to index 0 (meaning unbound) if it names nothing. That is exactly the
// tunnel-loop failure bindToInterface exists to prevent, with no error to
// catch it -- which is why the two encodings below are written out
// byte-by-byte rather than through a shared "convert to network order"
// helper that would hide the fact that v4 and v6 disagree.

// unicastIFIndexV4 renders idx the way IP_UNICAST_IF wants it: the four bytes
// of idx reversed, so the result reads as idx's big-endian (network byte
// order) encoding. E.g. index 5 (host bytes 00 00 00 05) becomes 0x05000000.
func unicastIFIndexV4(idx int) uint32 {
	u := uint32(idx)
	b0 := u & 0xff // least-significant byte of idx
	b1 := (u >> 8) & 0xff
	b2 := (u >> 16) & 0xff
	b3 := (u >> 24) & 0xff // most-significant byte of idx
	// Network order places the least-significant byte last; reversed here,
	// it goes first (most-significant position) in the returned value.
	return b0<<24 | b1<<16 | b2<<8 | b3
}

// unicastIFIndexV6 renders idx the way IPV6_UNICAST_IF wants it: unchanged,
// in host byte order. It exists as a named, tested function -- rather than
// callers just passing idx straight through -- so that the fact it differs
// from unicastIFIndexV4 is a decision visible in one place, not something a
// future edit could "simplify" into matching v4 by accident.
func unicastIFIndexV6(idx int) uint32 {
	return uint32(idx)
}
