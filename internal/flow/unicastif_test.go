package flow

import "testing"

// TestUnicastIFIndexByteOrder is the regression test for the trap documented
// in unicastif.go and dialer_windows.go: IP_UNICAST_IF wants the interface
// index in network byte order, IPV6_UNICAST_IF wants it in host byte order,
// and swapping them produces no error anywhere -- only a socket silently
// pinned to the wrong interface (or to index 0, meaning unbound). This file
// carries no build tag specifically so this test runs on every OS, including
// this development machine, which cannot run Windows at all; it is the only
// defence against the trap that this environment can actually execute rather
// than merely `GOOS=windows go vet` type-check.
func TestUnicastIFIndexByteOrder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		idx    int
		wantV4 uint32 // network (big-endian) byte order
		wantV6 uint32 // host byte order: idx unchanged
	}{
		{name: "index 1", idx: 1, wantV4: 0x01000000, wantV6: 1},
		{name: "index 5 (a typical uplink adapter index)", idx: 5, wantV4: 0x05000000, wantV6: 5},
		{name: "single byte 0x12", idx: 0x12, wantV4: 0x12000000, wantV6: 0x12},
		{name: "two bytes 0x1234", idx: 0x1234, wantV4: 0x34120000, wantV6: 0x1234},
		{name: "three bytes 0x010203", idx: 0x010203, wantV4: 0x03020100, wantV6: 0x010203},
		{name: "max positive int32 0x7fffffff", idx: 0x7fffffff, wantV4: 0xffffff7f, wantV6: 0x7fffffff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := unicastIFIndexV4(c.idx); got != c.wantV4 {
				t.Errorf("unicastIFIndexV4(%#x) = %#08x, want %#08x", c.idx, got, c.wantV4)
			}
			if got := unicastIFIndexV6(c.idx); got != c.wantV6 {
				t.Errorf("unicastIFIndexV6(%#x) = %#08x, want %#08x", c.idx, got, c.wantV6)
			}
			// The whole point of having two functions: for any index with a
			// non-palindromic byte pattern, the two encodings must not match.
			// If they ever did, IP_UNICAST_IF and IPV6_UNICAST_IF could share
			// one code path -- and MSDN says they cannot.
			if v4, v6 := unicastIFIndexV4(c.idx), unicastIFIndexV6(c.idx); c.idx != 0 && v4 == v6 {
				t.Errorf("index %#x: v4 (%#08x) and v6 (%#08x) encodings must differ", c.idx, v4, v6)
			}
		})
	}
}

// TestUnicastIFIndexV4RoundTrip confirms unicastIFIndexV4 is its own inverse
// (reversing four bytes twice restores the original) -- a sanity check on
// the bit-shift arithmetic independent of the hand-picked expected values
// above.
func TestUnicastIFIndexV4RoundTrip(t *testing.T) {
	t.Parallel()
	for _, idx := range []int{0, 1, 2, 5, 0x12, 0x1234, 0x010203, 0x7fffffff} {
		swapped := unicastIFIndexV4(idx)
		if back := unicastIFIndexV4(int(swapped)); back != uint32(idx) {
			t.Errorf("unicastIFIndexV4(unicastIFIndexV4(%#x)) = %#x, want %#x", idx, back, idx)
		}
	}
}
