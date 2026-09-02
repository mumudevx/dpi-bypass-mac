package testcensor

import (
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

func TestCheckIntegrity(t *testing.T) {
	sent := []byte("abcdefgh")
	if err := CheckIntegrity(sent, []byte("abcdefgh")); err != nil {
		t.Fatalf("identical streams: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"corrupted", []byte("abXdefgh"), "byte 2"},
		{"truncated", []byte("abcd"), "truncated after 4"},
		{"duplicated", []byte("abcdefghabcdefgh"), "8 extra bytes"},
	} {
		err := CheckIntegrity(sent, tc.got)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: err = %v, want ErrCorrupt", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %q, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

// TestCheckHandshakeIntegrityAcceptsReframing is the property tlsfrag depends
// on: the record layer changes, the handshake does not. If this ever fails, the
// primary emitter is corrupting streams and is worse than no tool at all.
func TestCheckHandshakeIntegrityAcceptsReframing(t *testing.T) {
	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	for _, cut := range []int{1, sniStart, (sniStart + sniEnd) / 2, sniEnd - 1} {
		out := split(t, hello, cut)
		if err := CheckHandshakeIntegrity(hello, out); err != nil {
			t.Errorf("cut %d: %v", cut, err)
		}
		if err := CheckIntegrity(hello, out); err == nil {
			t.Errorf("cut %d: byte identity must NOT hold after reframing", cut)
		}
	}
}

func TestCheckHandshakeIntegrityRejectsCorruption(t *testing.T) {
	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	out := split(t, hello, (sniStart+sniEnd)/2)

	mangled := append([]byte(nil), out...)
	mangled[len(mangled)-1] ^= 0xff
	if err := CheckHandshakeIntegrity(hello, mangled); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a flipped body byte was accepted: %v", err)
	}

	// A dropped record is the failure mode a mis-implemented emitter produces.
	h, _ := tlsmsg.ParseHeader(out)
	if err := CheckHandshakeIntegrity(hello, out[:5+h.Length]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a dropped second record was accepted: %v", err)
	}

	// A record type change would mean the reframer rebuilt the header wrongly.
	retyped := append([]byte(nil), out...)
	retyped[5+h.Length] = 0x17
	if err := CheckHandshakeIntegrity(hello, retyped); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a changed record type was accepted: %v", err)
	}
}

func TestCheckHandshakeIntegrityRejectsNonRecords(t *testing.T) {
	hello := clientHello(t, "discord.com")
	for _, tc := range []struct {
		name       string
		orig, got  []byte
		wantSubstr string
	}{
		{"short original", []byte{0x16}, hello, "original"},
		{"short received", hello, []byte{0x16}, "received"},
		{"truncated body", hello, hello[:len(hello)-3], "body bytes"},
		{"trailing garbage", hello, append(append([]byte(nil), hello...), 0x16, 0x03), "record header"},
	} {
		err := CheckHandshakeIntegrity(tc.orig, tc.got)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: err = %v, want ErrCorrupt", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Errorf("%s: err = %q, want it to mention %q", tc.name, err, tc.wantSubstr)
		}
	}
}
