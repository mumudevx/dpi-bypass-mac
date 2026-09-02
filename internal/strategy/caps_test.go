package strategy

import "testing"

func TestCapHasAndMissing(t *testing.T) {
	have := CapStreamWrite | CapNoDelay
	want := CapStreamWrite | CapNoDelay | CapOOB

	if have.Has(want) {
		t.Fatalf("%s must not satisfy %s", have, want)
	}
	if !have.Has(CapStreamWrite | CapNoDelay) {
		t.Fatalf("%s must satisfy itself", have)
	}
	if !have.Has(0) {
		t.Fatal("every capability set satisfies the empty requirement")
	}
	// Missing must name the shortfall, not the whole requirement: an error that
	// prints both bitsets and leaves the subtraction to the reader is why the
	// previous tree's capability failures were invisible.
	if got := have.Missing(want); got != CapOOB {
		t.Fatalf("Missing = %s, want %s", got, CapOOB)
	}
	if got := want.Missing(have); got != 0 {
		t.Fatalf("a superset must be missing nothing, got %s", got)
	}
}

func TestCapString(t *testing.T) {
	for _, tc := range []struct {
		in   Cap
		want string
	}{
		{0, "none"},
		{CapStreamWrite, "streamwrite"},
		{CapStreamWrite | CapNoDelay, "streamwrite|nodelay"},
		{CapOOB | CapSockTTL, "sockttl|oob"},
		{CapRawSeq, "rawseq"},
		{CapUDPTTL | CapRawInject, "udpttl|rawinject"},
		{1 << 20, "unknown(0x100000)"},
		{CapNoDelay | 1<<20, "nodelay|unknown(0x100000)"},
	} {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("Cap(%#x).String() = %q, want %q", uint32(tc.in), got, tc.want)
		}
	}
}

func TestKindAndDeterminismStrings(t *testing.T) {
	for _, tc := range []struct {
		k    Kind
		want string
	}{{KindMutate, "mutate"}, {KindReframe, "reframe"}, {KindSchedule, "schedule"}, {KindSide, "side"}, {Kind(9), "kind(9)"}} {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("Kind(%d) = %q, want %q", tc.k, got, tc.want)
		}
	}
	if got := DetRuleBased.String(); got != "rule-based" {
		t.Errorf("DetRuleBased = %q", got)
	}
	if got := DetEmpirical.String(); got != "empirical" {
		t.Errorf("DetEmpirical = %q", got)
	}
}

func TestRequirementString(t *testing.T) {
	for _, tc := range []struct {
		r    Requirement
		want string
	}{
		{0, "none"},
		{ReqComplete, "complete"},
		{ReqSNI, "sni"},
		{ReqHost, "host"},
		{ReqComplete | ReqSNI, "complete|sni"},
	} {
		if got := tc.r.String(); got != tc.want {
			t.Errorf("Requirement(%d) = %q, want %q", tc.r, got, tc.want)
		}
	}
}

func TestSegKindString(t *testing.T) {
	for _, tc := range []struct {
		k    SegKind
		want string
	}{{SegStream, "stream"}, {SegOOBByte, "oob"}, {SegFakeRaw, "fakeraw"}, {SegKind(7), "segkind(7)"}} {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("SegKind(%d) = %q, want %q", tc.k, got, tc.want)
		}
	}
}
