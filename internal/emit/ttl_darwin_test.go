//go:build darwin

package emit

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/strategy"
)

// TestHopLimitFallsBackToTheOtherFamily is the dual-stack case in miniature: an
// AF_INET socket asked for IPV6_UNICAST_HOPS. The real occurrence is the mirror
// image — an AF_INET6 socket carrying a v4-mapped peer, where IP_TTL returns
// EINVAL — and getting the family wrong there would mean every disorder segment
// silently going out at the default hop limit.
func TestHopLimitFallsBackToTheOtherFamily(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")

	if err := setHopLimit(st.rc, true, 5); err != nil {
		t.Fatalf("setHopLimit with the wrong family did not fall back: %v", err)
	}
	got, err := getHopLimit(st.rc, true)
	if err != nil {
		t.Fatalf("getHopLimit with the wrong family did not fall back: %v", err)
	}
	if got != 5 {
		t.Fatalf("hop limit = %d, want 5", got)
	}
}

func TestHopLimitFailsOnAClosedSocket(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := setHopLimit(st.rc, false, 1); err == nil {
		t.Fatal("setHopLimit succeeded on a closed socket")
	}
	if _, err := getHopLimit(st.rc, false); err == nil {
		t.Fatal("getHopLimit succeeded on a closed socket")
	}
	if _, err := sendOOB(st.rc, []byte{'X'}); err == nil {
		t.Fatal("sendOOB succeeded on a closed socket")
	}
}

// TestCapabilitiesAreWithheldWithAReason covers the machine where the sysctl read
// fails: CapSockTTL is withheld, and every call that needed it must say which
// capability is missing rather than silently emitting the plan unmodified.
func TestCapabilitiesAreWithheldWithAReason(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	st.caps = strategy.CapStreamWrite | strategy.CapNoDelay

	for name, err := range map[string]error{
		"SetTTL":   st.SetTTL(1),
		"ResetTTL": st.ResetTTL(),
	} {
		if !errors.Is(err, ErrCapUnavailable) {
			t.Fatalf("%s err = %v, want ErrCapUnavailable", name, err)
		}
		if !strings.Contains(err.Error(), "sockttl") {
			t.Fatalf("%s err = %v, must name the missing capability", name, err)
		}
	}
	if _, err := st.WriteOOB([]byte{'X'}); !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("WriteOOB err = %v, want ErrCapUnavailable", err)
	}
}

func TestUDPCapabilitiesAreWithheldWithAReason(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()

	ut, err := NewUDPTransport(client)
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	ut.caps = strategy.CapStreamWrite | strategy.CapNoDelay

	if err := ut.SetTTL(2); !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("SetTTL err = %v, want ErrCapUnavailable", err)
	}
	if err := ut.ResetTTL(); !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("ResetTTL err = %v, want ErrCapUnavailable", err)
	}
}
