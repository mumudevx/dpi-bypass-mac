package policy

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestReverseMapLearnAndLookup(t *testing.T) {
	clk := newClock()
	m := NewReverseMapClock(8, clk.now)

	// The measured Discord addresses (MEASUREMENTS.md §2): the DNS path learns
	// them, and the TCP flow that follows is named from them.
	ips := []netip.Addr{
		netip.MustParseAddr("162.159.128.233"),
		netip.MustParseAddr("162.159.136.232"),
	}
	m.Learn("Discord.com.", ips, 5*time.Minute)

	for _, ip := range ips {
		name, ok := m.Lookup(ip)
		if !ok || name != "discord.com" {
			t.Errorf("Lookup(%s) = %q, %v, want discord.com", ip, name, ok)
		}
	}
	if _, ok := m.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
		t.Error("Lookup invented a name")
	}
	if _, ok := m.Lookup(netip.Addr{}); ok {
		t.Error("Lookup accepted an invalid address")
	}
	// A 4-in-6 spelling of the same address is the same address; the netstack
	// hands v4 flows over as 4-in-6 often enough that this is load-bearing.
	if _, ok := m.Lookup(netip.MustParseAddr("::ffff:162.159.128.233")); !ok {
		t.Error("the 4-in-6 form of a learned address was not found")
	}

	// Garbage in is dropped rather than stored under a nonsense key.
	m.Learn("", ips, time.Minute)
	m.Learn("not a host", ips, time.Minute)
	m.Learn("example.com", nil, time.Minute)
	m.Learn("example.com", []netip.Addr{{}}, time.Minute)
	if name, _ := m.Lookup(ips[0]); name != "discord.com" {
		t.Errorf("a rejected Learn overwrote a good entry: %q", name)
	}
}

func TestReverseMapExpiry(t *testing.T) {
	clk := newClock()
	m := NewReverseMapClock(8, clk.now)
	ip := netip.MustParseAddr("1.2.3.4")

	// A CDN's five-second TTL is floored: the connection that follows our own
	// answer must still find the name, and it may live for minutes.
	m.Learn("cdn.example", []netip.Addr{ip}, 5*time.Second)
	clk.advance(30 * time.Second)
	if _, ok := m.Lookup(ip); !ok {
		t.Error("a short DNS TTL was not floored")
	}
	clk.advance(minReverseTTL)
	if _, ok := m.Lookup(ip); ok {
		t.Error("the entry outlived the floored TTL")
	}
	if m.(*reverseMap).Len() != 0 {
		t.Error("an expired entry was not reclaimed on lookup")
	}

	// A hostile TTL is capped.
	m.Learn("forever.example", []netip.Addr{ip}, 365*24*time.Hour)
	clk.advance(maxReverseTTL + time.Second)
	if _, ok := m.Lookup(ip); ok {
		t.Error("an over-long TTL was not capped")
	}
}

// Many names share one CDN address; the newest answer is the best guess for
// the flow that arrives next.
func TestReverseMapNewestNameWins(t *testing.T) {
	clk := newClock()
	m := NewReverseMapClock(8, clk.now)
	ip := netip.MustParseAddr("162.159.128.233")
	m.Learn("cloudflare.com", []netip.Addr{ip}, time.Minute)
	m.Learn("discord.com", []netip.Addr{ip}, time.Minute)
	if name, _ := m.Lookup(ip); name != "discord.com" {
		t.Errorf("Lookup = %q, want the most recently learned name", name)
	}
	if m.(*reverseMap).Len() != 1 {
		t.Error("relearning an address duplicated it")
	}
}

func TestReverseMapEvictsLeastRecentlyUsed(t *testing.T) {
	clk := newClock()
	m := NewReverseMapClock(3, clk.now)
	addr := func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i)) }

	for i := 1; i <= 3; i++ {
		m.Learn(fmt.Sprintf("h%d.example", i), []netip.Addr{addr(i)}, time.Minute)
	}
	// Touch the oldest so recency, not insertion order, decides.
	if _, ok := m.Lookup(addr(1)); !ok {
		t.Fatal("setup lookup failed")
	}
	m.Learn("h4.example", []netip.Addr{addr(4)}, time.Minute)

	if _, ok := m.Lookup(addr(2)); ok {
		t.Error("the least recently used entry survived eviction")
	}
	if _, ok := m.Lookup(addr(1)); !ok {
		t.Error("a recently used entry was evicted")
	}
	if got := m.(*reverseMap).Len(); got != 3 {
		t.Errorf("Len = %d, want the cap 3", got)
	}
}

func TestNewReverseMapDefaults(t *testing.T) {
	m := NewReverseMap(0).(*reverseMap)
	if m.max != defaultReverseMax || m.now == nil {
		t.Errorf("defaults not applied: max=%d now=%v", m.max, m.now != nil)
	}
	ip := netip.MustParseAddr("9.9.9.9")
	m.Learn("quad9.example", []netip.Addr{ip}, time.Hour)
	if _, ok := m.Lookup(ip); !ok {
		t.Error("the default clock did not record a live entry")
	}
}

// The DNS server learns from one goroutine while every connection looks up
// from another.
func TestReverseMapIsConcurrencySafe(t *testing.T) {
	m := NewReverseMap(64)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ip := netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i, j%256))
				m.Learn(fmt.Sprintf("h%d.example", j%16), []netip.Addr{ip}, time.Minute)
				m.Lookup(ip)
			}
		}(i)
	}
	wg.Wait()
}
