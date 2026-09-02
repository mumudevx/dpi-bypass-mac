package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func netA() NetworkID {
	return NetworkID{Kind: "wifi", SSID: "home", ResolverSet: "aaa"}
}

func netB() NetworkID {
	return NetworkID{Kind: "cellular", SSID: "", ResolverSet: "bbb"}
}

func desyncVerdict(spec string, expires time.Time) Verdict {
	return Verdict{
		Class:   ScopeDesync,
		Spec:    spec,
		Ladder:  []string{"", "tlsfrag:pos=snimid"},
		Source:  SrcLearnedDesync,
		Expires: expires,
	}
}

// A verdict learned on one network must never be replayed on another: the
// middlebox is a property of the line, not of the laptop.
func TestStoreIsNamespacedByNetworkID(t *testing.T) {
	clk := newClock()
	path := filepath.Join(t.TempDir(), "verdicts.json")
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	if err := s.Put(netA(), "discord.com", desyncVerdict("tlsfrag:pos=snimid", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if v, ok := s.Get(netA(), "discord.com"); !ok || v.Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("Get on network A = %+v, %v", v, ok)
	}
	if v, ok := s.Get(netB(), "discord.com"); ok {
		t.Fatalf("Get on network B returned %+v, want not-found", v)
	}
	// Host lookups are normalised, so a CONNECT for DISCORD.COM. hits the same
	// entry the DNS path wrote.
	if _, ok := s.Get(netA(), "DISCORD.COM."); !ok {
		t.Error("Get did not normalise the host key")
	}
	if _, ok := s.Get(netA(), "unknown.example"); ok {
		t.Error("Get invented an entry")
	}
	if _, ok := s.Get(netA(), "not a host"); ok {
		t.Error("Get accepted an unusable key")
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	clk := newClock()
	path := filepath.Join(t.TempDir(), "sub", "verdicts.json")
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := s.Put(netA(), "discord.com", desyncVerdict("chunk:size=12", clk.now().Add(7*24*time.Hour))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	plain := Verdict{Class: ScopeDirect, Source: SrcLearnedPlain}
	if err := s.Put(netA(), "isbank.com.tr", plain); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	s2, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	v, ok := s2.Get(netA(), "discord.com")
	if !ok || v.Spec != "chunk:size=12" || v.Source != SrcLearnedDesync {
		t.Fatalf("after reopen = %+v, %v", v, ok)
	}
	if len(v.Ladder) != 2 || v.Ladder[1] != "tlsfrag:pos=snimid" {
		t.Errorf("ladder did not survive the round trip: %v", v.Ladder)
	}
	if v.Learned.IsZero() {
		t.Error("Learned was not stamped")
	}
	// MEASUREMENTS.md §5.2: "plain works" must be as durable as a desync
	// winner, so a bank is desynced at most once, ever.
	if v2, ok := s2.Get(netA(), "isbank.com.tr"); !ok || v2.Source != SrcLearnedPlain {
		t.Fatalf("learned-plain did not survive: %+v %v", v2, ok)
	}

	hosts := map[string]bool{}
	s2.ForEach(netA(), func(h string, _ Verdict) bool {
		hosts[h] = true
		return true
	})
	if !hosts["discord.com"] || !hosts["isbank.com.tr"] || len(hosts) != 2 {
		t.Errorf("ForEach = %v", hosts)
	}
	n := 0
	s2.ForEach(netA(), func(string, Verdict) bool { n++; return false })
	if n != 1 {
		t.Errorf("ForEach ignored a false return: visited %d", n)
	}
	s2.ForEach(netB(), func(string, Verdict) bool { t.Error("visited an empty network"); return true })
	s2.ForEach(netA(), nil)
}

// The crash case the plan names: a truncated temp file must never be mistaken
// for the store. Because the temp file is only renamed after a complete
// fsynced write, reopening finds the previous store byte-intact.
func TestStoreSurvivesATruncatedTempFile(t *testing.T) {
	clk := newClock()
	dir := t.TempDir()
	path := filepath.Join(dir, "verdicts.json")
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := s.Put(netA(), "discord.com", desyncVerdict("tlsfrag:pos=snimid", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}

	// Simulate SIGKILL midway through the next write.
	tmp := path + ".tmp-123456"
	if err := os.WriteFile(tmp, good[:len(good)/2], 0o600); err != nil {
		t.Fatalf("write truncated temp: %v", err)
	}

	s2, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if v, ok := s2.Get(netA(), "discord.com"); !ok || v.Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("previous store was not intact: %+v %v", v, ok)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("the stale temp file was not swept on open")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(good) {
		t.Error("the store file changed on open")
	}
}

// Flush must leave no litter behind: a temp file that outlives the rename
// would accumulate on every write.
func TestFlushLeavesNoTempFiles(t *testing.T) {
	clk := newClock()
	dir := t.TempDir()
	path := filepath.Join(dir, "verdicts.json")
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()
	for i := 0; i < 3; i++ {
		if err := s.Put(netA(), fmt.Sprintf("h%d.example", i), Verdict{Source: SrcLearnedPlain}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "verdicts.json" {
		names := make([]string, len(ents))
		for i, e := range ents {
			names[i] = e.Name()
		}
		t.Errorf("directory holds %v, want only the store", names)
	}
	// A Flush with nothing dirty must not rewrite the file.
	if err := s.Flush(); err != nil {
		t.Fatalf("no-op Flush: %v", err)
	}
}

func TestStoreMovesACorruptFileAside(t *testing.T) {
	clk := newClock()
	dir := t.TempDir()
	path := filepath.Join(dir, "verdicts.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore on a corrupt file: %v", err)
	}
	defer s.Close()
	if _, ok := s.Get(netA(), "discord.com"); ok {
		t.Error("a corrupt store produced entries")
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Errorf("the corrupt file was not preserved for diagnosis: %v", err)
	}

	// A file from a future format version is treated the same way.
	path2 := filepath.Join(dir, "v2.json")
	if err := os.WriteFile(path2, []byte(`{"version":99,"networks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(path2, clk.now)
	if err != nil {
		t.Fatalf("OpenStore on a future version: %v", err)
	}
	defer s2.Close()
	if _, err := os.Stat(path2 + ".corrupt"); err != nil {
		t.Errorf("the unreadable version was not preserved: %v", err)
	}
}

func TestStoreOpenErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(filepath.Join(blocker, "sub", "verdicts.json"), nil); err == nil {
		t.Error("OpenStore succeeded with a file where a directory belongs")
	}
	// A directory in place of the store file is a read error, not a corrupt
	// store: destroying a directory the user pointed us at would be worse.
	if _, err := OpenStore(dir, nil); err == nil {
		t.Error("OpenStore succeeded on a directory")
	}
}

func TestStoreExpiry(t *testing.T) {
	clk := newClock()
	s, err := OpenStore("", clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	// verdict_ttl_desync is 7d (GT21's months-scale rot cadence); the entry
	// must be gone after it, so a lifted block is rediscovered.
	if err := s.Put(netA(), "discord.com", desyncVerdict("tlsfrag:pos=snimid", clk.now().Add(7*24*time.Hour))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// verdict_ttl_plain never expires.
	if err := s.Put(netA(), "isbank.com.tr", Verdict{Source: SrcLearnedPlain}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	clk.advance(7*24*time.Hour - time.Second)
	if _, ok := s.Get(netA(), "discord.com"); !ok {
		t.Error("the desync verdict expired early")
	}
	clk.advance(2 * time.Second)
	if _, ok := s.Get(netA(), "discord.com"); ok {
		t.Error("the desync verdict outlived its TTL")
	}
	if _, ok := s.Get(netA(), "isbank.com.tr"); !ok {
		t.Error("the never-expiring plain verdict was dropped")
	}

	seen := 0
	s.ForEach(netA(), func(string, Verdict) bool { seen++; return true })
	if seen != 1 {
		t.Errorf("ForEach visited %d entries, want only the unexpired one", seen)
	}
}

// Three consecutive failures on a cached winner reset the host to unknown so
// the ladder is re-walked from plain.
func TestDemoteResetsAfterThreeFailures(t *testing.T) {
	clk := newClock()
	s, err := OpenStore("", clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()
	if err := s.Put(netA(), "discord.com", desyncVerdict("chunk:size=12", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for i := 1; i < DemoteThreshold; i++ {
		if err := s.Demote(netA(), "discord.com"); err != nil {
			t.Fatalf("Demote: %v", err)
		}
		v, ok := s.Get(netA(), "discord.com")
		if !ok {
			t.Fatalf("entry vanished after %d failures, want %d", i, DemoteThreshold)
		}
		if v.Losses != i {
			t.Errorf("Losses = %d after %d demotions", v.Losses, i)
		}
	}
	if err := s.Demote(netA(), "discord.com"); err != nil {
		t.Fatalf("Demote: %v", err)
	}
	if _, ok := s.Get(netA(), "discord.com"); ok {
		t.Fatalf("entry survived %d failures", DemoteThreshold)
	}

	// Demoting something that is not there is not an error; the caller races
	// with expiry and with a concurrent demotion from another connection.
	if err := s.Demote(netA(), "discord.com"); err != nil {
		t.Errorf("Demote of a missing host: %v", err)
	}
	if err := s.Demote(netB(), "discord.com"); err != nil {
		t.Errorf("Demote on an unknown network: %v", err)
	}
	if err := s.Demote(netA(), "not a host"); err == nil {
		t.Error("Demote accepted an unusable key")
	}
	if err := s.Put(netA(), "not a host", Verdict{}); err == nil {
		t.Error("Put accepted an unusable key")
	}
}

func TestStoreEvictsLeastRecentlyUsed(t *testing.T) {
	clk := newClock()
	s, err := OpenStore("", clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()
	fs := s.(*fileStore)

	for i := 0; i <= HostCap; i++ {
		clk.advance(time.Second)
		if err := fs.Put(netA(), fmt.Sprintf("h%d.example", i), Verdict{Source: SrcLearnedPlain}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if got := len(fs.nets[netA().Key()].Hosts); got != HostCap {
		t.Fatalf("host count = %d, want the cap %d", got, HostCap)
	}
	if _, ok := fs.Get(netA(), "h0.example"); ok {
		t.Error("the oldest entry was not evicted")
	}
	if _, ok := fs.Get(netA(), fmt.Sprintf("h%d.example", HostCap)); !ok {
		t.Error("the newest entry was evicted")
	}

	for i := 0; i <= NetworkCap; i++ {
		clk.advance(time.Second)
		n := NetworkID{Kind: "wifi", SSID: fmt.Sprintf("net%d", i)}
		if err := fs.Put(n, "discord.com", Verdict{Source: SrcLearnedPlain}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if len(fs.nets) > NetworkCap {
		t.Errorf("network count = %d, want at most %d", len(fs.nets), NetworkCap)
	}
	if _, ok := fs.Get(NetworkID{Kind: "wifi", SSID: "net0"}, "discord.com"); ok {
		t.Error("the oldest network namespace was not evicted")
	}
}

// The store must stay off the connection path, so writes coalesce: a burst of
// puts produces one file write, and time alone eventually forces one.
func TestStoreCoalescesWrites(t *testing.T) {
	clk := newClock()
	path := filepath.Join(t.TempDir(), "verdicts.json")
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	if err := s.Put(netA(), "a.example", Verdict{Source: SrcLearnedPlain}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a single Put wrote to disk immediately")
	}
	clk.advance(flushInterval)
	if err := s.Put(netA(), "b.example", Verdict{Source: SrcLearnedPlain}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the flush interval did not force a write: %v", err)
	}

	// The pending-count trigger fires without the clock moving at all.
	path2 := filepath.Join(t.TempDir(), "verdicts.json")
	s2, err := OpenStore(path2, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s2.Close()
	for i := 0; i < flushPending; i++ {
		if err := s2.Put(netA(), fmt.Sprintf("h%d.example", i), Verdict{Source: SrcLearnedPlain}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if _, err := os.Stat(path2); err != nil {
		t.Errorf("the pending-write trigger did not fire: %v", err)
	}
}

func TestStoreRejectsUseAfterClose(t *testing.T) {
	s, err := OpenStore("", nil)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Put(netA(), "discord.com", Verdict{}); err == nil {
		t.Error("Put succeeded after Close")
	}
	if err := s.Demote(netA(), "discord.com"); err == nil {
		t.Error("Demote succeeded after Close")
	}
}

func TestNopStore(t *testing.T) {
	s := NopStore()
	if err := s.Put(netA(), "discord.com", desyncVerdict("chunk:size=12", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get(netA(), "discord.com"); ok {
		t.Error("NopStore remembered something")
	}
	s.ForEach(netA(), func(string, Verdict) bool { t.Error("NopStore visited an entry"); return true })
	if err := s.Demote(netA(), "discord.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// The store is read and written from every connection goroutine at once.
func TestStoreIsConcurrencySafe(t *testing.T) {
	clk := newClock()
	path := filepath.Join(t.TempDir(), "verdicts.json")
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("h%d.example", i%3)
			for j := 0; j < 50; j++ {
				if err := s.Put(netA(), host, desyncVerdict("chunk:size=12", time.Time{})); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
				s.Get(netA(), host)
				_ = s.Demote(netA(), host)
				s.ForEach(netA(), func(string, Verdict) bool { return true })
				if err := s.Flush(); err != nil {
					t.Errorf("Flush: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if !strings.HasPrefix(string(b), `{"version":1`) {
		t.Errorf("store file is not a complete document: %.40q", b)
	}
}

// A cached verdict is on disk for up to seven days, so its encoding must not
// depend on the numeric value of an iota constant.
func TestVerdictEncodesClassAndSourceAsNames(t *testing.T) {
	clk := newClock()
	path := filepath.Join(t.TempDir(), "verdicts.json")
	s, err := OpenStore(path, clk.now)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := s.Put(netA(), "discord.com", desyncVerdict("tlsfrag:pos=snimid", time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"Class":"desync"`) ||
		!strings.Contains(string(b), `"Source":"learned-desync"`) {
		t.Errorf("store encodes enums numerically: %s", b)
	}

	var c ScopeClass
	if err := c.UnmarshalText([]byte("watch")); err != nil || c != ScopeWatch {
		t.Errorf("UnmarshalText(watch) = %v, %v", c, err)
	}
	if err := c.UnmarshalText([]byte("nope")); err == nil {
		t.Error("UnmarshalText accepted an unknown class")
	}
	var src Source
	if err := src.UnmarshalText([]byte("probed")); err != nil || src != SrcProbed {
		t.Errorf("UnmarshalText(probed) = %v, %v", src, err)
	}
	if err := src.UnmarshalText([]byte("nope")); err == nil {
		t.Error("UnmarshalText accepted an unknown source")
	}
	if _, err := ScopeClass(9).MarshalText(); err == nil {
		t.Error("MarshalText accepted an out-of-range class")
	}
	if _, err := Source(9).MarshalText(); err == nil {
		t.Error("MarshalText accepted an out-of-range source")
	}
	if ScopeClass(9).String() == "" || Source(9).String() == "" {
		t.Error("String must stay printable for an out-of-range value")
	}
	if ScopeWatch.String() != "watch" || SrcLearnedPlain.String() != "learned-plain" {
		t.Error("String names drifted from the wire names")
	}
}
