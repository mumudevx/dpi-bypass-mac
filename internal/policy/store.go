package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store is the durable verdict cache. MEASUREMENTS.md §5.2 requires both
// outcomes to be remembered — "cache the winning strategy per hostname, with a
// TTL, persisted across restarts" and "cache 'plain works' just as durably, so
// a bank is desynced at most once, ever" — so this is not an optimisation
// either: without it every restart re-desyncs every fragile host once.
type Store interface {
	Get(net NetworkID, host string) (Verdict, bool)
	Put(net NetworkID, host string, v Verdict) error
	Demote(net NetworkID, host string) error
	ForEach(net NetworkID, fn func(host string, v Verdict) bool)
	Flush() error
	Close() error
}

const (
	// HostCap is the per-network LRU cap. A sizing choice, not a measurement:
	// 4096 hosts is far more than a browsing session touches, and the whole
	// file still encodes in well under a megabyte.
	HostCap = 4096
	// NetworkCap bounds how many networks are remembered. A laptop sees a
	// handful; the cap only stops an unbounded file on a machine that roams.
	NetworkCap = 32
	// DemoteThreshold is the "three consecutive failures on a cached winner
	// reset the host to unknown and re-walk from plain" rule. Demote counts;
	// the caller does not have to.
	DemoteThreshold = 3

	// flushInterval and flushPending bound how much learning a SIGKILL can
	// cost. Losing a verdict costs one extra round trip on the next visit and
	// nothing else, so this trades durability for staying off the connection
	// path — deliberately, and only in the harmless direction.
	flushInterval = 5 * time.Second
	flushPending  = 64

	storeVersion = 1
)

type storeFile struct {
	Version  int                   `json:"version"`
	Networks map[string]*netRecord `json:"networks"`
}

type netRecord struct {
	Used  time.Time          `json:"used"`
	Hosts map[string]*record `json:"hosts"`
}

type record struct {
	Verdict Verdict   `json:"verdict"`
	Used    time.Time `json:"used"`
}

// fileStore is the shipped Store. A path of "" makes it memory-only, which is
// what tests and `--no-learn`-adjacent callers want without a second type.
type fileStore struct {
	mu   sync.Mutex
	path string
	now  func() time.Time

	nets map[string]*netRecord

	dirty     bool
	pending   int
	lastFlush time.Time
	closed    bool
}

var _ Store = (*fileStore)(nil)

// OpenStore opens (or creates) the verdict store at path. A corrupt or
// truncated file is moved aside rather than deleted and the store starts
// empty: losing a cache is recoverable, and keeping the evidence is how the
// corruption gets diagnosed.
func OpenStore(path string, now func() time.Time) (Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &fileStore{
		path:      path,
		now:       now,
		nets:      make(map[string]*netRecord),
		lastFlush: now(),
	}
	if path == "" {
		return s, nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("policy: create store directory: %w", err)
		}
	}
	// Sweep temp files left by a process that died mid-write. They can never
	// have been renamed into place, so they are pure litter.
	if matches, err := filepath.Glob(path + ".tmp-*"); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}

	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("policy: read verdict store %s: %w", path, err)
	}
	var f storeFile
	if err := json.Unmarshal(b, &f); err != nil || f.Version != storeVersion {
		if rerr := os.Rename(path, path+".corrupt"); rerr != nil {
			_ = os.Remove(path)
		}
		return s, nil
	}
	for k, nr := range f.Networks {
		if nr == nil {
			continue
		}
		if nr.Hosts == nil {
			nr.Hosts = make(map[string]*record)
		}
		s.nets[k] = nr
	}
	return s, nil
}

// NopStore returns a Store that remembers nothing. It backs --no-learn, and it
// is a real object rather than a nil check so no caller has to remember one.
func NopStore() Store { return nopStore{} }

type nopStore struct{}

func (nopStore) Get(NetworkID, string) (Verdict, bool) { return Verdict{}, false }
func (nopStore) Put(NetworkID, string, Verdict) error  { return nil }
func (nopStore) Demote(NetworkID, string) error        { return nil }
func (nopStore) ForEach(NetworkID, func(string, Verdict) bool) {
	// Nothing is stored, so nothing is visited. The explicit return is not
	// decoration: an empty body reports 0.0% coverage, and `make cover-gate`
	// treats a 0.0% function in this package as a build failure.
	return
}
func (nopStore) Flush() error { return nil }
func (nopStore) Close() error { return nil }

// Get returns the verdict for (net, host) if one is cached and unexpired. An
// expired entry is dropped on the spot, which is how GT20's "Roblox was
// unblocked after 680 days" gets rediscovered.
func (s *fileStore) Get(net NetworkID, host string) (Verdict, bool) {
	key := Normalize(host)
	if key == "" {
		return Verdict{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nr := s.nets[net.Key()]
	if nr == nil {
		return Verdict{}, false
	}
	rec := nr.Hosts[key]
	if rec == nil {
		return Verdict{}, false
	}
	now := s.now()
	if rec.Verdict.Expired(now) {
		delete(nr.Hosts, key)
		s.dirty = true
		return Verdict{}, false
	}
	// Touch for LRU only. A recency update is not worth a disk write: losing
	// it can at worst evict a slightly wrong entry once the cap is reached.
	rec.Used = now
	nr.Used = now
	return rec.Verdict.clone(), true
}

// Put records a verdict. Learned is stamped if the caller left it zero.
func (s *fileStore) Put(net NetworkID, host string, v Verdict) error {
	key := Normalize(host)
	if key == "" {
		return fmt.Errorf("policy: store put: %q is not a usable host key", host)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("policy: store is closed")
	}
	now := s.now()
	if v.Learned.IsZero() {
		v.Learned = now
	}
	nk := net.Key()
	nr := s.nets[nk]
	if nr == nil {
		nr = &netRecord{Hosts: make(map[string]*record)}
		s.nets[nk] = nr
		s.evictNetworks(nk)
	}
	nr.Used = now
	nr.Hosts[key] = &record{Verdict: v.clone(), Used: now}
	s.evictHosts(nr)
	s.dirty = true
	s.pending++
	flush := s.shouldFlush(now)
	s.mu.Unlock()
	if flush {
		return s.Flush()
	}
	return nil
}

// Demote applies the failure rule from the plan's runtime-adaptation section:
// three consecutive failures on a cached winner reset the host to unknown so
// the ladder is re-walked from plain. Counting lives here rather than in the
// caller so every front end agrees on what "demoted" means.
func (s *fileStore) Demote(net NetworkID, host string) error {
	key := Normalize(host)
	if key == "" {
		return fmt.Errorf("policy: store demote: %q is not a usable host key", host)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("policy: store is closed")
	}
	nk := net.Key()
	nr := s.nets[nk]
	if nr == nil {
		s.mu.Unlock()
		return nil
	}
	rec := nr.Hosts[key]
	if rec == nil {
		s.mu.Unlock()
		return nil
	}
	now := s.now()
	rec.Verdict.Losses++
	rec.Used = now
	nr.Used = now
	if rec.Verdict.Losses >= DemoteThreshold {
		delete(nr.Hosts, key)
	}
	s.dirty = true
	s.pending++
	flush := s.shouldFlush(now)
	s.mu.Unlock()
	if flush {
		return s.Flush()
	}
	return nil
}

// ForEach visits every unexpired verdict for one network. Returning false from
// fn stops the walk.
func (s *fileStore) ForEach(net NetworkID, fn func(host string, v Verdict) bool) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	nr := s.nets[net.Key()]
	if nr == nil {
		s.mu.Unlock()
		return
	}
	now := s.now()
	type kv struct {
		host string
		v    Verdict
	}
	out := make([]kv, 0, len(nr.Hosts))
	for h, rec := range nr.Hosts {
		if rec.Verdict.Expired(now) {
			continue
		}
		out = append(out, kv{host: h, v: rec.Verdict.clone()})
	}
	s.mu.Unlock()
	// The callback runs outside the lock: `dpb cache list` writes to a socket
	// from it, and holding the store lock across that would stall every
	// connection.
	for _, e := range out {
		if !fn(e.host, e.v) {
			return
		}
	}
}

// Flush writes the store to disk atomically: a fully written and fsynced temp
// file is renamed over the target, so a crash at any instant leaves either the
// previous store or the new one, never a half-written mixture.
func (s *fileStore) Flush() error {
	s.mu.Lock()
	if s.path == "" || !s.dirty {
		s.mu.Unlock()
		return nil
	}
	f := storeFile{Version: storeVersion, Networks: make(map[string]*netRecord, len(s.nets))}
	now := s.now()
	for k, nr := range s.nets {
		hosts := make(map[string]*record, len(nr.Hosts))
		for h, rec := range nr.Hosts {
			if rec.Verdict.Expired(now) {
				continue
			}
			hosts[h] = &record{Verdict: rec.Verdict, Used: rec.Used}
		}
		f.Networks[k] = &netRecord{Used: nr.Used, Hosts: hosts}
	}
	path := s.path
	s.mu.Unlock()

	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("policy: encode verdict store: %w", err)
	}
	if err := writeFileAtomic(path, b); err != nil {
		return err
	}

	s.mu.Lock()
	s.dirty = false
	s.pending = 0
	s.lastFlush = now
	s.mu.Unlock()
	return nil
}

// Close flushes and marks the store unusable. It is idempotent.
func (s *fileStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.Flush()
}

// shouldFlush is called with the lock held.
func (s *fileStore) shouldFlush(now time.Time) bool {
	if s.path == "" || !s.dirty {
		return false
	}
	return s.pending >= flushPending || now.Sub(s.lastFlush) >= flushInterval
}

// evictHosts drops the least recently used entries once the per-network cap is
// exceeded. A linear scan beats sorting here: it runs only at the cap and only
// once per Put.
func (s *fileStore) evictHosts(nr *netRecord) {
	for len(nr.Hosts) > HostCap {
		var oldestKey string
		var oldest time.Time
		for h, rec := range nr.Hosts {
			if oldestKey == "" || rec.Used.Before(oldest) {
				oldestKey, oldest = h, rec.Used
			}
		}
		delete(nr.Hosts, oldestKey)
	}
}

// evictNetworks keeps the newest NetworkCap namespaces, never evicting the one
// just created.
func (s *fileStore) evictNetworks(keep string) {
	for len(s.nets) > NetworkCap {
		var oldestKey string
		var oldest time.Time
		for k, nr := range s.nets {
			if k == keep {
				continue
			}
			if oldestKey == "" || nr.Used.Before(oldest) {
				oldestKey, oldest = k, nr.Used
			}
		}
		if oldestKey == "" {
			return
		}
		delete(s.nets, oldestKey)
	}
}

func (v Verdict) clone() Verdict {
	v.Ladder = append([]string(nil), v.Ladder...)
	return v
}

// writeFileAtomic is the write half of the durability promise: temp file in
// the same directory (so rename cannot cross a filesystem), fsync the data,
// rename, then fsync the directory so the rename itself survives power loss.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("policy: create temp store: %w", err)
	}
	name := tmp.Name()
	defer func() {
		// Removing a file that was successfully renamed is a no-op error we
		// deliberately ignore; leaving one behind would be litter the next
		// OpenStore has to sweep.
		_ = os.Remove(name)
	}()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("policy: write temp store: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("policy: sync temp store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("policy: close temp store: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("policy: rename temp store: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil // the data is already durable; only the rename is at risk
	}
	defer d.Close()
	_ = d.Sync()
	return nil
}
