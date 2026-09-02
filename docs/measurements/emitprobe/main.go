// emitprobe compares candidate desync emitters against the local DPI, to find
// out WHICH MECHANISM defeats it: segment count, an SNI-straddling boundary,
// TLS record-layer reframing, or out-of-order delivery.
//
// Every emitter is applied to the first write only (the ClientHello). Trials are
// shuffled and a benign-SNI control is interleaved.
package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ip      = "162.159.128.233"
	blocked = "discord.com"
	control = "cloudflare.com"
	reps    = 5
)

// emitter writes the ClientHello record to the socket in some deliberate shape.
type emitter struct {
	name string
	fn   func(c *desyncConn, rec []byte) error
}

type desyncConn struct {
	*net.TCPConn
	em    *emitter
	first bool
}

func (c *desyncConn) Write(b []byte) (int, error) {
	if !c.first || c.em == nil {
		return c.TCPConn.Write(b)
	}
	c.first = false
	if err := c.em.fn(c, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *desyncConn) raw(f func(fd uintptr) error) error {
	sc, err := c.TCPConn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := sc.Control(func(fd uintptr) { inner = f(fd) }); err != nil {
		return err
	}
	return inner
}

func (c *desyncConn) setTTL(ttl int) error {
	return c.raw(func(fd uintptr) error {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
	})
}

func (c *desyncConn) sendOOB(b []byte) error {
	return c.raw(func(fd uintptr) error {
		return unix.Sendto(int(fd), b, unix.MSG_OOB, nil)
	})
}

// writeAll emits b as fixed-size TCP segments.
func chunkAll(c *desyncConn, b []byte, n int) error {
	for off := 0; off < len(b); off += n {
		end := off + n
		if end > len(b) {
			end = len(b)
		}
		if _, err := c.TCPConn.Write(b[off:end]); err != nil {
			return err
		}
	}
	return nil
}

// sniOffset finds the SNI hostname inside a ClientHello record.
func sniOffset(rec []byte, host string) int {
	h := []byte(host)
outer:
	for i := 0; i+len(h) <= len(rec); i++ {
		for j := range h {
			if rec[i+j] != h[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

// reframe splits one TLS record into k records carrying consecutive slices of
// the original fragment. Each output record is structurally valid.
func reframe(rec []byte, cuts []int) [][]byte {
	hdr, body := rec[:5], rec[5:]
	var out [][]byte
	prev := 0
	bounds := append(append([]int{}, cuts...), len(body))
	for _, b := range bounds {
		if b <= prev || b > len(body) {
			continue
		}
		frag := body[prev:b]
		r := make([]byte, 0, 5+len(frag))
		r = append(r, hdr[0], hdr[1], hdr[2], byte(len(frag)>>8), byte(len(frag)))
		r = append(r, frag...)
		out = append(out, r)
		prev = b
	}
	return out
}

func emitters() []*emitter {
	var es []*emitter
	add := func(n string, f func(*desyncConn, []byte) error) {
		es = append(es, &emitter{name: n, fn: f})
	}

	add("baseline-none", func(c *desyncConn, b []byte) error {
		_, err := c.TCPConn.Write(b)
		return err
	})

	// Pure segment-count probes.
	for _, n := range []int{1, 4, 12, 40} {
		n := n
		add(fmt.Sprintf("chunk-%d", n), func(c *desyncConn, b []byte) error { return chunkAll(c, b, n) })
	}

	// Two segments only, boundary at a fixed offset.
	for _, n := range []int{1, 2, 3, 5, 64} {
		n := n
		add(fmt.Sprintf("split2-at-%d", n), func(c *desyncConn, b []byte) error {
			if n >= len(b) {
				_, err := c.TCPConn.Write(b)
				return err
			}
			if _, err := c.TCPConn.Write(b[:n]); err != nil {
				return err
			}
			_, err := c.TCPConn.Write(b[n:])
			return err
		})
	}

	// Two segments, boundary inside the SNI hostname.
	add("split2-in-sni", func(c *desyncConn, b []byte) error {
		off := sniOffset(b, blocked)
		if off < 0 {
			off = len(b) / 2
		}
		cut := off + len(blocked)/2
		if _, err := c.TCPConn.Write(b[:cut]); err != nil {
			return err
		}
		_, err := c.TCPConn.Write(b[cut:])
		return err
	})

	// TLS record-layer fragmentation: one record becomes two, cut inside the SNI.
	add("tlsrec-in-sni", func(c *desyncConn, b []byte) error {
		off := sniOffset(b, blocked)
		if off < 0 {
			off = len(b) / 2
		}
		cut := off + len(blocked)/2 - 5 // offset within the record body
		for _, r := range reframe(b, []int{cut}) {
			if _, err := c.TCPConn.Write(r); err != nil {
				return err
			}
		}
		return nil
	})

	// TLS record fragmentation into many small records.
	add("tlsrec-many", func(c *desyncConn, b []byte) error {
		var cuts []int
		for i := 16; i < len(b)-5; i += 16 {
			cuts = append(cuts, i)
		}
		for _, r := range reframe(b, cuts) {
			if _, err := c.TCPConn.Write(r); err != nil {
				return err
			}
		}
		return nil
	})

	// Disorder: emit the first segment with TTL=1 so it dies in the network,
	// send the remainder, then let TCP retransmit the head out of order.
	add("disorder-at-3", func(c *desyncConn, b []byte) error {
		if len(b) <= 3 {
			_, err := c.TCPConn.Write(b)
			return err
		}
		if err := c.setTTL(1); err != nil {
			return err
		}
		if _, err := c.TCPConn.Write(b[:3]); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
		if err := c.setTTL(64); err != nil {
			return err
		}
		_, err := c.TCPConn.Write(b[3:])
		return err
	})

	add("disorder-in-sni", func(c *desyncConn, b []byte) error {
		off := sniOffset(b, blocked)
		if off < 0 {
			off = len(b) / 2
		}
		cut := off + len(blocked)/2
		if err := c.setTTL(1); err != nil {
			return err
		}
		if _, err := c.TCPConn.Write(b[:cut]); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
		if err := c.setTTL(64); err != nil {
			return err
		}
		_, err := c.TCPConn.Write(b[cut:])
		return err
	})

	// OOB: send one urgent byte before the real data.
	add("oob-at-1", func(c *desyncConn, b []byte) error {
		if _, err := c.TCPConn.Write(b[:1]); err != nil {
			return err
		}
		if err := c.sendOOB([]byte{0x61}); err != nil {
			return fmt.Errorf("oob: %w", err)
		}
		_, err := c.TCPConn.Write(b[1:])
		return err
	})

	return es
}

func try(sni string, em *emitter) error {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 6*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	tcp.SetNoDelay(true)
	c := &desyncConn{TCPConn: tcp, em: em, first: true}
	tc := tls.Client(c, &tls.Config{ServerName: sni})
	tc.SetDeadline(time.Now().Add(8 * time.Second))
	return tc.Handshake()
}

type job struct {
	em      *emitter
	ctl     bool
}

func main() {
	es := emitters()
	var queue []job
	for i := 0; i < reps; i++ {
		for _, e := range es {
			queue = append(queue, job{em: e})
		}
		queue = append(queue, job{em: es[0], ctl: true})
	}
	r := rand.New(rand.NewSource(902))
	r.Shuffle(len(queue), func(i, j int) { queue[i], queue[j] = queue[j], queue[i] })

	ok := map[string]int{}
	tot := map[string]int{}
	errs := map[string]string{}
	okCtl, nCtl := 0, 0

	fmt.Printf("%d shuffled trials over %d emitters, %d reps each\n", len(queue), len(es), reps)
	for i, j := range queue {
		sni := blocked
		if j.ctl {
			sni = control
		}
		err := try(sni, j.em)
		if j.ctl {
			nCtl++
			if err == nil {
				okCtl++
			}
			continue
		}
		tot[j.em.name]++
		if err == nil {
			ok[j.em.name]++
		} else {
			e := err.Error()
			if len(e) > 60 {
				e = e[len(e)-60:]
			}
			errs[j.em.name] = e
		}
		if i%25 == 24 {
			fmt.Printf("  ...%d/%d\n", i+1, len(queue))
		}
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Printf("\ncontrol (%s, same IP): %d/%d OK\n\n", control, okCtl, nCtl)
	names := make([]string, 0, len(tot))
	for n := range tot {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if ok[names[i]] != ok[names[j]] {
			return ok[names[i]] > ok[names[j]]
		}
		return names[i] < names[j]
	})
	fmt.Printf("%-18s %-8s %-7s %s\n", "emitter", "ok", "verdict", "last error")
	for _, n := range names {
		v := "FAIL"
		if ok[n] == tot[n] {
			v = "PASS"
		} else if ok[n] > 0 {
			v = "FLAKY"
		}
		fmt.Printf("%-18s %d/%-6d %-7s %s\n", n, ok[n], tot[n], v, errs[n])
	}
}
