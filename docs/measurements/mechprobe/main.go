// mechprobe isolates WHICH property of an emitter defeats the DPI, across
// several blocked targets, so the answer is a mechanism rather than a magic
// number tied to one hostname.
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

type target struct{ host, ip string }

var targets = []target{
	{"discord.com", "162.159.128.233"},
	{"discord.gg", "162.159.136.234"},
	{"cdn.discordapp.com", "162.159.129.233"},
}

const reps = 3

type emitter struct {
	name string
	fn   func(c *dconn, rec []byte) error
}

type dconn struct {
	*net.TCPConn
	em    *emitter
	host  string
	first bool
}

func (c *dconn) Write(b []byte) (int, error) {
	if !c.first || c.em == nil {
		return c.TCPConn.Write(b)
	}
	c.first = false
	if err := c.em.fn(c, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *dconn) sendOOB(b []byte) error {
	sc, err := c.TCPConn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := sc.Control(func(fd uintptr) {
		inner = unix.Sendto(int(fd), b, unix.MSG_OOB, nil)
	}); err != nil {
		return err
	}
	return inner
}

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

// reframe splits one TLS record into consecutive records at the given body cuts.
func reframe(rec []byte, cuts []int) [][]byte {
	hdr, body := rec[:5], rec[5:]
	var out [][]byte
	prev := 0
	for _, b := range append(append([]int{}, cuts...), len(body)) {
		if b <= prev || b > len(body) {
			continue
		}
		f := body[prev:b]
		r := make([]byte, 0, 5+len(f))
		r = append(r, hdr[0], hdr[1], hdr[2], byte(len(f)>>8), byte(len(f)))
		r = append(r, f...)
		out = append(out, r)
		prev = b
	}
	return out
}

func writeRecs(c *dconn, recs [][]byte) error {
	if len(recs) < 2 {
		_, err := c.TCPConn.Write(recs[0])
		return err
	}
	for _, r := range recs {
		if _, err := c.TCPConn.Write(r); err != nil {
			return err
		}
	}
	return nil
}

func emitters() []*emitter {
	var es []*emitter
	add := func(n string, f func(*dconn, []byte) error) { es = append(es, &emitter{n, f}) }

	add("baseline", func(c *dconn, b []byte) error { _, e := c.TCPConn.Write(b); return e })

	add("chunk-4", func(c *dconn, b []byte) error {
		for off := 0; off < len(b); off += 4 {
			end := off + 4
			if end > len(b) {
				end = len(b)
			}
			if _, err := c.TCPConn.Write(b[off:end]); err != nil {
				return err
			}
		}
		return nil
	})

	// Two TLS records, cut at a fixed body offset — does position matter?
	for _, n := range []int{1, 5, 20, 100, 400} {
		n := n
		add(fmt.Sprintf("tlsrec2-at-%d", n), func(c *dconn, b []byte) error {
			return writeRecs(c, reframe(b, []int{n}))
		})
	}

	// Two TLS records, cut inside the SNI hostname.
	add("tlsrec2-in-sni", func(c *dconn, b []byte) error {
		off := sniOffset(b, c.host)
		cut := len(b) / 2
		if off >= 0 {
			cut = off + len(c.host)/2 - 5
		}
		return writeRecs(c, reframe(b, []int{cut}))
	})

	// Many small TLS records.
	for _, step := range []int{16, 64, 256} {
		step := step
		add(fmt.Sprintf("tlsrec-every-%d", step), func(c *dconn, b []byte) error {
			var cuts []int
			for i := step; i < len(b)-5; i += step {
				cuts = append(cuts, i)
			}
			return writeRecs(c, reframe(b, cuts))
		})
	}

	// Two TLS records emitted inside ONE TCP segment — separates record-layer
	// reframing from TCP segmentation as the operative mechanism.
	add("tlsrec2-1seg", func(c *dconn, b []byte) error {
		off := sniOffset(b, c.host)
		cut := len(b) / 2
		if off >= 0 {
			cut = off + len(c.host)/2 - 5
		}
		recs := reframe(b, []int{cut})
		var joined []byte
		for _, r := range recs {
			joined = append(joined, r...)
		}
		_, err := c.TCPConn.Write(joined)
		return err
	})

	for _, n := range []int{1, 3} {
		n := n
		add(fmt.Sprintf("oob-at-%d", n), func(c *dconn, b []byte) error {
			if _, err := c.TCPConn.Write(b[:n]); err != nil {
				return err
			}
			if err := c.sendOOB([]byte{0x61}); err != nil {
				return fmt.Errorf("oob: %w", err)
			}
			_, err := c.TCPConn.Write(b[n:])
			return err
		})
	}
	return es
}

func try(t target, sni string, em *emitter) error {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(t.ip, "443"), 6*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	tcp.SetNoDelay(true)
	c := &dconn{TCPConn: tcp, em: em, host: sni, first: true}
	tc := tls.Client(c, &tls.Config{ServerName: sni})
	tc.SetDeadline(time.Now().Add(8 * time.Second))
	return tc.Handshake()
}

type job struct {
	t   target
	em  *emitter
	ctl bool
}

func main() {
	es := emitters()
	var queue []job
	for i := 0; i < reps; i++ {
		for _, t := range targets {
			for _, e := range es {
				queue = append(queue, job{t: t, em: e})
			}
		}
		queue = append(queue, job{t: targets[0], em: es[0], ctl: true})
	}
	r := rand.New(rand.NewSource(4242))
	r.Shuffle(len(queue), func(i, j int) { queue[i], queue[j] = queue[j], queue[i] })

	type key struct{ em, host string }
	ok := map[key]int{}
	tot := map[key]int{}
	okCtl, nCtl := 0, 0

	fmt.Printf("%d shuffled trials: %d emitters x %d targets x %d reps\n", len(queue), len(es), len(targets), reps)
	for i, j := range queue {
		sni := j.t.host
		if j.ctl {
			sni = "cloudflare.com"
		}
		err := try(j.t, sni, j.em)
		if j.ctl {
			nCtl++
			if err == nil {
				okCtl++
			}
			continue
		}
		k := key{j.em.name, j.t.host}
		tot[k]++
		if err == nil {
			ok[k]++
		}
		if i%30 == 29 {
			fmt.Printf("  ...%d/%d\n", i+1, len(queue))
		}
		time.Sleep(180 * time.Millisecond)
	}

	fmt.Printf("\ncontrol (cloudflare.com): %d/%d OK\n\n", okCtl, nCtl)
	fmt.Printf("%-18s", "emitter")
	for _, t := range targets {
		fmt.Printf(" %-20s", t.host)
	}
	fmt.Printf(" %s\n", "verdict")
	for _, e := range es {
		fmt.Printf("%-18s", e.name)
		all, any := true, false
		for _, t := range targets {
			k := key{e.name, t.host}
			fmt.Printf(" %-20s", fmt.Sprintf("%d/%d", ok[k], tot[k]))
			if ok[k] != tot[k] {
				all = false
			}
			if ok[k] > 0 {
				any = true
			}
		}
		v := "FAIL"
		if all {
			v = "PASS-ALL"
		} else if any {
			v = "PARTIAL"
		}
		fmt.Printf(" %s\n", v)
	}
	_ = sort.Ints
}
