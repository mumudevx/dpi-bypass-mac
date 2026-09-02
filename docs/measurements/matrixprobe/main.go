// matrixprobe scores every candidate emitter on BOTH axes at once:
//   bypass      — does it get through the DPI to a blocked host?
//   compatibility — does it leave ordinary hosts working?
// An emitter is only shippable if it wins on both.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type host struct {
	name    string
	blocked bool
	fragile bool // known to reject a split ClientHello
}

var hosts = []host{
	// blocked by the DPI
	{"discord.com", true, false},
	{"discord.gg", true, false},
	{"cdn.discordapp.com", true, false},
	// known fragile (broke under record splitting)
	{"www.akbank.com", false, true},
	{"www.isbank.com.tr", false, true},
	{"www.yapikredi.com.tr", false, true},
	{"www.ziraatbank.com.tr", false, true},
	{"www.turkiye.gov.tr", false, true},
	{"www.gib.gov.tr", false, true},
	{"www.vakifbank.com.tr", false, true},
	{"www.denizbank.com", false, true},
	{"www.mhrs.gov.tr", false, true},
	{"www.btk.gov.tr", false, true},
	// ordinary controls
	{"www.garantibbva.com.tr", false, false},
	{"www.teb.com.tr", false, false},
	{"www.google.com", false, false},
	{"github.com", false, false},
}

type emit func(c *dconn, rec []byte) error

type emitter struct {
	name string
	fn   emit
}

type dconn struct {
	*net.TCPConn
	host  string
	em    *emitter
	first bool
}

func find(b []byte, h string) int {
	n := []byte(h)
outer:
	for i := 0; i+len(n) <= len(b); i++ {
		for j := range n {
			if b[i+j] != n[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

func (c *dconn) Write(b []byte) (int, error) {
	if !c.first {
		return c.TCPConn.Write(b)
	}
	c.first = false
	if err := c.em.fn(c, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *dconn) oob(b []byte) error {
	sc, err := c.TCPConn.SyscallConn()
	if err != nil {
		return err
	}
	var in error
	if err := sc.Control(func(fd uintptr) { in = unix.Sendto(int(fd), b, unix.MSG_OOB, nil) }); err != nil {
		return err
	}
	return in
}

func records(rec []byte, cut int) []byte {
	body := rec[5:]
	if cut <= 0 || cut >= len(body) {
		return rec
	}
	f1, f2 := body[:cut], body[cut:]
	out := make([]byte, 0, len(rec)+5)
	out = append(out, rec[0], rec[1], rec[2], byte(len(f1)>>8), byte(len(f1)))
	out = append(out, f1...)
	out = append(out, rec[0], rec[1], rec[2], byte(len(f2)>>8), byte(len(f2)))
	out = append(out, f2...)
	return out
}

func emitters() []*emitter {
	var es []*emitter
	add := func(n string, f emit) { es = append(es, &emitter{n, f}) }

	add("plain", func(c *dconn, b []byte) error { _, e := c.TCPConn.Write(b); return e })

	add("tlsrec-mid-sni", func(c *dconn, b []byte) error {
		s := find(b[5:], c.host)
		cut := len(b[5:]) / 2
		if s >= 0 {
			cut = s + len(c.host)/2
		}
		_, e := c.TCPConn.Write(records(b, cut))
		return e
	})

	add("tlsrec-at-1", func(c *dconn, b []byte) error {
		_, e := c.TCPConn.Write(records(b, 1))
		return e
	})

	for _, n := range []int{2, 4, 12} {
		n := n
		add(fmt.Sprintf("chunk-%d", n), func(c *dconn, b []byte) error {
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
		})
	}

	for _, n := range []int{1, 3} {
		n := n
		add(fmt.Sprintf("oob-at-%d", n), func(c *dconn, b []byte) error {
			if _, err := c.TCPConn.Write(b[:n]); err != nil {
				return err
			}
			if err := c.oob([]byte{0x61}); err != nil {
				return err
			}
			_, err := c.TCPConn.Write(b[n:])
			return err
		})
	}

	// TCP-segment split placed inside the SNI, combined with record split —
	// tests whether TCP-only framing preserves compatibility.
	add("tcpsplit-in-sni", func(c *dconn, b []byte) error {
		s := find(b, c.host)
		cut := len(b) / 2
		if s >= 0 {
			cut = s + len(c.host)/2
		}
		if _, err := c.TCPConn.Write(b[:cut]); err != nil {
			return err
		}
		_, err := c.TCPConn.Write(b[cut:])
		return err
	})

	return es
}

// resolver queries a public resolver on an alternate UDP port. The system
// resolver returns the BTK sinkhole 195.175.254.2 for every blocked name, and
// port 53 to public resolvers is dropped per-QNAME, so neither can be used.
var resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", "77.88.8.8:1253")
	},
}

var (
	ipMu    sync.Mutex
	ipCache = map[string]string{}
)

func resolve(h string) (string, error) {
	ipMu.Lock()
	if v, ok := ipCache[h]; ok {
		ipMu.Unlock()
		return v, nil
	}
	ipMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := resolver.LookupIP(ctx, "ip4", h)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("resolve %s: %v", h, err)
	}
	ip := addrs[0].String()
	if ip == "195.175.254.2" {
		return "", fmt.Errorf("resolve %s: got BTK sinkhole", h)
	}
	ipMu.Lock()
	ipCache[h] = ip
	ipMu.Unlock()
	return ip, nil
}

func probe(h, sni string, em *emitter) error {
	ip, err := resolve(h)
	if err != nil {
		return err
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	raw, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return err
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	tcp.SetNoDelay(true)
	c := &dconn{TCPConn: tcp, host: sni, em: em, first: true}
	tc := tls.Client(c, &tls.Config{ServerName: sni})
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	return tc.Handshake()
}

func main() {
	es := emitters()
	type key struct{ em, host string }
	var mu sync.Mutex
	ok := map[key]int{}
	tot := map[key]int{}
	const reps = 2

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, h := range hosts {
		for _, e := range es {
			for i := 0; i < reps; i++ {
				wg.Add(1)
				go func(h host, e *emitter) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					err := probe(h.name, h.name, e)
					mu.Lock()
					k := key{e.name, h.name}
					tot[k]++
					if err == nil {
						ok[k]++
					}
					mu.Unlock()
				}(h, e)
			}
		}
	}
	wg.Wait()

	fmt.Printf("%-17s %-9s %-13s %-11s %s\n", "emitter", "bypass", "fragile-hosts", "controls", "shippable")
	for _, e := range es {
		var bOK, bN, fOK, fN, cOK, cN int
		for _, h := range hosts {
			k := key{e.name, h.name}
			switch {
			case h.blocked:
				bOK += ok[k]
				bN += tot[k]
			case h.fragile:
				fOK += ok[k]
				fN += tot[k]
			default:
				cOK += ok[k]
				cN += tot[k]
			}
		}
		verdict := "no"
		if bOK == bN && fOK == fN && cOK == cN {
			verdict = "YES"
		} else if bOK == bN {
			verdict = "bypasses, breaks sites"
		} else if fOK == fN && cOK == cN {
			verdict = "safe, no bypass"
		}
		fmt.Printf("%-17s %-9s %-13s %-11s %s\n", e.name,
			fmt.Sprintf("%d/%d", bOK, bN),
			fmt.Sprintf("%d/%d", fOK, fN),
			fmt.Sprintf("%d/%d", cOK, cN), verdict)
	}
}
