// retryprobe validates the proposed control flow: connect plain, and on an
// RST/EOF handshake failure immediately re-dial with a desync strategy. It
// measures whether the retry succeeds, how much latency it costs, and whether
// repeated blocked attempts provoke the DPI into escalating to IP-level blocking.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type tgt struct{ host, ip string }

var targets = []tgt{
	{"discord.com", "162.159.128.233"},
	{"discord.gg", "162.159.136.234"},
	{"cdn.discordapp.com", "162.159.129.233"},
}

type dconn struct {
	*net.TCPConn
	host  string
	split bool
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
	if !c.first || !c.split {
		return c.TCPConn.Write(b)
	}
	c.first = false
	body := b[5:]
	s := find(body, c.host)
	cut := len(body) / 2
	if s >= 0 {
		cut = s + len(c.host)/2
	}
	f1, f2 := body[:cut], body[cut:]
	out := make([]byte, 0, len(b)+5)
	out = append(out, b[0], b[1], b[2], byte(len(f1)>>8), byte(len(f1)))
	out = append(out, f1...)
	out = append(out, b[0], b[1], b[2], byte(len(f2)>>8), byte(len(f2)))
	out = append(out, f2...)
	_, err := c.TCPConn.Write(out)
	return len(b), err
}

func attempt(t tgt, split bool) (time.Duration, error) {
	start := time.Now()
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(t.ip, "443"), 6*time.Second)
	if err != nil {
		return time.Since(start), err
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	tcp.SetNoDelay(true)
	c := &dconn{TCPConn: tcp, host: t.host, split: split, first: true}
	tc := tls.Client(c, &tls.Config{ServerName: t.host})
	tc.SetDeadline(time.Now().Add(8 * time.Second))
	return time.Since(start), tc.Handshake()
}

func main() {
	const rounds = 6
	fmt.Println("A. plain -> immediate desync retry, no delay between them")
	fmt.Printf("%-20s %-8s %-12s %-12s %-12s %s\n", "target", "round", "plain", "retry", "retry-lat", "total-lat")
	okRetry, nRetry := 0, 0
	for r := 1; r <= rounds; r++ {
		for _, t := range targets {
			d1, e1 := attempt(t, false)
			d2, e2 := attempt(t, true)
			nRetry++
			if e2 == nil {
				okRetry++
			}
			p, q := "blocked", "OK"
			if e1 == nil {
				p = "OK(!)"
			}
			if e2 != nil {
				q = "FAILED"
			}
			fmt.Printf("%-20s %-8d %-12s %-12s %-12s %s\n", t.host, r, p, q,
				d2.Round(time.Millisecond), (d1 + d2).Round(time.Millisecond))
		}
	}
	fmt.Printf("\nretry success: %d/%d\n", okRetry, nRetry)

	fmt.Println("\nB. escalation check — 15 back-to-back blocked attempts, then a desync attempt")
	for i := 0; i < 15; i++ {
		attempt(targets[0], false)
	}
	d, err := attempt(targets[0], true)
	fmt.Printf("   desync after 15 blocked attempts: err=%v lat=%v\n", err, d.Round(time.Millisecond))
	d, err = attempt(tgt{"cloudflare.com", targets[0].ip}, false)
	fmt.Printf("   benign SNI to same IP after burst: err=%v lat=%v\n", err, d.Round(time.Millisecond))

	fmt.Println("\nC. cost of the plain-first probe on a NON-blocked host (the common case)")
	for _, h := range []tgt{{"www.google.com", ""}, {"www.akbank.com", ""}} {
		ips, _ := net.LookupIP(h.host)
		if len(ips) == 0 {
			continue
		}
		t := tgt{h.host, ips[0].String()}
		d, err := attempt(t, false)
		fmt.Printf("   %-22s plain: err=%v lat=%v (no retry needed)\n", h.host, err, d.Round(time.Millisecond))
	}
}
