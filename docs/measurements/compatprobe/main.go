// compatprobe checks whether splitting the ClientHello across two TLS records
// breaks ordinary sites — banks, government, CDNs, package registries. A desync
// that fixes Discord and breaks online banking is worse than no desync at all.
package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var hosts = []string{
	// Turkish banking
	"www.garantibbva.com.tr", "www.isbank.com.tr", "www.akbank.com",
	"www.ziraatbank.com.tr", "www.yapikredi.com.tr", "www.vakifbank.com.tr",
	"www.qnbfinansbank.com", "www.denizbank.com", "www.teb.com.tr",
	// Turkish government / public
	"www.turkiye.gov.tr", "www.gib.gov.tr", "www.btk.gov.tr", "www.nvi.gov.tr",
	"www.sgk.gov.tr", "www.mhrs.gov.tr",
	// Turkish commerce / media
	"www.trendyol.com", "www.hepsiburada.com", "www.sahibinden.com",
	"www.migros.com.tr", "www.hurriyet.com.tr",
	// Global majors
	"www.google.com", "www.apple.com", "www.microsoft.com", "www.amazon.com",
	"www.cloudflare.com", "github.com", "api.github.com", "x.com",
	"www.youtube.com", "www.instagram.com", "www.netflix.com", "open.spotify.com",
	"www.wikipedia.org", "www.reddit.com", "duckduckgo.com",
	// Developer infrastructure
	"registry.npmjs.org", "proxy.golang.org", "pypi.org", "auth.docker.io",
	"objects.githubusercontent.com", "raw.githubusercontent.com",
}

type mode struct {
	name  string
	split bool
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
	start := find(body, c.host)
	if start < 0 {
		_, err := c.TCPConn.Write(b)
		return len(b), err
	}
	cut := start + len(c.host)/2
	if cut <= 0 || cut >= len(body) {
		_, err := c.TCPConn.Write(b)
		return len(b), err
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

// probe does a full TLS handshake plus one HTTP request, so a middlebox that
// accepts the handshake but mangles the stream is still caught.
func probe(host string, split bool) (string, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	raw, err := d.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return "", err
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	tcp.SetNoDelay(true)
	c := &dconn{TCPConn: tcp, host: host, split: split, first: true}
	tc := tls.Client(c, &tls.Config{ServerName: host})
	tc.SetDeadline(time.Now().Add(12 * time.Second))
	if err := tc.Handshake(); err != nil {
		return "", fmt.Errorf("handshake: %w", err)
	}
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: compatprobe/1\r\nConnection: close\r\nAccept: */*\r\n\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	resp.Body.Close()
	return fmt.Sprintf("%d %s", resp.StatusCode, tls.CipherSuiteName(tc.ConnectionState().CipherSuite)[:0]), nil
}

type row struct {
	host           string
	plain, split   string
	plainE, splitE error
}

func main() {
	modes := []mode{{"plain", false}, {"split", true}}
	_ = modes
	results := make([]row, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := row{host: h}
			r.plain, r.plainE = probe(h, false)
			time.Sleep(200 * time.Millisecond)
			r.split, r.splitE = probe(h, true)
			results[i] = r
		}(i, h)
	}
	wg.Wait()

	var broke, bothFail, ok int
	var brokeList []string
	fmt.Printf("%-34s %-14s %-14s %s\n", "host", "plain", "tlsrec-split", "verdict")
	sort.Slice(results, func(i, j int) bool { return results[i].host < results[j].host })
	for _, r := range results {
		fp := r.plainE != nil
		fs := r.splitE != nil
		v := ""
		switch {
		case !fp && !fs:
			v = "ok"
			ok++
		case fp && fs:
			v = "both fail (site/network)"
			bothFail++
		case !fp && fs:
			v = "REGRESSION"
			broke++
			brokeList = append(brokeList, r.host+": "+r.splitE.Error())
		case fp && !fs:
			v = "fixed by split"
		}
		p, s := r.plain, r.split
		if fp {
			p = "ERR"
		}
		if fs {
			s = "ERR"
		}
		fmt.Printf("%-34s %-14s %-14s %s\n", r.host, p, s, v)
	}
	fmt.Printf("\n%d ok, %d regressions, %d failed in both modes\n", ok, broke, bothFail)
	if len(brokeList) > 0 {
		fmt.Println("\nregressions:")
		for _, b := range brokeList {
			if len(b) > 130 {
				b = b[:130]
			}
			fmt.Println("  " + strings.TrimSpace(b))
		}
	}
}
