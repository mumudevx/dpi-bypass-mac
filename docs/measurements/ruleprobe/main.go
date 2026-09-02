// ruleprobe pins down the exact rule for the TLS record-fragmentation emitter:
// where must the record boundary fall, relative to the SNI hostname, for the
// DPI to fail to match? Cuts are expressed relative to the hostname's position
// inside the ClientHello record body.
package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"time"
)

type target struct{ host, ip string }

var targets = []target{
	{"discord.com", "162.159.128.233"},
	{"discord.gg", "162.159.136.234"},
}

const reps = 3

type cutSpec struct {
	name string
	// at returns the body-relative cut offset given the hostname's start and end.
	at func(start, end, bodyLen int) int
}

var cuts = []cutSpec{
	{"no-cut(baseline)", func(s, e, n int) int { return -1 }},
	{"start-20", func(s, e, n int) int { return s - 20 }},
	{"start-1", func(s, e, n int) int { return s - 1 }},
	{"start+0", func(s, e, n int) int { return s }},
	{"start+1", func(s, e, n int) int { return s + 1 }},
	{"mid-sni", func(s, e, n int) int { return s + (e-s)/2 }},
	{"end-1", func(s, e, n int) int { return e - 1 }},
	{"end+0", func(s, e, n int) int { return e }},
	{"end+1", func(s, e, n int) int { return e + 1 }},
	{"end+20", func(s, e, n int) int { return e + 20 }},
	{"end+200", func(s, e, n int) int { return e + 200 }},
}

type dconn struct {
	*net.TCPConn
	spec  cutSpec
	host  string
	first bool
	info  *string
}

func find(rec []byte, host string) int {
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

func (c *dconn) Write(b []byte) (int, error) {
	if !c.first {
		return c.TCPConn.Write(b)
	}
	c.first = false
	body := b[5:]
	start := find(body, c.host)
	if start < 0 {
		return 0, fmt.Errorf("sni not found")
	}
	end := start + len(c.host)
	cut := c.spec.at(start, end, len(body))
	if c.info != nil && *c.info == "" {
		*c.info = fmt.Sprintf("record body=%d  sni at [%d,%d)", len(body), start, end)
	}
	if cut <= 0 || cut >= len(body) {
		_, err := c.TCPConn.Write(b)
		return len(b), err
	}
	// Two structurally valid records carrying consecutive halves of the body,
	// written as ONE TCP segment so TCP segmentation cannot be the variable.
	out := make([]byte, 0, len(b)+5)
	f1, f2 := body[:cut], body[cut:]
	out = append(out, b[0], b[1], b[2], byte(len(f1)>>8), byte(len(f1)))
	out = append(out, f1...)
	out = append(out, b[0], b[1], b[2], byte(len(f2)>>8), byte(len(f2)))
	out = append(out, f2...)
	_, err := c.TCPConn.Write(out)
	return len(b), err
}

func try(t target, spec cutSpec, info *string) error {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(t.ip, "443"), 6*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	tcp.SetNoDelay(true)
	c := &dconn{TCPConn: tcp, spec: spec, host: t.host, first: true, info: info}
	tc := tls.Client(c, &tls.Config{ServerName: t.host})
	tc.SetDeadline(time.Now().Add(8 * time.Second))
	return tc.Handshake()
}

type job struct {
	t    target
	spec cutSpec
}

func main() {
	var queue []job
	for i := 0; i < reps; i++ {
		for _, t := range targets {
			for _, s := range cuts {
				queue = append(queue, job{t, s})
			}
		}
	}
	r := rand.New(rand.NewSource(77))
	r.Shuffle(len(queue), func(i, j int) { queue[i], queue[j] = queue[j], queue[i] })

	type key struct{ spec, host string }
	ok, tot := map[key]int{}, map[key]int{}
	info := ""

	fmt.Printf("%d shuffled trials; both records in ONE TCP segment\n", len(queue))
	for _, j := range queue {
		err := try(j.t, j.spec, &info)
		k := key{j.spec.name, j.t.host}
		tot[k]++
		if err == nil {
			ok[k]++
		}
		time.Sleep(180 * time.Millisecond)
	}
	fmt.Printf("%s\n\n", info)

	fmt.Printf("%-18s", "cut position")
	for _, t := range targets {
		fmt.Printf(" %-14s", t.host)
	}
	fmt.Println(" verdict")
	for _, s := range cuts {
		fmt.Printf("%-18s", s.name)
		all := true
		for _, t := range targets {
			k := key{s.name, t.host}
			fmt.Printf(" %-14s", fmt.Sprintf("%d/%d", ok[k], tot[k]))
			if ok[k] != tot[k] {
				all = false
			}
		}
		v := "BLOCKED"
		if all {
			v = "THROUGH"
		}
		fmt.Printf(" %s\n", v)
	}
}
