// chunkprobe measures which ClientHello chunk sizes survive the local DPI.
// Trials are fully shuffled so a temporal effect (DPI hardening after repeated
// blocked attempts) cannot masquerade as a chunk-size effect, and a benign SNI
// to the same IP is interleaved as a control for "is the network up at all".
package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

type chunker struct {
	*net.TCPConn
	size  int
	first bool
}

func (c *chunker) Write(b []byte) (int, error) {
	if !c.first || c.size <= 0 || len(b) <= c.size {
		return c.TCPConn.Write(b)
	}
	c.first = false
	for off := 0; off < len(b); off += c.size {
		end := off + c.size
		if end > len(b) {
			end = len(b)
		}
		if _, err := c.TCPConn.Write(b[off:end]); err != nil {
			return off, err
		}
	}
	return len(b), nil
}

func try(ip, sni string, size int) error {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 6*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	tcp := raw.(*net.TCPConn)
	tcp.SetNoDelay(true)
	c := &chunker{TCPConn: tcp, size: size, first: true}
	tc := tls.Client(c, &tls.Config{ServerName: sni})
	tc.SetDeadline(time.Now().Add(8 * time.Second))
	return tc.Handshake()
}

type trial struct {
	size    int
	control bool
}

func main() {
	const ip = "162.159.128.233"
	const blocked = "discord.com"
	const control = "cloudflare.com"
	const reps = 5
	sizes := []int{0, 1, 2, 3, 4, 5, 8, 12, 20, 35, 60, 120}

	var queue []trial
	for i := 0; i < reps; i++ {
		for _, s := range sizes {
			queue = append(queue, trial{size: s})
		}
		queue = append(queue, trial{size: 0, control: true})
		queue = append(queue, trial{size: 5, control: true})
	}
	r := rand.New(rand.NewSource(20260902))
	r.Shuffle(len(queue), func(i, j int) { queue[i], queue[j] = queue[j], queue[i] })

	okBlocked := map[int]int{}
	nBlocked := map[int]int{}
	okCtl, nCtl := 0, 0

	fmt.Printf("%d shuffled trials, %d reps per chunk size, control SNI interleaved\n", len(queue), reps)
	for i, t := range queue {
		sni := blocked
		if t.control {
			sni = control
		}
		err := try(ip, sni, t.size)
		if t.control {
			nCtl++
			if err == nil {
				okCtl++
			}
		} else {
			nBlocked[t.size]++
			if err == nil {
				okBlocked[t.size]++
			}
		}
		if i%20 == 19 {
			fmt.Printf("  ...%d/%d\n", i+1, len(queue))
		}
		time.Sleep(250 * time.Millisecond)
	}

	fmt.Printf("\ncontrol (%s, same IP): %d/%d handshakes OK\n\n", control, okCtl, nCtl)
	fmt.Printf("%-8s %-8s %s\n", "chunk", "ok", "verdict")
	var work []int
	for _, s := range sizes {
		label := strconv.Itoa(s)
		if s == 0 {
			label = "none"
		}
		v := "FAIL"
		switch {
		case okBlocked[s] == nBlocked[s]:
			v = "PASS"
			work = append(work, s)
		case okBlocked[s] > 0:
			v = "FLAKY"
		}
		fmt.Printf("%-8s %d/%-6d %s\n", label, okBlocked[s], nBlocked[s], v)
	}
	sort.Ints(work)
	strs := make([]string, len(work))
	for i, w := range work {
		strs[i] = strconv.Itoa(w)
	}
	fmt.Printf("\n100%% working chunk sizes: %s\n", strings.Join(strs, " "))
}
