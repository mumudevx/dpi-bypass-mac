package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/miekg/dns"
)

// headerLen is the fixed DNS message header size (RFC 1035 §4.1.1).
const headerLen = 12

// Exchanger answers a raw wire-format DNS query. Resolvers implement it so that
// TUN mode can serve the system stub resolver over DoH instead of letting
// plaintext port 53 traffic reach a poisoned upstream.
type Exchanger interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

// Exchange forwards a wire-format query down the resolver chain and returns the
// first usable reply. Resolvers that cannot carry raw queries are skipped.
//
// Wire replies are deliberately not cached: they carry per-record TTLs that a
// naive cache would have to rewrite. The client's own stub resolver caches them.
func (c *Chain) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < headerLen {
		return nil, fmt.Errorf("dns: query too short (%d bytes)", len(query))
	}
	var lastErr error
	for _, r := range c.resolvers {
		ex, ok := r.(Exchanger)
		if !ok {
			continue
		}
		reply, err := ex.Exchange(ctx, query)
		if err != nil {
			lastErr = err
			c.logf("dns: %s wire exchange failed: %v", r.Label(), err)
			continue
		}
		if len(reply) < headerLen {
			lastErr = fmt.Errorf("%s: truncated reply (%d bytes)", r.Label(), len(reply))
			continue
		}
		if rc := rcodeOf(reply); !isAnswer(rc) {
			lastErr = fmt.Errorf("%s: rcode %d", r.Label(), rc)
			c.logf("dns: %s returned rcode %d, trying the next resolver", r.Label(), rc)
			continue
		}
		return reply, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolver in the chain supports wire queries")
	}
	return nil, fmt.Errorf("dns exchange: %w", lastErr)
}

// rcodeOf reads the 4-bit response code from the message header.
func rcodeOf(msg []byte) int { return int(msg[3] & 0x0F) }

// isAnswer reports whether an rcode settles the question. NXDOMAIN counts: the
// name genuinely does not exist, so retrying the next resolver only adds latency.
func isAnswer(rc int) bool {
	return rc == dns.RcodeSuccess || rc == dns.RcodeNameError
}

// Exchange posts the raw query to the DoH endpoint.
func (d *doh) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < headerLen {
		return nil, fmt.Errorf("doh: query too short (%d bytes)", len(query))
	}
	// RFC 8484 §4.1 recommends a zero message ID so identical questions share an
	// HTTP cache entry. The caller's ID goes back on the reply, otherwise its stub
	// resolver drops the answer as unsolicited. Copy first — the caller's buffer
	// is not ours to mutate.
	q := append([]byte(nil), query...)
	idHi, idLo := q[0], q[1]
	q[0], q[1] = 0, 0

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(body) < headerLen {
		return nil, fmt.Errorf("doh: truncated reply (%d bytes)", len(body))
	}
	body[0], body[1] = idHi, idLo
	return body, nil
}

// Exchange relays the raw query to the plain UDP upstream.
func (r *udpResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	return exchangeWire(ctx, r.client, r.addr, query)
}

// Exchange relays the raw query over DNS-over-TLS.
func (r *dotResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	return exchangeWire(ctx, r.client, r.addr, query)
}

// exchangeWire round-trips a packed query through a miekg client, which handles
// timeouts and (for UDP) truncation retries.
func exchangeWire(ctx context.Context, c *dns.Client, addr string, query []byte) ([]byte, error) {
	m := new(dns.Msg)
	if err := m.Unpack(query); err != nil {
		return nil, fmt.Errorf("unpack query: %w", err)
	}
	reply, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	return reply.Pack()
}
