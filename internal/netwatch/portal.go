package netwatch

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/mumudevx/dpb/internal/buildinfo"
	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/resolve"
)

// Portal is the verdict on one probe round.
type Portal struct {
	// Behind is true ONLY on affirmative evidence of interception. A probe
	// that could not reach anything sets Err and leaves this false: absence of
	// evidence is not a portal, and treating "the network is down" as "a
	// portal appeared" would suspend dpb every time a user walks out of range.
	Behind bool
	// Reason is a short machine-readable cause: "intercepted", "dns-uniform".
	Reason string
	// LoginURL is the address the portal redirected to, when it named one. It
	// is what `dpb status` tells the user to open.
	LoginURL string
	Detail   string
	// Err records why a probe was inconclusive. It never on its own means a
	// portal.
	Err error
	At  time.Time
}

// Prober is the captive-portal check. It is an interface so a test can hand
// the watcher a scripted verdict, and so a run with no network of its own to
// probe with can pass nil and disable the check.
type Prober interface {
	Probe(ctx context.Context) Portal
}

// Canary is one connectivity endpoint whose clean answer is known in advance.
//
// Plain HTTP on port 80 is the point: a captive portal cannot intercept HTTPS
// without a certificate error, so every portal-detection scheme in the
// industry — Apple's, Google's, Mozilla's — asks an unencrypted question whose
// right answer is a constant. A portal answers something else.
type Canary struct {
	Host string
	Path string
	// Port is 80 unless set. Nothing else is sensible: a portal that lets 443
	// through has not intercepted anything.
	Port int
	// WantStatus is the status code a clean network returns.
	WantStatus int
	// WantBody, when set, must appear in the body (case-insensitively). It is
	// what catches a portal that answers 200 with its own login page at an
	// endpoint whose clean answer is a 200 with a fixed word in it.
	WantBody string
}

// DefaultCanaries are the three the operating systems themselves use.
//
// They are deliberately NOT hosts this tool cares about. A canary that is
// censored here would make every censored network look like a captive portal
// and suspend dpb exactly where it is needed — the worst failure this file
// can have. These three are the endpoints macOS, Android and Firefox probe on
// every network join, they are unblocked on the measured Türk Telekom line
// (MEASUREMENTS.md §2 uses google.com as its control for the same reason), and
// blocking them would break Wi-Fi association for every device in the country.
var DefaultCanaries = []Canary{
	{Host: "captive.apple.com", Path: "/hotspot-detect.html", WantStatus: 200, WantBody: "success"},
	{Host: "connectivitycheck.gstatic.com", Path: "/generate_204", WantStatus: 204},
	{Host: "detectportal.firefox.com", Path: "/success.txt", WantStatus: 200, WantBody: "success"},
}

const (
	// portalBodyCap bounds what is read from a canary. A portal's login page
	// can be a megabyte of JavaScript and none of it is evidence.
	portalBodyCap = 8 << 10
	// portalDialTimeout bounds one canary. Three canaries under a whole-probe
	// context means a dead network costs one step budget, not three.
	portalDialTimeout = 4 * time.Second
)

// PortalProbe is the shipped Prober: the 204 canary plus the DNS-uniformity
// heuristic docs/PLAN.md specifies.
type PortalProbe struct {
	// Dial is flow.NetDialer — the same dialer the datapath uses, so the
	// canary resolves through resolve.Chain and never through Go's resolver
	// (MEASUREMENTS.md §5.4). Required.
	Dial flow.Dialer
	// Resolve feeds the uniformity heuristic. Optional: without it the probe
	// is the canary alone, which is still an affirmative test.
	Resolve flow.ResolveFunc
	// Detector is resolve's poison detector, reused because a captive portal
	// and a DNS censor produce the same shape — several unrelated names
	// collapsing onto one address — and having two implementations of that
	// heuristic would mean two places to get the quorum wrong. Nil builds one
	// over the canary names.
	Detector resolve.Detector
	// Canaries is DefaultCanaries when empty.
	Canaries []Canary
	Now      func() time.Time
	Logf     func(string, ...any)
}

var _ Prober = (*PortalProbe)(nil)

func (p *PortalProbe) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *PortalProbe) logf(format string, a ...any) {
	if p.Logf != nil {
		p.Logf(format, a...)
	}
}

func (p *PortalProbe) canaries() []Canary {
	if len(p.Canaries) > 0 {
		return p.Canaries
	}
	return DefaultCanaries
}

// Probe runs every canary and returns one verdict.
//
// The decision rule is asymmetric on purpose:
//
//   - ONE clean canary refutes a portal outright. A captive portal intercepts
//     everything; a network where one well-known endpoint answers correctly is
//     not behind one, whatever the other endpoints did.
//   - TWO intercepted canaries are needed to declare one, so that a single
//     endpoint being censored, DNS-failed or simply down cannot suspend dpb.
//     One interception plus DNS uniformity — several unrelated names answering
//     with the same address — also reaches the quorum, because that pair is
//     what an intercepting gateway looks like from both sides at once.
//   - Everything else is inconclusive: Err is set, Behind stays false, and the
//     caller keeps doing whatever it was doing.
func (p *PortalProbe) Probe(ctx context.Context) Portal {
	out := Portal{At: p.now()}
	if p.Dial == nil {
		out.Err = errors.New("netwatch: the portal probe has no dialer")
		return out
	}
	cs := p.canaries()
	det := p.detector(cs)

	var (
		clean       int
		intercepted int
		errs        []error
		firstHit    canaryResult
		uniform     bool
		uniformWhy  string
	)
	for _, c := range cs {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if p.Resolve != nil {
			if u, why := p.checkUniform(ctx, det, c.Host); u {
				uniform, uniformWhy = true, why
			}
		}
		r := p.probeOne(ctx, c)
		switch {
		case r.err != nil:
			errs = append(errs, r.err)
		case r.intercepted:
			intercepted++
			if firstHit.host == "" {
				firstHit = r
			}
		default:
			clean++
		}
	}

	switch {
	case clean > 0:
		out.Detail = fmt.Sprintf("%d of %d connectivity canaries answered correctly", clean, len(cs))
		return out
	case intercepted >= 2 || (intercepted == 1 && uniform):
		out.Behind = true
		out.Reason = "intercepted"
		out.LoginURL = firstHit.location
		out.Detail = fmt.Sprintf("%s answered %s instead of the expected %d%s",
			firstHit.host, firstHit.got, firstHit.want, loginSuffix(firstHit.location))
		if uniform {
			out.Reason = "intercepted+dns-uniform"
			out.Detail += "; " + uniformWhy
		}
		return out
	case intercepted == 1:
		out.Err = fmt.Errorf("only one canary (%s) looked intercepted, which is as likely to be "+
			"one blocked endpoint as a portal", firstHit.host)
		return out
	default:
		out.Err = fmt.Errorf("no connectivity canary could be reached: %w", errors.Join(errs...))
		return out
	}
}

func loginSuffix(loc string) string {
	if loc == "" {
		return ""
	}
	return "; the login page is at " + loc
}

// detector builds the uniformity detector over the canary names.
//
// resolve.NewDetector's probe list is "names that are blocked somewhere", and
// the canary names are the opposite — names that are blocked nowhere. That is
// what makes them a stronger reference set here, not a weaker one: three
// unrelated always-reachable zones answering with one identical address is a
// gateway answering for the whole internet.
func (p *PortalProbe) detector(cs []Canary) resolve.Detector {
	if p.Detector != nil {
		return p.Detector
	}
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Host)
	}
	return resolve.NewDetector(nil, names)
}

func (p *PortalProbe) checkUniform(ctx context.Context, det resolve.Detector, host string) (bool, string) {
	addrs, err := p.Resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return false, ""
	}
	det.Learn(host, addrs)
	sig := det.Check(host, addrs)
	if !sig.Poisoned {
		return false, ""
	}
	return true, sig.Detail
}

type canaryResult struct {
	host        string
	intercepted bool
	got         string
	want        int
	location    string
	err         error
}

func (p *PortalProbe) probeOne(ctx context.Context, c Canary) canaryResult {
	res := canaryResult{host: c.Host, want: c.WantStatus}
	port := c.Port
	if port == 0 {
		port = 80
	}
	dctx, cancel := context.WithTimeout(ctx, portalDialTimeout)
	defer cancel()

	// flow.Target carries the NAME, and flow.NetDialer resolves it through
	// resolve.Chain. That is the only sanctioned way a name becomes an address
	// in this tree (MEASUREMENTS.md §5.4), and it is why this file dials
	// through flow rather than through net or net/http.
	conn, err := p.Dial.DialTCP(dctx, flow.Target{Name: c.Host, Port: port})
	if err != nil {
		res.err = fmt.Errorf("netwatch: canary %s: %w", c.Host, err)
		return res
	}
	defer conn.Close()

	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	path := c.Path
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + hostHeader(c.Host, port) + "\r\n" +
		"User-Agent: " + buildinfo.UserAgent() + "\r\n" +
		// Cache-Control matters: a portal that has already been logged in to
		// often leaves a cached 302 behind, and a cached answer is evidence
		// about the past.
		"Cache-Control: no-cache\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		res.err = fmt.Errorf("netwatch: canary %s: write: %w", c.Host, err)
		return res
	}

	status, hdr, body, err := readResponse(conn)
	if err != nil {
		res.err = fmt.Errorf("netwatch: canary %s: %w", c.Host, err)
		return res
	}
	res.location = strings.TrimSpace(hdr.Get("Location"))
	res.got = strconv.Itoa(status)

	if status != c.WantStatus {
		res.intercepted = true
		return res
	}
	if c.WantBody != "" && !strings.Contains(strings.ToLower(body), strings.ToLower(c.WantBody)) {
		res.intercepted = true
		res.got = fmt.Sprintf("%d with a body that does not say %q", status, c.WantBody)
		return res
	}
	p.logf("netwatch: canary %s answered %d as expected", c.Host, status)
	return res
}

// hostHeader renders the Host header. Port 80 is elided because that is what
// every client does and a portal fingerprinting the request should see nothing
// unusual.
func hostHeader(host string, port int) string {
	if port == 80 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// readResponse parses just enough HTTP/1.x to classify an answer.
//
// It is hand-rolled rather than net/http's because an http.Client outside
// internal/resolve owns a dial that would resolve through Go's resolver, and
// the build gate rejects one on sight (internal/flow/nohostdial_test.go). What
// is needed here is a status line, one header and a bounded body.
func readResponse(r io.Reader) (status int, hdr textproto.MIMEHeader, body string, err error) {
	br := bufio.NewReader(io.LimitReader(r, portalBodyCap))
	tp := textproto.NewReader(br)

	line, err := tp.ReadLine()
	if err != nil {
		return 0, nil, "", fmt.Errorf("read status line: %w", err)
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		// Not HTTP at all. A transparent proxy that answers a plain socket
		// with something else has still intercepted us, but this function
		// reports facts and lets the caller decide.
		return 0, nil, "", fmt.Errorf("not an HTTP response: %q", truncate(line, 64))
	}
	status, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, "", fmt.Errorf("unparseable status %q", truncate(parts[1], 16))
	}
	hdr, err = tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return status, textproto.MIMEHeader{}, "", nil
	}
	b, _ := io.ReadAll(br)
	return status, hdr, string(b), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
