package probe_test

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/probe"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/testcensor"
)

// The three mechanism probes, spelled here rather than imported so the test
// pins the strings a reader of `dpb tune` actually sees.
const (
	evRecordFrag = "tlsfrag:pos=snimid"
	evTCPSplit   = "split:pos=snimid"
	evChunk      = "chunk:size=12"
)

// recordJoining is a middlebox that reassembles every complete TLS record
// before parsing the handshake, so record reframing does not hide the SNI from
// it. It is a Model literal built from the shipped TT2026 rather than an edit
// to any shipped model, and it varies exactly one flag: the negative outcome of
// the record-framing axis has to come from a middlebox that differs from
// TT2026 in that property and in nothing else, or the test is not measuring
// the axis.
//
// testcensor.Naive cannot serve here: tlsfrag:pos=snimid inserts a five-byte
// record header INSIDE the hostname, so a raw substring matcher is defeated by
// it too (MEASUREMENTS.md §3.3 names that as a deliberate property of the
// snimid cut), and the axis would pass under both models.
func recordJoining(blocked ...string) testcensor.Model {
	m := testcensor.TT2026(blocked...)
	m.Name = "record-joining"
	m.Doc = "hypothetical: record-aware and joins every complete record before parsing; contrast model only"
	m.FirstRecordOnly = false
	return m
}

// classifyUnder runs Baseline + Classify against one modelled middlebox and
// returns what the classifier concluded. It is the real classifier over the
// real datapath; only the middlebox is substituted.
func classifyUnder(t *testing.T, m testcensor.Model, sr *strategy.Registry) probe.Classification {
	t.Helper()
	l := newLab(t, m, "discord.com", "cloudflare.com")

	host, portStr, err := net.SplitHostPort(l.origin.Addr())
	if err != nil {
		t.Fatalf("origin addr %q: %v", l.origin.Addr(), err)
	}
	port, _ := strconv.Atoi(portStr)

	r := probe.NewRunner(probe.Options{
		Targets: []probe.Target{
			{Host: "discord.com", Kind: probe.TargetBlocked, Addr: host, Port: port},
			{Host: "cloudflare.com", Kind: probe.TargetControl, Addr: host, Port: port},
		},
		Registry:  sr,
		Dial:      boxDialer{box: l.box, addr: l.origin.Addr()},
		Caps:      l.caps,
		Sender:    &emit.Sender{Logf: t.Logf},
		Wrap:      func(c net.Conn) (emit.Transport, error) { return newBoxTransport(c, l.caps) },
		TLSConfig: func(h string) *tls.Config { return l.origin.ClientConfig(h) },
		Timeout:   5 * time.Second,
		Cooldown:  time.Nanosecond,
		Logf:      t.Logf,
	})
	blocked, _, err := r.Baseline(context.Background())
	if err != nil {
		t.Fatalf("Baseline under %s: %v", m.Name, err)
	}
	if len(blocked) == 0 {
		t.Fatalf("Baseline under %s found nothing blocked; the fixture is not censoring", m.Name)
	}
	c, err := r.Classify(context.Background())
	if err != nil {
		t.Fatalf("Classify under %s: %v", m.Name, err)
	}
	return c
}

func evidenceFor(t *testing.T, c probe.Classification, method string) probe.Evidence {
	t.Helper()
	for _, e := range c.Evidence {
		if e.Method == method {
			return e
		}
	}
	t.Fatalf("no evidence for method %q; have %+v", method, c.Evidence)
	return probe.Evidence{}
}

// TestAxisEvidenceFollowsTheMeasurement is the regression test for a prober
// that narrated a conclusion its own numbers contradicted.
//
// Observed on the live Türk Telekom line before the fix, with the split axis
// measured 0/2 in the same breath:
//
//	the DPI does not reassemble TCP, so segment splitting also bypasses
//	  via split:pos=snimid: 0/2 PASS
//
// Every axis is therefore run over BOTH of its outcomes, against models that
// differ in exactly the property the axis is about, and the two claims must
// differ and each must be true of what was measured beside it.
func TestAxisEvidenceFollowsTheMeasurement(t *testing.T) {
	// TT2026 reassembles TCP and parses only the first record: record framing
	// bypasses, plain segment splitting does not (MEASUREMENTS.md §3.1, §3.2).
	firstRecordOnly := classifyUnder(t, testcensor.TT2026("discord.com"), reg)
	// A middlebox that joins every complete record before parsing: reframing
	// the record layer buys nothing against it, and neither does splitting.
	joining := classifyUnder(t, recordJoining("discord.com"), reg)
	// NoReassembly inspects each TCP segment on its own, so splitting the
	// hostname across two segments is enough.
	segmentwise := classifyUnder(t, testcensor.NoReassembly("discord.com"), reg)

	cases := []struct {
		axis    string
		method  string
		pos     probe.Classification
		neg     probe.Classification
		posWord string
		// negForbid are substrings a claim beside a 0/N may never contain.
		negForbid []string
	}{
		{
			axis:      "record framing",
			method:    evRecordFrag,
			pos:       firstRecordOnly,
			neg:       joining,
			posWord:   "first TLS record",
			negForbid: []string{"record layer bypasses"},
		},
		{
			axis:      "TCP splitting",
			method:    evTCPSplit,
			pos:       segmentwise,
			neg:       firstRecordOnly,
			posWord:   "does not reassemble",
			negForbid: []string{"does not reassemble"},
		},
		{
			axis:      "chunking",
			method:    evChunk,
			pos:       segmentwise,
			neg:       firstRecordOnly,
			posWord:   "chunking bypasses",
			negForbid: []string{"chunking bypasses"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.axis, func(t *testing.T) {
			pass := evidenceFor(t, tc.pos, tc.method)
			fail := evidenceFor(t, tc.neg, tc.method)

			if !strings.HasPrefix(pass.Observed, "2/2") {
				t.Fatalf("the %s axis was expected to pass here, observed %q", tc.axis, pass.Observed)
			}
			if !strings.HasPrefix(fail.Observed, "0/2") {
				t.Fatalf("the %s axis was expected to fail here, observed %q", tc.axis, fail.Observed)
			}
			if pass.Claim == fail.Claim {
				t.Errorf("the %s axis makes the same claim whether it passed or failed:\n  claim: %s\n"+
					"  passing run: %s\n  failing run: %s", tc.axis, pass.Claim, pass.Observed, fail.Observed)
			}
			if !strings.Contains(pass.Claim, tc.posWord) {
				t.Errorf("the passing %s claim %q does not contain %q", tc.axis, pass.Claim, tc.posWord)
			}
			for _, bad := range tc.negForbid {
				if strings.Contains(fail.Claim, bad) {
					t.Errorf("the %s axis measured %s but claims %q, which asserts the opposite",
						tc.axis, fail.Observed, fail.Claim)
				}
			}
		})
	}
}

// TestAxisEvidenceSaysNothingWhenNothingWasMeasured: an axis whose op this
// build does not register produces no measurement, and the claim beside it must
// not assert a mechanism in either direction.
func TestAxisEvidenceSaysNothingWhenNothingWasMeasured(t *testing.T) {
	c := classifyUnder(t, testcensor.TT2026("discord.com"), registryWithout(t, "split"))
	e := evidenceFor(t, c, evTCPSplit)
	if !strings.Contains(e.Observed, "unmeasurable") {
		t.Fatalf("the split axis was expected unmeasurable, observed %q", e.Observed)
	}
	for _, bad := range []string{"does not reassemble", "reassembles TCP"} {
		if strings.Contains(e.Claim, bad) {
			t.Errorf("an unmeasured axis asserts a mechanism: %q (observed %q)", e.Claim, e.Observed)
		}
	}
}
