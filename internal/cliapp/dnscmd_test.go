package cliapp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
)

// TestDNSMatrixDistinguishesDroppedFromPoisoned is the rendering that decides
// what a user does next. MEASUREMENTS.md §2 measured three different things on
// this line, and a table that blurs them is worse than no table: a transport
// that was never asked is not broken, and one that answers 195.175.254.2 is
// worse than one that answers nothing, because its answer looks like success.
func TestDNSMatrixDistinguishesDroppedFromPoisoned(t *testing.T) {
	m := probe.DNSMatrix{
		Control: "google.com",
		Names:   []string{"google.com", "discord.com"},
		Rows: []probe.DNSRow{
			{
				Label: "udp-8.8.8.8-53", Transport: "udp",
				Cells: []probe.DNSCell{
					{Name: "google.com", Outcome: probe.DNSOK},
					{Name: "discord.com", Outcome: probe.DNSTimeout},
				},
			},
			{
				Label: "udp-isp", Transport: "udp",
				Cells: []probe.DNSCell{
					{Name: "google.com", Outcome: probe.DNSOK},
					{Name: "discord.com", Outcome: probe.DNSSinkhole},
				},
			},
			{
				Label: "udp-yandex-1253", Transport: "udp-alt", Clean: true,
				Cells: []probe.DNSCell{
					{Name: "google.com", Outcome: probe.DNSOK, Latency: 30 * time.Millisecond},
					{Name: "discord.com", Outcome: probe.DNSOK},
				},
			},
			{
				Label: "doh-cloudflare", Transport: "doh",
				Cells: []probe.DNSCell{
					{Name: "google.com", Outcome: probe.DNSUntried},
					{Name: "discord.com", Outcome: probe.DNSUntried},
				},
			},
		},
	}

	var buf bytes.Buffer
	writeDNSMatrix(&buf, m)
	out := buf.String()
	for _, want := range []string{"timeout", "SINKHOLE", "ok", "-", "udp-yandex-1253", "chain order"} {
		if !strings.Contains(out, want) {
			t.Errorf("the matrix is missing %q:\n%s", want, out)
		}
	}
	// The usable transport is marked, and it is the one the chain order leads with.
	if !strings.Contains(out, "* udp-yandex-1253") {
		t.Errorf("the usable transport is not marked:\n%s", out)
	}
	if !strings.Contains(out, "chain order implied by these measurements: udp-yandex-1253") {
		t.Errorf("the implied chain order does not lead with the clean transport:\n%s", out)
	}
}

func TestDNSMatrixOnNoMeasurement(t *testing.T) {
	var buf bytes.Buffer
	writeDNSMatrix(&buf, probe.DNSMatrix{})
	if !strings.Contains(buf.String(), "no DNS transports were measured") {
		t.Errorf("an empty matrix does not say so: %q", buf.String())
	}
}

// TestDNSHealthCallsAnUntriedRungUntried: a rung that was never reached reports
// OK=false with a nil error, and rendering that as "broken" invents a network
// problem the user does not have.
func TestDNSHealthCallsAnUntriedRungUntried(t *testing.T) {
	var buf bytes.Buffer
	writeDNSHealth(&buf, []resolve.Health{
		{Label: "doh-cloudflare", OK: true, Latency: 26 * time.Millisecond},
		{Label: "udp-8.8.8.8-53", Err: errors.New("i/o timeout")},
		{Label: "udp-isp", Signal: resolve.Signal{Poisoned: true, Sinkhole: true,
			Detail: "answered discord.com with 195.175.254.2"}},
		{Label: "dot-9.9.9.9"},
	})
	out := buf.String()
	for _, want := range []string{"ok", "broken", "poisoned", "untried", "195.175.254.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("chain health is missing %q:\n%s", want, out)
		}
	}
}

func TestSignalNote(t *testing.T) {
	for _, tc := range []struct {
		s    resolve.Signal
		want string
	}{
		{resolve.Signal{Detail: "explicit"}, "explicit"},
		{resolve.Signal{Sinkhole: true}, "sinkhole"},
		{resolve.Signal{Poisoned: true}, "censorship"},
		{resolve.Signal{}, ""},
	} {
		got := signalNote(tc.s)
		if tc.want == "" && got != "" {
			t.Errorf("signalNote(%+v) = %q, want empty", tc.s, got)
		}
		if tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("signalNote(%+v) = %q, want it to mention %q", tc.s, got, tc.want)
		}
	}
}

func TestDNSNeedsASubcommand(t *testing.T) {
	if r := run(t, "dns"); r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

// TestDNSCheckRejectsABadName: the name flags go through the same parser as
// tune's targets, so a malformed one is a usage error rather than a run that
// measures the wrong thing.
func TestDNSCheckRejectsABadName(t *testing.T) {
	if r := run(t, "dns", "check", "--name", "discord.com@nope"); r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d\n%s", r.code, ExitUsage, r.stderr)
	}
}

// TestDNSResolveNeverQueriesForAnIPLiteral: resolve.Chain returns an IP literal
// unchanged and never asks a resolver about it — on this line, asking would be
// a way to get an answer that is not the address (MEASUREMENTS.md §2). The CLI
// path around it has to preserve that, so this exercises `dpb dns resolve`
// end to end with no network at all.
func TestDNSResolveNeverQueriesForAnIPLiteral(t *testing.T) {
	r := run(t, "dns", "resolve", "192.0.2.7", "--trace")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", r.code, ExitOK, r.stderr)
	}
	if !strings.Contains(r.stdout, "192.0.2.7") {
		t.Errorf("the literal was not echoed back:\n%s", r.stdout)
	}
	// --trace prints the chain, and every rung is untried because nothing was
	// asked. Rendering an untried rung as broken invents a network problem.
	if !strings.Contains(r.stdout, "untried") {
		t.Errorf("--trace did not report the chain as untried:\n%s", r.stdout)
	}
}

// TestDNSResolveRejectsAnEmptyName: the chain refuses it, and the command must
// surface that as an error rather than printing nothing and exiting 0.
func TestDNSResolveRejectsAnEmptyName(t *testing.T) {
	if r := run(t, "dns", "resolve", ""); r.code == ExitOK {
		t.Errorf("an empty name exited 0:\n%s%s", r.stdout, r.stderr)
	}
}
