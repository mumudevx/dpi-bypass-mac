package cliapp

import (
	"fmt"
	"io"
	"strings"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/proxyfe"
)

// banner is what `dpb run` prints once it is up.
//
// It prints only VERIFIED facts, never intentions. Every listener address comes
// from the socket that is actually bound rather than from the configuration
// that asked for it; every system setting listed under "system" was applied AND
// verified through a different subsystem by netstate.Manager, and anything that
// was refused is printed under "not applied" with the reason.
//
// The previous implementation printed "Ready" from a code path that had not
// checked anything, which is how a run under a full-tunnel VPN could report
// success while capturing nothing. A banner that can only describe what already
// happened cannot do that.
type banner struct {
	Config    *config.Loaded
	Sources   []string
	Listeners []listener
	Ladder    []string
	Resolvers []string
	Applied   []string
	Notes     []string
	DryRun    bool
	Journal   string
}

func (b banner) write(w io.Writer) {
	fmt.Fprintf(w, "dpb is running.\n\n")

	for _, l := range b.Listeners {
		fmt.Fprintf(w, "  %-8s %s\n", l.Kind, l.Addr)
	}
	if addr := addrOf(b.Listeners, "http"); addr != "" {
		fmt.Fprintf(w, "  %-8s http://%s%s\n", "pac", addr, proxyfe.PACPath)
	}

	fmt.Fprintf(w, "\n  profile  %s (%s)\n", b.Config.Profile, strings.Join(b.Sources, " → "))
	fmt.Fprintf(w, "  mode     %s\n", b.Config.Mode)
	fmt.Fprintf(w, "  ladder   %s\n", strings.Join(labelled(b.Ladder), " → "))
	if b.Config.Strategy != "" {
		fmt.Fprintf(w, "  strategy %s (forced)\n", b.Config.Strategy)
	}
	fmt.Fprintf(w, "  dns      %s\n", strings.Join(b.Resolvers, " → "))
	fmt.Fprintf(w, "  ports    %s inspected\n", joinInts(b.Config.InspectPorts))

	if b.DryRun {
		fmt.Fprintf(w, "\n  --dry-run: nothing below was applied.\n")
	}
	if len(b.Applied) > 0 {
		fmt.Fprintf(w, "\n  system settings applied and verified:\n")
		for _, a := range b.Applied {
			fmt.Fprintf(w, "    - %s\n", a)
		}
	} else if !b.DryRun && len(b.Notes) == 0 {
		fmt.Fprintf(w, "\n  no system setting was changed.\n")
	}
	if len(b.Notes) > 0 {
		fmt.Fprintf(w, "\n  NOT applied:\n")
		for _, n := range b.Notes {
			fmt.Fprintf(w, "    ! %s\n", n)
		}
	}

	// Everything above is reverted on the way out, and the journal is how that
	// promise survives a kill -9. Saying where it is turns "my proxy settings
	// are stuck" into one command.
	fmt.Fprintf(w, "\n  Ctrl-C reverts every change above. If dpb is killed instead,\n"+
		"  `dpb doctor --repair` replays %s.\n", b.Journal)
}

// labelled renders the plain rung as "plain" rather than as an empty string,
// which would print as a gap and read like a bug.
func labelled(specs []string) []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		if s == "" {
			s = "plain"
		}
		out = append(out, s)
	}
	return out
}

func joinInts(in []int) string {
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}
