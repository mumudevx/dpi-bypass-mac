package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"github.com/mumudevx/dpi-bypass-mac/internal/dns"
)

func printBanner(prof config.Profile, engine *desync.Engine, chain *dns.Chain, f *runFlags, proxySet bool) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "dpb %s  profile=%s  mode=%s\n", version, prof.Name, f.mode)
	fmt.Fprintf(&sb, "  DNS      %s\n", strings.Join(chain.Labels(), ", "))

	strat := ""
	if ts := engine.TransformerNames(); len(ts) > 0 {
		strat = strings.Join(ts, " → ") + " → "
	}
	strat += engine.EmitterName()
	fmt.Fprintf(&sb, "  Strategy %s  window=%d  ports=%s\n",
		strat, prof.Strategy.FragWindow, portsStr(prof.Filter.Ports))

	fmt.Fprintf(&sb, "  Listen   http://%s:%d\n", f.listen, f.port)
	if proxySet {
		fmt.Fprintf(&sb, "  System   proxy set on active service (restores on exit)\n")
	} else {
		fmt.Fprintf(&sb, "  System   not modified (point your proxy at %s:%d)\n", f.listen, f.port)
	}
	fmt.Fprintf(&sb, "  Ready. Press Ctrl-C to stop.\n")
	fmt.Fprint(os.Stderr, sb.String())
}

func portsStr(ports []int) string {
	if len(ports) == 0 {
		return "443,80"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
