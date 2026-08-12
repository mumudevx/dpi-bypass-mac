//go:build darwin

package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"github.com/mumudevx/dpi-bypass-mac/internal/dns"
	"github.com/mumudevx/dpi-bypass-mac/internal/logx"
	"github.com/mumudevx/dpi-bypass-mac/internal/sysnet"
	"github.com/mumudevx/dpi-bypass-mac/internal/tun"
)

const (
	tunLocalAddr = "198.18.0.1"
	tunPeerAddr  = "198.18.0.2"
)

// runTun brings up the transparent TUN datapath: a utun device + gVisor
// netstack capturing all TCP and UDP, with the desync engine (and
// per-connection raw injector) applied to TCP and DNS served from the profile's
// encrypted resolver chain. Requires root.
func runTun(ctx context.Context, f *runFlags, prof config.Profile, engine *desync.Engine, log *logx.Logger) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("tun mode requires root — re-run with: sudo dpb run --mode tun --profile %s", f.profile)
	}

	runner := sysnet.ExecRunner{}
	iface := sysnet.DefaultInterface(ctx, runner)
	if iface == "" {
		return fmt.Errorf("could not determine the physical uplink interface")
	}
	boundDialer, err := sysnet.BoundNetDialer(iface, 10*time.Second)
	if err != nil {
		return err
	}
	// The plaintext resolvers dial through the uplink: a fallback query that
	// left on the default route would be pulled back into the tunnel, land on
	// serveDNS as ordinary port 53 traffic, and re-enter the chain that issued
	// it. DoH keeps the default dialer so it still travels through the desync
	// engine — its own SNI is a censorship target.
	chain, err := buildResolver(prof, log, boundDialer)
	if err != nil {
		return err
	}

	dev, err := tun.Open("utun", 1500)
	if err != nil {
		return fmt.Errorf("open utun (needs root): %w", err)
	}

	rm := sysnet.NewRouteManager(dev.Name(), runner, log.Warnf)
	if err := rm.Configure(ctx, tunLocalAddr, tunPeerAddr, dev.MTU()); err != nil {
		_ = dev.Close()
		return err
	}
	// Guaranteed teardown (and the utun fd close removes interface-scoped routes
	// even on a hard kill).
	defer func() {
		tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rm.Teardown(tctx)
	}()
	// The scoped route must exist before the split-default routes, or the very
	// first relayed connection has no way off the machine.
	gateway := sysnet.DefaultGateway(ctx, runner)
	if gateway == "" {
		_ = dev.Close()
		return fmt.Errorf("could not determine the default gateway for %s", iface)
	}
	if err := rm.ScopeUplink(ctx, gateway, iface); err != nil {
		_ = dev.Close()
		return err
	}

	if err := rm.CaptureAll(ctx); err != nil {
		_ = dev.Close()
		return err
	}
	// Resolvers that are not the default gateway can be pulled in with a host
	// route; the gateway itself cannot (see CapturableNameservers).
	nameservers := sysnet.CapturableNameservers(ctx, runner)
	if err := rm.CaptureHosts(ctx, nameservers); err != nil {
		log.Warnf("could not capture system resolvers (%v): %v", nameservers, err)
	}

	// Point the active service at an address the routes above do cover, so the
	// queries dpb cannot reach by routing arrive here anyway.
	dm := sysnet.NewDNSManager(sysnet.DNSConfig{
		Runner: runner,
		Logf:   log.Warnf,
	})
	if err := dm.Enable(ctx); err != nil {
		log.Warnf("could not redirect system DNS (%v); queries may stay on the ISP resolver", err)
		dm = nil
	}
	defer func() {
		if dm != nil {
			rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dm.Restore(rctx)
		}
	}()

	srv, err := tun.NewServer(tun.Options{
		Device:      dev,
		Engine:      engine,
		Dial:        tun.DialFunc(boundDialer.DialContext),
		DesyncPorts: desyncPorts(prof.Filter.Ports),
		DNSExchange: chain.Exchange,
		NewInjector: func(local, remote netip.AddrPort) (desync.RawInjector, func()) {
			inj, err := sysnet.NewRawInjector(local, remote, 0)
			if err != nil {
				return nil, func() {}
			}
			return inj, func() { _ = inj.Close() }
		},
		Logf: log.Debugf,
	})
	if err != nil {
		_ = dev.Close()
		return err
	}
	defer srv.Close()

	printTunBanner(prof, engine, chain, dev.Name(), iface, nameservers, dm != nil)
	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "\ndpb: stopping, tearing down tun…")
	return nil
}

func printTunBanner(prof config.Profile, engine *desync.Engine, chain *dns.Chain, ifaceName, uplink string, nameservers []string, dnsRedirected bool) {
	strat := engine.EmitterName()
	if ts := engine.TransformerNames(); len(ts) > 0 {
		strat = strings.Join(ts, " → ") + " → " + strat
	}
	resolverLine := "system resolver → " + sysnet.DefaultTunResolver + " (restores on exit)"
	if !dnsRedirected {
		resolverLine = "NOT redirected — queries may stay on the ISP resolver"
	}
	if len(nameservers) > 0 {
		resolverLine += ", host routes for " + strings.Join(nameservers, ", ")
	}
	fmt.Fprintf(os.Stderr, "dpb %s  profile=%s  mode=tun\n", version, prof.Name)
	fmt.Fprintf(os.Stderr, "  Device   %s (uplink %s)\n", ifaceName, uplink)
	fmt.Fprintf(os.Stderr, "  DNS      %s\n", strings.Join(chain.Labels(), ", "))
	fmt.Fprintf(os.Stderr, "  Resolver %s\n", resolverLine)
	fmt.Fprintf(os.Stderr, "  Strategy %s  ports=%s\n", strat, portsStr(prof.Filter.Ports))
	fmt.Fprintf(os.Stderr, "  Capture  all TCP + UDP via split-default route (restores on exit)\n")
	fmt.Fprintf(os.Stderr, "  Ready. Press Ctrl-C to stop and tear down.\n")
}
