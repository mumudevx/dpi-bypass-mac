//go:build darwin

package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"github.com/mumudevx/dpi-bypass-mac/internal/logx"
	"github.com/mumudevx/dpi-bypass-mac/internal/sysnet"
	"github.com/mumudevx/dpi-bypass-mac/internal/tun"
)

const (
	tunLocalAddr = "198.18.0.1"
	tunPeerAddr  = "198.18.0.2"
)

// runTun brings up the transparent TUN datapath: a utun device + gVisor
// netstack capturing all TCP, with the desync engine (and per-connection raw
// injector) applied. Requires root.
func runTun(ctx context.Context, f *runFlags, prof config.Profile, engine *desync.Engine, log *logx.Logger) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("tun mode requires root — re-run with: sudo dpb run --mode tun --profile %s", f.profile)
	}

	runner := sysnet.ExecRunner{}
	iface := sysnet.DefaultInterface(ctx, runner)
	if iface == "" {
		return fmt.Errorf("could not determine the physical uplink interface")
	}
	dial, err := sysnet.BoundDialer(iface, 10*time.Second)
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
	if err := rm.CaptureAll(ctx); err != nil {
		_ = dev.Close()
		return err
	}

	srv, err := tun.NewServer(tun.Options{
		Device:      dev,
		Engine:      engine,
		Dial:        tun.DialFunc(dial),
		DesyncPorts: desyncPorts(prof.Filter.Ports),
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

	printTunBanner(prof, engine, dev.Name(), iface, f)
	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "\ndpb: stopping, tearing down tun…")
	return nil
}

func printTunBanner(prof config.Profile, engine *desync.Engine, ifaceName, uplink string, f *runFlags) {
	strat := engine.EmitterName()
	if ts := engine.TransformerNames(); len(ts) > 0 {
		strat = join(ts, " → ") + " → " + strat
	}
	fmt.Fprintf(os.Stderr, "dpb %s  profile=%s  mode=tun\n", version, prof.Name)
	fmt.Fprintf(os.Stderr, "  Device   %s (uplink %s)\n", ifaceName, uplink)
	fmt.Fprintf(os.Stderr, "  Strategy %s  ports=%s\n", strat, portsStr(prof.Filter.Ports))
	fmt.Fprintf(os.Stderr, "  Capture  all TCP via split-default route (restores on exit)\n")
	fmt.Fprintf(os.Stderr, "  Ready. Press Ctrl-C to stop and tear down.\n")
}

func join(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
