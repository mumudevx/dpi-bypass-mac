package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/desync"
	"github.com/mumudevx/dpi-bypass-mac/internal/dns"
	"github.com/mumudevx/dpi-bypass-mac/internal/logx"
	"github.com/mumudevx/dpi-bypass-mac/internal/proxy"
	"github.com/mumudevx/dpi-bypass-mac/internal/sysnet"
	"github.com/spf13/cobra"
)

type runFlags struct {
	profile     string
	mode        string
	listen      string
	port        int
	emitter     string
	splitOffset int
	fragWindow  int
	fakeTTL     int
	dohURL      string
	configPath  string
	noSetProxy  bool
	verbose     int
}

func newRunCmd() *cobra.Command {
	f := &runFlags{}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the DPI-bypass proxy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDpb(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.profile, "profile", "global", "region profile (see `dpb profiles list`)")
	fl.StringVar(&f.mode, "mode", "proxy", "interception mode: proxy | tun")
	fl.StringVar(&f.listen, "listen", "127.0.0.1", "listen address")
	fl.IntVar(&f.port, "port", 8080, "HTTP/HTTPS proxy port")
	fl.StringVar(&f.emitter, "emitter", "", "override desync emitter")
	fl.IntVar(&f.splitOffset, "split-offset", 0, "override split offset (bytes)")
	fl.IntVar(&f.fragWindow, "frag-window", 0, "override fragmentation window (bytes)")
	fl.IntVar(&f.fakeTTL, "fake-ttl", 0, "override fake-packet TTL (tun mode)")
	fl.StringVar(&f.dohURL, "dns-doh", "", "prepend a DoH resolver URL")
	fl.StringVar(&f.configPath, "config", config.DefaultConfigPath(), "user config file")
	fl.BoolVar(&f.noSetProxy, "no-set-proxy", false, "do not modify the system proxy")
	fl.CountVarP(&f.verbose, "verbose", "v", "verbose output (-vv for debug)")
	return cmd
}

func runDpb(cmd *cobra.Command, f *runFlags) error {
	log := logx.New(f.verbose)

	if f.mode != "proxy" && f.mode != "tun" {
		return fmt.Errorf("unknown mode %q (use proxy or tun)", f.mode)
	}

	prof, err := config.Resolve(f.profile, f.configPath, overridesFrom(cmd, f))
	if err != nil {
		return err
	}
	engine, err := desync.New(prof.ToSpec())
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if f.mode == "tun" {
		return runTun(ctx, f, prof, engine, log)
	}

	chain, err := buildResolver(prof, log)
	if err != nil {
		return err
	}

	srv := proxy.New(proxy.Options{
		Resolver:    chain,
		Apply:       proxy.EngineApply(engine),
		DesyncPorts: desyncPorts(prof.Filter.Ports),
		SkipHost:    skipHostFunc(prof.Filter.SNISkip),
		Logf:        log.Debugf,
	})

	// System proxy lifecycle with guaranteed restore.
	var pm *sysnet.ProxyManager
	if !f.noSetProxy {
		pm = sysnet.NewProxyManager(sysnet.ProxyConfig{
			Host:     f.listen,
			HTTPPort: f.port,
			Logf:     log.Warnf,
		})
		if err := pm.Enable(ctx); err != nil {
			log.Warnf("could not set system proxy: %v (continuing; configure proxy manually)", err)
			pm = nil
		}
		defer func() {
			if pm != nil {
				rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				pm.Restore(rctx)
			}
		}()
	}

	printBanner(prof, engine, chain, f, pm != nil)

	addr := fmt.Sprintf("%s:%d", f.listen, f.port)
	if err := srv.ListenAndServe(ctx, addr); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "\ndpb: stopping, restoring system settings…")
	return nil
}

func overridesFrom(cmd *cobra.Command, f *runFlags) config.Overrides {
	var ov config.Overrides
	if cmd.Flags().Changed("emitter") {
		ov.Emitter = &f.emitter
	}
	if cmd.Flags().Changed("split-offset") {
		ov.SplitOffset = &f.splitOffset
	}
	if cmd.Flags().Changed("frag-window") {
		ov.FragWindow = &f.fragWindow
	}
	if cmd.Flags().Changed("fake-ttl") {
		ov.FakeTTL = &f.fakeTTL
	}
	if cmd.Flags().Changed("dns-doh") {
		ov.DoHURL = &f.dohURL
	}
	return ov
}

func buildResolver(prof config.Profile, log *logx.Logger) (*dns.Chain, error) {
	var resolvers []dns.Resolver
	for _, r := range prof.DNS.Resolvers {
		res, err := dns.ResolverFromSpec(r.Type, r.URL, r.Name)
		if err != nil {
			log.Warnf("dns: skipping resolver %s: %v", r.Name, err)
			continue
		}
		resolvers = append(resolvers, res)
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("profile %q has no usable DNS resolvers", prof.Name)
	}
	return dns.NewChain(resolvers, prof.DNS.CacheTTL.Std(), log.Debugf), nil
}

func desyncPorts(ports []int) map[int]bool {
	if len(ports) == 0 {
		return map[int]bool{443: true, 80: true}
	}
	m := make(map[int]bool, len(ports))
	for _, p := range ports {
		m[p] = true
	}
	return m
}

func skipHostFunc(suffixes []string) func(string) bool {
	return func(host string) bool {
		for _, s := range suffixes {
			if s != "" && strings.HasSuffix(host, s) {
				return true
			}
		}
		return false
	}
}
