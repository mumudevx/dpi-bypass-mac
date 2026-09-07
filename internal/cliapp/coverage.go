package cliapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/paths"
)

// `dpb coverage` answers "is anything actually going through this?"
//
// Proxy mode covers a program only if that program consults one of the two
// mechanisms dpb sets: the system proxy settings (which CFNetwork, Safari and
// Chromium read) or the login session's environment variables (which reqwest,
// curl, Go, Python and Node read). GT24 is why both exist — Discord's macOS
// updater is an in-process reqwest addon whose ONLY proxy sources are
// HTTP(S)_PROXY and NO_PROXY, so a run that set the proxy pane and nothing else
// would leave the one program the user cares about uncovered, silently.
//
// So this command reports two different things side by side: which mechanisms
// are SET, and which processes are actually CONNECTED. The second is the only
// one that is evidence.

func newCoverageCmd(g *globals) *cobra.Command {
	var (
		watch  time.Duration
		fix    bool
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show which proxy mechanisms are set and which processes are using them",
		Long: "coverage prints the two halves of the proxy-mode story.\n\n" +
			"The first is which mechanisms are in force: the system proxy settings, which\n" +
			"CFNetwork and Chromium read, and the login session's HTTP(S)_PROXY variables,\n" +
			"which reqwest, curl, Go, Python and Node read. Setting one and not the other\n" +
			"leaves a whole class of program uncovered.\n\n" +
			"The second is which processes are actually connected to dpb's listeners right\n" +
			"now, read with lsof. That is the only half that is evidence.",
		Example: "  dpb coverage\n  dpb coverage --watch 30s",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCoverage(cmd.Context(), g, watch, fix, asJSON)
		},
	}
	fl := cmd.Flags()
	fl.DurationVar(&watch, "watch", 0, "sample for this long, accumulating every process seen")
	fl.BoolVar(&fix, "fix", false, "ask the running dpb to re-assert the system settings it owns")
	fl.BoolVar(&asJSON, "json", false, "emit the report as JSON")
	return cmd
}

// mechanism is one way a program can be pointed at dpb.
type mechanism struct {
	Name  string `json:"name"`
	Set   bool   `json:"set"`
	Value string `json:"value,omitempty"`
	// Covers names the class of program this mechanism reaches, because "PAC is
	// on" means nothing to a user trying to work out why Discord still cannot
	// connect.
	Covers string `json:"covers"`
	Err    string `json:"error,omitempty"`
}

// client is one process observed connected to a dpb listener.
type client struct {
	Command string `json:"command"`
	PID     int    `json:"pid"`
	Port    int    `json:"port"`
}

type coverageReport struct {
	Running    bool        `json:"running"`
	Listeners  []int       `json:"listener_ports,omitempty"`
	Mechanisms []mechanism `json:"mechanisms"`
	Clients    []client    `json:"clients"`
	Sampled    string      `json:"sampled,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
}

func runCoverage(ctx context.Context, g *globals, watch time.Duration, fix, asJSON bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}
	if fix {
		return runCoverageFix(ctx, g, layout)
	}

	rep, err := buildCoverage(ctx, g, layout, watch)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(g.env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fmt.Errorf("coverage: write JSON: %w", err)
		}
		return nil
	}
	return renderCoverage(g.env.Stdout, rep)
}

// runCoverageFix asks the running dpb to re-assert its settings.
//
// It is a request to the daemon rather than something this process does,
// because the settings name THIS RUN's listener ports. A second process
// re-writing them would have to guess the port, and a proxy pane pointing at
// the wrong port is worse than one pointing at nothing: PAC fails open, an
// explicit proxy at a wrong port fails closed.
func runCoverageFix(ctx context.Context, g *globals, layout paths.Layout) error {
	note, err := g.controlClient(layout).Command(ctx, observ.CmdReapply)
	if errors.Is(err, observ.ErrNotRunning) {
		return fmt.Errorf("coverage --fix: no dpb is running. The system settings name a\n" +
			"listener port, so only the process that owns them can restore them: start one\n" +
			"with `dpb run`, or run `dpb doctor --repair` to clear what a dead one left behind")
	}
	if err != nil {
		return fmt.Errorf("coverage --fix: %w", err)
	}
	if note == "" {
		note = "system settings re-applied"
	}
	fmt.Fprintln(g.env.Stdout, note)
	return nil
}

func buildCoverage(ctx context.Context, g *globals, layout paths.Layout,
	watch time.Duration) (coverageReport, error) {

	rep := coverageReport{}
	env := netstate.Env{Runner: g.runnerOf(), RIB: g.ribOf(), Logf: g.logf}

	// Listener ports come from the running dpb when there is one, because it
	// knows which ports it actually BOUND — `--port 0` is a real thing to ask
	// for, and a report about the configured port would then be about nothing.
	var selfPID int
	if st, err := g.controlClient(layout).Status(ctx); err == nil {
		rep.Running = true
		selfPID = st.PID
		for _, l := range st.Listeners {
			if p, perr := portOf(l.Addr); perr == nil {
				rep.Listeners = append(rep.Listeners, p)
			}
		}
	} else {
		if !errors.Is(err, observ.ErrNotRunning) {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the control socket did not answer: %v", err))
		}
		cfg, cerr := scopeConfig(g)
		if cerr != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the configuration could not be loaded: %v", cerr))
		} else {
			for _, p := range []int{cfg.Port, cfg.SOCKSPort} {
				if p > 0 {
					rep.Listeners = append(rep.Listeners, p)
				}
			}
			rep.Notes = append(rep.Notes,
				"no dpb is running; the ports below are the CONFIGURED ones, not bound ones")
		}
	}

	rep.Mechanisms = readMechanisms(ctx, env)

	clients, note := sampleClients(ctx, env.Runner, rep.Listeners, selfPID, watch)
	rep.Clients = clients
	if watch > 0 {
		rep.Sampled = watch.String()
	}
	if note != "" {
		rep.Notes = append(rep.Notes, note)
	}
	return rep, nil
}

// readMechanisms reports which of the two coverage levers are in force.
func readMechanisms(ctx context.Context, env netstate.Env) []mechanism {
	var out []mechanism

	st, err := netstate.ReadProxyState(ctx, env)
	if err != nil {
		out = append(out, mechanism{
			Name:   "system proxy",
			Covers: "Safari, Chrome, Electron apps, anything on CFNetwork",
			Err:    err.Error(),
		})
	} else {
		out = append(out, mechanism{
			Name:   "auto-proxy URL (PAC)",
			Set:    st.On("ProxyAutoConfigEnable"),
			Value:  st.Str("ProxyAutoConfigURLString"),
			Covers: "Safari, Chrome, Electron apps, anything on CFNetwork",
		})
		out = append(out, mechanism{
			Name:   "secure web proxy",
			Set:    st.On("HTTPSEnable"),
			Value:  proxyTarget(st, "HTTPSProxy", "HTTPSPort"),
			Covers: "the same programs, without needing to fetch the PAC",
		})
		out = append(out, mechanism{
			Name:   "SOCKS proxy",
			Set:    st.On("SOCKSEnable"),
			Value:  proxyTarget(st, "SOCKSProxy", "SOCKSPort"),
			Covers: "programs configured to use SOCKS",
		})
	}

	for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"} {
		v, err := netstate.ReadLaunchEnv(ctx, env, name)
		m := mechanism{
			Name:   "launchd " + name,
			Covers: "reqwest, curl, Go, Python, Node — including Discord's own updater (GT24)",
		}
		if err != nil {
			m.Err = err.Error()
		} else {
			m.Set, m.Value = v != "", v
		}
		out = append(out, m)
	}
	return out
}

// lsofTimeout bounds one sample. lsof can block on a stuck filesystem, and a
// diagnostic that hangs is one nobody runs twice.
const lsofTimeout = 5 * time.Second

// sampleClients reads the processes connected to dpb's listeners.
//
// A single lsof is a snapshot, and a browser that opened and closed a
// connection a second ago is invisible in it. --watch is what turns the
// snapshot into evidence: it accumulates the union over repeated samples, which
// is what "which processes are actually using dpb" means.
func sampleClients(ctx context.Context, runner netstate.Runner, ports []int,
	selfPID int, watch time.Duration) ([]client, string) {

	if len(ports) == 0 {
		return nil, "no listener ports are known, so no client could be attributed to one"
	}
	seen := map[string]client{}
	sample := func() error {
		for _, p := range ports {
			cs, err := lsofPort(ctx, runner, p, selfPID)
			if err != nil {
				return err
			}
			for _, c := range cs {
				seen[fmt.Sprintf("%s/%d/%d", c.Command, c.PID, c.Port)] = c
			}
		}
		return nil
	}

	if err := sample(); err != nil {
		return nil, err.Error()
	}
	if watch > 0 {
		deadline := time.Now().Add(watch)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return sortClients(seen), "the watch was interrupted"
			case <-tick.C:
			}
			if err := sample(); err != nil {
				return sortClients(seen), err.Error()
			}
		}
	}
	return sortClients(seen), ""
}

func sortClients(m map[string]client) []client {
	out := make([]client, 0, len(m))
	for _, k := range sortedKeys(m) {
		out = append(out, m[k])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Command != out[j].Command {
			return out[i].Command < out[j].Command
		}
		return out[i].PID < out[j].PID
	})
	return out
}

// lsofPort lists established connections to one loopback port.
func lsofPort(ctx context.Context, runner netstate.Runner, port, selfPID int) ([]client, error) {
	lctx, cancel := context.WithTimeout(ctx, lsofTimeout)
	defer cancel()

	res := runner.Run(lctx, "lsof",
		"-nP", "-w", "-a",
		"-iTCP:"+strconv.Itoa(port),
		"-sTCP:ESTABLISHED",
		"-Fcpn")
	// lsof exits 1 when nothing matches, which is the ordinary case on a quiet
	// machine and not a failure. Anything with output on a non-zero exit is.
	out := strings.TrimSpace(res.Combined)
	if res.Err != nil {
		return nil, fmt.Errorf("coverage: run lsof: %w", res.Err)
	}
	if res.Code != 0 && out != "" && !strings.HasPrefix(out, "p") {
		return nil, fmt.Errorf("coverage: lsof: %s", firstLineOf(out))
	}
	return parseLsof(out, port, selfPID), nil
}

// parseLsof reads lsof's field output (-F), which is one prefixed value per
// line: p<pid>, c<command>, n<name>. It is used instead of the column format
// because a command name with a space in it — "Google Chrome Helper" — makes
// column splitting wrong in exactly the case a user cares about.
func parseLsof(out string, port, selfPID int) []client {
	var res []client
	var cur client
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		value := line[1:]
		switch line[0] {
		case 'p':
			pid, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			cur = client{PID: pid, Port: port}
		case 'c':
			cur.Command = value
		case 'n':
			// The name is "local->remote". Only the end that CONNECTED to our
			// port is a client; the other end of the same socket is dpb's own
			// accepted side, and counting it would report dpb as its own user.
			local, remote, ok := strings.Cut(value, "->")
			if !ok {
				continue
			}
			if portOfName(remote) != port {
				continue
			}
			if portOfName(local) == port {
				continue
			}
			if cur.PID == 0 || cur.PID == selfPID || cur.PID == os.Getpid() {
				continue
			}
			res = append(res, cur)
		}
	}
	return res
}

func portOfName(s string) int {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return 0
	}
	p, err := strconv.Atoi(strings.TrimSpace(s[i+1:]))
	if err != nil {
		return 0
	}
	return p
}

func portOf(addr string) (int, error) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return 0, fmt.Errorf("coverage: %q has no port", addr)
	}
	return strconv.Atoi(addr[i+1:])
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func renderCoverage(w io.Writer, rep coverageReport) error {
	var b strings.Builder
	if rep.Running {
		b.WriteString("dpb is running.\n")
	} else {
		b.WriteString("dpb is NOT running.\n")
	}
	if len(rep.Listeners) > 0 {
		strs := make([]string, len(rep.Listeners))
		for i, p := range rep.Listeners {
			strs[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&b, "ports:     %s\n", strings.Join(strs, ", "))
	}

	b.WriteString("\nmechanisms\n")
	for _, m := range rep.Mechanisms {
		state := "not set"
		switch {
		case m.Err != "":
			state = "unknown"
		case m.Set:
			state = "SET"
		}
		fmt.Fprintf(&b, "  %-24s %-8s %s\n", m.Name, state, m.Value)
		fmt.Fprintf(&b, "      covers %s\n", m.Covers)
		if m.Err != "" {
			fmt.Fprintf(&b, "      error: %s\n", m.Err)
		}
	}

	b.WriteString("\nprocesses connected right now\n")
	if len(rep.Clients) == 0 {
		b.WriteString("  none.\n")
		// The absence of clients is ambiguous on its own, and the ambiguity is
		// the whole reason --watch exists.
		b.WriteString("  A snapshot only sees connections that are open at this instant;\n")
		b.WriteString("  run `dpb coverage --watch 30s` and use the programs you care about.\n")
	} else {
		for _, c := range rep.Clients {
			fmt.Fprintf(&b, "  %-28s pid %-7d -> port %d\n", c.Command, c.PID, c.Port)
		}
	}
	if rep.Sampled != "" {
		fmt.Fprintf(&b, "  (accumulated over %s)\n", rep.Sampled)
	}

	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "\nnote: %s\n", n)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("coverage: write: %w", err)
	}
	return nil
}
