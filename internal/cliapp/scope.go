package cliapp

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// `dpb scope` reads and edits which hosts dpb is allowed to touch.
//
// The edits go to <config dir>/scope.toml, a file dpb owns and rewrites whole,
// and NOT to the user's own config.toml. Rewriting a file a person wrote by
// hand would eat their comments and reorder their settings the first time they
// typed `dpb scope bypass`; owning a separate layer costs one file and makes
// the edit reversible by deleting it.
func newScopeCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Show and edit which hosts dpb watches, and which it never touches",
		Long: "scope has two lists.\n\n" +
			"The BYPASS list is a hard veto: those hosts are relayed with nothing buffered\n" +
			"and are never desynced. It starts with the ten hosts MEASUREMENTS.md §5.1\n" +
			"measured breaking under desync — every one a bank or a .gov.tr site — and you\n" +
			"can add to it but not remove from it.\n\n" +
			"The INCLUDE list, if you set one, is an allow-list: only those names are ever\n" +
			"escalated and everything else is relayed directly.",
	}
	cmd.AddCommand(
		newScopeListCmd(g),
		newScopeTestCmd(g),
		newScopeEditCmd(g, "bypass", "Never touch this host", scopeBypass),
		newScopeEditCmd(g, "unbypass", "Undo a `scope bypass` you added", scopeUnbypass),
		newScopeEditCmd(g, "add", "Add a name to the include allow-list", scopeInclude),
		newScopeEditCmd(g, "remove", "Remove a name from the include allow-list", scopeUninclude),
	)
	return cmd
}

// scopeEdit is which list an edit touches and in which direction.
type scopeEdit int

const (
	scopeBypass scopeEdit = iota
	scopeUnbypass
	scopeInclude
	scopeUninclude
)

func newScopeListCmd(g *globals) *cobra.Command {
	var effective bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print every rule in force, with where it came from",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			cfg, err := scopeConfig(g)
			if err != nil {
				return err
			}
			rules, err := cfg.Rules()
			if err != nil {
				return usagef("%v", err)
			}
			ips, err := cfg.IPRules()
			if err != nil {
				return usagef("%v", err)
			}
			w := g.env.Stdout
			fmt.Fprintf(w, "profile %s\n\n", cfg.Profile)
			for _, r := range rules {
				line := fmt.Sprintf("  %-9s %-24s %s", r.Class, r.Pattern, r.Where())
				if why, ok := config.MandatoryReason(r.Pattern); ok {
					line += "  — " + why
				}
				fmt.Fprintln(w, line)
			}
			for _, r := range ips {
				fmt.Fprintf(w, "  %-9s %-24s %s\n", r.Class, r.Pattern, r.Where())
			}
			if effective {
				// The bogon table is applied by policy itself and is not
				// restated in any config, so it is invisible in the lists
				// above. --effective is the only way to see what is really
				// enforced.
				fmt.Fprintf(w, "\n  plus the compiled-in private-address table, applied by policy:\n")
				for _, p := range policy.BogonPrefixes() {
					fmt.Fprintf(w, "  %-9s %-24s %s\n", policy.ScopeBypass, p, policy.FromCompiledIn)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&effective, "effective", false,
		"also print the compiled-in private-address table policy applies on its own")
	return cmd
}

func newScopeTestCmd(g *globals) *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "test HOST",
		Short: "Show what dpb would do with a host, and why",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cfg, err := scopeConfig(g)
			if err != nil {
				return err
			}
			engine, err := scopeEngine(cfg, port)
			if err != nil {
				return err
			}
			x := engine.Explain(args[0])
			if err := x.Text(g.env.Stdout); err != nil {
				return fmt.Errorf("scope test: %w", err)
			}
			// The verdict Explain prints is the one for the port asked about,
			// and a host that is watched on 443 is relayed directly on 8443.
			// Saying which port this answer is about stops that reading as a
			// contradiction.
			fmt.Fprintf(g.env.Stdout, "\nport %d: %s\n", port, engine.ForName(args[0], port).Class)
			return nil
		},
	}
	cmd.Flags().IntVar(&port, "port", 443, "destination port to decide for")
	return cmd
}

func newScopeEditCmd(g *globals, verb, short string, edit scopeEdit) *cobra.Command {
	use := verb + " HOST"
	if edit == scopeBypass {
		use = verb + " HOST|CIDR"
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return applyScopeEdit(g, edit, args[0])
		},
	}
}

// scopeConfig loads the configuration the scope commands read, which is the
// same layering `dpb run` uses so the two can never disagree about a rule.
func scopeConfig(g *globals) (*config.Loaded, error) {
	layout, err := g.layoutOf()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(config.Options{
		System: config.DefaultSystemFile,
		User:   layout.ConfigFile(),
		Files:  []string{scopeFile(layout)},
		Env:    g.getenvOf(),
	})
	if err != nil {
		return nil, usagef("%v", err)
	}
	return cfg, nil
}

func scopeEngine(cfg *config.Loaded, port int) (*policy.Engine, error) {
	rules, err := cfg.Rules()
	if err != nil {
		return nil, usagef("%v", err)
	}
	ips, err := cfg.IPRules()
	if err != nil {
		return nil, usagef("%v", err)
	}
	m, err := policy.NewMatcher(rules)
	if err != nil {
		return nil, usagef("%v", err)
	}
	set, err := policy.NewIPSet(ips)
	if err != nil {
		return nil, usagef("%v", err)
	}
	ports := cfg.InspectPorts
	if port != 0 {
		ports = append(append([]int(nil), ports...), port)
	}
	return policy.NewEngine(policy.EngineOptions{
		Rules:        m,
		IPs:          set,
		IncludeOnly:  cfg.IncludeOnly(),
		InspectPorts: ports,
	}), nil
}

// scopeState is the file `dpb scope` owns.
type scopeState struct {
	Bypass  []string `toml:"bypass"`
	Include []string `toml:"include"`
}

const scopeHeader = "# Written by `dpb scope`. Edit it by hand if you like; dpb rewrites the two\n" +
	"# lists below and nothing else, so keep your own settings in config.toml.\n" +
	"#\n" +
	"# The ten hosts MEASUREMENTS.md 5.1 measured breaking under desync are compiled\n" +
	"# into the binary and are NOT listed here: they cannot be removed.\n\n"

func applyScopeEdit(g *globals, edit scopeEdit, host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return usagef("scope: an empty host")
	}
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}
	if err := layout.EnsureDirs(); err != nil {
		return fmt.Errorf("scope: create the config directory: %w", err)
	}

	state, err := readScopeState(layout)
	if err != nil {
		return err
	}

	switch edit {
	case scopeBypass:
		if _, ok := config.MandatoryReason(host); ok {
			fmt.Fprintf(g.env.Stdout, "%s is already bypassed, compiled in: %s\n", host, mustReason(host))
			return nil
		}
		if !validScopePattern(host) {
			return usagef("scope: %q is neither a hostname pattern nor a CIDR", host)
		}
		state.Bypass = addOnce(state.Bypass, host)
	case scopeUnbypass:
		if _, ok := config.MandatoryReason(host); ok {
			return refusedError{fmt.Errorf(
				"scope: %s is bypassed by measurement, not by preference (%s); "+
					"the compiled-in list is extendable but not removable", host, mustReason(host))}
		}
		state.Bypass = remove(state.Bypass, host)
	case scopeInclude:
		if !validScopePattern(host) {
			return usagef("scope: %q is not a hostname pattern", host)
		}
		state.Include = addOnce(state.Include, host)
	case scopeUninclude:
		state.Include = remove(state.Include, host)
	}

	if err := writeScopeState(layout, state); err != nil {
		return err
	}
	fmt.Fprintf(g.env.Stdout, "wrote %s\n", scopeFile(layout))
	// A running dpb does not see this until it reloads: saying so beats letting
	// the user believe an edit took effect on connections already in flight.
	fmt.Fprintln(g.env.Stdout, "restart `dpb run` for it to take effect.")
	return nil
}

func mustReason(host string) string {
	why, _ := config.MandatoryReason(host)
	return why
}

func validScopePattern(s string) bool {
	if _, err := policy.ParsePrefix(s); err == nil {
		return true
	}
	_, err := policy.NewMatcher([]policy.Rule{{Pattern: s, Class: policy.ScopeBypass, From: "scope"}})
	return err == nil
}

func addOnce(list []string, v string) []string {
	for _, e := range list {
		if strings.EqualFold(e, v) {
			return list
		}
	}
	list = append(list, v)
	sort.Strings(list)
	return list
}

func remove(list []string, v string) []string {
	out := list[:0]
	for _, e := range list {
		if !strings.EqualFold(e, v) {
			out = append(out, e)
		}
	}
	return out
}

func readScopeState(l paths.Layout) (scopeState, error) {
	var st scopeState
	data, err := os.ReadFile(scopeFile(l))
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("scope: read %s: %w", scopeFile(l), err)
	}
	if err := decodeScope(data, &st); err != nil {
		return st, usagef("scope: %s: %v", scopeFile(l), err)
	}
	return st, nil
}

func writeScopeState(l paths.Layout, st scopeState) error {
	var b strings.Builder
	b.WriteString(scopeHeader)
	b.WriteString("bypass = " + tomlList(st.Bypass) + "\n")
	b.WriteString("include = " + tomlList(st.Include) + "\n")
	path := scopeFile(l)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("scope: write %s: %w", path, err)
	}
	return l.Chown(path)
}

// decodeScope reads the file `dpb scope` wrote, rejecting anything it did not
// write. The file is ours, so a key we do not recognise means it has been
// hand-edited into something we would silently ignore.
func decodeScope(data []byte, st *scopeState) error {
	md, err := toml.Decode(string(data), st)
	if err != nil {
		return err
	}
	if un := md.Undecoded(); len(un) > 0 {
		return fmt.Errorf("unknown key %s; this file holds only bypass and include", un[0])
	}
	return nil
}

func tomlList(in []string) string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strconv.Quote(s))
	}
	return "[" + strings.Join(out, ", ") + "]"
}
