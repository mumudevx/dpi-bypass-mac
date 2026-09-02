package cliapp

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// The verdict cache is what makes MEASUREMENTS.md §5.2 step 4 real — "cache
// 'plain works' just as durably, so a bank is desynced at most once, ever" —
// and it is therefore a thing a user needs to be able to read and to reset.
//
// NAMESPACE NOTE for M11/M15. Verdicts are namespaced by policy.NetworkID, and
// collecting a real one needs the netstate facts a running dpb has and a
// one-shot CLI does not. These commands therefore operate on the zero
// NetworkID, which is the namespace used before the first fact collection
// completes. `dpb cache export` sidesteps the question entirely by streaming
// the whole store. Once the runtime can hand over a NetworkID, `--network` can
// select one; until then, saying so is better than printing another network's
// rows under this one's name.
func newCacheCmd(g *globals) *cobra.Command {
	var store string

	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect and reset the learned verdict cache",
		Long: "cache reads the per-host verdicts dpb learned: which hosts needed a desync, and\n" +
			"which ones work plain and must never be desynced again.\n\n" +
			"Both halves matter. MEASUREMENTS.md §5.1 measured every bypassing emitter\n" +
			"breaking Turkish banking, so \"plain works\" is cached exactly as durably as a\n" +
			"desync winner — that is what keeps a bank from being desynced twice.",
	}
	cmd.PersistentFlags().StringVar(&store, "store", "",
		"verdict store path (default: the state directory)")

	cmd.AddCommand(
		newCacheListCmd(g, &store),
		newCacheForgetCmd(g, &store),
		newCacheClearCmd(g, &store),
		newCacheExportCmd(g, &store),
	)
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		c.SetOut(g.env.Stderr)
		_ = c.Help()
		return usagef("cache: no subcommand given")
	}
	return cmd
}

func cachePath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	l, err := paths.Resolve()
	if err != nil {
		return "", fmt.Errorf("cache: locate the state directory: %w", err)
	}
	return l.VerdictFile(), nil
}

// openCache opens the store for reading or writing. A missing file is not an
// error: nothing has been learned yet, which is a state and not a fault.
func openCache(explicit string) (policy.Store, string, error) {
	path, err := cachePath(explicit)
	if err != nil {
		return nil, "", err
	}
	s, err := policy.OpenStore(path, time.Now)
	if err != nil {
		return nil, path, fmt.Errorf("cache: open %s: %w", path, err)
	}
	return s, path, nil
}

func newCacheListCmd(g *globals, store *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the learned verdicts",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			s, path, err := openCache(*store)
			if err != nil {
				return err
			}
			defer s.Close()
			writeCache(g.env.Stdout, s, path)
			return nil
		},
	}
}

type cacheRow struct {
	host string
	v    policy.Verdict
}

func writeCache(w io.Writer, s policy.Store, path string) {
	var rows []cacheRow
	s.ForEach(policy.NetworkID{}, func(host string, v policy.Verdict) bool {
		rows = append(rows, cacheRow{host: host, v: v})
		return true
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].host < rows[j].host })

	fmt.Fprintf(w, "%s\n\n", path)
	if len(rows) == 0 {
		fmt.Fprintln(w, "nothing learned yet on the default namespace.")
		fmt.Fprintln(w, "verdicts are namespaced per network; a running dpb writes them under the")
		fmt.Fprintln(w, "network it measured. `dpb cache export` prints every namespace.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  host\tclass\tstrategy\tsource\texpires\twins/losses")
	for _, r := range rows {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%d/%d\n",
			r.host, r.v.Class, labelSpec(r.v.Spec), r.v.Source,
			expiryText(r.v.Expires), r.v.Wins, r.v.Losses)
	}
	tw.Flush()
}

func labelSpec(spec string) string {
	if spec == "" {
		return "plain"
	}
	return spec
}

func expiryText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func newCacheForgetCmd(g *globals, store *string) *cobra.Command {
	return &cobra.Command{
		Use:   "forget HOST",
		Short: "Drop what was learned about one host",
		Long: "forget removes a host's verdict so the next connection walks the ladder from\n" +
			"plain again. It is the fix for a host that changed behind a cached answer.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, _, err := openCache(*store)
			if err != nil {
				return err
			}
			defer s.Close()

			host := args[0]
			// Demote counts toward policy.DemoteThreshold and deletes the record
			// when it is reached, so forgetting is that threshold applied at
			// once. Going through Demote rather than reaching into the file
			// keeps one owner for the store's format.
			for i := 0; i < policy.DemoteThreshold; i++ {
				if err := s.Demote(policy.NetworkID{}, host); err != nil {
					return fmt.Errorf("cache forget %s: %w", host, err)
				}
			}
			if err := s.Flush(); err != nil {
				return fmt.Errorf("cache forget %s: %w", host, err)
			}
			if _, ok := s.Get(policy.NetworkID{}, host); ok {
				return fmt.Errorf("cache forget %s: the verdict is still cached", host)
			}
			fmt.Fprintf(g.env.Stdout, "forgot %s; the next connection walks the ladder from plain\n", host)
			return nil
		},
	}
}

func newCacheClearCmd(g *globals, store *string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete every learned verdict",
		Long: "clear removes the whole store. Every host is then unknown again, so the first\n" +
			"visit to each blocked host costs one extra round trip (~23 ms, MEASUREMENTS.md\n" +
			"§6) and each fragile host is judged plain-first exactly as it was originally.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			path, err := cachePath(*store)
			if err != nil {
				return err
			}
			if !yes {
				return usagef("cache clear: this deletes every learned verdict in %s; "+
					"pass --yes to confirm", path)
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("cache clear: %w", err)
			}
			fmt.Fprintf(g.env.Stdout, "cleared %s\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deleting every learned verdict")
	return cmd
}

func newCacheExportCmd(g *globals, store *string) *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Print the whole store, every namespace",
		Long: "export writes the store verbatim. It is the shareable diagnostic — and it names\n" +
			"every host this machine connected to, so read it before sending it to anyone.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			path, err := cachePath(*store)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(path)
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(g.env.Stdout, "{}")
				return nil
			}
			if err != nil {
				return fmt.Errorf("cache export: %w", err)
			}
			_, err = g.env.Stdout.Write(b)
			return err
		},
	}
}
