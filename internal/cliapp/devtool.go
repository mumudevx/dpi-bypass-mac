package cliapp

import (
	"github.com/spf13/cobra"
)

// `dpb devtool` is a group for commands that exist to help develop dpb, not
// to run it. It is hidden for the same reason `dpb _janitor` is (see
// janitorcmd.go): a user never types this, but the project benefits from it
// existing as a real subcommand rather than a script someone has to
// remember lives outside the binary.
func newDevtoolCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "devtool",
		Short:  "internal: developer utilities, not part of dpb's supported surface",
		Hidden: true,
	}
	cmd.AddCommand(newCaptureSysconfCmd(g))
	return cmd
}

// newCaptureSysconfCmd is `dpb devtool capture-sysconf`.
//
// Plan 4 deferred this command because there was no Windows machine to
// capture from; the windows-latest CI job Plan 6 Task 1 added is one, which
// is what makes writing it now worth doing rather than premature.
//
// It exists to keep internal/testnet's package comment's guarantee alive on
// Windows: the macOS fakes in internal/testnet are driven by CLI output
// captured from a real machine, so a test asserts against what the machine
// actually printed rather than against what the author assumed. scwindows
// reads Win32 APIs that return STRUCTS, not text — MibIpForwardTable2 rows,
// IpAdapterAddresses blocks, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG — so there
// is no CLI output to capture. This command captures the struct instead, as
// JSON. See internal/sysconf/scwindows/capture.go for what is captured and
// why it keeps more of each row than any production reader in this tree
// consumes today.
//
// --out is REQUIRED and has no default. It used to default to
// internal/testwin/fixtures, relative to the current directory, on the
// reasoning that a developer runs this from a checkout — which is true and is
// exactly the problem: the one command whose whole job is to read a machine's
// live network configuration wrote its output into a git working tree by
// default. Run on a managed laptop that is a corporate PAC URL and the
// operator's own addresses, one `git add -A` away from a public commit.
// scwindows redacts what identifies a network now, but the redaction and the
// destination are two separate mistakes and only one of them is fixed by
// redacting: a required flag means the operator says where the file lands, and
// nothing lands in a checkout unless they typed the path.
//
// It only makes sense on a Windows host, because scwindows' three exported
// Capture* functions are windows-tagged. runCaptureSysconf is therefore
// build-tagged into devtool_windows.go (the real implementation) and
// devtool_other.go (a refusal by name, never a silent no-op) — the same
// pattern internal/netwatch/route_other.go and internal/emit/stub_other.go
// use for a capability a platform genuinely does not have.
func newCaptureSysconfCmd(g *globals) *cobra.Command {
	var outDir string
	cmd := &cobra.Command{
		Use:   "capture-sysconf",
		Short: "capture live Windows sysconf API returns as JSON fixtures (Windows only)",
		Long: "capture-sysconf calls the same Win32 APIs internal/sysconf/scwindows reads —\n" +
			"GetIpForwardTable2, GetAdaptersAddresses, WinHttpGetIEProxyConfigForCurrentUser —\n" +
			"and writes what they returned as JSON under --out, so a future test can be\n" +
			"written against a real machine's answer instead of an assumed one.\n\n" +
			"PRIVACY. This reads the live network configuration of the machine it runs on,\n" +
			"so the capture is redacted before it is written:\n\n" +
			"  - the WinHTTP auto-config (PAC) URL, proxy and proxy-bypass strings are NOT\n" +
			"    written. On a managed machine these name an employer's internal hosts and\n" +
			"    domains. proxy.json records only WHICH of them were set, by field name.\n" +
			"  - every IP address and route prefix is replaced by a documentation address\n" +
			"    (RFC 5737 / RFC 3849) of the same family and category, keeping the prefix\n" +
			"    length. A fixture still says \"default route, on-link route, link-local\n" +
			"    address\"; it no longer says whose network.\n" +
			"  - adapter friendly names and descriptions are KEPT, because they name\n" +
			"    hardware rather than a network and a fixture without them is useless.\n" +
			"    A VPN client's adapter description can still name its vendor, so read the\n" +
			"    three files before committing them anywhere.\n\n" +
			"--out is required and has no default: nothing is written into a git checkout\n" +
			"unless you name a path inside one.\n\n" +
			"It is implemented for Windows only; running it on any other platform refuses\n" +
			"by name rather than silently doing nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCaptureSysconf(g.env.Stdout, outDir)
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "",
		"directory to write routes.json, adapters.json and proxy.json into (required)")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}
