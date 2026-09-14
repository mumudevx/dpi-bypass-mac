package cliapp

import (
	"path/filepath"

	"github.com/spf13/cobra"
)

// `dpb devtool` is a group for commands that exist to help develop dpb, not
// to run it. It is hidden for the same reason `dpb _janitor` is (see
// janitorcmd.go): a user never types this, but the project benefits from it
// existing as a real subcommand rather than a script someone has to
// remember lives outside the binary.
//
// defaultCaptureSysconfDir is relative to the CURRENT DIRECTORY, on purpose:
// this is a command a developer runs from a checkout of this repository on a
// real Windows machine, the same way `go test` and `gofmt -l cmd internal
// tools` already assume a repo root working directory. A test that actually
// executes capture-sysconf always overrides --out with a temporary
// directory, so nothing under this default path is ever written by `go
// test`.
var defaultCaptureSysconfDir = filepath.Join("internal", "testwin", "fixtures")

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
// JSON, into internal/testwin/fixtures. See
// internal/sysconf/scwindows/capture.go for what is captured and why it
// keeps more of each row than any production reader in this tree consumes
// today.
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
			"It is implemented for Windows only; running it on any other platform refuses\n" +
			"by name rather than silently doing nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCaptureSysconf(g.env.Stdout, outDir)
		},
	}
	cmd.Flags().StringVar(&outDir, "out", defaultCaptureSysconfDir,
		"directory to write routes.json, adapters.json and proxy.json into")
	return cmd
}
