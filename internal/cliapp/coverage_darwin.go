//go:build darwin

package cliapp

// What `dpb coverage` tells a macOS user each of the two levers actually
// reaches. See coverage_windows.go for why these are a platform leaf at all
// rather than the constants they used to be inline in coverage.go.
const (
	// The system proxy pane is read through CFNetwork, so everything built on
	// it is covered whether or not it knows what a proxy is.
	systemProxyCovers = "Safari, Chrome, Electron apps, anything on CFNetwork"

	// The session-environment lever is launchd's: `launchctl setenv` writes
	// into the user's launchd domain, which is what every process the session
	// starts afterwards inherits. GT24 is why this half exists at all —
	// Discord's macOS updater is an in-process reqwest addon whose only proxy
	// sources are these variables.
	envMechanismPrefix = "launchd "
	envMechanismCovers = "reqwest, curl, Go, Python, Node — including Discord's own updater (GT24)"
)
