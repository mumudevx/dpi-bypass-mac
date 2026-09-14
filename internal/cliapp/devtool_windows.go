//go:build windows

package cliapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/mumudevx/dpb/internal/sysconf/scwindows"
)

// captureMeta is embedded in every fixture file this command writes, so a
// fixture found later carries its own provenance: when it was taken and on
// what binary. Neither field is read by anything today — it exists for the
// same reason a photograph's timestamp does, not because a consumer asked
// for it yet.
type captureMeta struct {
	CapturedAt time.Time `json:"captured_at"`
	GOARCH     string    `json:"goarch"`
}

// routesFixture, adaptersFixture and proxyFixture are the JSON shape written
// to routes.json, adapters.json and proxy.json. Each is its own top-level
// object (not a bare array) so captureMeta can travel with the data it
// describes, and so a future field can be added to one fixture without
// changing the others' shape.
type routesFixture struct {
	captureMeta
	Routes []scwindows.CapturedRoute `json:"routes"`
}

type adaptersFixture struct {
	captureMeta
	Adapters []scwindows.CapturedAdapter `json:"adapters"`
}

type proxyFixture struct {
	captureMeta
	Proxy scwindows.CapturedProxyConfig `json:"proxy"`
}

// runCaptureSysconf is devtool.go's platform hook. See newCaptureSysconfCmd's
// doc comment for what this exists to preserve.
//
// A capture that fails partway still writes what it could and reports what
// it could not, rather than aborting the whole run: routes.json and
// adapters.json are independent Win32 calls, and proxy.json (see
// scwindows.CaptureProxyConfig) is designed to never fail its OWN call in the
// first place — an unavailable IE proxy configuration is data it records,
// not an error it raises. So the only realistic partial failure here is
// GetIpForwardTable2 or GetAdaptersAddresses erroring outright, which on a
// real machine (see scwindows' own comment on why an empty routing table is
// read as a failed read, never "no routes") means something is genuinely
// wrong with that API on this host — worth surfacing, not worth losing the
// other two captures over.
func runCaptureSysconf(out io.Writer, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("devtool: create %s: %w", dir, err)
	}
	meta := captureMeta{CapturedAt: time.Now().UTC(), GOARCH: runtime.GOARCH}

	var errs []error
	note := func(name string, err error) {
		if err != nil {
			fmt.Fprintf(out, "devtool: capture %s: %v (not written)\n", name, err)
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}

	if routes, err := scwindows.CaptureRoutes(); err != nil {
		note("routes", err)
	} else if err := writeCaptureFixture(dir, "routes.json", routesFixture{meta, routes}); err != nil {
		note("routes", err)
	} else {
		fmt.Fprintf(out, "wrote %s (%d routes)\n", filepath.Join(dir, "routes.json"), len(routes))
	}

	if adapters, err := scwindows.CaptureAdapters(); err != nil {
		note("adapters", err)
	} else if err := writeCaptureFixture(dir, "adapters.json", adaptersFixture{meta, adapters}); err != nil {
		note("adapters", err)
	} else {
		fmt.Fprintf(out, "wrote %s (%d adapters)\n", filepath.Join(dir, "adapters.json"), len(adapters))
	}

	proxy := scwindows.CaptureProxyConfig()
	if err := writeCaptureFixture(dir, "proxy.json", proxyFixture{meta, proxy}); err != nil {
		note("proxy", err)
	} else {
		fmt.Fprintf(out, "wrote %s (available=%v)\n", filepath.Join(dir, "proxy.json"), proxy.Available)
	}

	return errors.Join(errs...)
}

// writeCaptureFixture marshals v as indented JSON and writes it to
// filepath.Join(dir, name). Indented so a fixture is reviewable in a diff —
// the same reason internal/testnet's captured .txt fixtures are plain text
// rather than a denser encoding.
func writeCaptureFixture(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}
