//go:build darwin

package scdarwin

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Service is one macOS network service, as networksetup understands it. The
// name is what every networksetup verb takes; the device is what the routing
// table talks about. Nothing else in the system bridges the two.
type Service struct {
	Name     string
	Device   string
	Hardware string
	Order    int
	Disabled bool
}

var serviceOrderLine = regexp.MustCompile(`^\((\d+)\)\s+(.*)$`)
var serviceHardwareLine = regexp.MustCompile(`^\(Hardware Port:\s*([^,]*),\s*Device:\s*([^)]*)\)$`)

// parseServiceOrder parses `networksetup -listnetworkserviceorder`, which is
// the only networksetup verb that reports the service-to-device mapping.
//
// A leading '*' on the name marks a disabled service; the header line says so.
func parseServiceOrder(out string) []Service {
	var svcs []Service
	var pending *Service
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "An asterisk") {
			continue
		}
		if m := serviceOrderLine.FindStringSubmatch(trimmed); m != nil {
			if pending != nil {
				svcs = append(svcs, *pending)
			}
			order := 0
			fmt.Sscanf(m[1], "%d", &order)
			name := strings.TrimSpace(m[2])
			disabled := strings.HasPrefix(name, "*")
			pending = &Service{Name: strings.TrimPrefix(name, "*"), Order: order, Disabled: disabled}
			continue
		}
		if m := serviceHardwareLine.FindStringSubmatch(trimmed); m != nil && pending != nil {
			pending.Hardware = strings.TrimSpace(m[1])
			pending.Device = strings.TrimSpace(m[2])
			svcs = append(svcs, *pending)
			pending = nil
		}
	}
	if pending != nil {
		svcs = append(svcs, *pending)
	}
	return svcs
}

// ListServices enumerates the machine's network services in order.
func ListServices(ctx context.Context, e Env) ([]Service, error) {
	res := e.runner().Run(ctx, "networksetup", "-listnetworkserviceorder")
	if err := res.Error(); err != nil {
		return nil, fmt.Errorf("netstate: list network services: %w", err)
	}
	svcs := parseServiceOrder(res.Combined)
	if len(svcs) == 0 {
		return nil, fmt.Errorf("netstate: list network services: no services parsed from %q", firstLine(res.Combined))
	}
	return svcs, nil
}

// serviceNames returns the enabled services' names, in order. Disabled services
// are dropped: setting a proxy on one succeeds and changes nothing, which is
// exactly the sort of silent no-op this package exists to prevent.
func serviceNames(svcs []Service) []string {
	out := make([]string, 0, len(svcs))
	for _, s := range svcs {
		if s.Disabled {
			continue
		}
		out = append(out, s.Name)
	}
	return out
}

// ServiceForDevice maps a BSD device name (en0, utun4) to the network service
// that owns it. ok is false when the device has no service, which is normal for
// a utun we created ourselves.
func ServiceForDevice(svcs []Service, device string) (Service, bool) {
	for _, s := range svcs {
		if s.Device == device {
			return s, true
		}
	}
	return Service{}, false
}
