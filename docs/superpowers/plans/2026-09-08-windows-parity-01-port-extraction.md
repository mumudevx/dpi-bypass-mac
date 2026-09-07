# Windows Parity, Plan 1: Module Rename and Port Extraction

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the module to `github.com/mumudevx/dpb`, then make `internal/netstate` platform-free by extracting system access behind interfaces — with zero behaviour change on macOS, proven by the existing test suite passing unchanged.

**Architecture:** A new leaf package `internal/sysport` holds the types and interfaces (`Port`, the six controllers, `RouteEntry`, `RIBReader`, `ProxyState`, `Facts`, `Runner`, `Result`). The darwin implementation moves to `internal/sysconf/scdarwin`. `netstate` keeps the Ops, Manager and journal, and **type-aliases** every moved type so its ~200 external references compile untouched. The alias is what makes the "tests unchanged" gate achievable rather than aspirational.

**Tech Stack:** Go 1.26.4, `golang.org/x/sys`, stdlib only. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-07-windows-parity-design.md` (§3, §11, §12)

## Global Constraints

- Module path after Task 1: `github.com/mumudevx/dpb`. Every import, plus `MODULE` in `Makefile:2`, plus `.goreleaser.yaml`.
- Go version floor: `1.26.4` (`go.mod`, `.github/workflows/ci.yml` `GO_VERSION`).
- **No new module dependencies in this plan.** `go mod tidy` must leave `go.mod`/`go.sum` byte-identical; CI enforces this.
- **No behaviour change.** This plan moves code and adds indirection. It fixes no bugs and adds no features. If you find a bug, note it and leave it.
- Test *files* may move to follow their subject. Test *bodies* must not change. A diff that edits an assertion is a plan violation — stop and report it.
- Every new package must be added to `COVER_GATED` and `COVER_GATED_RE` in `Makefile:22-38`. A package outside the gate escapes the 0.0%-function check entirely.
- `netstate`'s coverage floor is 70 (`Makefile:56`), `cliapp`'s is 83, everything else 85. **Never lower a floor to make a red build pass** — the Makefile comment says so explicitly.
- Every file keeps the existing comment idiom: comments explain *why*, and cite evidence (a measurement, a man page, a verified machine behaviour). Do not add restating-the-code comments.

---

## Why this ordering

The spec's Phase 1 gate is: *the existing 4781 lines of netstate tests, and the full suite, pass unchanged.* That gate is only meetable because of two decisions locked in below:

1. **`sysport` is a leaf.** It imports nothing of ours. `scdarwin` imports `sysport`; `netstate` imports both. No cycle. If instead the interfaces lived in `netstate` and the impls in `sysconf`, `netstate` could not construct a default Port without importing `sysconf`, which imports `netstate` — a cycle.
2. **`netstate` aliases the moved types.** `type Result = sysport.Result` is an alias, not a definition, so `netstate.Result` and `sysport.Result` are the *same type*. All 51 external uses of `netstate.Result`, 56 of `netstate.Facts`, 28 of `netstate.RouteEntry` and 12 of `netstate.Runner` keep compiling.

Measured before writing this plan: `netstate.Env` 36 uses, `Facts` 56, `Op` 31, `OpKind` 6, `ProxyState` 1, `Record` 3, `Result` 51, `RIBReader` 9, `RouteEntry` 28, `Runner` 12, `VPNState` 13 — all outside `netstate`.

---

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `internal/sysport/doc.go` | Package comment: why this package is a leaf, and the two-subsystem rule it exists to let both platforms honour. |
| `internal/sysport/runner.go` | `Runner`, `Result`, `liars`, `Failed`, `Reason`, `Error` — moved verbatim from `netstate/runner.go`. |
| `internal/sysport/types.go` | `RouteEntry`, `RIBReader`, `ProxyState`, `Facts`, `VPNState`, `ProxySettings` — moved from the darwin files. |
| `internal/sysport/port.go` | `Port` and the six controller interfaces. New code. |
| `internal/sysconf/scdarwin/*.go` | The darwin implementation: everything currently in `netstate/*_darwin.go` that touches the system. |
| `internal/netstate/aliases.go` | The type aliases. |
| `internal/netstate/port_darwin.go` | `newDefaultPort(Runner) Port` → `scdarwin.New(r)`. Build-tagged. |
| `internal/netstate/port_other.go` | `newDefaultPort` returning a Port whose every method errors with a named reason. Build-tagged `!darwin`. |

**Modified:** `Makefile:2,22-38`, `internal/netstate/manager.go` (adds `Env.Sys` + `Env.sys()`), the six `op_*.go` files, `.goreleaser.yaml`, `.github/workflows/ci.yml`, and every file's import block (Task 1, mechanical).

**Deleted after their contents move:** `netstate/rib_darwin.go`, `scutil_darwin.go`, `facts_darwin.go`, `services_darwin.go`, `op_route_darwin.go`, `op_ifconfig_darwin.go`, `inspect_darwin.go`.

---

## The interfaces

This is the contract every later plan codes against. It refines the spec's §3.3 sketch in one place, noted below.

```go
// internal/sysport/port.go
package sysport

import (
	"context"
	"net/netip"
)

// Port is everything an Op needs from the operating system.
type Port interface {
	Proxy() ProxyController
	DNS() DNSController
	Route() RouteController
	Iface() IfaceController
	Env() EnvController
	Facts() FactsCollector
	Caps() Caps
}

// RouteSpec names one route. It is the same value on every platform; only the
// mechanism that installs it differs.
//
//   - Gw valid, Iface set   → a gateway route scoped to Iface
//   - Gw valid, Iface empty → a plain gateway route
//   - Gw invalid, Iface set → an interface route
type RouteSpec struct {
	Dst   netip.Prefix
	Gw    netip.Addr
	Iface string
}

type RouteController interface {
	Add(ctx context.Context, s RouteSpec) error
	Delete(ctx context.Context, s RouteSpec) error
	// RIB is the independent verifier. It MUST NOT share a code path with Add
	// and Delete; see the package comment.
	RIB() RIBReader
}

// ProxyKind distinguishes the three proxy settings macOS treats separately.
type ProxyKind int

const (
	ProxyAuto ProxyKind = iota // PAC URL
	ProxyWeb                   // web + secure web, always set together
	ProxySOCKS
)

// ProxySettings is one service's stored proxy configuration — the writer's own
// view of it, used to capture what must be restored later.
type ProxySettings struct {
	AutoURL     string
	AutoOn      bool
	WebHost     string
	WebPort     int
	WebOn       bool
	SecureHost  string
	SecurePort  int
	SecureOn    bool
	SOCKSHost   string
	SOCKSPort   int
	SOCKSOn     bool
}

type ProxyController interface {
	// Services lists the network services a proxy may be set on. On Windows
	// this is a single pseudo-service; see scwindows.
	Services(ctx context.Context) ([]string, error)
	// Configured reads one service's stored settings through the same subsystem
	// the setters write to. This is for CAPTURE, never for verification.
	Configured(ctx context.Context, svc string) (ProxySettings, error)
	SetAuto(ctx context.Context, svc, url string) error
	SetManual(ctx context.Context, svc string, kind ProxyKind, host string, port int) error
	Restore(ctx context.Context, svc string, prev ProxySettings) error
	// Live reads the system's RESOLVED proxy configuration through a DIFFERENT
	// subsystem than the setters write to. This is the verifier.
	Live(ctx context.Context) (ProxyState, error)
}

type DNSController interface {
	// Configured reads one service's stored resolvers (capture).
	Configured(ctx context.Context, svc string) ([]string, error)
	Set(ctx context.Context, svc string, servers []string) error
	// Clear restores svc to DHCP-supplied resolvers.
	Clear(ctx context.Context, svc string) error
	// Live reads the resolvers the system actually consults (verify).
	Live(ctx context.Context) ([]string, error)
}

type IfaceController interface {
	SetAddr(ctx context.Context, iface, local, peer string) error
	SetMTU(ctx context.Context, iface string, mtu int) error
	Up(ctx context.Context, iface string) error
	// Addrs reads an interface's addresses back through a different subsystem
	// than SetAddr wrote through (verify).
	Addrs(ctx context.Context, iface string) ([]netip.Addr, error)
}

type EnvController interface {
	Get(ctx context.Context, name string) (string, bool, error)
	Set(ctx context.Context, name, value string) error
	Unset(ctx context.Context, name string) error
}

type FactsCollector interface {
	Collect(ctx context.Context) (*Facts, error)
}

// Caps is the system-mutation analogue of strategy.Cap. A capability a platform
// lacks is refused BY NAME AND WITH A REASON, never skipped quietly — the rule
// emit/stub_other.go states for wire techniques, applied to system state.
type Caps uint32

const (
	CapProxyAuto Caps = 1 << iota // can point the system at a PAC URL
	CapProxyManual                // can set an explicit host:port proxy
	CapDNSOverride                // can replace the system resolvers
	CapRouteWrite                 // can add and delete routes
	CapIfaceConfig                // can address and MTU a tunnel device
	CapSessionEnv                 // can set a login-session environment variable
	CapPerService                 // system state is per network service, not global
)

func (c Caps) Has(want Caps) bool { return c&want == want }
func (c Caps) Missing(want Caps) Caps { return want &^ c }
```

**Refinement of spec §3.3, and why.** The spec sketched `ProxyController` as "Get, SetManual, SetAuto, Clear". This plan splits the read in two — `Configured` (capture) and `Live` (verify) — and adds `Services`. The reason is the invariant the whole port exists to preserve: `netstate`'s package comment requires Verify to read through a different subsystem than Apply wrote through. A single `Get` would collapse `networksetup -getwebproxy` and `scutil --proxy` into one method and quietly destroy that distinction on both platforms. `DNSController` and `IfaceController` carry the same split for the same reason.

---

## Task 1: Rename the module

**Files:**
- Modify: every `.go` file's import block, `go.mod:1`, `Makefile:2`, `.goreleaser.yaml`, `README.md`
- Test: the whole suite

**Interfaces:**
- Consumes: nothing
- Produces: module path `github.com/mumudevx/dpb` for every later task

- [ ] **Step 1: Confirm the tree is clean and green before touching it**

```bash
git status --porcelain   # expect empty
go test ./... 2>&1 | tail -5
```

Expected: no output from `git status`; every package `ok` or `no test files`.

- [ ] **Step 2: Rewrite the module path**

```bash
OLD=github.com/mumudevx/dpb
NEW=github.com/mumudevx/dpb
grep -rl "$OLD" --include='*.go' --include='go.mod' --include='Makefile' \
  --include='*.yaml' --include='*.yml' --include='*.md' . \
  | grep -v '^./.git/' \
  | xargs sed -i '' "s|$OLD|$NEW|g"
```

- [ ] **Step 3: Verify nothing was missed**

```bash
grep -rn "dpi-bypass-mac" --include='*' . | grep -v '^./.git/' | grep -v coverage.out
```

Expected: no output. If `docs/` mentions the old GitHub URL in prose, that is fine to leave — but an *import path* or a `MODULE :=` line is not.

- [ ] **Step 4: Confirm tidy is a no-op and the suite is green**

```bash
go mod tidy && git diff --exit-code go.mod go.sum
go build ./... && go vet ./... && go test ./...
```

Expected: `git diff` exits 0; build, vet and tests all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor: rename the module to dpb, because the old name is about to be false

dpi-bypass-mac names a platform the tool is about to outgrow. Doing this
now costs one mechanical commit; doing it after the Windows port touches
every file that port adds. GitHub redirects the old repository path, so
no external link breaks.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 2: Create `internal/sysport` with Runner and Result

**Files:**
- Create: `internal/sysport/doc.go`, `internal/sysport/runner.go`
- Move: `internal/netstate/runner_test.go` → `internal/sysport/runner_test.go` (body unchanged)
- Move: `internal/netstate/testdata/*.txt` → `internal/sysport/testdata/` (only the fixtures `runner_test.go` reads)
- Modify: `internal/netstate/runner.go` (keeps `newExecRunner`, `newExecRunnerEnv`, `NewExecRunner`, `noRunner`), `internal/netstate/aliases.go` (create), `Makefile:22-38`

**Interfaces:**
- Consumes: nothing
- Produces: `sysport.Runner` (interface, `Run(ctx, name string, args ...string) Result`), `sysport.Result` (struct: `Argv []string`, `Combined string`, `Code int`, `Err error`, `Duration time.Duration`; methods `Failed() bool`, `Reason() string`, `Error() error`)

**Note on the `liars` table.** It moves to `sysport` verbatim, keyed by command basename (`route`, `networksetup`, `ifconfig`, `launchctl`). On Windows those commands never run, so the table is inert — no risk, no test churn. Do **not** make it pluggable in this plan; that is speculative generality until a Windows tool is found that lies.

- [ ] **Step 1: Move the test first, and watch it fail to compile**

```bash
mkdir -p internal/sysport/testdata
git mv internal/netstate/runner_test.go internal/sysport/runner_test.go
for f in route_exit0_fail networksetup_error ifconfig_missing; do
  git mv internal/netstate/testdata/$f.txt internal/sysport/testdata/$f.txt
done
sed -i '' 's/^package netstate$/package sysport/' internal/sysport/runner_test.go
go test ./internal/sysport/
```

Expected: FAIL — `undefined: Result`, `undefined: liars`. That is the point: the test defines what `sysport` must provide.

If `runner_test.go` reads a fixture not in the three names above, move that one too and note it.

- [ ] **Step 2: Write the package comment**

Create `internal/sysport/doc.go`:

```go
// Package sysport is the boundary between dpb's system mutations and the
// operating system underneath them.
//
// It is a leaf: it imports nothing else in this module. That is what lets the
// implementations (internal/sysconf/scdarwin, internal/sysconf/scwindows)
// depend on these types while internal/netstate depends on both, with no
// import cycle.
//
// The rule this package exists to make portable is netstate's: verification
// never uses the subsystem that applied the change. Every controller here
// therefore splits its reads in two — one method reading through the writer's
// own subsystem (for capturing state to restore), one reading through a
// different subsystem (for verifying a mutation landed). Collapsing those into
// a single Get is how the rule gets lost.
//
// The rule matters differently on each platform. On macOS the risk is a tool
// that exits 0 while failing, which is why Result carries a liar table. On
// Windows the risk is text: netsh and route.exe emit the system UI language,
// and there is no LC_ALL=C for a child's thread UI language, so the Windows
// implementation parses no output at all.
package sysport
```

- [ ] **Step 3: Move Runner, Result and the liars table**

Create `internal/sysport/runner.go` containing, moved verbatim from `internal/netstate/runner.go`: the `Result` struct, the `liars` map, `Failed`, `liar`, `Reason`, `Error`, `cmdline`, `firstLine`, and the `Runner` interface. Keep every comment — the `route(8)` evidence in them is the reason the table exists.

Delete those declarations from `netstate/runner.go`, leaving it with `newExecRunner`, `newExecRunnerEnv`, `NewExecRunner` and `noRunner`.

- [ ] **Step 4: Add the aliases**

Create `internal/netstate/aliases.go`:

```go
package netstate

import "github.com/mumudevx/dpb/internal/sysport"

// These are aliases, not definitions: netstate.Result and sysport.Result are
// the same type. That is deliberate and load-bearing. Roughly two hundred
// references to these names live outside this package — 51 to Result alone —
// and an alias moves the declaration without touching any of them.
type (
	Runner = sysport.Runner
	Result = sysport.Result
)
```

- [ ] **Step 5: Add sysport to the coverage gate**

In `Makefile`, add `internal/sysport` to `COVER_GATED` (line 22 block) and add `sysport` to the alternation in `COVER_GATED_RE` (line 38).

- [ ] **Step 6: Run the moved test, then the whole suite**

```bash
go test ./internal/sysport/ -v
go build ./... && go vet ./... && go test ./...
```

Expected: `sysport` tests PASS with bodies unchanged; whole suite green.

- [ ] **Step 7: Confirm the gate sees the new package**

```bash
make cover-gate 2>&1 | grep -E "sysport|netstate"
```

Expected: a line for `internal/sysport` that is `ok`, not `SKIP`. `internal/netstate` still `ok` against floor 70.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor: sysport, a leaf package the OS implementations can both depend on

Runner and Result move first because everything else needs them and they
carry no platform assumption of their own. netstate aliases both, so its
callers — 51 references to Result alone — do not move with them.

The liar table comes along verbatim. It is keyed by command basename, so
on Windows, where route(8) and networksetup do not exist, it is simply
inert. Making it pluggable now would be generality with no second case.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 3: Move the shared types into `sysport`

**Files:**
- Create: `internal/sysport/types.go`
- Modify: `internal/netstate/rib_darwin.go` (drop the type decls, keep `kernelRIB`), `scutil_darwin.go` (drop `ProxyState`, keep the parser), `facts_darwin.go` (drop `Facts`/`VPNState`, keep `CollectFacts`), `internal/netstate/aliases.go`
- Test: existing tests, unchanged

**Interfaces:**
- Consumes: `sysport` package from Task 2
- Produces: `sysport.RouteEntry` (`Dst netip.Prefix`, `Gateway netip.Addr`, `Iface string`, `Index int`, `Scoped bool`, method `String() string`), `sysport.RIBReader` (`Routes() ([]RouteEntry, error)`, `Default() (RouteEntry, bool, error)`, `ScopedDefault(iface string) (RouteEntry, bool, error)`, `Exists(dst netip.Prefix, iface string) (bool, error)`), `sysport.ProxyState` (`Keys map[string]string`, methods `Str`, `On`, `Int`), `sysport.Facts`, `sysport.VPNState`, `sysport.ProxySettings`

- [ ] **Step 1: Move the type declarations**

Create `internal/sysport/types.go`. Move, verbatim with their comments:

- `RouteEntry` + `String()` ← `netstate/rib_darwin.go:16-33`
- `RIBReader` ← `netstate/rib_darwin.go:45-50`
- `ProxyState` + `Str` + `On` + `Int` ← `netstate/scutil_darwin.go:19-44`
- `VPNState` ← `netstate/facts_darwin.go:12-22`
- `Facts` ← `netstate/facts_darwin.go:26-44`

Add `ProxySettings` as given in the interfaces section above — it is new, and it is the capture shape both platforms fill in.

The comments moving with these types carry the evidence (`RTF_IFSCOPE` is part of a route's identity; `FullTunnel` is the field that changes behaviour). Keep them.

- [ ] **Step 2: Delete the moved declarations from the darwin files**

Remove those declarations from `rib_darwin.go`, `scutil_darwin.go` and `facts_darwin.go`. Each file keeps its *implementation* — `kernelRIB`, `parseProxyState`/`readProxyState`, `CollectFacts` — and imports `sysport` for the types.

- [ ] **Step 3: Extend the aliases**

```go
type (
	Runner       = sysport.Runner
	Result       = sysport.Result
	RouteEntry   = sysport.RouteEntry
	RIBReader    = sysport.RIBReader
	ProxyState   = sysport.ProxyState
	Facts        = sysport.Facts
	VPNState     = sysport.VPNState
)
```

- [ ] **Step 4: Build and run the whole suite**

```bash
go build ./... && go vet ./... && go test ./...
```

Expected: green, with **no test file edited**. Confirm that:

```bash
git diff --name-only | grep '_test.go' || echo "no test files touched — correct"
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor: the types both platforms share move to sysport

RouteEntry, RIBReader, ProxyState, Facts and VPNState describe a machine's
network state, not macOS's way of reading it, so they belong where both
implementations can see them. The darwin files keep their readers.

Every one of the ~160 references outside this package is untouched: the
names in netstate are aliases of these, which means the same type.

ProxySettings is new — the shape a capture takes, so that restoring is a
value both platforms can journal rather than a per-OS blob.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 4: Define the Port interfaces

**Files:**
- Create: `internal/sysport/port.go`, `internal/sysport/port_test.go`
- Modify: `internal/netstate/aliases.go`

**Interfaces:**
- Consumes: `sysport` types from Task 3
- Produces: every interface listed in **The interfaces** section above — `Port`, `ProxyController`, `DNSController`, `RouteController`, `IfaceController`, `EnvController`, `FactsCollector`, `RouteSpec`, `ProxyKind`, `Caps` and its constants

- [ ] **Step 1: Write the failing test for Caps**

Create `internal/sysport/port_test.go`:

```go
package sysport

import "testing"

func TestCapsHasAndMissing(t *testing.T) {
	got := CapProxyAuto | CapRouteWrite
	if !got.Has(CapProxyAuto) {
		t.Errorf("Has(CapProxyAuto) = false, want true")
	}
	if got.Has(CapDNSOverride) {
		t.Errorf("Has(CapDNSOverride) = true, want false")
	}
	// Has(0) is true: an Op needing nothing is satisfied by any Port. This
	// mirrors strategy.Cap, whose comment states the same rule.
	if !got.Has(0) {
		t.Errorf("Has(0) = false, want true")
	}
	want := CapDNSOverride | CapSessionEnv
	if m := got.Missing(want); m != want {
		t.Errorf("Missing(%b) = %b, want %b", want, m, want)
	}
	if m := got.Missing(CapProxyAuto); m != 0 {
		t.Errorf("Missing(CapProxyAuto) = %b, want 0", m)
	}
}
```

- [ ] **Step 2: Run it and watch it fail**

```bash
go test ./internal/sysport/ -run TestCapsHasAndMissing
```

Expected: FAIL — `undefined: CapProxyAuto`.

- [ ] **Step 3: Write `port.go`**

Create `internal/sysport/port.go` with exactly the content given in **The interfaces** section above. Every interface, every comment. The comments explaining *why* `Configured` and `Live` are separate methods are the reason this file exists — do not trim them.

- [ ] **Step 4: Run the test**

```bash
go test ./internal/sysport/ -run TestCapsHasAndMissing -v
```

Expected: PASS.

- [ ] **Step 5: Alias Port into netstate and build**

Add to `internal/netstate/aliases.go`:

```go
type (
	Port      = sysport.Port
	RouteSpec = sysport.RouteSpec
	ProxyKind = sysport.ProxyKind
	Caps      = sysport.Caps
)
```

```bash
go build ./... && go test ./...
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(sysport): the Port contract, with the two-subsystem rule built into it

Each controller splits its reads: Configured reads through the same
subsystem the setters write to, and is only for capturing what to restore;
Live reads through a different one, and is the verifier. netstate's package
comment has required that separation since the beginning — this makes it a
type signature instead of a convention a new implementation could miss.

Caps is strategy.Cap's shape applied to system state, for the reason
emit/stub_other.go already gives: a capability that is silently absent is
how a strategy gets downgraded without anyone noticing.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 5: Build `scdarwin` and satisfy the Port

**Files:**
- Create: `internal/sysconf/scdarwin/darwin.go` (the `Port` value + `New`), `proxy.go`, `dns.go`, `route.go`, `iface.go`, `env.go`, `facts.go`, `rib.go`, `services.go`
- Move into those files: the bodies currently in `netstate/{rib,scutil,facts,services,op_route,op_ifconfig,inspect}_darwin.go` and the `networksetup`/`launchctl` call sites in `netstate/{op_proxy,op_dns,op_launchenv}.go`
- Move: the corresponding `_test.go` files, bodies unchanged
- Modify: `Makefile:22-38`

**Interfaces:**
- Consumes: every interface from Task 4
- Produces: `scdarwin.New(r sysport.Runner) sysport.Port`

**This is the largest task in the plan.** It is one task rather than six because the Port is only satisfiable as a whole — a partial `scdarwin` does not compile against `sysport.Port`, so there is no smaller green checkpoint. Work controller by controller inside it and run `go build ./internal/sysconf/...` between each.

- [ ] **Step 1: Skeleton that compiles against the interface**

Create `internal/sysconf/scdarwin/darwin.go`:

```go
//go:build darwin

// Package scdarwin is sysport.Port for macOS.
//
// Every mutation goes through a command-line tool and every verification goes
// through a different subsystem: networksetup writes proxies and `scutil
// --proxy` reads them, route(8) writes routes and an AF_ROUTE socket reads
// them, ifconfig addresses an interface and net.Interfaces() reads it back.
// The one documented exception is launchctl setenv/getenv, which has no second
// observer; see sysport.EnvController.
package scdarwin

import "github.com/mumudevx/dpb/internal/sysport"

type port struct {
	run sysport.Runner
	rib sysport.RIBReader
}

// New returns the macOS Port. r is the command runner every tool call goes
// through; passing it in rather than constructing one is what lets a test drive
// this implementation with recorded output (internal/testnet).
func New(r sysport.Runner) sysport.Port {
	return &port{run: r, rib: newKernelRIB()}
}

var _ sysport.Port = (*port)(nil)
```

Then add the seven accessor methods returning the per-controller types you create in the following steps.

- [ ] **Step 2: Move the RIB**

`internal/sysconf/scdarwin/rib.go` takes `kernelRIB` and everything under it from `netstate/rib_darwin.go`, plus `newKernelRIB()`. Move `netstate/rib_darwin_test.go` if one exists (check: `ls internal/netstate/*rib*_test.go`).

```bash
go build ./internal/sysconf/...
```

- [ ] **Step 3: Move proxy, DNS, iface, route, env, facts and services**

One at a time, each followed by `go build ./internal/sysconf/...`:

| New file | Takes from | Implements |
| --- | --- | --- |
| `proxy.go` | `netstate/op_proxy.go` argv builders + `netstate/scutil_darwin.go` `readProxyState` | `Services`, `Configured`, `SetAuto`, `SetManual`, `Restore`, `Live` |
| `dns.go` | `netstate/op_dns.go` `networksetup` and `scutil --dns` call sites | `Configured`, `Set`, `Clear`, `Live` |
| `route.go` | `netstate/op_route_darwin.go` `args()` + the `route` invocations | `Add`, `Delete`, `RIB` |
| `iface.go` | `netstate/op_ifconfig_darwin.go` `ifconfig` invocations | `SetAddr`, `SetMTU`, `Up`, `Addrs` |
| `env.go` | `netstate/op_launchenv.go` `launchctl` invocations | `Get`, `Set`, `Unset` |
| `facts.go` | `netstate/facts_darwin.go` `CollectFacts` | `Collect` |
| `services.go` | `netstate/services_darwin.go` | supports `proxy.Services` |

Take the *system calls*, not the *policy*. `routeOp.args()` moves (it builds a route(8) argv). `matchRoute` does **not** — it decides whether a RIB entry satisfies a request, which is Op logic and stays in `netstate` (Task 6).

The same test applies throughout: if the code would read identically on Windows with different syscalls underneath, it is Op logic and stays. If it names a macOS tool or flag, it moves.

- [ ] **Step 4: Declare the caps**

In `darwin.go`:

```go
// macOS grants every capability dpb has an Op for. The constant is spelled out
// rather than left implicit so that the Windows implementation's shortfall, when
// it lands, is a diff against something.
func (p *port) Caps() sysport.Caps {
	return sysport.CapProxyAuto | sysport.CapProxyManual | sysport.CapDNSOverride |
		sysport.CapRouteWrite | sysport.CapIfaceConfig | sysport.CapSessionEnv |
		sysport.CapPerService
}
```

- [ ] **Step 5: Move the darwin tests**

```bash
git mv internal/netstate/inspect_darwin_test.go internal/sysconf/scdarwin/
git mv internal/netstate/services_test.go internal/sysconf/scdarwin/
```

Change only the `package` line in each. If a test references an unexported `netstate` helper that did not move, move that helper too — do not rewrite the test to avoid it.

- [ ] **Step 6: Add scdarwin to the coverage gate**

`Makefile`: add `internal/sysconf/scdarwin` to `COVER_GATED` and `sysconf/scdarwin` to the `COVER_GATED_RE` alternation.

- [ ] **Step 7: Build the new package; expect `netstate` to be red**

```bash
go build ./internal/sysport/... ./internal/sysconf/...
go test ./internal/sysconf/...
```

Expected: both green.

```bash
go build ./... 2>&1 | head
```

Expected: **`internal/netstate` FAILS here, and that is correct.** Its Ops still call tool argv builders that have moved out. Task 6 is what makes it build again. Do not patch `netstate` in this task, and above all do not edit a test to paper over it — Task 6 Step 6 checks that no test body changed across the whole plan.

This is the one task that does not end green. It is a single task because `sysport.Port` is only satisfiable as a whole: a partial `scdarwin` does not compile, so there is no smaller checkpoint to stop at.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor: the macOS system calls move to scdarwin behind sysport.Port

What moved is the part that names a tool or a flag: networksetup argv,
route(8) argv, scutil parsing, the AF_ROUTE reader, ifconfig, launchctl.
What stayed is the part that decides — matchRoute, the adoption rules, the
capture-and-restore policy — because none of it is macOS-specific and all
of it is what the existing tests cover.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 6: Rewire the Ops through `Env.Sys`

**Files:**
- Modify: `internal/netstate/manager.go:11-33` (add `Sys` field + `sys()` accessor), `op_proxy.go`, `op_dns.go`, `op_launchenv.go`, and the route/iface Ops moving out of their `_darwin` filenames
- Create: `internal/netstate/port_darwin.go`, `internal/netstate/port_other.go`
- Rename: `op_route_darwin.go` → `op_route.go`, `op_ifconfig_darwin.go` → `op_iface.go`

**Interfaces:**
- Consumes: `scdarwin.New`, every controller interface
- Produces: `Env.Sys sysport.Port` field; `Env.sys() sysport.Port` returning `e.Sys` or the platform default

- [ ] **Step 1: Add the field and accessor**

In `manager.go`, add to `Env`:

```go
	// Sys is the operating system this run mutates. It is an interface so that
	// an Op's logic — which routes to install, what to capture before
	// overwriting, when adoption is allowed — is testable without a machine to
	// mutate, and identical on every platform.
	Sys Port
```

and:

```go
// sys returns the configured Port, or the platform's default built from the
// runner. The default exists so that an Env assembled the old way — with only a
// Runner — keeps working; every existing caller and test does exactly that.
func (e Env) sys() Port {
	if e.Sys != nil {
		return e.Sys
	}
	return newDefaultPort(e.runner())
}
```

- [ ] **Step 2: Write the two factory files**

`internal/netstate/port_darwin.go`:

```go
//go:build darwin

package netstate

import "github.com/mumudevx/dpb/internal/sysconf/scdarwin"

func newDefaultPort(r Runner) Port { return scdarwin.New(r) }
```

`internal/netstate/port_other.go`:

```go
//go:build !darwin && !windows

package netstate

import (
	"fmt"
	"runtime"

	"github.com/mumudevx/dpb/internal/sysport"
)

// dpb has no system-mutation implementation for this platform. Every method
// errors by name rather than returning a zero value, for the reason
// emit/stub_other.go gives: a capability that is silently absent is how a
// mutation gets skipped without anyone noticing.
func newDefaultPort(Runner) Port { return unsupportedPort{} }

func unsupported(what string) error {
	return fmt.Errorf("netstate: %s is implemented for darwin and windows only; this binary is %s/%s",
		what, runtime.GOOS, runtime.GOARCH)
}
```

Implement `unsupportedPort` and its controllers so every method returns `unsupported("...")` naming the operation, and `Caps()` returns 0.

The `!windows` in the tag is deliberate: Plan 3 adds `port_windows.go`, and writing the tag now means that file drops in without editing this one.

- [ ] **Step 3: Rewire `routeOp`**

Replace the `route(8)` calls with controller calls. `Apply` becomes:

```go
func (o *routeOp) Apply(ctx context.Context, e Env) error {
	// The error is checked, but it is only the first line of defence: Verify
	// reading the RIB is the one that decides.
	o.added = false
	if err := e.sys().Route().Add(ctx, o.spec()); err != nil {
		return err
	}
	o.added = true
	return nil
}

func (o *routeOp) spec() RouteSpec {
	return RouteSpec{Dst: o.dst, Gw: o.gw, Iface: o.iface}
}
```

`matchRoute`, `sameGateway`, `mutated()` and the look-before-deleting logic in `Revert` **stay exactly as they are** — including the comment explaining that RTM_DELETE ignores the link gateway, which is why the RIB is consulted first. Only the call that issues the delete changes. Rename the file to `op_route.go` and drop the build tag.

- [ ] **Step 4: Rewire the other five Ops**

Same shape for `proxyOp`, `dnsOp`, `launchEnvOp` and `ifconfigOp`: the tool invocation becomes a controller call; the capture, adoption, verification and revert *decisions* stay. `pacFileOp` needs no change — it only writes a file.

`proxyOp.prev` changes from `map[string]proxyPrev` to `map[string]ProxySettings`. Keep the journal's `revert` JSON shape backward-compatible if the field names already match; if they do not, keep `proxyPrev` as the wire type and convert at the boundary. **A journal written by the previous version must still be revertible** — that is what `Record`'s "self-sufficient" comment demands.

Rename `op_ifconfig_darwin.go` to `op_iface.go` and drop its build tag.

- [ ] **Step 5: Build and run the full suite**

```bash
go build ./... && go vet ./... && go test ./... 2>&1 | grep -v "^ok" | head -20
```

Expected: no failures.

- [ ] **Step 6: Prove the gate — no test body changed**

```bash
git diff --stat HEAD~4 -- '*_test.go'
```

Every line here must be a `package` declaration change or a pure file move. If an assertion, a table entry or a helper body changed, the migration altered behaviour: **stop and report it.** That is the Phase 1 gate.

- [ ] **Step 7: Confirm coverage floors still hold**

```bash
make cover-gate
```

Expected: `cover-gate: pass`. `internal/netstate` will have *fewer* statements now; if its percentage dropped below 70, the moved code took its tests with it and some did not follow — find them rather than lowering the floor.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor: Ops call a Port, so their logic is no longer macOS-shaped

Every Op now issues its mutation through sysport.Port and keeps every
decision it was already making: matchRoute still requires RTF_IFSCOPE to
agree, Revert still reads the RIB before deleting because RTM_DELETE
ignores the link gateway, proxyOp still refuses adoption because a proxy
Verify passing before Apply means a previous run died mid-flight.

Env.Sys defaults to the platform Port built from the Runner, so every
existing caller and every existing test constructs an Env exactly as
before. No test body changed in this commit or the three before it; that
is the gate this phase had to clear.

op_route_darwin.go and op_ifconfig_darwin.go lose their build tags along
with their tool calls.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 7: Prove the Port is fakeable, and wire the composition root

**Files:**
- Create: `internal/sysport/fake/fake.go` (a recording fake Port for tests)
- Create: `internal/netstate/op_route_port_test.go` (new test — the first that could not have been written before this plan)
- Modify: `internal/cliapp/root.go` or wherever `Env` is assembled — set `Sys` explicitly

**Interfaces:**
- Consumes: everything above
- Produces: `fake.Port` with recorded calls; `fake.New() *Port`

**This task is the payoff.** Until now the plan has only moved code. This proves the move bought something: an Op's logic testable with no machine to mutate, which is the only way Plan 3's Windows code gets coverage on a Mac.

- [ ] **Step 1: Write the fake**

Create `internal/sysport/fake/fake.go`. Each controller records what was asked of it and returns a scriptable error, so a test asserts *what the Op requested of the OS* rather than what a tool printed. The route controller — the one Step 2's test drives — is:

```go
package fake

import (
	"context"

	"github.com/mumudevx/dpb/internal/sysport"
)

// Port is a sysport.Port that mutates nothing and remembers everything.
type Port struct {
	ProxyC *Proxy
	DNSC   *DNS
	RouteC *Route
	IfaceC *Iface
	EnvC   *Env
	FactsC *FactsC
	CapsV  sysport.Caps
}

func New() *Port {
	return &Port{
		ProxyC: &Proxy{}, DNSC: &DNS{}, RouteC: &Route{}, IfaceC: &Iface{},
		EnvC: &Env{}, FactsC: &FactsC{},
		// Everything granted by default: a test asserting a capability
		// SHORTFALL must ask for it, so a missing grant is never accidental.
		CapsV: sysport.CapProxyAuto | sysport.CapProxyManual | sysport.CapDNSOverride |
			sysport.CapRouteWrite | sysport.CapIfaceConfig | sysport.CapSessionEnv |
			sysport.CapPerService,
	}
}

func (p *Port) Proxy() sysport.ProxyController { return p.ProxyC }
func (p *Port) DNS() sysport.DNSController     { return p.DNSC }
func (p *Port) Route() sysport.RouteController { return p.RouteC }
func (p *Port) Iface() sysport.IfaceController { return p.IfaceC }
func (p *Port) Env() sysport.EnvController     { return p.EnvC }
func (p *Port) Facts() sysport.FactsCollector  { return p.FactsC }
func (p *Port) Caps() sysport.Caps             { return p.CapsV }

var _ sysport.Port = (*Port)(nil)

// Route records every route request. Adds and Deletes are the specs asked for,
// in order; AddErr and DeleteErr are returned instead of performing them.
type Route struct {
	Adds     []sysport.RouteSpec
	Deletes  []sysport.RouteSpec
	AddErr    error
	DeleteErr error
	Table     []sysport.RouteEntry // what RIB() reports
}

func (r *Route) Add(_ context.Context, s sysport.RouteSpec) error {
	if r.AddErr != nil {
		return r.AddErr
	}
	r.Adds = append(r.Adds, s)
	return nil
}

func (r *Route) Delete(_ context.Context, s sysport.RouteSpec) error {
	if r.DeleteErr != nil {
		return r.DeleteErr
	}
	r.Deletes = append(r.Deletes, s)
	return nil
}

func (r *Route) RIB() sysport.RIBReader { return staticRIB{r} }
```

A failed call is **not** recorded — that is what lets a test assert "nothing was asked of the OS" after an error. Implement `staticRIB` over `Route.Table`, then the other five controllers on the same shape: a slice per mutating method, an `Err` field per method, and a settable return value per read.

- [ ] **Step 1b: Add the fake to the coverage gate exclusion**

`internal/sysport/fake` is test scaffolding, not shipped code. Do **not** add it to `COVER_GATED` — but confirm it is not swept in by the `COVER_GATED_RE` alternation you edited in Task 2. If `sysport` in that regex matches `sysport/fake`, tighten it to `sysport)/` so the subpackage is excluded.

- [ ] **Step 2: Write a test that was impossible before**

Create `internal/netstate/op_route_port_test.go`:

```go
package netstate

import (
	"context"
	"net/netip"
	"testing"

	"github.com/mumudevx/dpb/internal/sysport"
	"github.com/mumudevx/dpb/internal/sysport/fake"
)

// A failed Add must leave nothing to roll back. The exit-0 "File exists" liar
// is the common shape: the destination was already owned by somebody else, and
// issuing the delete anyway would remove their route rather than ours.
func TestRouteOpDoesNotRollBackAFailedAdd(t *testing.T) {
	p := fake.New()
	p.RouteC.AddErr = errAddFailed
	op := NewRoute(nil, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun9").(*routeOp)

	if err := op.Apply(context.Background(), Env{Sys: p}); err == nil {
		t.Fatal("Apply() = nil, want the Add error")
	}
	if op.mutated() {
		t.Error("mutated() = true after a failed Add; rollback would delete another owner's route")
	}
	if n := len(p.RouteC.Deletes); n != 0 {
		t.Errorf("Deletes = %d, want 0", n)
	}
}
```

Add whatever `errAddFailed` needs to be. Add a second test asserting the `RouteSpec` the Op passes down for each of the three shapes (scoped gateway, plain gateway, interface route).

- [ ] **Step 3: Run it and watch it fail**

```bash
go test ./internal/netstate/ -run TestRouteOpDoesNotRollBack -v
```

Expected: FAIL — `fake` not yet complete, or a compile error. Finish the fake until it passes.

- [ ] **Step 4: Run it green**

```bash
go test ./internal/netstate/ -run TestRouteOp -v
```

Expected: PASS.

- [ ] **Step 5: Set `Sys` explicitly at the composition root**

Find where `cliapp` builds a `netstate.Env` and set `Sys: scdarwin.New(runner)` — build-tagged, or through a small `sysconf.New(runner)` dispatcher. The `sys()` fallback stays as the safety net for tests, but production wiring should be explicit so a missing Port is a compile error rather than a runtime default.

- [ ] **Step 6: Full green + the gate**

```bash
go build ./... && go vet ./... && go test ./... -race
make cover-gate
```

Expected: all green.

- [ ] **Step 7: Confirm the cross-compile baseline improved**

```bash
for p in $(go list ./...); do
  GOOS=windows GOARCH=amd64 go build "$p" >/dev/null 2>&1 \
    && echo "OK   $p" || echo "FAIL $p"
done | sort | uniq -c | head
```

Expected: strictly more `OK` than the 10-of-22 baseline recorded in the spec. `netstate` itself should now be `OK` — it has no darwin-only code left. Record the new number; Plan 2 opens with it.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
test: an Op's decisions are now testable without a machine to mutate

This is what the refactor was for. TestRouteOpDoesNotRollBackAFailedAdd
asserts the rule routeOp.mutated() exists to enforce — a failed add created
nothing, so rolling it back would delete whatever else owns that prefix —
and it does so by asking the fake Port what was requested of the OS, not by
matching text a tool happened to print.

The same fake is how the Windows implementation will get coverage on a Mac,
which matters because its API returns cannot be captured as fixture text
the way testnet captures CLI output.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Phase 1 gate

Before starting Plan 2, all of these must hold:

- [ ] `go build ./... && go vet ./... && go test ./... -race` green on darwin/arm64
- [ ] `make cover-gate` passes, with `internal/sysport` and `internal/sysconf/scdarwin` both gated and neither `SKIP`
- [ ] `make fuzz FUZZTIME=60s` green
- [ ] `git diff --stat <plan-start>..HEAD -- '*_test.go'` shows only package-line changes, file moves, and the new files from Task 7 — **no edited assertion**
- [ ] `go mod tidy` leaves `go.mod`/`go.sum` unchanged
- [ ] `GOOS=windows go build ./internal/netstate/` succeeds
- [ ] `dpb run` still works on the development machine against a real blocked host (`dpb probe discord.com` before and after gives the same verdict)

The last one is the one a test cannot give you. Run it.

---

## The remaining plans

This plan is Phase 0–1 of eight. The rest, each producing working software on its own:

| Plan | Phases | Spec sections | Delivers | Gate |
| --- | --- | --- | --- | --- |
| **1** (this one) | 0, 1 | §3.1–3.3, §11, §12 | `sysport`, `scdarwin`, Ops on a Port | Suite passes with no test body changed |
| **2** — portable primitives | 2 | §3.4, §5, §7 | `flow`, `paths`, `lock`, `janitor`, `emit` twins | `GOOS=windows go build ./...` green for those packages; `emit` grants `CapSockTTL\|CapOOB` on Windows |
| **3** — the Windows Port | 3 | §2, §4 | `internal/sysconf/scwindows` | Fake-backed unit tests green **on the Mac**; `GOOS=windows go build ./...` fully green |
| **4** — front-ends | 4 | §5 (TUN), §8 tier 3 | `tunfe/link_windows.go`, `netwatch` windows, `devtool capture-sysconf` | wintun parity with utun, verified in the VM |
| **5** — ship it | 5, 5.5 | §6, §13 | Service (logon task + SCM), cliapp wiring, doctor/selftest branches, **README Windows section**, `v2.0.0-windows-preview` | An external tester installs and runs it |
| **6** — measure and release | 6, 7 | §9, §10 | `docs/MEASUREMENTS-windows.md`, goreleaser, winget, scoop, CI windows job, wintun DLL decision | Release green; ladder numbers are measured, not assumed |

Every spec section lands in exactly one plan. §1 and §14 are context, not work.

Plan 2 should be written after this plan's gate is green, not before — Task 7's cross-compile count is its starting input.
