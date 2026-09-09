# Windows Parity, Plan 3: The Windows Port

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `sysport.Port` for Windows in `internal/sysconf/scwindows`, and wire it through `netstate/port_windows.go` — so `GOOS=windows go build ./...` succeeds for the whole tree.

**Architecture:** `scwindows` mirrors `scdarwin` file for file. Every mutation goes through a typed Win32 call; every verification reads through a **different** subsystem. Where a CLI is unavoidable (`netsh`), only its exit status is consulted — never its text, because Windows localizes tool output and there is no `LC_ALL=C`.

**Tech Stack:** Go 1.26.4, `golang.org/x/sys/windows` (+ `/registry`), stdlib. **No new module dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-07-windows-parity-design.md` (§2, §4)

## Global Constraints

- Module path `github.com/mumudevx/dpb`. Go floor `1.26.4`.
- **No new module dependencies.** `go mod tidy` byte-identical.
- **No behaviour change on macOS.** The darwin suite must stay green throughout.
- **No test body may be edited.** Three plans have held this line with zero assertions weakened. Test files may gain build tags; assertions may not change.
- Coverage: every new package goes in `COVER_GATED` and `COVER_GATED_RE`. Floors: `tunfe` 70, `cliapp` 83, everything else **85**. Never lower one.
- `gofmt -l cmd internal tools` empty. Run it every task.
- **Nothing here can be executed.** `GOOS=windows go vet ./...` compiles a package *and its tests* and is the strongest check available. Never write "tests pass" for Windows. Plan 5 puts this on a real machine.
- Comments explain WHY and cite evidence: an MSDN contract, a measured behaviour, a verified API signature.

---

## What is verified, and what must be wrapped

Measured against `golang.org/x/sys@v0.43.0` before this plan was written.

**Present — use directly, do not re-wrap:**
`GetIpForwardTable2` · `FreeMibTable` · `GetAdaptersAddresses` · `GetIfEntry2Ex` · `NotifyRouteChange2` · `windows/registry` · `windows/svc`

**Present as TYPES — the struct layouts are already correct, do not redeclare them:**
`MibIpForwardRow2` · `MibUnicastIpAddressRow` · `MibIpInterfaceRow` · `IpAdapterAddresses`

**Absent — every one is a WRITE, and each needs a `NewLazySystemDLL` wrapper (Task 1):**
`CreateIpForwardEntry2` · `DeleteIpForwardEntry2` · `GetBestRoute2` · `CreateUnicastIpAddressEntry` · `DeleteUnicastIpAddressEntry` · `InitializeUnicastIpAddressEntry` · `GetIpInterfaceEntry` · `SetIpInterfaceEntry` · `ConvertInterfaceLuidToIndex` (all `iphlpapi.dll`), plus `InternetSetOptionW` (`wininet.dll`), `WinHttpGetIEProxyConfigForCurrentUser` (`winhttp.dll`), `SendMessageTimeoutW` (`user32.dll`).

That the reads exist and the writes do not is convenient: the reads are the verifiers, and they come from a maintained source.

### The lesson from Plan 2, which cost real defects

Windows ships functions that compile, look correct, and always fail. Plan 2 found three: `syscall.Sendto` returns `EWINDOWS`; `internal/poll`'s Windows `RawWrite` returns `EWINDOWS` on a false callback; `os.Process.Signal` handles only `Kill`. **Before using any Windows API this plan does not already name, read its actual Go source and confirm it is implemented.** A capability granted for a path that cannot run is worse than a capability withheld.

---

## The two contracts `scwindows` must honour

### 1. Verification reads through a different subsystem

| Op | Apply (Windows) | Verify (Windows) |
| --- | --- | --- |
| proxy | `HKCU\...\Internet Settings` registry write + `InternetSetOptionW` | `WinHttpGetIEProxyConfigForCurrentUser` |
| dns | `netsh interface ipv4\|ipv6 set dnsservers` — **exit status only** | `GetAdaptersAddresses` → `FirstDnsServerAddress` |
| route | `CreateIpForwardEntry2` | `GetIpForwardTable2` + `GetBestRoute2` |
| iface | `CreateUnicastIpAddressEntry` | `GetAdaptersAddresses` |
| env | `HKCU\Environment` + `WM_SETTINGCHANGE` broadcast | read back `HKCU\Environment` |

Route and iface apply and verify through the same API family. That is weaker than the macOS write-CLI/read-kernel split, and it must be **documented in the package comment, not papered over** — exactly as `scdarwin` documents the `launchctl setenv`/`getenv` exception. The mitigation is real but partial: `CreateIpForwardEntry2` writes one row, while `GetBestRoute2` asks the FIB which next hop it would *choose*, traversing route selection and interface state — a different question.

### 2. `ProxyState` speaks scutil, and Windows must translate

`internal/netstate/op_proxy.go` verifies against these exact keys, and it is platform-free code that must not change:

```
ProxyAutoConfigEnable      "0" / "1"
ProxyAutoConfigURLString   the PAC URL
HTTPEnable  HTTPProxy  HTTPPort
HTTPSEnable HTTPSProxy HTTPSPort
SOCKSEnable SOCKSProxy SOCKSPort
```

`scwindows`'s `Live()` must fill `ProxyState.Keys` with those names, translated from `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG`. This is not a wart to fix — it is a deliberate shared vocabulary, and the translation belongs in the platform layer where the rest of the platform's dialect lives. Say so in a comment.

**Windows has one proxy setting per user, not one per network service.** `Services()` therefore returns exactly one pseudo-service. Name it something that reads correctly in a user-facing error, and withhold `CapPerService`.

---

## File Structure

**Created**, mirroring `scdarwin` file for file:

| File | Responsibility |
| --- | --- |
| `internal/sysconf/scwindows/iphlp.go` | the lazy-DLL wrappers and their error mapping |
| `internal/sysconf/scwindows/windows.go` | the `port` value, `New`, `Caps` |
| `internal/sysconf/scwindows/rib.go` | `RIBReader` over `GetIpForwardTable2` |
| `internal/sysconf/scwindows/route.go` | `RouteController` |
| `internal/sysconf/scwindows/iface.go` | `IfaceController` |
| `internal/sysconf/scwindows/proxy.go` | `ProxyController` + the scutil translation |
| `internal/sysconf/scwindows/dns.go` | `DNSController` |
| `internal/sysconf/scwindows/env.go` | `EnvController` |
| `internal/sysconf/scwindows/facts.go` | `FactsCollector` |
| `internal/netstate/port_windows.go` | `newDefaultPort` / `newDefaultRIB` → `scwindows` |

**Modified:** `internal/netstate/port_other.go` (tag already excludes windows — verify), `Makefile`, `.github/workflows/ci.yml`.

---

## Task 1: `iphlp.go` — the wrappers, and proof they resolve

**Files:** Create `internal/sysconf/scwindows/iphlp.go`, `internal/sysconf/scwindows/iphlp_test.go`

**Produces:** Go wrappers for the twelve absent procedures listed above.

- [ ] **Step 1: Write the wrappers**

Use `windows.NewLazySystemDLL` (never `NewLazyDLL` — the system variant resolves from the system directory only, which is the documented defence against DLL preloading). One `*windows.LazyProc` per procedure, called through `.Call(...)`.

Every wrapper returns `error`, mapping a non-zero `NO_ERROR` return to `windows.Errno`. Do **not** invent struct types: `MibIpForwardRow2`, `MibUnicastIpAddressRow` and `MibIpInterfaceRow` already exist in `x/sys/windows` with correct layouts, and redeclaring them is how field offsets go wrong.

- [ ] **Step 2: Write the test that the procedures exist**

Create `iphlp_test.go` (`//go:build windows`) with a test that calls `.Find()` on every `LazyProc` and fails naming any that does not resolve. This is the cheapest possible guard against a typo'd export name or a procedure absent on a supported Windows version, and it is the Windows analogue of checking that a CLI exists before parsing it.

- [ ] **Step 3: Compile**

```bash
GOOS=windows go vet ./internal/sysconf/scwindows/
gofmt -l cmd internal tools
```

- [ ] **Step 4: Commit**

Message explains why the reads came from `x/sys` and the writes did not, and why `NewLazySystemDLL` rather than `NewLazyDLL`.

---

## Task 2: RIB and routes

**Files:** Create `windows.go`, `rib.go`, `route.go` and their tests.

**Consumes:** Task 1. **Produces:** `scwindows.New(...) sysport.Port` (skeleton), `sysport.RIBReader`, `RouteController`.

- [ ] **Step 1: The skeleton and its package comment**

`windows.go` holds the `port` struct, `New`, and a package comment stating both contracts from the section above — including, plainly, that route and iface verify through the same API family as they apply, and why that was chosen over `route.exe` (localized output, and its own liar behaviour).

- [ ] **Step 2: `RIBReader` over `GetIpForwardTable2`**

Implement `Routes`, `Default`, `ScopedDefault`, `Exists` returning `sysport.RouteEntry`. `FreeMibTable` must be deferred on every path — the table is unmanaged memory.

`RouteEntry.Scoped` has no direct Windows analogue: on macOS it carries `RTF_IFSCOPE`, which is part of a route's identity. Decide what it means here, write the decision in a comment, and be consistent — `matchRoute` in `netstate` compares it and will reject a mismatch.

- [ ] **Step 3: `RouteController`**

`Add` → `CreateIpForwardEntry2`, `Delete` → `DeleteIpForwardEntry2`, `RIB()` → the reader. Map `RouteSpec`'s three shapes (scoped gateway / plain gateway / interface route) onto `MibIpForwardRow2`, and say in a comment how each maps.

`ERROR_OBJECT_ALREADY_EXISTS` on Add is the analogue of macOS route(8)'s exit-0 "File exists" liar: it means someone else owns that destination. Return it as an error so `routeOp.mutated()` stays false and rollback does not delete another owner's route.

- [ ] **Step 4: Tests, compile, commit**

Tests must be table-driven over `RouteSpec` → expected `MibIpForwardRow2` fields, so the mapping is pinned without a machine.

---

## Task 3: interfaces

**Files:** Create `iface.go` + test.

- [ ] **Step 1: `Configure`**

macOS reaches the configured state in one `ifconfig`; Windows needs several calls — that asymmetry is exactly why `IfaceController` takes an `IfaceConfig` value rather than separate setters. Behind one `Configure`: `InitializeUnicastIpAddressEntry`, fill address/prefix, `CreateUnicastIpAddressEntry`; then MTU via `GetIpInterfaceEntry` + `SetIpInterfaceEntry`.

The family comes from whether `Local` parses as v6 — the same rule `scdarwin` uses, and for the same reason: a flag beside the address could disagree with the address actually given.

- [ ] **Step 2: `Unconfigure` and `Addrs`**

`Unconfigure` → `DeleteUnicastIpAddressEntry`. It must NOT bring the interface down, matching `scdarwin`: a tunnel belongs to whoever holds its handle.

`Addrs` reads through `GetAdaptersAddresses` — a different call family from the write, which is what makes it a verifier.

- [ ] **Step 3: Tests, compile, commit**

---

## Task 4: proxy — the one with the translation

**Files:** Create `proxy.go` + test.

- [ ] **Step 1: `Services`**

Return one pseudo-service. Withhold `CapPerService` in Task 6 to match.

- [ ] **Step 2: `SetAuto`, `SetManual`, `Restore`, `Configured`**

Write `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`: `AutoConfigURL` for PAC; `ProxyEnable` (DWORD) and `ProxyServer` for manual. Windows encodes per-scheme proxies in one `ProxyServer` string (`http=host:port;https=host:port;socks=host:port`) — parse and re-emit it rather than overwriting, or setting HTTPS will silently drop the user's HTTP proxy.

After any write, call `InternetSetOptionW` with `INTERNET_OPTION_SETTINGS_CHANGED` then `INTERNET_OPTION_REFRESH`. Without it the change does not reach running processes.

`Configured` must honour its `kinds ...ProxyKind` narrowing: read only what was asked for. Plan 1 established why — reading a kind the caller does not need means an unrelated failure aborts the whole apply.

`Restore` must refuse an empty `Kinds` (`sysport.CheckRestorable`).

- [ ] **Step 3: `Live` — the translation**

Call `WinHttpGetIEProxyConfigForCurrentUser` and translate into the scutil key names listed in the contracts section. Free the returned strings with `GlobalFree`; the struct is caller-freed.

Test this translation hard, table-driven: it is the only place where a Windows value becomes something platform-free code interprets, and a wrong key name means verification silently passes or silently fails.

- [ ] **Step 4: Tests, compile, commit**

---

## Task 5: DNS and environment

**Files:** Create `dns.go`, `env.go` + tests.

- [ ] **Step 1: `DNSController`**

`Set`/`Clear` shell out to `netsh interface ipv4|ipv6 set dnsservers`. **Consult the exit status and nothing else** — `netsh` prints in the system UI language, and on a Turkish Windows every string is Turkish. This is the rule §2 of the spec exists for.

`Configured` and `Live` both read `GetAdaptersAddresses`; `Live` is the verifier.

- [ ] **Step 2: `EnvController`**

`Get`/`Set`/`Unset` on `HKCU\Environment`, then broadcast `WM_SETTINGCHANGE` with `SendMessageTimeoutW(HWND_BROADCAST, ...)` and a short timeout so a hung window cannot stall teardown.

Carry `scdarwin`'s caveat verbatim in a comment: the variable only reaches processes started *after* the call, so a passing Verify says nothing about already-running apps.

**`Get` must distinguish "absent" from "could not read".** Plan 2 found this exact bug on the darwin side, where a tolerant read let `Revert` delete a user's pre-existing `HTTPS_PROXY`. A missing registry value is "not set"; any other error is an error.

- [ ] **Step 3: Tests, compile, commit**

---

## Task 6: facts, caps, and wiring the tree

**Files:** Create `facts.go`, `internal/netstate/port_windows.go`; modify `Makefile`, `.github/workflows/ci.yml`.

- [ ] **Step 1: `FactsCollector`**

Fill `sysport.Facts` from `GetAdaptersAddresses` + the RIB: uplink interface, v4/v6 gateways, global addresses, MAC. `Services` is the single pseudo-service.

`VPNState` needs a Windows definition of "a VPN owns the default route". Use the RIB: an unscoped default on an interface that is not the uplink and not `selfIface`. Write the reasoning down — `FullTunnel` is the field that changes behaviour, and `selfIface` exists because our own capture routes are indistinguishable from a full-tunnel VPN's.

- [ ] **Step 2: `Caps`**

Grant what is real: `CapProxyAuto | CapProxyManual | CapDNSOverride | CapRouteWrite | CapIfaceConfig | CapSessionEnv`. **Withhold `CapPerService`** — Windows proxy settings are per user, not per network service. Withholding it by name with a reason is the rule; silently granting it would let an Op iterate services that do not exist.

- [ ] **Step 3: `port_windows.go`**

```go
//go:build windows

package netstate

import "github.com/mumudevx/dpb/internal/sysconf/scwindows"

func newDefaultPort(r Runner) Port { return scwindows.New(r) }
func newDefaultRIB() RIBReader     { return scwindows.NewRIB() }
```

Match `port_darwin.go`'s actual signatures — read it, do not assume. Confirm `port_other.go`'s tag already excludes windows.

- [ ] **Step 4: The gate this whole plan exists for**

```bash
GOOS=windows go build ./...
```

Expected: **clean, the entire tree.** If anything still fails, name it precisely.

- [ ] **Step 5: Gate and CI**

Add `internal/sysconf/scwindows` to `COVER_GATED` and `COVER_GATED_RE`. Its darwin coverage will be **zero** — the package does not build on darwin at all — so confirm how `cover-gate` treats a package that contributes no statements on this platform, and if it cannot be gated meaningfully here, say so plainly rather than adding a floor exception.

Replace the CI cross-compile step's package list with `./...` now that the whole tree builds.

- [ ] **Step 6: Full verification and commit**

```bash
go build ./... && go vet ./... && go test ./... -race
gofmt -l cmd internal tools
make cover-gate
GOOS=windows go build ./...
GOOS=windows go vet ./...
go mod tidy && git diff --exit-code go.mod go.sum
```

---

## Phase gate

- [ ] `go build ./... && go vet ./... && go test ./... -race` green on darwin
- [ ] `gofmt -l cmd internal tools` empty
- [ ] `make cover-gate` passes, no floor lowered
- [ ] `go mod tidy` byte-identical, no new dependencies
- [ ] **`GOOS=windows go build ./...` succeeds for the whole tree** — the plan's headline
- [ ] `GOOS=windows go vet ./...` compiles every Windows test file
- [ ] `dpb probe --host discord.com --reps 3 --strategy tlsfrag:pos=snimid` still 3/3 PASS on the development machine

**Still not claimed:** nothing here has run. `GOOS=windows go build ./...` means it compiles, and that is all it means. Plan 4 brings up the TUN device; Plan 5 puts a binary on a real Windows 11 machine and finds out what is actually wrong.
