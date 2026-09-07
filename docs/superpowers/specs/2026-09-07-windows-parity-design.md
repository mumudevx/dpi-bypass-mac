# Windows 11 parity — design

Status: approved 2026-09-07. Supersedes nothing.

dpb is darwin/arm64 only. This adds full Windows 11 support — both front-ends,
the service, the Turkey profile — without weakening anything on macOS.

"Full parity" here means: every `dpb` verb that makes sense on Windows works
there, verified the same way, with the same evidence discipline. It does not
mean identical mechanisms; it means identical guarantees.

---

## 1. Why this is tractable

Three properties of the existing tree make the port a refactor rather than a
rewrite:

1. `internal/emit` is already capability-gated. `stub_other.go` withholds
   `CapSockTTL` and `CapOOB` on non-darwin **with a named reason**, and
   `strategy.Cap` makes the shortfall a typed error rather than a silent
   downgrade. The mechanism a Windows port needs already exists.
2. `netstate.Op` is already platform-free. `Kind/ID/Describe/Apply/Verify/
   Revert/VerifyReverted/Record` says nothing about macOS. Only the Op *bodies*
   and three types (`Facts`, `RIBReader`, `ProxyState`) are darwin-bound.
3. The suite is 51k lines against 42k of code, and `internal/testnet` is a
   fake macOS driven by output captured from a real machine. That is a real
   safety net for the migration in Phase 1.

Measured, not assumed: `GOOS=windows go build ./...` today produces 12 errors
with exactly two root causes — `internal/flow/dialer.go:214` (one line,
`syscall.Handle` vs `int`) and `internal/netstate` (the macOS system-config
layer). Every other failure cascades from those two. 10 of 22 packages already
cross-compile clean.

### No new dependencies

`golang.org/x/sys` (already a direct dependency) supplies everything:

| Need | Source |
| --- | --- |
| RIB read | `windows.GetIpForwardTable2` + `MibIpForwardRow2` + `FreeMibTable` |
| Route-change notification | `windows.NotifyRouteChange2` |
| Adapter/DNS inventory | `windows.GetAdaptersAddresses` + `IpAdapterAddresses` |
| Interface stats | `windows.GetIfEntry2Ex` + `MibIfRow2` |
| Unicast address row type | `windows.MibUnicastIpAddressRow` |
| Service control | `windows/svc` (`IsWindowsService`, `svc.Run`) |
| Service install/query/recovery | `windows/svc/mgr` (incl. `recovery.go`) |
| Registry | `windows/registry` |

Roughly eight procedures are missing and get thin `NewLazySystemDLL` wrappers
(~250 lines total): `CreateIpForwardEntry2`, `DeleteIpForwardEntry2`,
`GetBestRoute2`, `CreateUnicastIpAddressEntry`, `DeleteUnicastIpAddressEntry`,
`GetIpStatisticsEx`, `wininet!InternetSetOptionW`,
`winhttp!WinHttpGetIEProxyConfigForCurrentUser`.

`golang.zx2c4.com/wintun` is already an indirect dependency and
`golang.zx2c4.com/wireguard/tun/tun_windows.go` already exists — the TUN device
itself is not ours to write.

---

## 2. The constraint that shapes the whole port

`internal/netstate`'s package comment states the rule the design must preserve:

> Verification never uses the subsystem that applied the change.

and `runner.go` records a bug this project already paid for: on a
Turkish-language Mac, `ps -o lstart=` reorders its fields under `tr_TR`, which
made a live dpb look dead. The fix was `LC_ALL=C` on every parsed tool.

**Windows has no `LC_ALL=C`.** `netsh` and `route.exe` emit text in the system
UI language, and a parent process cannot force a child's thread UI language.
On a Turkish Windows 11 install, every string we might match is Turkish.

Therefore: **the Windows port never parses tool output.** Where a CLI is used at
all, only its exit status is consulted. All verification goes through typed API
calls that return structs.

This is not a compromise forced on us — it produces a stronger verifier than the
macOS side has, because there is no `liars` table to keep in step with a vendor's
wording.

---

## 3. Architecture

### 3.1 Package layout

```
internal/netstate/            platform-free
  port.go          (new)      Port + controller interfaces
  facts.go         (moved)    Facts, VPNState        <- facts_darwin.go
  rib.go           (moved)    RouteEntry, RIBReader  <- rib_darwin.go
  proxystate.go    (moved)    ProxyState             <- scutil_darwin.go
  lock.go                     record write/rename logic stays portable
  lock_unix.go / lock_windows.go   flock + process liveness (see 3.4)
  op_proxy.go op_dns.go op_route.go op_iface.go op_env.go op_pacfile.go
                              Op LOGIC only; no syscalls, calls Port
  manager.go journal.go adopt.go reverify.go        untouched

internal/sysconf/             new — port implementations
  scdarwin/                   existing darwin code moves here
  scwindows/                  iphlp.go rib.go route.go iface.go
                              proxy.go dns.go facts.go env.go
```

**No import cycle.** The interfaces live with their consumer (`netstate`), which
is idiomatic Go. `sysconf` imports `netstate` for the types; `netstate` never
imports `sysconf`. `cliapp` wires them: `env.Sys = sysconf.New(runner)`.

### 3.2 `Env` gains one field

```go
type Env struct {
	Runner Runner
	RIB    RIBReader
	Facts  *Facts
	Sys    Port        // new
	Logf   func(string, ...any)
	DryRun bool
	SelfIface    string
	PriorResidue bool
}
```

`Env`'s shape is preserved. `RIB` was already an interface and `Facts` was
already a value; only their producers move behind `Sys`.

### 3.3 Port interfaces

Each is narrow and single-purpose:

```go
type Port interface {
	Proxy() ProxyController   // Get, SetManual, SetAuto, Clear
	DNS()   DNSController     // Get, Set, Clear
	Route() RouteController   // Add, Delete, RIB
	Iface() IfaceController   // SetAddr, ClearAddr, SetMTU, Up
	Env()   EnvController     // Get, Set, Unset
	Facts() FactsCollector    // Collect
	Caps()  PortCaps
}
```

`PortCaps` is the system-mutation analogue of `strategy.Cap`. The reason is
already written in `emit/stub_other.go`:

> A capability that is silently absent is how a strategy gets downgraded
> without anyone noticing; every error below names the technique, the platform
> and the fact that the two do not meet here.

The same rule now governs system Ops. A capability a platform lacks is refused
**by name and with a reason**, never skipped quietly.

### 3.4 The run lock and process liveness

`netstate/lock.go` does two platform-bound things behind one portable record
format, and both need a Windows twin:

| Concern | darwin | windows |
| --- | --- | --- |
| Exclusive hold on the lock file | `unix.Flock(LOCK_EX\|LOCK_NB)` | `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK\|LOCKFILE_FAIL_IMMEDIATELY)` / `UnlockFileEx` |
| Is the recorded PID still our process? | `kernelProcessStart` via sysctl, falling back to `ps -o comm=` under `LC_ALL=C` | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessTimes` for creation time, `QueryFullProcessImageName` for identity |

The Windows path uses no external command at all, which removes the entire class
of bug the `LC_ALL=C` pin exists to prevent (§2). The PID-reuse defence — compare
the recorded start time against the live process's — is preserved exactly; only
the source of the start time changes.

The record write, the rename-based swap and the staleness policy stay in the
portable `lock.go`.

---

## 4. Op mappings

| Op | darwin Apply | darwin Verify | windows Apply | windows Verify |
| --- | --- | --- | --- | --- |
| proxy | `networksetup -setwebproxy` / `-setautoproxyurl` | `scutil --proxy` | `HKCU\...\Internet Settings` registry write + `InternetSetOptionW(SETTINGS_CHANGED\|REFRESH)` | `WinHttpGetIEProxyConfigForCurrentUser()` |
| dns | `networksetup -setdnsservers` | `scutil --dns` | `netsh interface ipv4\|ipv6 set dnsservers` — **exit status only** | `GetAdaptersAddresses()` → `FirstDnsServerAddress` |
| route | `route add/delete` | AF_ROUTE RIB | `CreateIpForwardEntry2` | `GetIpForwardTable2()` + `GetBestRoute2()` |
| iface | `ifconfig utunN inet ...` | `net.Interfaces()` | `CreateUnicastIpAddressEntry` | `GetAdaptersAddresses()` |
| pacfile | write file | stat + read back | same (already portable) | same |
| env | `launchctl setenv` | `launchctl getenv` | `HKCU\Environment` + `WM_SETTINGCHANGE` broadcast | read back `HKCU\Environment` |

### 4.1 Where the separation is weaker, and why we accept it

**proxy** and **dns** are clean: WinHTTP's resolved view is a genuinely different
subsystem from the registry keys we wrote, and `GetAdaptersAddresses` is a
different subsystem from `netsh`.

**route** and **iface** apply and verify through the same API family (IP Helper).
This is weaker than the macOS write-CLI / read-kernel split, and it is recorded
here rather than papered over.

The mitigation is real but partial: `CreateIpForwardEntry2` writes one row, while
`GetBestRoute2` asks the FIB *"which next hop would you choose for this
destination"* — a different code path answering a different question, traversing
route selection, metric and interface state. In one respect that is stronger than
reading the table back.

The rejected alternative was applying via `route.exe` to restore full separation.
It was rejected because `route.exe` brings localized output and its own liar
behaviour — reintroducing exactly the class of bug §2 exists to avoid.

This exception is documented in the `scwindows` package comment the same way the
`launchctl setenv`/`getenv` exception is documented on the `Op` interface.

### 4.2 The `env` Op is parity, not a gap

macOS sets user-session environment variables with `launchctl setenv`. Windows'
equivalent is `HKCU\Environment` plus a `WM_SETTINGCHANGE` broadcast. Both carry
the identical caveat already documented on `launchEnvOp`: the variable only
reaches processes started **after** the call, so a passing Verify says nothing
about the already-running Electron apps the variable exists for.

---

## 5. `emit` capability matrix

| Cap | darwin | windows | windows mechanism |
| --- | --- | --- | --- |
| `CapStreamWrite` | yes | yes | — |
| `CapNoDelay` | yes | yes | `TCP_NODELAY` |
| `CapSockTTL` | yes | yes | `setsockopt(IPPROTO_IP, IP_TTL)`; v6 `IPV6_UNICAST_HOPS` |
| `CapOOB` | yes | yes | Winsock `send(..., MSG_OOB)` |
| `CapUDPTTL` | yes | yes | same setsockopt |
| `CapDatagram` | yes | yes | portable |
| `CapRawInject` | no | no | Windows restricts raw sockets since XP SP2; would need a WinDivert driver — out of scope |
| `CapRawSeq` | no | no | never granted in v1 |

**All four rungs of the Turkey ladder work on Windows.** `tlsfrag:pos=snimid`
and `chunk:size=12` are pure userspace stream writes; `oob:pos=1` has a Winsock
equivalent.

One caveat: the Windows default TTL is 128 where macOS's is 64. No rung in the
shipped ladder uses TTL (`disorder` does, and it is 0/10 in MEASUREMENTS.md
§3.5), so the practical impact is small — but `DefaultTTL()` reads
`GetIpStatisticsEx` on Windows rather than hardcoding, for the same reason
DOSSIER §3 gives for reading `net.inet.ip.ttl` on macOS.

---

## 6. Service model

`serviceScope` generalises from "launchd domain" to "mechanism":

```go
type serviceMech int
const (
	launchdAgent  serviceMech = iota // darwin, gui/<uid>
	launchdDaemon                    // darwin, system
	winLogonTask                     // windows, user
	winService                       // windows, system
)
```

| | darwin user | darwin `--system` | windows user | windows `--system` |
| --- | --- | --- | --- | --- |
| Mechanism | LaunchAgent | LaunchDaemon | Scheduled Task (logon trigger) | SCM service (`svc/mgr`) |
| Runs as | the user | root | the interactive user | `LocalSystem` |
| Install | write plist + `bootstrap` | same | write XML + `schtasks /create /xml` | `mgr.CreateService` |
| Restart throttle | `ThrottleInterval` 30 s | same | task `RestartInterval` | `mgr.SetRecoveryActions` + delay |
| Verify | read the plist we wrote + `launchctl print` | same | read `%WINDIR%\System32\Tasks\dpb` XML from the **filesystem** + ask `schtasks` | read `HKLM\SYSTEM\CurrentControlSet\Services\dpb` from the **registry** + ask SCM |

Windows needs two mechanisms rather than one because a Windows service runs in
session 0 as `LocalSystem`: it can neither write the interactive user's `HKCU`
hive nor signal `INTERNET_OPTION_SETTINGS_CHANGED` into that user's session. So
proxy mode — which is per-user by construction — installs as a logon task, and
TUN mode — which needs administrator rights for the wintun adapter and the route
table anyway — installs as a service. This is the split WireGuard uses.

Both Windows mechanisms preserve the two-observer shape `service.go` documents:
the definition we wrote is read back independently, and the manager is asked
whether it knows the job.

`main` gains one branch: if `svc.IsWindowsService()` reports true, hand off to
`svc.Run`; otherwise the normal cobra path.

**Known difference:** launchd captures a job's stdout/stderr to files via plist
keys. A Windows service has no equivalent, so the service redirects its own
streams into `LogDir` at startup. dpb already writes an NDJSON event log there,
so the practical gap is small — but `dpb service logs` must know the difference.

---

## 7. `paths`

| Role | darwin user | darwin system | windows user | windows SYSTEM |
| --- | --- | --- | --- | --- |
| Config | `~/Library/Application Support/dpb` | `/Library/Application Support/dpb` | `%APPDATA%\dpb` | `%ProgramData%\dpb` |
| State | same as Config | same as Config | `%LOCALAPPDATA%\dpb` | `%ProgramData%\dpb` |
| Cache | `~/Library/Caches/dpb` | `/Library/Caches/dpb` | `%LOCALAPPDATA%\dpb\cache` | `%ProgramData%\dpb\cache` |
| Log | `~/Library/Logs/dpb` | `/Library/Logs/dpb` | `%LOCALAPPDATA%\dpb\logs` | `%ProgramData%\dpb\logs` |

The problem `paths` exists to solve does not exist on Windows. Its package
comment says "the hard problem it exists to solve is sudo" — root writing files
the unprivileged user must later read. UAC elevation keeps the **same user
account**, so `%LOCALAPPDATA%` resolves identically elevated or not.

Consequences:

- `UID`/`GID` are `-1` on Windows; `EnsureDirs` skips the ownership handback.
- `Elevated` comes from `windows.Token.IsElevated()`.
- `System` comes from `svc.IsWindowsService()`.
- ACLs need no work: `%ProgramData%\dpb` created by a `LocalSystem` service is
  writable by SYSTEM and Administrators by default, matching `/Library`.

---

## 8. Testing

Three tiers.

**Tier 1 — host-agnostic, runs on the Mac today.** This is Phase 1's real
payoff. Today the macOS Ops can only be tested through `testnet`'s captured CLI
text. Once Op logic calls a `Port`, it is testable with a hand-written fake on
any OS. **Windows Op logic gets the same coverage as macOS Op logic, on the
Mac, before a Windows machine is ever involved.**

**Tier 2 — CI.** A `windows-latest` job running `go build`, `go vet` and
`go test` for everything that needs neither administrator rights nor real
system mutation. The existing macOS job gains a cheap `GOOS=windows go vet ./...`
cross-check.

**Tier 3 — VM.** `testnet`'s fixture discipline transfers, but not as text. A
new `dpb devtool capture-sysconf` command runs in the VM and serialises real
`MibIpForwardTable2` rows, `IpAdapterAddresses` blocks and
`WINHTTP_CURRENT_USER_IE_PROXY_CONFIG` values as JSON into
`internal/testwin/fixtures/`. This keeps the guarantee `testnet`'s package
comment demands — *a test asserts against what the machine actually returned,
not against what the author assumed* — in a form that survives the move from a
CLI to an API.

### Test environment

Windows 11 **ARM64** in UTM or Parallels on the Apple Silicon host, **bridged**
networking so the VM sits on the same censored Türk Telekom line with its own
address. Go targets `windows/arm64` natively; wintun ships arm64. This makes
real DPI measurement possible from the VM, not just behavioural testing.

---

## 9. Distribution

goreleaser:

```yaml
goos:   [darwin, windows]
goarch: [arm64, amd64]
ignore:
  - { goos: darwin, goarch: amd64 }   # preserves the existing darwin/arm64-only policy
```

**Open item — `wintun.dll` redistribution.** The DLL must ship next to
`dpb.exe`, per architecture. This repo is MIT; wintun's redistribution terms
have **not** been verified and are not asserted here. Two options, decided in
Phase 7: (a) bundle it in the archive if the terms allow, or (b) download it on
first `dpb run --tun` with a pinned checksum.

Package managers mirror the existing Homebrew tap pattern: a
`mumudevx/scoop-dpb` bucket with a JSON manifest, and a manifest PR to
`microsoft/winget-pkgs`. No code signing (decided) — the README states the
SmartScreen warning plainly rather than hiding it.

---

## 10. The Turkey profile

`internal/config/embed/turkey.toml` **does not change**. It is pure TOML with no
platform code, and `ladder = "tr"` resolves to the same four rungs on both
systems.

Phase 6 re-measures on the VM against the Türk Telekom line. **If** the Windows
ladder differs from the macOS one, a `ladder = "tr-windows"` split is discussed
*then*, when there is evidence. No second ladder is invented in advance —
MEASUREMENTS.md §3.4 already shows efficacy is non-monotonic within one ISP on
one day, which is precisely why this project measures instead of reasoning.

---

## 11. Module rename

`github.com/mumudevx/dpb` → `github.com/mumudevx/dpb`.

The current name becomes false the moment Windows ships. The rename is
mechanical (all imports are internal), GitHub redirects the old repository path,
and doing it in Phase 0 costs one commit where doing it later touches every file
the port adds.

---

## 12. Phases

Each phase has a gate. A phase does not start until the previous gate is green.

| Phase | Work | Gate |
| --- | --- | --- |
| **0** | Module rename to `github.com/mumudevx/dpb` | Suite green, mechanical diff only |
| **1** | Extract Port interfaces; move darwin impls to `sysconf/scdarwin` | **The existing 4781 lines of netstate tests, and the full suite, pass unchanged.** Zero behaviour change. Not green ⇒ Phase 2 does not start |
| **2** | Easy twins: `flow`, `paths`, `lock`, `janitor`, `emit` | `GOOS=windows go build ./...` green for those packages |
| **3** | `sysconf/scwindows` — the substance | Fake-backed unit tests pass on the Mac (Tier 1) |
| **4** | `tunfe/link_windows.go`, `netwatch` windows | wintun parity with utun in the VM |
| **5** | Service (logon task + SCM), `cliapp` wiring, `doctor`/`selftest` windows branches, **README Windows section** | `dpb doctor` clean in the VM |
| **5.5** | **`v2.0.0-windows-preview` prerelease** | A Windows owner other than the author can install and run it |
| **6** | `dpb tune` on the TT line in the VM — **measure** the Windows ladder | `docs/MEASUREMENTS-windows.md` written from real runs |
| **7** | goreleaser `windows/{amd64,arm64}`, wintun DLL decision, winget manifest, scoop bucket, CI windows job | Release green |

Phase 1 is the keystone: no behaviour change, proven by the suite that already
exists. Nothing Windows-specific is written before it passes.

### 12.1 Why 5.5 exists

The first external tester is expected to be on **amd64** and on a **different
ISP**. That makes their run a *compatibility* test — does dpb install, start,
capture traffic, and clean up after itself on a Windows machine that is not the
author's — and **not** a ladder measurement. `turkey.toml` is explicit that
Superonline, Vodafone, Turknet and every mobile network are unmeasured, and that
efficacy is non-monotonic within one ISP on one day.

The README section written in Phase 5 must say this, so a tester does not report
"3/6 worked" as though it were a measurement of anything.

---

## 13. README deliverable (Phase 5)

`README.md` gains `## Install → Windows`, covering:

- **Requirements** — Windows 11, x64 or ARM64. Administrator rights for
  `--tun` only; proxy mode needs none.
- **Download** — GitHub Releases zip, with the SHA256 to check.
- **SmartScreen** — stated plainly: the binary is unsigned, Windows will warn,
  here is what the warning looks like and how to proceed. No euphemism.
- **First run** — the proxy-mode quickstart, mirroring the existing macOS
  `dpb run` section, minus `sudo`.
- **TUN mode** — the elevated path, and the wintun requirement.
- **Service** — `dpb service install` (logon task) vs `--system` (SCM service).
- **Uninstall** — `dpb service uninstall`, and how to confirm the machine's
  proxy, DNS and routes were restored.
- **Reporting a result** — what a tester's run does and does not establish
  (§12.1), so feedback arrives in a form the project can use.

The macOS half of `## Install` is unchanged.

---

## 14. Out of scope

| Excluded | Reason |
| --- | --- |
| WinDivert / `CapRawInject` | A second architecture plus a signed driver. All four rungs of the Turkey ladder work without it. |
| Linux | `stub_other.go` keeps compiling. Nothing more. |
| `windows/386` | Windows 11 has no 32-bit edition. |
| Windows 10 | Target is 11. It will probably work; it is not tested and not claimed. |
| GUI / tray app | A different product. |
| Per-application proxy rules | Not possible on Windows without WFP. |
| Code signing | Deferred by decision; winget and scoop manifests instead. |
