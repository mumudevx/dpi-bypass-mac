# Windows Parity, Plan 5: Service, Correctness, and a Binary Someone Can Run

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Windows support *usable*: `dpb service` installs and runs, the proxy actually reaches the user's browser, `dpb doctor` tells the truth on Windows, the README says how to install it, and a `v2.0.0-windows-preview` binary exists for someone other than the author to run.

**Architecture:** `serviceScope` generalises from "launchd domain" to "mechanism". Windows needs **two** mechanisms, not one — an SCM service for `--system` and a logon task for the user scope — and the reason is not stylistic: a service runs in session 0 as `LocalSystem` and can neither write the interactive user's `HKCU` hive nor signal a settings change into their session.

**Tech Stack:** Go 1.26.4, `golang.org/x/sys/windows` (`svc`, `svc/mgr`, `registry`), stdlib. **No new module dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-07-windows-parity-design.md` (§6, §13)

## Global Constraints

- Module path `github.com/mumudevx/dpb`. Go floor `1.26.4`.
- **No new module dependencies.** `go mod tidy` byte-identical; never hand-edit `go.mod`.
- **No behaviour change on macOS.** `dpb service` works on macOS today and its tests assert launchd behaviour exactly. The darwin suite must stay green with an unchanged test count unless a task adds tests.
- **No test body may be edited.** Four plans have held this with zero assertions weakened. Test files may gain build tags; a test written *within this branch* that encodes a defect may be corrected — say which and why.
- Coverage floors: `tunfe` 70, `cliapp` 83, everything else **85**. Never lower one.
- `gofmt -l cmd internal tools` empty. `GOOS=windows go build ./...` must stay at exit 0 and `GOOS=windows go vet ./...` clean except `internal/sysconf/scdarwin`, which is darwin-only by design.
- **Windows tool output is never parsed.** `schtasks` is consulted for its exit status only. Verification reads the XML file we wrote or the registry — both are filesystem/registry reads, not localized text. This is the rule the whole port is built on.
- Comments explain WHY and cite evidence.

---

## What is still not true on Windows

Four plans built the machinery. This plan makes it work. Carried forward, in the order that matters:

1. **`HKCU` is the *elevated* token's hive** (`scwindows/proxy.go`, `env.go`). On a standard-user-plus-admin-account machine — the enterprise default — an elevated dpb writes proxy settings into the **admin's** hive, and `Live` reads that same hive, so **Verify passes while the user's browser is untouched.** Silent, and precisely the failure class the two-subsystem rule exists to catch. Task 4.
2. **`Live` assumes WinHTTP returns `lpszProxy` NULL when `ProxyEnable` is 0.** If false, a disabled proxy reads as enabled. Task 4.
3. **A dual-homed machine may read as a full tunnel** and refuse to run (`scwindows/facts.go`). The refusal direction is safe; the detection is unmeasured.
4. **`OnLinkPrefixLength = 32`** substitutes for macOS's point-to-point `/32`; unconfirmed against Windows' own on-link route derivation.
5. `stack.go` installs the v6 escape route on the **v4** uplink; `Capture` has no `UplinkV6` though `Facts` does. Pre-existing on macOS too.
6. Adopted Ops are listed under "Ctrl-C reverts every change above", so Windows prints a route change dpb never made.

Items 3–6 need a real machine and belong to first contact. **Items 1 and 2 are correctness bugs we can reason about now**, and item 1 makes proxy mode silently useless on a common configuration — so this plan fixes them rather than shipping a preview that does nothing on an enterprise laptop.

---

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `internal/cliapp/service_windows.go` | SCM install/uninstall/start/stop/status |
| `internal/cliapp/service_task_windows.go` | the logon-task mechanism |
| `internal/cliapp/service_darwin.go` | launchd, moved out of `service.go` unchanged |
| `internal/cliapp/svcrun_windows.go` | the `svc.Run` entry point |
| `internal/sysconf/scwindows/userhive.go` | the interactive user's registry hive |
| `docs/MEASUREMENTS-windows.md` | created empty-but-honest by Task 6; Plan 6 fills it |

**Modified:** `internal/cliapp/service.go` (the mechanism abstraction), `cmd/dpb/main.go` (service entry branch), `internal/cliapp/doctor.go` and `selftest.go` (Windows branches), `internal/sysconf/scwindows/proxy.go` and `env.go` (hive), `README.md`, `.goreleaser.yaml`.

---

## Task 1: `serviceScope` becomes mechanism-shaped

**Files:** modify `internal/cliapp/service.go`; create `internal/cliapp/service_darwin.go`.

Today `serviceScope` holds a launchd `domain` and a `plist` path, and `target()` returns `domain + "/" + label`. That is launchd vocabulary in what must become platform-free code.

- [ ] **Step 1: Read `service.go` end to end before changing anything.** It is 25 KB and its comments carry real evidence — why `load -w`/`unload -w` were abandoned for `enable`/`bootstrap`/`bootout`, why the throttle is 30 s rather than launchd's 10 s floor, and why `--system` does not take the invoking user's log directory. None of that may be lost.

- [ ] **Step 2: Introduce the mechanism**

```go
type serviceMech int

const (
	launchdAgent  serviceMech = iota // darwin, gui/<uid>
	launchdDaemon                    // darwin, system
	winLogonTask                     // windows, the interactive user
	winService                       // windows, LocalSystem
)
```

Give `serviceScope` a `mech` and move the launchd-specific fields behind a per-platform accessor. The verbs (`install`, `uninstall`, `start`, `stop`, `status`, `logs`) stay in `service.go`; what each *does* becomes a platform call.

- [ ] **Step 3: Move launchd out unchanged**

Everything launchd-specific moves to `service_darwin.go`. **This is a move, not a rewrite** — the same decomposition `janitor` and `tunfe` needed in Plans 2 and 4. Verify by diffing the moved bodies against their originals.

- [ ] **Step 4: darwin proves unchanged**

```bash
go test ./internal/cliapp/ -run TestService -v 2>&1 | tail -5
go build ./... && GOOS=windows go build ./...
```

Report the `TestService*` count before and after; it must be identical.

---

## Task 2: the Windows service

**Files:** create `internal/cliapp/service_windows.go`, `internal/cliapp/svcrun_windows.go`; modify `cmd/dpb/main.go`.

This is the `--system` mechanism: `LocalSystem`, for TUN mode, which needs administrator rights for the wintun adapter and the route table anyway.

- [ ] **Step 1: install / uninstall**

`mgr.Connect`, `CreateService`, `Delete` — all verified present in `x/sys@v0.43.0`. Set recovery actions with `SetRecoveryActions` (`svc/mgr/recovery.go`) so a crashed service restarts, and give it a delay for the same reason launchd's throttle is 30 s rather than 10: read that comment in `service.go` — restarting instantly into a network that is still broken is not recovery.

- [ ] **Step 2: start / stop / status**

`Service.Start`, `Service.Control(svc.Stop)`, `Service.Query`.

**Verify through a different subsystem than you wrote through**, as `service.go` already does on macOS: read the service's own definition back from `HKLM\SYSTEM\CurrentControlSet\Services\dpb` — a registry read, not a parsed tool — *and* ask the SCM whether it knows the service. The macOS comment explains the shape: check the half that can be independently checked.

- [ ] **Step 3: the `svc.Run` entry point**

`cmd/dpb/main.go` gains one branch: if `svc.IsWindowsService()` reports true, hand off to `svc.Run`; otherwise the normal cobra path. Keep it to one branch — a service binary that also has to be a CLI is where this gets tangled.

The handler must answer `svc.Interrogate` promptly and treat `svc.Stop`/`svc.Shutdown` as the teardown signal, mapping onto whatever `run` already does for SIGINT. **Find that path and reuse it** — do not write a second teardown.

- [ ] **Step 4: log capture, and say what differs**

launchd captures a job's stdout/stderr to files via plist keys. **A Windows service has no equivalent**, so the service must redirect its own streams into `LogDir` at startup. dpb already writes an NDJSON event log there, so the practical gap is small — but `dpb service logs` must know the difference, and the difference belongs in a comment rather than being papered over.

- [ ] **Step 5: verify and commit**

---

## Task 3: the logon task

**Files:** create `internal/cliapp/service_task_windows.go`.

This is the **user** scope, and it exists because a service cannot do this job.

- [ ] **Step 1: write down why there are two mechanisms**

A Windows service runs in session 0 as `LocalSystem`. It can neither write the interactive user's `HKCU` hive — where WinINET proxy settings live — nor deliver `INTERNET_OPTION_SETTINGS_CHANGED` into that user's session. So proxy mode, which is per-user by construction, installs as a **logon task**; TUN mode, which needs administrator rights anyway, installs as a **service**. This is the split WireGuard uses. Put the reasoning in the package comment, not just the commit message.

- [ ] **Step 2: install / uninstall**

Write a Task Scheduler XML with a logon trigger running in the user's context, then `schtasks /create /xml`. **Consult its exit status and nothing else** — `schtasks` prints in the system UI language and there is no `LC_ALL=C`.

- [ ] **Step 3: verify by reading what you wrote**

Read back `%WINDIR%\System32\Tasks\<name>` — the XML file, from the filesystem — and separately ask `schtasks` whether the task exists (exit status only). Same two-observer shape macOS uses, and neither half parses localized text.

- [ ] **Step 4: verify and commit**

---

## Task 4: make proxy mode actually reach the user

**Files:** create `internal/sysconf/scwindows/userhive.go`; modify `proxy.go`, `env.go`.

**This is the most important task in the plan.** Without it, proxy mode on a standard-user-plus-admin machine silently does nothing while reporting success.

- [ ] **Step 1: the problem, stated exactly**

`registry.CURRENT_USER` resolves against the **calling process's token**. An elevated dpb on a machine where the admin is a *separate account* therefore reads and writes the administrator's hive. `Live()` reads the same wrong hive, so Verify passes. The user's browser never sees a proxy, and dpb reports Ready.

- [ ] **Step 2: get the interactive user's hive**

The shape: find the interactive session (`WTSGetActiveConsoleSessionId`), get its user token (`WTSQueryUserToken` — needs `SE_TCB_NAME`, which `LocalSystem` has), and open that user's registry root (`RegOpenCurrentUser` while impersonating, or `HKEY_USERS\<SID>` derived from the token).

**Verify every one of those procedures exists before relying on it.** This project has found six functions that compile, look correct and always fail — `syscall.Sendto`, `internal/poll`'s `RawWrite`, `os.Process.Signal`, and three more. Read the Go source for each. Wrap what is missing following `scwindows/iphlp.go`'s convention, noting that error conventions differ per DLL.

- [ ] **Step 3: fall back honestly**

When dpb is **not** elevated, or the process already *is* the interactive user, `CURRENT_USER` is correct and cheap — use it. Only take the token path when they differ.

When the token path fails, **do not silently fall back to the wrong hive.** Return an error naming what could not be determined. This project's rule, learned twice the hard way: reporting "could not find out" as a definite answer is how a live user's configuration gets destroyed. A proxy silently written to the wrong hive is the same class of lie.

- [ ] **Step 4: while you are here — the `lpszProxy` assumption**

`Live` assumes WinHTTP returns `lpszProxy` NULL when `ProxyEnable` is 0. If that is false, a **disabled** proxy reads as enabled. Make `Live` derive the enabled state from something it actually observes rather than from that assumption, or — if WinHTTP genuinely cannot distinguish them — read `ProxyEnable` from the (now correct) hive and say in a comment why the verifier needs it.

- [ ] **Step 5: test what is testable**

The hive-selection *decision* is testable without Windows: elevated-and-different-user takes the token path, not-elevated takes `CURRENT_USER`, token failure returns an error rather than a fallback. Table-drive it.

- [ ] **Step 6: verify and commit**

---

## Task 5: `doctor`, `selftest`, and the README

**Files:** modify `internal/cliapp/doctor.go`, `selftest.go`, `README.md`.

- [ ] **Step 1: `doctor` and `selftest` on Windows**

Both currently reason in macOS terms. Find every check that names a macOS tool, path or concept and give it a Windows counterpart or an honest "not applicable here". A `doctor` that reports a clean bill of health by skipping every check it does not understand is worse than one that says it cannot tell.

Include a check for the two things a Windows user will actually hit: **is `wintun.dll` present** (TUN mode needs it), and **is the proxy hive the interactive user's** (Task 4's failure mode).

- [ ] **Step 2: the README Windows section**

`README.md` gains `## Install → Windows`, covering exactly what spec §13 lists:

- **Requirements** — Windows 11, x64 or ARM64. Administrator for `--tun` only; proxy mode needs none.
- **Download** — the GitHub Releases zip and its SHA256.
- **SmartScreen** — stated plainly: the binary is unsigned, Windows will warn, here is what the warning looks like and how to proceed. No euphemism.
- **First run** — the proxy-mode quickstart, mirroring the macOS section, minus `sudo`.
- **TUN mode** — the elevated path, and the wintun requirement.
- **Service** — `dpb service install` (logon task) versus `--system` (SCM service), and why they differ.
- **Uninstall** — and how to confirm the machine's proxy, DNS and routes were restored.
- **Reporting a result** — see Step 3.

The macOS half of `## Install` is unchanged. The title says "macOS DPI bypass"; update it to name both platforms.

- [ ] **Step 3: tell a tester what their result means**

This is the part most likely to be skipped and the most valuable. The first external tester will be on **amd64** and on a **different ISP**. Their run is a *compatibility* test — does dpb install, start, capture traffic and clean up on a machine that is not the author's — and **not** a ladder measurement.

`internal/config/embed/turkey.toml` is explicit that Superonline, Vodafone, Turknet and every mobile network are unmeasured, and MEASUREMENTS.md §3.4 records that efficacy is non-monotonic within one ISP on one day. So the README must say plainly what a tester's result does and does not establish, or "3/6 worked" will be reported as though it measured something.

- [ ] **Step 4: verify and commit**

---

## Task 6: the preview binary

**Files:** modify `.goreleaser.yaml`; create `docs/MEASUREMENTS-windows.md`.

- [ ] **Step 1: goreleaser builds Windows**

```yaml
goos:   [darwin, windows]
goarch: [arm64, amd64]
ignore:
  - { goos: darwin, goarch: amd64 }   # preserves the existing darwin/arm64-only policy
```

**Do not bundle `wintun.dll`.** Spec §9 records its redistribution terms as unverified, and that decision is Plan 6's. The archive ships without it and the README says where to get it.

- [ ] **Step 2: `docs/MEASUREMENTS-windows.md`, created honest and empty**

One short file stating that **no Windows measurement exists yet**, what would have to be true to make one (a Windows machine on a censored line, `dpb tune` run there), and that the Turkey ladder's numbers in `MEASUREMENTS.md` were measured on macOS and do not transfer. Plan 6 fills it with real numbers or deletes it.

This file exists so that nobody reads `turkey.toml`'s ladder and assumes it was measured on Windows.

- [ ] **Step 3: verify the release config without publishing**

```bash
goreleaser build --snapshot --clean --single-target 2>&1 | tail -20
```

or `goreleaser check`. **Do not tag, do not publish, do not push a release.** Cutting `v2.0.0-windows-preview` is the user's action — report that the config is ready and what command cuts it.

- [ ] **Step 4: the phase gate and commit**

---

## Phase gate

Every item names a package or file in this plan's File Structure, per the rule Plan 3 established.

- [ ] darwin `go build ./... && go vet ./... && go test ./... -race` green
- [ ] `TestService*` count on darwin unchanged by Task 1
- [ ] `gofmt -l cmd internal tools` empty
- [ ] `make cover-gate` passes, no floor lowered
- [ ] `go mod tidy` byte-identical
- [ ] `GOOS=windows go build ./...` exit 0
- [ ] `GOOS=windows go vet ./...` clean except `internal/sysconf/scdarwin`
- [ ] `README.md` has a Windows install section that states the SmartScreen warning plainly and says what a tester's result does not establish
- [ ] `goreleaser check` passes with Windows targets
- [ ] `dpb probe --host discord.com --reps 3 --strategy tlsfrag:pos=snimid` still 3/3 PASS on the development machine

**What this plan still does not do:** nothing here has run on Windows. It produces a *config* that can cut a preview binary, and the four items above that need a real machine stay open. Plan 6 cuts the release, adds the Windows CI job, decides the wintun DLL question, and — on a Windows machine on a censored line — **measures** the ladder instead of assuming it.
