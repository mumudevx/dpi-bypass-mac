# Windows Parity, Plan 4: Front-ends and the Last Build Gaps

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `netwatch` a real Windows route source, make the TUN front-end open a wintun device, close the last two build gaps, and answer the routing question Plan 3 uncovered — so every package in the tree builds for Windows except the one that is darwin-only by design.

**Architecture:** Three of the four pieces are the decomposition this project keeps arriving at — extract the portable body into an untagged file, leave a small per-platform leaf. The fourth, the Windows route source, is genuinely new code over `NotifyRouteChange2`.

**Tech Stack:** Go 1.26.4, `golang.org/x/sys/windows`, `golang.zx2c4.com/wireguard/tun`, `golang.zx2c4.com/wintun`. **No new module dependencies** — wintun is already an indirect dependency and `wireguard/tun/tun_windows.go` already exists.

**Spec:** `docs/superpowers/specs/2026-09-07-windows-parity-design.md` (§5 TUN, §3.1)

## Global Constraints

- Module path `github.com/mumudevx/dpb`. Go floor `1.26.4`.
- **No new module dependencies.** `go mod tidy` byte-identical. `wintun` moving from indirect to direct is acceptable **only** if `go mod tidy` makes that change itself; do not hand-edit `go.mod`.
- **No behaviour change on macOS.** The darwin suite must stay green throughout.
- **No test body may be edited.** Four plans have held this with zero assertions weakened. Test files may gain build tags; assertions may not change. A test written *within this branch* that encodes a defect may be corrected — say which and why.
- Coverage: floors are `tunfe` 70, `cliapp` 83, everything else **85**. Never lower one. New packages go in `COVER_GATED` and `COVER_GATED_RE`.
- `gofmt -l cmd internal tools` empty. Run it every task.
- **Nothing Windows here can be executed.** `GOOS=windows go vet ./...` compiles packages *and their tests*; `GOOS=windows go test -c` proves a test binary links. Those are the strongest checks available. Never write "tests pass" for Windows.
- Comments explain WHY and cite evidence.

---

## Exactly what is left, measured

```
internal/netwatch   watcher.go:535  undefined: newDefaultSource   ← and cliapp + cmd/dpb fail only through it
internal/testnet    killfuzz.go:116 undefined: syscall.Kill
internal/sysconf/scdarwin           build constraints exclude all Go files  ← CORRECT, darwin-only by design
```

Two real root causes. Everything else already builds.

---

## What earlier plans learned that applies here

- **Windows ships functions that compile, look right, and always fail.** Five were found across Plans 2 and 3: `syscall.Sendto`, `internal/poll`'s `RawWrite`, `os.Process.Signal`, plus two "could not query" → "definitely dead" conflations. Before using any Windows API this plan does not name, read its Go source and confirm it is implemented.
- **A phase gate may only name packages in this plan's own File Structure section.** Three gates in this series demanded other plans' work. This plan's gate is written from the list above.
- **`internal/netwatch/route_other.go`'s comment is the specification for Task 1.** It already says what a real Windows source must be and why a nil stub is unacceptable: *"A Windows netwatch that compiled against this stub would run with no route source at all and say nothing about it… 'dpb is watching the network' would be true in the wiring and false in fact."* Read it before starting.

---

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `internal/netwatch/route_windows.go` | `Source` over `NotifyRouteChange2` |
| `internal/front/tunfe/link.go` | the portable `deviceLink` body, moved out of `link_darwin.go` |
| `internal/front/tunfe/link_windows.go` | the wintun-specific open path and default name |
| `internal/testnet/killfuzz_unix.go` / `killfuzz_windows.go` | the `syscall.Kill` leaf |
| `internal/cliapp/sysport_windows.go` | the composition root's Windows Port |

**Modified:** `internal/netwatch/route_other.go` (tag narrows), `internal/front/tunfe/link_darwin.go` (shrinks to the darwin leaf), `internal/cliapp/sysport_other.go` (tag narrows), `.github/workflows/ci.yml`, `Makefile` if a package is added to the gate.

**Not in this plan:** `dpb devtool capture-sysconf`, which the Plan 1 sequence assigned here. It exists to capture fixtures **from a real Windows machine**, and there is none yet. Writing it now would be building a tool whose output we cannot obtain. It moves to Plan 5, where it is used on first contact.

---

## Task 1: a real Windows route source

**Files:** Create `internal/netwatch/route_windows.go` + test; modify `route_other.go`'s build tag.

**Produces:** `newDefaultSource() Source` for Windows.

`Source` is one method:

```go
// Run blocks until ctx is done or the source fails, sending one value on
// out per routing message. It must not close out, and it must return
// promptly once ctx is done.
Run(ctx context.Context, out chan<- struct{}) error
```

- [ ] **Step 1: Read the specification that already exists**

`internal/netwatch/route_other.go`'s comment states what this must be and why a stub is not acceptable. `internal/netwatch/route_darwin.go` is the working PF_ROUTE implementation whose *contract* you are matching — read how it handles `ctx` cancellation, how it avoids blocking on `out`, and what it does on source failure.

- [ ] **Step 2: Write the failing test**

A test that the source delivers on `out` and returns promptly when `ctx` is cancelled. It cannot trigger a real routing change, so drive whatever seam you introduce. `GOOS=windows go vet ./internal/netwatch/` is how you see it compile.

- [ ] **Step 3: Implement over `NotifyRouteChange2`**

`windows.NotifyRouteChange2(family uint16, callback uintptr, callerContext unsafe.Pointer, initialNotification bool, notificationHandle *Handle)` — **verified present** in `x/sys@v0.43.0`.

Three things this API will punish you for:

1. **The callback runs on a Windows thread pool thread, not a goroutine.** It must be a `syscall.NewCallback` function, it must do the absolute minimum, and it must not block. A non-blocking send onto a buffered channel is the shape; dropping a signal when one is already pending is correct, because the watcher only needs to know that *something* changed.
2. **`callerContext` must not be a Go pointer.** Passing one violates cgocheck and can crash or corrupt. Use a handle/index into a registry guarded by a mutex, or a package-level singleton if only one source can exist — decide, and write down why it is safe.
3. **The handle must be cancelled with `CancelMibChangeNotify2` before `Run` returns**, or the callback can fire into a torn-down world. That procedure is **not** in `x/sys` — check, and if absent add it as a `NewLazySystemDLL` wrapper following the convention in `internal/sysconf/scwindows/iphlp.go`. Note that package's per-DLL convention differences before copying its error mapping.

Register for both `AF_INET` and `AF_INET6`, or explain in a comment why one suffices.

- [ ] **Step 4: Narrow `route_other.go`**

Its tag becomes `!darwin && !windows`. Update its comment: it currently says Windows is deliberately excluded *"until the plan that owns netwatch ships a real source over the IP Helper notification API"* — that plan is this one, so say what now exists instead of promising it.

- [ ] **Step 5: Verify and commit**

```bash
GOOS=windows go vet ./internal/netwatch/ ./internal/cliapp/ ./cmd/dpb/
go build ./... && go test ./internal/netwatch/
gofmt -l cmd internal tools
```

---

## Task 2: the TUN link

**Files:** Create `internal/front/tunfe/link.go`, `link_windows.go`; shrink `link_darwin.go`.

**Measured before this plan was written:** `wgtun.CreateTUN(ifname string, mtu int) (Device, error)` has the **same signature** on Windows and darwin, and `wgtun.Device`'s method set is identical. So `deviceLink` — the adapter, the event pump, the `Read`/`Write`/`MTU`/`Name` translation — is **already portable**. Only two things are darwin-specific in `link_darwin.go`: the build tag, and the default device name `"utun"`.

This is the same decomposition Plan 2 found in `janitor`, where `Spawn` was portable and only `detachAttrs` needed a per-OS home. Do not rewrite the adapter; move it.

- [ ] **Step 1: Extract the portable body**

Move everything except the name defaulting into an untagged `link.go`: `wgDevice`, `deviceLink`, `newDeviceLink`, `pumpEvents`, `Read`, `Write`, and the rest. Keep every comment with its code — the one explaining why `deviceLink` is written against an interface rather than `*wgtun.NativeTun` records why the translation is testable without root, and it is still true.

- [ ] **Step 2: The per-platform leaf**

`link_darwin.go` keeps only the darwin default: `name == ""` becomes `"utun"`, and the doc comment about `utunN` and the kernel picking a unit.

`link_windows.go` supplies the Windows default. A wintun adapter takes a **friendly name**, not a kernel-assigned `utunN`; pick one and say why in a comment. Note what `Name()` will then report, because `netstate`'s route and interface Ops are told the name the device actually got — never the one requested.

- [ ] **Step 3: The wintun runtime dependency, stated honestly**

`wgtun.CreateTUN` on Windows calls `wintun.CreateAdapter`, which loads `wintun.dll` at runtime. If the DLL is absent the call fails. Make that failure message say so plainly — a user whose `dpb run --tun` fails should learn that a driver is missing, not read a wrapped Win32 error code.

Do **not** attempt to bundle or download the DLL here. Spec §9 records that its redistribution terms are unverified; that is Plan 6's decision.

- [ ] **Step 4: Verify and commit**

```bash
GOOS=windows go vet ./internal/front/tunfe/
go build ./... && go test ./internal/front/tunfe/
make cover-gate     # tunfe floor is 70
```

---

## Task 3: the last two build gaps

**Files:** Create `internal/testnet/killfuzz_unix.go` + `killfuzz_windows.go`, `internal/cliapp/sysport_windows.go`; modify `internal/cliapp/sysport_other.go`.

- [ ] **Step 1: `testnet/killfuzz.go`**

It uses `syscall.Kill`, which does not exist on Windows. Read what the two call sites are actually doing — this is test scaffolding that kills a spawned process — and split the leaf. On Windows the equivalent is `os.Process.Kill()`; note that `os.Process.Signal` handles **only** `Kill` there, which Plan 2 established the hard way.

Keep the portable body untagged; only the leaf moves.

- [ ] **Step 2: `cliapp/sysport_windows.go`**

`sysport_other.go` currently carries `//go:build !darwin` and returns nil, and its own comment says this file is where Plan 3's `scwindows` gets wired in and that only the body should need to change.

Returning nil is not *broken* today — `netstate.Env.sys()` falls back to `newDefaultPort`, which on Windows now resolves to `scwindows`. But Plan 1 Task 7 wired `Sys` explicitly at the composition root for a reason: **a missing Port should be a compile error, not a runtime default.** So:

- narrow `sysport_other.go` to `!darwin && !windows`, and update its comment — it promises a future that has now arrived
- add `sysport_windows.go` building the real `scwindows` Port, mirroring `sysport_darwin.go`'s shape exactly (read it)

- [ ] **Step 3: Verify and commit**

```bash
GOOS=windows go vet ./internal/testnet/ ./internal/cliapp/
go build ./... && go test ./...
```

---

## Task 4: the routing question Plan 3 uncovered

**Files:** whichever of `internal/front/tunfe/stack.go` and `internal/netstate/op_route.go` the answer requires; tests alongside.

**This task is analysis first and code second. Do not write code until the question is answered.**

`internal/front/tunfe/stack.go` installs a **scoped uplink default** before the capture routes, and its comment says why:

> *The scoped defaults first, and before the datapath starts: they are the routes our own upstream sockets take, and installing the capture routes without them is how a tunnel eats its own resolver traffic.*

On macOS, `RTF_IFSCOPE` makes that a distinct row from the unscoped default. **Windows has no scope flag**, so the row it wants is the row the machine already has, and `CreateIpForwardEntry2` answers `ERROR_OBJECT_ALREADY_EXISTS`.

- [ ] **Step 1: Establish what actually protects our upstream sockets on Windows**

The hypothesis, which you must confirm or refute rather than assume: the capture routes are `0.0.0.0/1` and `128.0.0.0/1`, which are **more specific** than `0.0.0.0/0`. Longest-prefix-match therefore sends our own upstream sockets out of the surviving default anyway — meaning the existing default already *is* the scoped default, and nothing needs installing.

Read `stack.go` to confirm which prefixes are actually installed, and check whether anything else depends on that Op having run (a journal record, a revert step, an adoption decision).

- [ ] **Step 2: Decide, and distinguish the two collisions**

If the hypothesis holds, this is **adoption**: `netstate` already has the machinery, and `canAdopt`'s doc comment describes exactly this — *"was this state already here? answer yes by never touching it again."*

But adoption must not swallow the other collision. A capture route colliding with a **coexisting VPN's** route is a real conflict, and Plan 3 deliberately made `ERROR_OBJECT_ALREADY_EXISTS` an error so that `routeOp.mutated()` stays false and rollback does not delete someone else's route. **Adopting that would be wrong.**

So the decision needs a discriminator: *which* destination collided, and with *what*. Read `routeOp`'s `Apply`, `mutated`, `Revert` and the `adoptChecker` interface before choosing where the distinction lives.

- [ ] **Step 3: Implement the smallest change that expresses the decision**

Prefer a change in `tunfe` (do not install a route Windows does not need) over one in `netstate` (do not change what an error means), if the analysis supports it. Whatever you choose, the reasoning goes in a comment — the next person will meet this and needs the argument, not the conclusion.

- [ ] **Step 4: Test it**

Test the discriminator, not the happy path: a collision that must be adopted and a collision that must stay an error, and the assertion that the second still leaves `mutated()` false.

- [ ] **Step 5: Verify and commit**

---

## Task 5: the gate and CI

- [ ] **Step 1: Measure**

```bash
for p in $(go list ./...); do
  GOOS=windows go build "$p" >/dev/null 2>&1 && echo "OK   $p" || echo "FAIL $p"
done | sort | tee /tmp/xc.txt | uniq -c -w4
grep '^FAIL' /tmp/xc.txt
```

Expected: every package OK **except `internal/sysconf/scdarwin`**, which is darwin-only by design and whose failure is the correct answer. Record the count.

- [ ] **Step 2: CI**

Update `.github/workflows/ci.yml`'s cross-compile step to cover everything except `scdarwin`. Keep it `go list`-driven with the exclusion named and justified in a comment, as the current step is — a step that lists a package which cannot build teaches people to ignore red builds.

- [ ] **Step 3: Full verification and commit**

```bash
go build ./... && go vet ./... && go test ./... -race
gofmt -l cmd internal tools
make cover-gate
GOOS=windows go vet ./...
go mod tidy && git diff --exit-code go.mod go.sum
```

---

## Phase gate

Every item names a package in this plan's File Structure, per the rule Plan 3 established.

- [ ] darwin `go build ./... && go vet ./... && go test ./... -race` green
- [ ] `gofmt -l cmd internal tools` empty
- [ ] `make cover-gate` passes, no floor lowered
- [ ] `go mod tidy` byte-identical, no hand-edited `go.mod`
- [ ] `GOOS=windows go build` clean for `netwatch`, `tunfe`, `testnet`, `cliapp`, `cmd/dpb`
- [ ] `GOOS=windows go build ./...` clean for **every package except `internal/sysconf/scdarwin`**
- [ ] `GOOS=windows go vet ./...` compiles every Windows test file
- [ ] `netwatch` on Windows has a **real** route source — not nil, not a stub
- [ ] `dpb probe --host discord.com --reps 3 --strategy tlsfrag:pos=snimid` still 3/3 PASS on the development machine

**Still not claimed:** no Windows code in this repository has ever run. Plan 5 builds a binary, puts it on Windows 11, and finds out what is actually wrong — including the four items Plan 3 documented for first contact, of which the `HKCU` elevated-hive question is the most likely to bite.
