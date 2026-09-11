# Windows Parity, Plan 2: Portable Primitives

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `flow`, `paths`, `netstate/lock`, `janitor` and `emit` their Windows twins, so those five packages cross-compile and `emit` grants `CapSockTTL | CapOOB | CapUDPTTL` on Windows — which is what makes all four rungs of the Turkey ladder available there.

**Architecture:** Each package keeps its portable logic in the untagged file and moves the platform-bound leaves into `_unix.go` / `_windows.go` twins. No interfaces are introduced; these are syscall leaves, not policy. Plan 1 already proved the shape works — `netstate` is platform-free apart from `lock.go`, which this plan finishes.

**Tech Stack:** Go 1.26.4, `golang.org/x/sys/windows`, stdlib. **No new module dependencies** — every API below was verified present in `golang.org/x/sys@v0.43.0`.

**Spec:** `docs/superpowers/specs/2026-09-07-windows-parity-design.md` (§3.4, §5, §7)

## Global Constraints

- Module path `github.com/mumudevx/dpb`. Go floor `1.26.4`.
- **No new module dependencies.** `go mod tidy` must leave `go.mod`/`go.sum` byte-identical; CI enforces it.
- **No behaviour change on macOS.** Every darwin path must behave exactly as it does today. The full suite runs on darwin and must stay green.
- **No test body may be edited.** Nineteen commits of Plan 1 held this line with zero assertions weakened; hold it. Test *files* may gain a `//go:build` tag or move; assertions may not change.
- Coverage floors (`Makefile`): `internal/front/tunfe` 70, `internal/cliapp` 83, everything else **85**. Never lower one. New packages must be added to `COVER_GATED` and `COVER_GATED_RE`.
- `gofmt -l cmd internal tools` must be empty. This is a CI gate that was missed once in Plan 1 — run it every task.
- Comments explain WHY and cite evidence: a man page, an MSDN contract, a measured behaviour. Do not add comments that restate the code.
- **Windows code cannot be run yet.** It must compile under `GOOS=windows` and be reviewed by reading. Do not claim any Windows path is "tested" — Plan 5 ships the preview that gets it onto a real machine.

---

## Verified API inventory

Checked against `golang.org/x/sys@v0.43.0` before this plan was written. Use these exact names.

| Need | API | Notes |
| --- | --- | --- |
| Exclusive file lock | `windows.LockFileEx` / `windows.UnlockFileEx` | flags `LOCKFILE_EXCLUSIVE_LOCK`, `LOCKFILE_FAIL_IMMEDIATELY` |
| Process handle | `windows.OpenProcess` | access `windows.PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`) |
| Process start time | `windows.GetProcessTimes` | fills a `windows.Filetime` creation time |
| Process identity | `windows.QueryFullProcessImageName` | the `comm=` equivalent |
| Urgent byte | `windows.WSASend` with flag `windows.MSG_OOB` (`0x1`) | **see the trap below** |
| Service context | `golang.org/x/sys/windows/svc`.`IsWindowsService` | for `paths.Layout.System` |

### The trap: `syscall.Sendto` is a stub on Windows

`$GOROOT/src/syscall/syscall_windows.go:1193` reads:

```go
func Sendto(fd Handle, p []byte, flags int, to Sockaddr) (err error) { return EWINDOWS }
```

It is **unimplemented and always fails**. An implementer reaching for the obvious analogue of the darwin `unix.SendmsgN` call gets a function that can never succeed, and `CapOOB` would be granted for a code path that cannot work. Use `windows.WSASend`.

---

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `internal/flow/dialer_unix.go` | `setNoDelay` taking an `int` fd |
| `internal/flow/dialer_windows.go` | `setNoDelay` taking a `syscall.Handle` |
| `internal/paths/paths_unix.go` | the macOS/Unix layout rules, moved |
| `internal/paths/paths_windows.go` | `%APPDATA%` / `%LOCALAPPDATA%` / `%ProgramData%` layout |
| `internal/netstate/lock_unix.go` | `flock`, `SysctlKinfoProc`, the `ps` fallback |
| `internal/netstate/lock_windows.go` | `LockFileEx`, `OpenProcess` + `GetProcessTimes` |
| `internal/janitor/spawn_windows.go` | detached spawn via `CreationFlags` |
| `internal/janitor/wait_windows.go` | `WaitForSingleObject` on a process handle |
| `internal/emit/ttl_windows.go` | `IP_TTL` / `IPV6_UNICAST_HOPS`, default TTL |
| `internal/emit/oob_windows.go` | `WSASend` + `MSG_OOB` |

**Modified:** `internal/flow/dialer.go`, `internal/paths/paths.go`, `internal/netstate/lock.go`, `internal/janitor/{spawn,wait}_darwin.go` (renamed to `_unix`), `internal/emit/stub_other.go` (its build tag narrows).

---

## Task 1: `flow` — the one-line split

**Files:**
- Modify: `internal/flow/dialer.go` (remove `setNoDelay`)
- Create: `internal/flow/dialer_unix.go`, `internal/flow/dialer_windows.go`

**Interfaces:**
- Consumes: nothing
- Produces: `setNoDelay(fd uintptr) error` on both platforms

- [ ] **Step 1: See the current failure**

```bash
GOOS=windows go build ./internal/flow/ 2>&1 | head -3
```

Expected: `cannot use int(fd) (value of type int) as syscall.Handle value`.

- [ ] **Step 2: Move `setNoDelay` out**

Delete it from `internal/flow/dialer.go:213-215`. Create `internal/flow/dialer_unix.go`:

```go
//go:build !windows

package flow

import "syscall"

// setNoDelay disables Nagle. Every desync technique in the ladder depends on
// the segments it writes reaching the wire as separate packets; with Nagle on,
// the kernel would coalesce a fragment with what follows and the split the DPI
// is supposed to see would never exist.
func setNoDelay(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
}
```

Create `internal/flow/dialer_windows.go` — identical but for the handle type:

```go
//go:build windows

package flow

import "syscall"

// setNoDelay disables Nagle; see the comment in dialer_unix.go for why every
// rung depends on it. Winsock's setsockopt takes a Handle rather than an int,
// which is the whole reason this file exists.
func setNoDelay(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
}
```

- [ ] **Step 3: Both platforms build**

```bash
go build ./internal/flow/ && GOOS=windows go build ./internal/flow/ && echo "both OK"
go test ./internal/flow/ 2>&1 | tail -2
```

Expected: `both OK`, tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "$(cat <<'EOF'
fix(flow): Winsock's setsockopt takes a Handle, not an int

One line, one type, and the only thing standing between this package and a
Windows build. The comment about why Nagle must be off travels with it: every
rung in the ladder writes segments that the DPI has to see separately, and a
coalesced write is a split that never happened.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 2: `paths` — the Windows layout

**Files:**
- Modify: `internal/paths/paths.go`
- Create: `internal/paths/paths_unix.go`, `internal/paths/paths_windows.go`
- Test: `internal/paths/paths_windows_test.go` (new)

**Interfaces:**
- Consumes: nothing
- Produces: `paths.Layout` unchanged in shape; `resolve(env) (Layout, error)` per platform

**The reason this package exists does not apply on Windows.** Its comment says "the hard problem it exists to solve is sudo" — root writing files the unprivileged user must later read. UAC elevation keeps the **same user account**, so `%LOCALAPPDATA%` resolves identically elevated or not. Say so in the new file; do not silently port the sudo machinery.

- [ ] **Step 1: Write the failing test**

Create `internal/paths/paths_windows_test.go`:

```go
//go:build windows

package paths

import "testing"

func TestWindowsUserLayout(t *testing.T) {
	got, err := resolve(env{
		getenv: func(k string) string {
			switch k {
			case "APPDATA":
				return `C:\Users\muhsin\AppData\Roaming`
			case "LOCALAPPDATA":
				return `C:\Users\muhsin\AppData\Local`
			}
			return ""
		},
		uid: -1, gid: -1,
	})
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if want := `C:\Users\muhsin\AppData\Roaming\dpb`; got.ConfigDir != want {
		t.Errorf("ConfigDir = %q, want %q", got.ConfigDir, want)
	}
	if want := `C:\Users\muhsin\AppData\Local\dpb`; got.StateDir != want {
		t.Errorf("StateDir = %q, want %q", got.StateDir, want)
	}
	// UID/GID are meaningless on Windows: elevation keeps the same account, so
	// there is no ownership handback for EnsureDirs to perform.
	if got.UID != -1 || got.GID != -1 {
		t.Errorf("UID/GID = %d/%d, want -1/-1", got.UID, got.GID)
	}
}
```

- [ ] **Step 2: Run it under GOOS=windows and watch it fail**

```bash
GOOS=windows go vet ./internal/paths/
```

Expected: failure — `resolve` is not defined for windows yet. (`go test` cannot RUN a windows binary on this host; `go vet` compiles it, which is the check available.)

- [ ] **Step 3: Split the existing implementation**

Move everything in `paths.go` that is Unix-shaped — `ownerOf`, the `SUDO_USER` handling, the `/Library` constants, the current `resolve` — into `internal/paths/paths_unix.go` with `//go:build !windows`. Leave in `paths.go` only what is genuinely portable: the `Layout` struct, its doc comment, the `env` struct, `Resolve()`, and any pure path joining.

- [ ] **Step 4: Write the Windows layout**

Create `internal/paths/paths_windows.go`:

```go
//go:build windows

package paths

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// The problem this package exists to solve — sudo splitting ownership between
// root and the invoking user — has no Windows equivalent. UAC elevation keeps
// the SAME user account, so %LOCALAPPDATA% resolves to one place whether or not
// the process is elevated, and there is no ownership to hand back.
//
// So UID and GID are -1 here and EnsureDirs performs no chown. The one real
// split is service context: a service runs as LocalSystem with no user profile,
// which is the Windows analogue of a launchd daemon and gets the machine-wide
// locations under %ProgramData%.
const (
	systemRootEnv = "ProgramData"
	userRoamEnv   = "APPDATA"
	userLocalEnv  = "LOCALAPPDATA"
)

func resolve(e env) (Layout, error) {
	l := Layout{UID: -1, GID: -1}

	if elevated, err := isElevated(); err == nil {
		l.Elevated = elevated
	}
	// A service has no user profile to write into. svc.IsWindowsService is the
	// authority; an error means "not a service", which is the safe reading for
	// an interactive run.
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		l.System = true
	}

	if l.System {
		root := strings.TrimSpace(e.getenv(systemRootEnv))
		if root == "" {
			return Layout{}, fmt.Errorf("paths: %%%s%% is unset; cannot place machine-wide state", systemRootEnv)
		}
		base := filepath.Join(root, appDir)
		l.User = "SYSTEM"
		l.ConfigDir, l.StateDir = base, base
		l.CacheDir = filepath.Join(base, "cache")
		l.LogDir = filepath.Join(base, "logs")
		return l, nil
	}

	roam := strings.TrimSpace(e.getenv(userRoamEnv))
	local := strings.TrimSpace(e.getenv(userLocalEnv))
	if roam == "" || local == "" {
		return Layout{}, fmt.Errorf("paths: %%APPDATA%% and %%LOCALAPPDATA%% must both be set")
	}
	// Config is roaming because a profile follows the user between machines and
	// a bypass strategy is worth carrying. State, cache and logs are local:
	// a journal describing THIS machine's routes must not roam to another.
	l.ConfigDir = filepath.Join(roam, appDir)
	l.StateDir = filepath.Join(local, appDir)
	l.CacheDir = filepath.Join(local, appDir, "cache")
	l.LogDir = filepath.Join(local, appDir, "logs")
	return l, nil
}
```

Implement `isElevated()` in the same file using `windows.OpenCurrentProcessToken` and the token's elevation query. **Verify the exact method name against `golang.org/x/sys@v0.43.0` before writing it** — if `Token.IsElevated` is not present in this version, use `GetTokenInformation` with `TokenElevation` and say so in a comment.

Ensure `EnsureDirs` skips its chown when `UID == -1`.

- [ ] **Step 5: Both platforms compile, darwin tests still pass**

```bash
go build ./... && GOOS=windows go vet ./internal/paths/
go test ./internal/paths/ -v 2>&1 | tail -3
gofmt -l cmd internal tools
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "$(cat <<'EOF'
feat(paths): a Windows layout, and the reason this package shrinks there

The hard problem paths exists to solve is sudo — root writing files the
invoking user must later read. Windows has no such split: UAC elevation keeps
the same account, so %LOCALAPPDATA% is one place whether elevated or not, and
there is no ownership to hand back. UID and GID are -1 and EnsureDirs does
no chown.

Config roams and state does not, deliberately: a strategy is worth carrying
between machines, a journal describing THIS machine's routes is not.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 3: `netstate/lock` — the last thing keeping netstate off Windows

**Files:**
- Modify: `internal/netstate/lock.go`
- Create: `internal/netstate/lock_unix.go`, `internal/netstate/lock_windows.go`
- Test: `internal/netstate/lock_windows_test.go` (new)

**Interfaces:**
- Consumes: nothing
- Produces: `lockFile(f *os.File) error`, `unlockFile(f *os.File) error`, `ProcessStart(pid int) (time.Time, bool)`, `processIdentity(pid int) (string, bool)`

**This is the single error standing between `internal/netstate` and a Windows build.** Plan 1's gate measured it: `GOOS=linux go build ./internal/netstate/` fails only on `lock.go:209`.

**The PID-reuse defence must be preserved exactly.** The lock record stores a start time, and a live process whose start time differs is a *different* process that inherited the PID. That check is what stops a stale lock from being honoured forever, and it must work identically on Windows — only the source of the start time changes.

- [ ] **Step 1: Write the failing test**

Create `internal/netstate/lock_windows_test.go`:

```go
//go:build windows

package netstate

import (
	"os"
	"testing"
)

// A second acquire must fail while the first is held. LockFileEx with
// LOCKFILE_FAIL_IMMEDIATELY is the Windows analogue of flock(LOCK_EX|LOCK_NB);
// without FAIL_IMMEDIATELY it blocks forever instead of reporting contention.
func TestLockIsExclusive(t *testing.T) {
	path := t.TempDir() + `\dpb.lock`
	f1, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f1.Close()
	if err := lockFile(f1); err != nil {
		t.Fatalf("first lockFile() = %v, want nil", err)
	}

	f2, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer f2.Close()
	if err := lockFile(f2); err == nil {
		t.Fatal("second lockFile() = nil, want a contention error")
	}

	if err := unlockFile(f1); err != nil {
		t.Fatalf("unlockFile() = %v", err)
	}
	if err := lockFile(f2); err != nil {
		t.Fatalf("lockFile() after release = %v, want nil", err)
	}
	_ = unlockFile(f2)
}

// Our own PID must report a start time, and a PID that cannot exist must not.
func TestProcessStartAnswersForOurselves(t *testing.T) {
	if _, ok := ProcessStart(os.Getpid()); !ok {
		t.Error("ProcessStart(self) reported no start time")
	}
	if _, ok := ProcessStart(-1); ok {
		t.Error("ProcessStart(-1) reported a start time for an impossible pid")
	}
}
```

- [ ] **Step 2: Compile it and watch it fail**

```bash
GOOS=windows go vet ./internal/netstate/
```

Expected: `undefined: lockFile`, `undefined: unlockFile`.

- [ ] **Step 3: Extract the Unix leaves**

Create `internal/netstate/lock_unix.go` with `//go:build !windows`, holding `lockFile`/`unlockFile` wrapping `unix.Flock`, plus `psRunner`, `kernelProcessStart`, `psInfo` and `ProcessStart` exactly as they are today — **including the `LC_ALL=C` pin and its comment**, which exists because `ps` output changes shape under a Turkish locale and once made a live dpb look dead.

Replace the inline `unix.Flock` calls in `lock.go` (lines 68, 82, 150) with `lockFile`/`unlockFile`, and delete the Unix-only declarations from it. `lock.go` keeps the record format, the rename-based swap and the staleness policy.

- [ ] **Step 4: Write the Windows leaves**

Create `internal/netstate/lock_windows.go`:

```go
//go:build windows

package netstate

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive, non-blocking lock on the whole file.
//
// LOCKFILE_FAIL_IMMEDIATELY is not optional: without it LockFileEx BLOCKS until
// the holder releases, and `dpb status` would hang behind a running dpb instead
// of reporting that one is running. That is the same contract flock's LOCK_NB
// gives on the Unix side.
//
// The range is the maximum 64-bit length rather than the file's current size,
// because the record is rewritten and a lock over "the first N bytes" would
// stop covering the file the moment it grew.
func lockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, ^uint32(0), ^uint32(0), ol)
	if err != nil {
		return fmt.Errorf("netstate: lock %s: %w", f.Name(), err)
	}
	return nil
}

func unlockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), ol); err != nil {
		return fmt.Errorf("netstate: unlock %s: %w", f.Name(), err)
	}
	return nil
}

// ProcessStart reports when the process holding pid started.
//
// It exists for one reason: PID reuse. A lock record naming a dead process
// whose PID has been recycled must not be honoured, and comparing the recorded
// start time against the live one is what tells those apart. The Unix side
// reads it from a sysctl; here it comes from the kernel's own creation
// timestamp, so no external command is involved at all — which removes the
// entire class of bug the LC_ALL=C pin on the Unix side exists to prevent.
//
// PROCESS_QUERY_LIMITED_INFORMATION is deliberately the narrowest access that
// answers the question: it works across integrity levels, where
// PROCESS_QUERY_INFORMATION would be refused for a process we do not own.
func ProcessStart(pid int) (time.Time, bool) {
	if pid <= 0 {
		return time.Time{}, false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return time.Time{}, false
	}
	defer windows.CloseHandle(h)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, creation.Nanoseconds()), true
}
```

Add a `processIdentity(pid int) (string, bool)` using `windows.QueryFullProcessImageName` if `lock.go`'s portable half needs the `comm=` equivalent; if it does not, do not add it.

**Do not write a stub that always answers "dead".** A `ProcessStart` that reports every process as gone would make `Replay` revert a *running* dpb — tearing down a live user's proxy and routes. If any part of this cannot be implemented, return `false` only for the specific unanswerable case and report the rest.

- [ ] **Step 5: The gate this task exists to move**

```bash
GOOS=windows go vet ./internal/netstate/
GOOS=linux go build ./internal/netstate/
go test ./internal/netstate/ 2>&1 | tail -2
gofmt -l cmd internal tools
```

Expected: the `GOOS=windows` vet now fails only on the absent `port_windows.go` (Plan 3's scope) or passes outright; `GOOS=linux` build **succeeds**; darwin tests green.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "$(cat <<'EOF'
feat(netstate): the run lock learns Windows, and stops shelling out entirely

flock becomes LockFileEx with LOCKFILE_FAIL_IMMEDIATELY — not optional, since
without it the call blocks until the holder releases and `dpb status` would
hang behind a running dpb instead of reporting one.

The PID-reuse defence is preserved exactly; only the source of the start time
changes. On Unix it is a sysctl with a ps fallback pinned to LC_ALL=C, because
ps reorders its columns under a Turkish locale and once made a live dpb look
dead. Windows reads the kernel's creation timestamp through GetProcessTimes and
runs no external command at all, so that entire class of bug cannot occur there.

This was the last darwin-only line in netstate: GOOS=linux now builds it clean.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 4: `janitor` — detached spawn and process wait

**Files:**
- Rename: `internal/janitor/spawn_darwin.go` → `spawn_unix.go`, `wait_darwin.go` → `wait_unix.go` (tags become `!windows`)
- Create: `internal/janitor/spawn_windows.go`, `internal/janitor/wait_windows.go`
- Rename: the matching `_darwin_test.go` files to `_unix_test.go`, changing only the build tag

**Interfaces:**
- Consumes: nothing
- Produces: `detachAttrs() *syscall.SysProcAttr`, `WaitForExit(ctx context.Context, pid int) error`

The janitor is the process that cleans up if dpb dies without reverting. Two things are platform-bound: how a child detaches from its parent, and how you wait for a process you did not spawn.

- [ ] **Step 1: Rename the darwin files and narrow their tags**

```bash
git mv internal/janitor/spawn_darwin.go internal/janitor/spawn_unix.go
git mv internal/janitor/wait_darwin.go internal/janitor/wait_unix.go
```

Add `//go:build !windows` to each (they currently carry no tag and rely on the filename). Do the same for their `_test.go` files. Extract the `cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}` line from `Spawn` into a `detachAttrs()` helper in `spawn_unix.go`, and have `Spawn` call it — `Spawn` itself is portable.

- [ ] **Step 2: Write the Windows spawn attrs**

Create `internal/janitor/spawn_windows.go`:

```go
//go:build windows

package janitor

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachAttrs makes the janitor outlive the dpb that spawned it.
//
// Setsid is the Unix mechanism; Windows has two flags and needs both.
// DETACHED_PROCESS gives the child no console, so closing the terminal that
// started dpb does not take the janitor with it. CREATE_NEW_PROCESS_GROUP stops
// a Ctrl-C in that terminal from being delivered to the janitor — which matters
// precisely because Ctrl-C is the case the janitor exists to clean up after.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
}
```

- [ ] **Step 3: Write the Windows wait**

Create `internal/janitor/wait_windows.go` implementing `WaitForExit(ctx, pid)` with `windows.OpenProcess(windows.SYNCHRONIZE, ...)` plus `windows.WaitForSingleObject`. Honour `ctx`: wait in bounded slices (a second at a time) and check `ctx.Err()` between them, rather than passing `INFINITE` and becoming uncancellable. A process that has already exited — `OpenProcess` failing with `ERROR_INVALID_PARAMETER` — is not an error; it is the answer, and the Unix side treats it the same way.

Match `wait_unix.go`'s exact error semantics for an already-dead process. Read it first.

- [ ] **Step 4: Both platforms**

```bash
go build ./... && GOOS=windows go vet ./internal/janitor/
go test ./internal/janitor/ 2>&1 | tail -2
gofmt -l cmd internal tools
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "$(cat <<'EOF'
feat(janitor): detach and wait, the Windows way

Setsid becomes DETACHED_PROCESS plus CREATE_NEW_PROCESS_GROUP, and both are
needed: the first keeps the janitor alive when the terminal closes, the second
keeps a Ctrl-C in that terminal from reaching it — which is exactly the case
the janitor exists to clean up after.

kqueue's NOTE_EXIT becomes WaitForSingleObject on a SYNCHRONIZE handle, sliced
so the context stays cancellable rather than passing INFINITE. A process that
has already exited is the answer, not an error, on both sides.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 5: `emit` — the capabilities that make the Turkey ladder work

**Files:**
- Create: `internal/emit/ttl_windows.go`, `internal/emit/oob_windows.go`
- Modify: `internal/emit/stub_other.go` (tag narrows to `!darwin && !windows`)
- Test: `internal/emit/caps_windows_test.go` (new)

**Interfaces:**
- Consumes: `strategy.Cap`
- Produces: `sockTTLCaps`, `oobCaps`, `DefaultTTL()`, `defaultHopLimit(bool)`, `setHopLimit(syscall.RawConn, bool, int)`, `getHopLimit(syscall.RawConn, bool)`, `sendOOB(syscall.RawConn, []byte)`

**This task is why Plan 2 matters.** Three of the four rungs in `turkey.toml` need only `CapStreamWrite`+`CapNoDelay`, but `oob:pos=1` needs `CapOOB`, and the ladder's own documentation treats it as the last rung that works. Granting these correctly is what makes the measured Turkey profile available on Windows at all.

- [ ] **Step 1: Write the failing capability test**

Create `internal/emit/caps_windows_test.go`:

```go
//go:build windows

package emit

import (
	"testing"

	"github.com/mumudevx/dpb/internal/strategy"
)

// The Turkey ladder's last rung is oob:pos=1 and its TTL rungs need IP_TTL.
// If either capability is withheld on Windows, a strategy that measured as
// working is silently downgraded — the exact failure stub_other.go's comment
// warns about.
func TestWindowsGrantsTheLadderCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  strategy.Cap
		want strategy.Cap
	}{
		{"sockTTL", sockTTLCaps, strategy.CapSockTTL},
		{"udpTTL", sockTTLCaps, strategy.CapUDPTTL},
		{"oob", oobCaps, strategy.CapOOB},
	} {
		if !tc.got.Has(tc.want) {
			t.Errorf("%s: caps %v lack %v", tc.name, tc.got, tc.want)
		}
	}
}

// A hardcoded 64 is what DOSSIER §3 warns against, and Windows defaults to 128
// rather than 64 — so a guess here is wrong on every Windows machine.
func TestWindowsDefaultTTLIsRead(t *testing.T) {
	n, err := DefaultTTL()
	if err != nil {
		t.Fatalf("DefaultTTL() error = %v", err)
	}
	if n <= 0 || n > 255 {
		t.Errorf("DefaultTTL() = %d, want a plausible hop limit", n)
	}
}
```

- [ ] **Step 2: Compile and watch it fail**

```bash
GOOS=windows go vet ./internal/emit/
```

Expected: the stub's `sockTTLCaps = 0` makes the test's intent unmet, and once the tag narrows, `undefined` errors.

- [ ] **Step 3: Narrow the stub's build tag**

`internal/emit/stub_other.go` becomes `//go:build !darwin && !windows`. Its comment says dpb "ships for darwin only" — update that sentence to name both platforms, and keep the paragraph explaining why a withheld capability must carry a reason. That paragraph is the design rule this whole plan follows.

- [ ] **Step 4: Write `ttl_windows.go`**

Mirror `ttl_darwin.go`'s structure. Key differences to get right, each with a comment:

- **`setHopLimit`/`getHopLimit`** use `syscall.SetsockoptInt`/`GetsockoptInt` with a `syscall.Handle`, level `IPPROTO_IP` option `IP_TTL` for v4, and `IPPROTO_IPV6` option `IPV6_UNICAST_HOPS` for v6. Go through `rc.Control`, matching the darwin file.
- **`DefaultTTL`** has no sysctl. Read it from the socket instead: open a throwaway UDP socket and `getsockopt(IP_TTL)` — the value the kernel puts on a fresh socket *is* the machine's default. This needs no new API and no registry read, and it answers the same question `net.inet.ip.ttl` answers on macOS. Cache it with a `sync.Once` exactly as the darwin file does, and say in the comment that Windows's default is 128 where macOS's is 64, so hardcoding would be wrong on every machine.
- `defaultHopLimit(v6 bool)` follows the darwin shape, falling back to the v4 value when the v6 read fails.

- [ ] **Step 5: Write `oob_windows.go`**

```go
//go:build windows

package emit

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/strategy"
)

// oobCaps: Winsock implements MSG_OOB, so the last rung of the measured Turkey
// ladder is available here. Whether it performs the same against Türk Telekom's
// DPI from a Windows TCP stack is unmeasured — see docs/MEASUREMENTS.md §4 and
// Plan 6, which re-measures rather than assuming.
const oobCaps = strategy.CapOOB

// sendOOB writes b as TCP urgent data.
//
// It uses WSASend and NOT syscall.Sendto: on Windows, Sendto is a stub that
// returns EWINDOWS unconditionally (see $GOROOT/src/syscall/syscall_windows.go).
// Reaching for the obvious analogue of the darwin unix.SendmsgN call would grant
// CapOOB for a code path that can never succeed.
func sendOOB(rc syscall.RawConn, b []byte) (int, error) {
	if rc == nil {
		return 0, fmt.Errorf("emit: send MSG_OOB: no raw conn")
	}
	if len(b) == 0 {
		return 0, fmt.Errorf("emit: send MSG_OOB: empty urgent byte")
	}
	var (
		sent  uint32
		opErr error
	)
	if err := rc.Control(func(fd uintptr) {
		buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
		opErr = windows.WSASend(windows.Handle(fd), &buf, 1, &sent, windows.MSG_OOB, nil, nil)
	}); err != nil {
		return 0, fmt.Errorf("emit: send MSG_OOB: %w", err)
	}
	if opErr != nil {
		return int(sent), fmt.Errorf("emit: send MSG_OOB: %w", opErr)
	}
	return int(sent), nil
}
```

Note in a comment why this uses `rc.Control` rather than `rc.Write`: the darwin file uses `Write` to get the poller's "wake me when writable" contract for `EAGAIN`, and if the same handling is achievable here, prefer `Write` and match it. **Decide deliberately and say which you chose and why** — a blocking Winsock socket does not return `WSAEWOULDBLOCK` the way a non-blocking Unix socket returns `EAGAIN`, so the two are not automatically equivalent.

- [ ] **Step 6: Verify the capabilities are actually granted**

```bash
GOOS=windows go vet ./internal/emit/
go build ./... && go test ./internal/emit/ 2>&1 | tail -2
gofmt -l cmd internal tools
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "$(cat <<'EOF'
feat(emit): Windows grants the capabilities the Turkey ladder needs

CapSockTTL, CapUDPTTL and CapOOB are all reachable on Winsock, so all four
measured rungs are available. Whether they perform the same from a Windows TCP
stack is unmeasured and is Plan 6's question, not an assumption made here.

Two things worth knowing. syscall.Sendto is a STUB on Windows that returns
EWINDOWS unconditionally, so MSG_OOB goes through WSASend — reaching for the
obvious analogue of the darwin call would grant CapOOB for a path that can never
succeed. And DefaultTTL is read from a fresh socket rather than guessed: Windows
defaults to 128 where macOS defaults to 64, so the hardcoded 64 DOSSIER §3 warns
against would be wrong on every Windows machine.

stub_other.go narrows to !darwin && !windows and keeps its rule intact: a
capability that is absent must say so by name and with a reason.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Task 6: Prove the gate and record the number

**Files:**
- Modify: `.github/workflows/ci.yml` (add a cross-compile step)

- [ ] **Step 1: Measure the cross-compile count**

```bash
for p in $(go list ./...); do
  GOOS=windows go build "$p" >/dev/null 2>&1 && echo "OK $p" || echo "FAIL $p"
done | sort | tee /tmp/xc.txt | uniq -c -w4
grep '^FAIL' /tmp/xc.txt
```

Plan 1 ended at **12 of 25**. Record the new count and name every remaining failure. Expect the survivors to be `netstate` (needs `port_windows.go`, Plan 3), `scdarwin` (darwin-tagged by design, correct), and whatever imports them transitively.

- [ ] **Step 2: Add the cross-compile check to CI**

In `.github/workflows/ci.yml`, after the `vet` step, add:

```yaml
      - name: cross-compile check (windows)
        run: GOOS=windows go build ./internal/flow/ ./internal/paths/ ./internal/janitor/ ./internal/emit/ ./internal/sysport/ ./internal/strategy/ ./internal/policy/ ./internal/ops/
```

List exactly the packages that pass at the end of this plan — no more. A step that lists a package which cannot build yet is a red CI that teaches people to ignore CI. Widen the list in later plans as packages land.

- [ ] **Step 3: Full verification**

```bash
go build ./... && go vet ./... && go test ./... -race 2>&1 | tail -3
gofmt -l cmd internal tools
make cover-gate
GOOS=linux go build ./internal/netstate/
```

Expected: all green, and the `GOOS=linux` netstate build now **succeeds** — the thing Plan 1's gate could not reach.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "$(cat <<'EOF'
ci: check the packages that actually cross-compile, and only those

The list names exactly what builds for windows at the end of this plan. A CI
step that lists a package which cannot build yet is a red build that teaches
people to ignore red builds; the list widens as later plans land.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Cc8HxT1TC4hgjKd5MXAW82
EOF
)"
```

---

## Phase gate

- [ ] `go build ./... && go vet ./... && go test ./... -race` green on darwin
- [ ] `gofmt -l cmd internal tools` empty
- [ ] `make cover-gate` passes, no floor lowered
- [ ] `go mod tidy` leaves `go.mod`/`go.sum` byte-identical
- [ ] **`GOOS=linux go build ./internal/netstate/` succeeds** — Plan 1 could not reach this; `lock.go` was the only thing left
- [ ] `GOOS=windows go build` succeeds for `flow`, `paths`, `janitor`, `emit`
- [ ] `emit` grants `CapSockTTL | CapUDPTTL | CapOOB` under `GOOS=windows`
- [ ] `dpb probe --host discord.com --reps 3 --strategy tlsfrag:pos=snimid` still gives 3/3 PASS on the development machine

The last one is the one no test can give. Run it.

**Not in this plan:** no Windows code here has ever executed. It compiles and it has been read. Plan 5 puts it on a real machine; until then, no claim beyond "it builds" is honest.
