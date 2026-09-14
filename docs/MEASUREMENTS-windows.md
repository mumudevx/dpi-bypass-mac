# Windows measurements

**No Windows measurement exists yet.** Nothing in this repository has run on a Windows machine.

The ladder in `internal/config/embed/turkey.toml` was measured on **macOS** (Türk Telekom AS9121, Kayseri, 2026-09-02). Windows has a different TCP stack; those numbers do not transfer.

## What would establish a Windows measurement

- A Windows 11 machine on a live censored line (Türk Telekom or equivalent).
- Running `dpb tune` on that machine to measure the same block and emitters.
- The resulting ladder, stored and committed the same way the macOS numbers are.

Until that happens, every emitter choice on Windows is unverified. Use the first `-windows-preview` release as a release candidate, not a verified install. Read "Reporting a result" in the main README before filing an issue.

## What running the code for the first time revealed (2026-09-14, CI, not a ladder measurement)

Plans 1-5 built Windows support entirely by compiling and reading. The
`windows-latest` CI job added in this plan's Task 1 is the first time any of
it has executed. It found two things before a single test ran:

- **No `.gitattributes` existed.** `actions/checkout` on Windows applies Git
  for Windows' default `core.autocrlf=true`, so every tracked text file
  arrived CRLF and `gofmt -l` flagged all 449 `.go` files under
  `cmd`/`internal`/`tools`. This was a repository hygiene gap, not a code
  defect — fixed by adding `.gitattributes` (`* text=auto eol=lf`, with the
  three `internal/tlsmsg/testdata/*.bin` fixtures marked `binary`).
- Once checkout was fixed, `gofmt`, `go build ./...`, and `go vet ./...` all
  passed clean on Windows. `go test ./...` did not: 9 of 25 tested packages
  failed, 44 failing test cases in total. That is the real finding of this
  exercise — a representative sample, triaged below into what actually
  needs fixing, what the test suite got wrong about the platform, and what
  the CI machine itself cannot supply.

**Real defects in the Windows implementation (code, not tests):**

- `internal/netstate/journal.go` opens the journal with `os.O_APPEND`, then
  later calls `(*os.File).Truncate` on that same handle to heal a torn line
  or close a replayed entry. On Windows, `O_APPEND` grants only
  `FILE_APPEND_DATA`, not the `FILE_WRITE_DATA` access `SetEndOfFile`
  (what `Truncate` calls) needs — so every truncate on this handle fails
  with "Access is denied," even though it is the process's own file. This is
  the journal — the mechanism the whole project relies on to guarantee
  nothing is left half-applied on a machine — and on Windows today it cannot
  heal or close itself. It surfaced through 12 different tests across
  `internal/netstate`, `internal/janitor`, and `internal/cliapp`'s doctor
  `--repair` and tun-teardown paths.
- `internal/observ/client.go`'s dial classifies "nothing is listening" via
  `errors.Is(err, syscall.ECONNREFUSED)`. On Windows, `syscall.ECONNREFUSED`
  is a synthetic constant Go defines for its own emulated syscalls
  (`APPLICATION_ERROR + offset`), not the real Winsock `WSAECONNREFUSED`
  (10061) a genuinely refused connection returns — so the check never
  matches, and every "no dpb is running" command path (`coverage --fix`,
  `off`, `panic`, `_janitor`) fails to name that condition.
- `internal/sysconf/scwindows/proxy.go`'s `formatProxyServer` does not fully
  expand a bare (all-schemes) proxy token once one of its schemes has been
  given a different explicit value, producing
  `"https=127.0.0.1:8080;user.example:3128"` instead of the fully expanded
  `"http=user.example:3128;https=127.0.0.1:8080;ftp=user.example:3128"`.
- `os.Chmod(0o600)` does not privatize a file on Windows — there are no POSIX
  permission bits to set, so `os.Chmod` there only toggles the read-only
  attribute and the file ends up mode 0666. The tuned-profile file
  (`internal/config/tuned.go`) and the control socket
  (`internal/observ/control.go`) both rely on this call for a "this user
  only" guarantee that Windows silently does not provide; a real
  implementation needs a Windows ACL, not a chmod call.
- `internal/cliapp/coverage.go` hardcodes "Safari, Chrome, Electron apps,
  anything on CFNetwork" as the description of what the system-proxy
  mechanism covers, unconditionally — including when built for Windows,
  where none of those are the right answer.
- `internal/policy`'s atomic store (`fileStore.Flush`, write-temp-then-rename)
  is not safe under concurrent writers on Windows: `TestStoreIsConcurrencySafe`
  hit repeated "Access is denied" renaming over the destination file. POSIX
  `rename()` succeeds unconditionally even over open handles; Windows'
  rename does not.
- `internal/testnet`'s kill/exit classification (`killfuzz.go`) already
  carries a comment acknowledging this: `syscall.WaitStatus.Signaled()` is
  hardcoded `false` on Windows, so the fuzzer can never report a process as
  "killed" there, only "exited" — a real, pre-existing, self-documented gap
  in what Windows can currently tell apart, not a hidden one.

**Tests that encode a macOS assumption (test problem, not a Windows code
problem):**

- `internal/cliapp/m12harness_test.go` wires every `cliapp` command test —
  `doctor`, `coverage`, `off`, `panic`, `_janitor` — to a fake **macOS**
  system unconditionally (`fakeMac` driving `networksetup`/`launchctl`, and
  hardcoded `netstate.Facts{Uplink: "en0", Services: []string{"Wi-Fi"}}`).
  There is no Windows counterpart, so on Windows a test that seeds state via
  `c.mac.Run(t.Context(), "networksetup", ...)` seeds a tool with no bearing
  on what the Windows proxy/DNS code actually reads. This is the single
  biggest test-infrastructure gap the run exposed: `internal/cliapp`'s
  command-level suite has never actually exercised the Windows proxy/DNS
  code paths — it needs a Windows-flavored harness before its results mean
  anything on this platform.
- `internal/cliapp/tunrun_test.go` bakes in BSD/macOS conventions
  throughout — the loopback name `lo0`, tunnel device names like `utun7`,
  and an assertion that `--tun-name` should default to the literal `"utun"`
  so the kernel auto-numbers the unit. Wintun has no such auto-numbering; it
  always needs a concrete adapter name, so the actual default (`"dpb"`)
  looks like the *intended* Windows behavior, not a bug the test caught.
- `internal/netstate/runner_test.go`'s `TestExecRunner` shells out to the
  hardcoded path `/bin/echo`, which does not exist on Windows.
- `internal/netstate/rib_test.go`'s `TestLiveRIBReadableUnprivileged` looks
  up a route by the BSD interface name `lo0`; the live RIB read itself
  succeeded (26 real routes), the lookup just used the wrong platform's name
  for loopback.

**CI environment limitations (the machine, not the code):**

- `dpb doctor`'s "wintun driver" check correctly reports FAIL, because no
  GitHub-hosted Windows runner has wintun.dll installed. That single check
  makes `doctor`'s exit code non-zero on every invocation, which is why
  several "clean machine" doctor tests failed even though nothing in their
  actual scenario was broken — the check was doing its job.
- One test, `internal/flow`'s `TestLadderObservesTheDialledAddress`, failed
  once on `windows-latest` but passed 8/8 times locally on darwin (isolated
  and full-package, with and without repetition). The transport under test
  is a pure in-memory fake with no real OS calls, so this could not be
  attributed to a Windows API difference by reading the source. It is left
  unresolved rather than force-fit into a category — it needs a second
  Windows run (ideally `-count=20` on just that test) before anyone spends
  fix effort on it.

None of the above was fixed in the pass that produced it — Task 2 of this
plan's brief was to produce and triage the list, not to close it out; that
was deliberate, so the fix work happened with the categorization already
agreed rather than conflated with it. The next section records what the fix
pass then did, and what the same job measured afterwards.

## What fixing the real defects changed (2026-09-14, same day, second Windows run)

Six of the seven Category-1 items above were fixed; the seventh turned out not
to be a code defect. **Windows test failures went from 44 to 27, and failing
packages from 9 to 7** — `internal/policy` and `internal/testnet` are green on
Windows for the first time. The darwin suite was unchanged: 2367 tests in 25
packages before and after, `make cover-gate` passing with no floor touched. Full
per-defect reasoning is in
`.superpowers/sdd/2026-09-14-windows-parity-06-ci-distribution-measurement/task-2b-report.md`.

What each fix actually was, in one line, because the shape matters more than
the count:

- **The journal** truncates through a second, short-lived handle. `O_APPEND` is
  NOT dropped: it is the guarantee that two dpb processes appending to the same
  journal cannot overwrite each other's records, and the extra handle never
  writes file data, so it cannot weld a fragment to a record. 11 failures.
- **`syscall.ECONNREFUSED` → `windows.WSAECONNREFUSED`**, behind a platform
  leaf. A second thing was measured on the way: Windows' AF_UNIX reports a
  MISSING socket path as `WSAECONNREFUSED` too, so the `os.ErrNotExist` branch
  beside it is never reached there and this one errno carries both halves of
  "not running". 5 failures.
- **`os.Chmod(0o600)` → a real protected Windows DACL** (`paths.RestrictToOwner`),
  one ACE for the process's own token SID. Two limits are now stated in the code
  rather than implied: `os.Stat().Mode().Perm()` still reports 0666 on Windows
  afterwards, because Go derives that from file attributes and nothing else, so
  the mode is not evidence of anything there; and for the control socket, what
  the DACL gates is who may OPEN the socket file — whether AFD also consults it
  on connect cannot be demonstrated on a single-account runner. Cleared no test,
  because both tests assert a POSIX mode Windows cannot produce.
- **`internal/policy`'s rename** retries the two transient Windows sharing
  errors. `MoveFileEx` must open the destination to replace it and POSIX
  `rename(2)` need not; 7 of 400 concurrent flushes were losing verdicts. This
  is also the well-known Defender/indexer failure for write-temp-then-rename, so
  it is a desktop problem and not only a test one.
- **`internal/testnet`** can now tell a kill from an exit on Windows, by
  `TerminateProcess`'s exit code. The self-documented note it already carried
  was accurate but not sufficient: a kill-fuzz report reading
  `{Killed:0 Exited:3}` for a child killed three times says the crash window was
  never explored, so the crash-safety that fuzzer exists to prove was quietly
  unproven on Windows.
- **`dpb coverage`** no longer tells a Windows user that the proxy pane covers
  "Safari, anything on CFNetwork" and that the environment lever is launchd's.
  The Windows mechanism genuinely is a different one — `HKCU\Environment`, per
  `internal/sysconf/scwindows/env.go`.
- **`scwindows`'s bare-proxy emit was NOT changed.** Judged on evidence, the
  code is right and `TestSetManualExpandsABareProxy`'s expected string is wrong:
  two other tests in the same file pin the opposite shape and passed on Windows,
  no principled rule can satisfy both, and expanding the bare token would break
  the byte-identical revert the package is built for — permanently unticking the
  user's "use the same proxy server for all protocols" and dropping the proxy for
  every scheme `bareProxySchemes` does not model.

### The most useful thing the second run said

One test, `internal/janitor`'s `TestReplayReportsAFailedRevert`, PASSED before
these fixes and FAILS after them — and it is not a regression. It makes a revert
fail with `os.Chmod(dir, 0o500)`, which on Windows does not stop a file inside
being deleted, so its premise never held; it reported the one failure it checks
for only because the journal close afterwards died on the truncate defect. The
count was right and the reason was the bug. Fixing the defect is what made the
test's own POSIX assumption visible, which is a thing no amount of reading finds.

Two further attributions in the triage above were corrected by re-reading the
log rather than trusting it: `TestReplayReportsAnUnopenableJournal` is the same
`0o500` assumption and not the journal defect, and `doctor --repair`'s two tests
hit the journal defect AND the missing wintun driver, so they still fail on the
latter alone.

### The unresolved one now has its second data point

`internal/flow`'s `TestLadderObservesTheDialledAddress` — left uncategorised
above pending a second Windows run — failed again: **2 of 2 on
`windows-latest`, against 8 of 8 passing on darwin.** It is reproducible on
Windows, not flaky, so it now deserves a real investigation. It is still not a
Windows-API defect of the kind this pass fixed: the transport under test is a
pure in-memory fake that makes no OS calls at all, so whatever is different
about Windows here is somewhere the source does not say.

### One gap found while fixing, larger than any of the above

`dpb coverage`'s second half — the one its own doc calls "the only one that is
evidence" — shells out to `lsof`, which does not exist on Windows. It fails
loudly (the exec error becomes a `note:` line in the report) rather than
silently, which is why it was not fixed here, but "which processes are actually
connected to dpb" does not work on Windows at all. Replacing it needs a Windows
connection-table reader — `GetExtendedTcpTable`, which
`internal/sysconf/scwindows/iphlp.go` already has the shape for.

## What the harness was actually reading (2026-09-14, third Windows run)

27 failures became 1, and 7 failing packages became 1: every package except
`internal/sysconf/scwindows` is green on `windows-latest` for the first time.
The number is not the finding; what the remaining
Category 2 pass had to discover to get there is.

### The command tests were reading the runner, not the fixture

`internal/cliapp`'s harness injects a `netstate.Runner`. On darwin that IS the
platform — `scdarwin` reaches the system by *running* `networksetup`, `scutil`
and `launchctl`, so `fakeMac` substitutes for the whole OS. `scwindows` calls
advapi32, winhttp.dll and iphlpapi directly and takes a Runner only for
`netsh`, whose exit status alone it consults.

So the Windows runs of those tests were never "passing against a fake macOS".
They were reading — and on the write paths mutating — **the CI runner's own
registry hive**, and reporting "no system proxy is set" whatever the test had
just set up. `scwindows` has real tests; the command layer above it had none
that ran here at all.

`harnessPort` is a `sysport.Port` over the same `fakeMac` state, injected on
Windows only. Fifteen test functions and two subtests went from testing nothing
to testing the Windows build of `dpb doctor` and `dpb coverage`, platform leaves
included.

### The unresolved `internal/flow` failure was the clock

`TestLadderObservesTheDialledAddress` — uncategorised in the first triage,
reproducible 2 of 2 in the second, "somewhere the source does not say" — is Go's
monotonic clock on windows/amd64. It reads the interrupt time out of
`KUSER_SHARED_DATA`, whose granularity is the system timer tick: **15.6 ms by
default**, 1 ms if something on the machine has raised it.

A first response arriving inside one tick therefore measures as **exactly
zero**, and `RTTTracker.Observe` discards non-positive samples — a guard written
for a clock that went *backwards*. The destination is never learned, `Known()`
stays false, and the adaptive response window never engages. §6 above puts a
successful desynced handshake on the measured line at ~23 ms, the same order as
the tick, so **a large share of real Windows responses would have read as zero
and been thrown away.** That is a live product defect, not a test artefact, and
it was invisible on darwin where the reading is nanosecond-grained.

The direct measurement of the tick came from a different test in the same run:
`TestTunTeardownRevertsBeforeTheDeviceCloses` printed two `time.Now()` values
taken at different moments as byte-identical, monotonic reading included —
`m=+11.619999501` on both sides of an `After()` comparison — and reported
teardown in the wrong order.

Both are fixed at the measurement site: a sample the clock was too coarse to
time now says "faster than this clock can see" rather than "no sample".

### `dpb doctor` on Windows answers about the machine it runs on

Six of the eight doctor failures were one fact: a GitHub-hosted runner has no
`wintun.dll`, `checkWintun()` calls `LoadLibraryEx` on the real machine, and
there was no seam. A test that set up a clean machine and asked `dpb doctor`
whether it was clean got an answer about the runner's driver inventory —
`rep.Failed` 1 where it wanted 0, exit 3 where it wanted 0, and `--quiet`
printing a remedy on a machine with nothing wrong with it.

Worth keeping in mind beyond the test: on any Windows machine without the
driver, `dpb doctor` exits 3. That is correct for a `--tun` user and arguably
loud for a proxy-only one; the remedy line says "proxy mode does not need it",
which is the mitigation actually shipped.

### `paths.RestrictToOwner` had no test on either platform

The two `Mode().Perm() == 0600` assertions the second run caught (the tuned
profile and the control socket) were testing `RestrictToOwner` without being
able to see it: Go derives `Mode().Perm()` from the file ATTRIBUTES, so it
reports 0666 on Windows however tight the DACL is. Those two assertions are now
`!windows`, and the function they were about has its first test — reading the
security descriptor back and asserting the DACL is the file's own, holds exactly
one entry, and is PROTECTED, which is the half that does the work.

### The bare-proxy disagreement is settled, and still not fixed

`TestSetManualExpandsABareProxy` is the one failure left on the whole job, and the git history
says which side is wrong. `23d165c` introduced the test; the later `e9ac983`
introduced `proxyEntry.Bare` and a table case in the same file asserting the
OPPOSITE shape for an input of the same form, because re-emitting an expanded
bare token "silently narrow[s] 'same proxy for all protocols' down to three" —
it was fixing a Critical. The code is right. The test asserts the narrowing the
fix removed, and nobody noticed because the Windows suite had never run. It
should be deleted; the property it names is already covered by that table case.

## What CI still cannot tell you

Every result above came from a GitHub-hosted `windows-latest` runner. That
machine is not a desktop, and several things this project depends on cannot
be exercised there at all:

- **No interactive session.** Nothing that requires a logged-in desktop
  session (the Explorer shell, a visible tray icon, a UAC prompt a human
  answers) has ever run.
- **No wintun driver.** `--tun` mode — the actual DPI-bypass path on
  Windows — has never opened a real adapter, sent a real packet, or torn one
  down under real conditions. Everything gated on wintun's absence (the
  doctor check, `internal/front/tunfe`'s Windows link path) has only ever
  been told "it's missing," never exercised as present.
- **No Administrator.** Every "requires elevation" code path (the ones
  Plans 1-5 reviewed for `ERROR_ACCESS_DENIED` handling) has only run
  unprivileged; the elevated path itself is unverified.
- **No censored network.** GitHub's datacentre network is not Türk Telekom.
  Nothing about strategy effectiveness, RTT, or middlebox behavior can be
  learned from this job — that is what the measurement protocol above is
  for, once a real Windows machine on a real censored line exists.

The difference between "CI is green" and "this works" is exactly that list.
A green Windows job after this task's fixes would mean the code compiles,
vets, and its non-OS-dependent logic is correct — not that `dpb` has ever
actually bypassed anything on a Windows machine.
