# Windows measurements

**No Windows measurement exists yet.** Nothing in this repository has run `dpb` on a Windows machine that is actually on a censored line. Everything below the protocol section is what a `windows-latest` CI runner in a datacentre revealed by running the *code* — real evidence about the Windows implementation, but not a ladder measurement; "What CI still cannot tell you" at the end of this document says exactly where that evidence stops.

The ladder in `internal/config/embed/turkey.toml` was measured on **macOS** (Türk Telekom AS9121, Kayseri, 2026-09-02, `docs/MEASUREMENTS.md`). Windows has a different TCP stack; those numbers do not transfer as-is — see "Why the macOS numbers do not transfer" below for what specifically is and is not at risk.

Until a Windows measurement exists, every emitter choice on Windows is unverified. Use the first `-windows-preview` release as a release candidate, not a verified install. Read "Reporting a result" in the main README before filing an issue.

## The measurement protocol

This is the exact procedure a measurement session follows once a Windows machine on a censored line exists, so that session is a matter of running these steps rather than re-deriving method from `docs/MEASUREMENTS.md` on the day. Every parameter below is copied from that file or from the code it drove — cited at each point — so the resulting numbers are *comparable* to the macOS ones, not merely produced the same way in spirit.

### Setup

- Windows 11, on a censored line — Türk Telekom AS9121 if it is available again, otherwise whatever ISP the session actually runs on, recorded plainly (§4 of `docs/MEASUREMENTS.md` already documents that Superonline, Vodafone, Turknet and every mobile network are unmeasured; a session on any of them is new evidence, not a repeat of the macOS one).
- **Bridged, not NAT'd.** The Windows machine needs its own address on the censored line, not a translated address behind whatever host or router is doing NAT for it. `docs/MEASUREMENTS.md`'s numbers describe what the DPI does to a flow carrying a real address on that line; a NAT'd guest is measuring from behind an address something else already claimed. `docs/superpowers/specs/2026-09-07-windows-parity-design.md` §8 ("Test environment") already settled this for the same reason — a bridged UTM/Parallels VM on Apple Silicon, on the same physical line, is the reference layout.
- Before measuring anything, confirm the line is the censored one it is assumed to be: the system resolver's answer for a known-blocked name must be the sinkhole (`dig discord.com` -> `195.175.254.2` or `2a01:358:4014:a00::3`, `resolve.DefaultSinkholes`; `docs/MEASUREMENTS.md` §2). If it answers with a real address instead, this is not the network the ladder was measured against and nothing below is comparable to it.

### Commands

The reps and cooldown below are not chosen for this document — they are the numbers `docs/MEASUREMENTS.md` already used, copied from where the code itself already records that fact:

- `internal/probe/runner.go` defines `DefaultReps = 3`, commented **verbatim** as "the rep count MEASUREMENTS.md used throughout" — §3's 129 trials were 14 emitters x 3 targets x 3 reps, §3.2's 66 trials were run at 3 reps per cut position. The same file's `DefaultCooldown = 400 * time.Millisecond` is described as "anti-noise rather than anti-escalation": `docs/MEASUREMENTS.md` §6 measured the DPI as stateless between flows (15 back-to-back blocked attempts did not change the 16th's outcome), so the pause exists only to make each rep an independent sample of the network, not to dodge a penalty that was measured not to exist.
- `internal/config/embed/turkey.toml`'s own `[prober]` block hardcodes the identical triple — `reps = 3`, `cooldown = "400ms"`, `concurrency = 4` — against the exact three hosts `docs/MEASUREMENTS.md` §1 confirmed blocked and the one control host from the same section. A session that runs `dpb tune` with no flags at all is already running `docs/MEASUREMENTS.md`'s own parameters, not a guess at them.

**Per rung, with `dpb probe`.** One command per rung of the current `tr` ladder (`turkey.toml`'s four measured rungs), against each of the three confirmed-blocked hosts (`docs/MEASUREMENTS.md` §1):

```
dpb probe --host discord.com --addr <resolved-ip> --reps 3
dpb probe --host discord.com --addr <resolved-ip> --reps 3 --strategy tlsfrag:pos=snimid
dpb probe --host discord.com --addr <resolved-ip> --reps 3 --strategy chunk:size=12
dpb probe --host discord.com --addr <resolved-ip> --reps 3 --strategy oob:pos=1
```

— repeated for `discord.gg` and `cdn.discordapp.com`. Resolve `<resolved-ip>` on the day of the session through a non-system resolver (`dig -p 1253 @77.88.8.8 discord.com`, `docs/MEASUREMENTS.md` §2), rather than reusing `162.159.128.233` from the macOS run: it is a Cloudflare anycast address, and there is no claim here that it is still the same one.

`--reps 3` is passed explicitly rather than left at `dpb probe`'s own default of 5. That default exists for a different purpose — `internal/cliapp/probe.go`'s `probeCooldown` comment explains it as "five reps are five independent samples" for a quick spot-check — and 5 is not the number this comparison needs; 3 is.

**The full sweep, with `dpb tune`:**

```
dpb tune --json --export
```

With no target arguments, this measures `turkey.toml`'s own seeded targets: the same three blocked hosts, `cloudflare.com` as the control, and the ten fragile Turkish banks and `.gov.tr` sites from `docs/MEASUREMENTS.md` §5 (`internal/cliapp/tune.go`'s `seedBlocked`/`seedControl`/`seedFragile`, whose own comment calls them measurements, "not a guess"). Its two defaults already land on the same numbers as the per-rung commands above, by two different routes: `--depth full` (the default) resolves `reps` to 3 (`probe.DepthReps(probe.DepthFull) == 3`, pinned by `internal/probe/candidates_test.go`), and `--cooldown` defaults directly to `probe.DefaultCooldown`, 400 ms. This is the closest single command to reproducing §5.1's two-axis compatibility matrix: bypass against the blocked set, safety against the fragile set and the control, scored together.

Keep both outputs: the JSON is the full report, and `--export` prints the one pasteable line another session can verify independently — the artifact `docs/MEASUREMENTS.md`'s own numbers should have had from the start and did not, until code existed to produce one.

### What would invalidate the result

This is the most important section. `docs/MEASUREMENTS.md` §5.4 records losing an entire compatibility matrix to exactly this trap: the harness dialled by hostname, Go's resolver used the machine's *system* resolver, and the system resolver answered every blocked name with the ISP sinkhole (`195.175.254.2`). Every emitter that day was scored against a connection to the sinkhole, not to the origin — a result that reads as "nothing bypasses this DPI" while measuring nothing about the DPI at all. In that document's own words: "no desync strategy can help with that." `--addr` exists on `dpb probe` specifically because of this incident.

The trap on Windows is the same trap, not a new one — and it is still live even though its original trigger, dialling by hostname straight through `net.Dial`, is no longer what `dpb probe`/`dpb tune` do. Both already resolve through `internal/resolve`'s own chain (`resolve.DefaultResolvers`, wired in as `probeChain` in `internal/cliapp/probe.go` and directly in `internal/cliapp/tune.go`) rather than the OS resolver — which is the fix §5.4's own conclusion demanded: "Every outbound dial in the implementation must resolve through the tool's own chain, never through the system resolver." What can still reintroduce the trap on a Windows session specifically:

- **Sanity-checking a result with anything other than `dpb probe`/`dpb tune`.** `curl.exe`, `Invoke-WebRequest`, a browser, `Test-NetConnection` — every one of them uses Windows' own system resolver, the one already shown to answer blocked names with the sinkhole. A "manual" confirmation through any of them is not a confirmation; it is a repeat of §5.4's mistake with different tool names.
- **Passing a bare hostname to `dpb probe` without `--addr`.** The resolve-chain path is a safety net, not a substitute for pinning: it depends on the DoH/DoT/alternate-port endpoints in `resolve.DefaultEndpoints()` all being reachable from wherever the session actually runs, which has never been verified from a Windows machine — a fresh install's own DNS-over-HTTPS setting, a corporate or ISP-injected resolver, or a VPN client's split-DNS could each interpose ahead of it. `--addr` removes the resolver from the picture entirely for that command, which is why `dpb probe --help`'s own long description already carries this warning, citing §5.4 by name.
- **Trusting a PASS without checking what actually answered.** Before scoring any rung, confirm the dialled address is not `195.175.254.2` or `2a01:358:4014:a00::3` (`resolve.DefaultSinkholes`). A PASS against the sinkhole is not a PASS.
- **A captive portal, or a VPN client silently owning the default route.** Worth confirming by hand on a fresh Windows install before trusting that traffic left over the censored line at all: `route print`'s IPv4 table should show the bridged adapter at the lowest metric, not a VPN adapter that quietly took over after boot.

### Why the macOS numbers do not transfer

`internal/config/embed/turkey.toml`'s ladder — `""` (plain), `tlsfrag:pos=snimid`, `chunk:size=12`, `oob:pos=1` — was measured on macOS (`docs/MEASUREMENTS.md`'s own title: "Türk Telekom (AS9121, Kayseri), 2026-09-02"). Every rung's number depends, to a different degree, on the TCP stack that produced it:

- §3.4 already makes this point about a difference *within* one OS, and it applies with more force across two: "a chunk size is meaningless without the write geometry it was measured under. Quote a size only together with the segment budget, and never carry a size from one implementation to another." `chunk:size=12`'s 12 is a number about `internal/ops`'s 16-segment write cap (chosen to stay clear of XNU's `if_sndbyte_unsent` panic, §3.4) as much as it is a number about the DPI's parser. Windows' TCP stack paces, coalesces and segments outbound writes on its own schedule, with no XNU panic to cap around, so a boundary macOS places at byte `12 x N` is not guaranteed to land at the same place on the wire.
- §3.2's record-split rule (`tlsfrag:pos=snimid`, cutting before the SNI ends within the first TLS record) is the more portable of the two mechanisms — it is a claim about TLS *record* boundaries, which `internal/tlsmsg` constructs identically regardless of OS, not about TCP segmentation (§3.1 already shows TCP framing is irrelevant to this rule even on macOS). That makes it the better candidate for transferring, not a confirmed transfer.
- `oob:pos=1` depends on Winsock's urgent-data (MSG_OOB) handling, which has historically diverged from BSD's in exactly what a receiver sees and where. This rung was tuned against BSD's behaviour; nothing here has exercised Winsock's.

None of this predicts the Windows numbers will be worse, better, or different in a particular direction — only that they are unmeasured, and unmeasured is the state a Windows session exists to fix, not to assume away as "it's the same TLS bytes, it should be the same result."

### A `tr-windows` ladder is created only if measurement shows one is needed

`turkey.toml`'s own comment states the rule this follows without needing a new one written for Windows, quoted verbatim: "docs/MEASUREMENTS.md 4 is explicit that Superonline, Vodafone, Turknet and every mobile network are unmeasured, and 3.4 shows efficacy is non-monotonic within one ISP on one day — which is why there is no turkey-superonline.toml and never will be. `dpb tune` running on the user's own line is the ISP-specific knowledge."

The same ethic covers operating systems, not only ISPs: a `tr-windows` ladder is not created in advance of evidence that the `tr` ladder actually fails, or measurably underperforms, on Windows. If a Windows session's `dpb tune` output agrees with `turkey.toml` — the same rungs bypass, the same fragile hosts do or do not break — nothing changes: `turkey.toml` is already platform-free TOML (`docs/superpowers/specs/2026-09-07-windows-parity-design.md` §10: "`ladder = "tr"` resolves to the same four rungs on both systems") and it stays that way. A split gets discussed only once a measured divergence exists to discuss — the same bar §3.4's non-monotonicity finding already sets for a second ISP profile, applied here to a second platform instead.

---

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
