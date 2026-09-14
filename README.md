# dpb — DPI bypass for macOS and Windows

`dpb` gets past the two censorship techniques that were actually measured on a
Türk Telekom line: passive SNI inspection of the TLS ClientHello, and DNS
poisoning. It runs a local proxy, reframes the first ClientHello record so the
hostname is not complete inside the record the middlebox inspects, and resolves
names over its own encrypted DNS chain.

It is **not a VPN**. It changes how bytes are framed on the wire. It adds no
encryption and no anonymity beyond what HTTPS already gives you.

## The one design decision that matters

Every emitter that got through the DPI also broke something. In a two-axis
measurement over 41 hosts — 3 blocked, 10 fragile, 4 controls — *no emitter was
both a bypass and universally safe*:

| emitter | bypassed the block | fragile hosts still working |
|---|---|---|
| plain (no desync) | 0/6 | 20/20 |
| `tlsfrag` (record split at the SNI) | **6/6** | **1/20** |
| `chunk:size=12` | **6/6** | 14/20 |
| `oob:pos=1` | **6/6** | 0/20 |

The 10 fragile hosts are every Turkish bank and `.gov.tr` site tested —
İşbank, Ziraat, Yapı Kredi, Akbank, VakıfBank, DenizBank, turkiye.gov.tr,
gib.gov.tr, mhrs.gov.tr, btk.gov.tr.

So dpb **connects with no desync first**, and escalates only when a connection
is reset or closed *before any server byte has reached the client*. A bank
succeeds on the first attempt and is never desynced. A blocked host costs one
extra round trip (measured: ~22 ms to the RST, ~23 ms for the retry) on the
first visit, and nothing afterwards, because both outcomes — "this needs
desync" and "plain works here" — are cached per host.

Full numbers: [`docs/MEASUREMENTS.md`](docs/MEASUREMENTS.md).

## Install

### Homebrew

```sh
brew tap mumudevx/tap
brew trust mumudevx/tap
brew install dpb
```

The middle line is not optional on Homebrew 6.x, which refuses to load a
formula from a third-party tap until the tap is trusted:

```
Error: Refusing to load formula mumudevx/tap/dpb from untrusted tap mumudevx/tap.
```

> **Status.** Installed and run end to end on macOS 26.3.1 / Homebrew 6.0.18,
> Apple Silicon, from the `v0.1.0` release: `dpb 0.1.0 (b3c9bcce65ed)`, and
> `dpb probe --host discord.com --strategy tlsfrag:pos=snimid` passes on a live
> Türk Telekom line while the same probe with no strategy is reset. dpb ships
> for Apple Silicon only — there is no darwin/amd64 archive, on purpose — so
> `brew install dpb` on an Intel Mac reports that plainly rather than
> installing anything. Check `dpb version` against the tag you expected.

A brew-installed `dpb` is never evaluated by Gatekeeper, and this is not luck:
Homebrew downloads formulae with `curl`, and `curl` sets no
`com.apple.quarantine` attribute. Checked on macOS 26.3.1 with Homebrew
6.0.18 — brew-installed binaries carry only `com.apple.provenance`:

```sh
xattr -p com.apple.quarantine "$(which dpb)"   # -> No such xattr
codesign -dv "$(which dpb)"                     # -> Signature=adhoc, linker-signed
```

The ad-hoc signature comes from Go's own linker, which signs every
`darwin/arm64` binary host-independently. There is no `codesign` step in the
release pipeline, no notarization, and no Apple Developer account. None of
those would change anything above.

### From source

```sh
git clone https://github.com/mumudevx/dpi-bypass-mac
cd dpi-bypass-mac
make build        # -> ./dpb
```

Requires Go 1.26.4 on macOS. `make install` puts it in `$GOBIN`.

### Windows

> **Preview.** This section describes what the Windows code does, not what
> has been observed doing it: nothing below has run on a real Windows machine
> yet. Treat the first `-windows-preview` release as a release candidate
> waiting on its first outside report, not a verified install — and read
> "Reporting a result" before you file one.

**Requirements.** Windows 11, x64 or ARM64. Proxy mode needs no special
privilege at all. `--tun` needs Administrator — the same reason `--tun` needs
`sudo` on macOS: creating the wintun adapter and writing the route table both
require it.

**Download.** Get `dpb_<version>_windows_<arch>.zip` from
[GitHub Releases](https://github.com/mumudevx/dpi-bypass-mac/releases) and
check it against that release's `checksums.txt` before running anything:

```powershell
Get-FileHash dpb_<version>_windows_amd64.zip -Algorithm SHA256
```

The printed hash has to match the line for that file in `checksums.txt`. If it
does not, do not run the binary — re-download it.

**SmartScreen.** `dpb.exe` is not code-signed. There is no Apple-Developer
equivalent in this project's release pipeline on macOS either — see
`.goreleaser.yaml`'s header — and Windows has no back door around it: the
first time you run `dpb.exe`, Windows Defender SmartScreen will show a blue
"Windows protected your PC" screen with one visible button, **Don't run**.
Click **More info** first; a second button, **Run anyway**, appears below it.
That is the standard warning for any unsigned binary downloaded from the
internet, not something specific to dpb, and there is no way to make it stop
appearing without a paid code-signing certificate this project does not have.
Only proceed if you verified the SHA256 above.

**First run** (proxy mode, no Administrator needed):

```powershell
dpb run --profile turkey
```

`dpb run` points Windows at itself the same way it points macOS at itself —
writing the per-user proxy settings (`HKCU\...\Internet Settings`, or the
signed-in user's hive by SID if dpb is elevated as a different account; see
"Service" below) — and reverts them on the way out: on Ctrl-C and on a panic.
Every change is written to a journal before it is attempted, the same journal
`dpb doctor --repair` reads, so even a killed process leaves a record of what
to undo.

```powershell
dpb why www.isbank.com.tr   # every rule that matched, and the verdict in force
dpb status                  # running? which strategy? cache hit rate?
dpb doctor                  # audit this machine; --repair puts back what a crash left
```

**TUN mode.** `dpb run --tun` needs an elevated (Administrator) prompt or
shell, and needs the wintun driver — dpb does not bundle `wintun.dll`.
Download it for your architecture from [wintun.net](https://www.wintun.net)
and place `wintun.dll` next to `dpb.exe`. `dpb doctor` checks for it before
you have to find out the hard way; without it, `--tun` fails with "the wintun
driver is not installed".

wintun.net's prebuilt-binaries licence (bundled in their ZIP as
`LICENSE.txt`) does permit redistributing the signed DLL alongside software
that calls it only through the documented `wintun.h` API, which is exactly
what `golang.zx2c4.com/wintun` (an MIT-licensed Go wrapper, not the driver
itself) does. dpb does not bundle the DLL anyway: doing so would mean
fetching and pinning a third-party binary during release, per architecture,
outside anything `go build` or `go mod` verifies, and wintun.net is already a
single authoritative place to get driver updates. That is an engineering
choice, not a licensing block.

**Service.** Two commands, for two different things:

```powershell
dpb service install            # a logon Scheduled Task, running as YOU; no Administrator
dpb service install --system   # a real Windows service, running as LocalSystem; needs Administrator
dpb service status
dpb service logs
dpb service uninstall          # add --system to match whichever you installed
```

They are not interchangeable, and the difference is not cosmetic. A Windows
service runs in session 0 as `LocalSystem`, which can neither write the
signed-in user's `HKCU` hive — where proxy settings live — nor deliver a
settings-changed notification into that user's session; both only make sense
inside a real interactive logon. So:

- **Proxy mode** is per-user by construction (it sets environment variables
  and Internet Settings for one desktop session), and installs as the **logon
  task**. This needs no Administrator rights and is the supported way to run
  proxy mode unattended.
- **TUN mode** needs Administrator anyway, for the wintun adapter and the
  route table, so it installs as the **SCM service** (`--system`), which is
  what the SCM is actually for.

This is the same split WireGuard uses on Windows, for the same reason:
wireguard-windows runs its tunnel as SYSTEM and leaves the per-user
configuration surface to a process in the user's own session, because SYSTEM
cannot reach that session either.

One consequence worth knowing before you go looking for a log file: a
Scheduled Task action gets no console and no output redirection, so the logon
task writes no `service.out.log` / `service.err.log` — only the `--system`
service does, because that process redirects its own streams. `dpb service
logs` says so, and the logon task's own record is Task Scheduler's:
`schtasks /query /tn dpb /v` for the Last Run Result, and Event Viewer's
**Microsoft > Windows > TaskScheduler > Operational** log for why a start was
refused.

**Uninstall.**

```powershell
dpb service uninstall   # or: dpb service uninstall --system
```

Confirm the machine was actually put back the way it was, not just that the
task or service is gone:

```powershell
dpb doctor                       # system proxy, proxy environment and journal checks
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                                 # the per-user proxy settings dpb actually writes
reg query HKCU\Environment       # the per-user HTTP_PROXY / HTTPS_PROXY variables
```

`netsh winhttp show proxy` is **not** the check to use here: it reports the
machine-wide WinHTTP proxy, a different setting that dpb never touches. It
prints "Direct access (no proxy server)" whether or not dpb's per-user proxy
is live, so it can only mislead you in both directions.

If you ran with `--tun`, also check that DNS and the routing table were
restored — `ipconfig /all` for the resolvers, `route print` for the routes
`--tun` added — since those are the two things full-tunnel mode changes that
proxy mode never touches.

**Reporting a result.** If you are the first person other than the author to
try this on Windows, you are almost certainly on **amd64** and on a
**different ISP**. That makes your run a *compatibility* test — does dpb
install, start, capture traffic, and clean up after itself on a machine that
is not the author's — and it is **not** a measurement of the bypass ladder,
however many of the test sites do or do not get through. Three things say so
directly, and are worth reading before drawing a conclusion from a number:

- [`docs/MEASUREMENTS.md`](docs/MEASUREMENTS.md) §4 is explicit that Superonline,
  Vodafone, Turknet and every mobile network are unmeasured — Türk Telekom is the
  only ISP any number in this repository comes from. `internal/config/embed/turkey.toml`
  cites that finding as the reason it ships no per-ISP variants.
- [`docs/MEASUREMENTS.md`](docs/MEASUREMENTS.md) §3.4 records efficacy that is
  *non-monotonic within one ISP on one day* — the same chunk size passing on
  one sweep and failing on the next, with no single rule that explains it.
  Nothing about a different day, city or account on the **same** ISP is
  guaranteed to reproduce.
- Every number in `MEASUREMENTS.md` was measured on **macOS**. Windows has a
  different TCP stack, and nothing in this repository has re-measured the
  ladder against it yet (that is Phase 6 of the Windows-parity plan).

So "3 of 6 test sites worked" is not, by itself, something the project can act
on — it conflates the ladder, the ISP, the day and the OS into one number. A
report that IS useful says which of these happened, plainly, and pastes any
error text verbatim:

- did `dpb.exe` install and start (proxy mode, and separately `--tun` if you
  tried it);
- did `dpb service install` (and `--system`) actually survive a reboot;
- did traffic visibly flow through the proxy or the tunnel;
- did `dpb service uninstall` and `dpb doctor` leave the machine's proxy, DNS
  and routes back the way they started;
- and only then, separately, what `dpb probe` or ordinary browsing showed
  against whichever sites you tried, with the ISP and city named.

## Use

```sh
# Start the proxy. No sudo.
dpb run --profile turkey

# Is this host blocked here, and does a strategy fix it? Read-only, no sudo,
# changes nothing on the machine.
dpb probe --host discord.com --addr 162.159.128.233 --strategy '' --reps 5
dpb probe --host discord.com --addr 162.159.128.233 --strategy tlsfrag:pos=snimid --reps 5

# Measure your own line and write a profile from what you measure.
dpb tune

# What would this strategy actually put on the wire?
dpb strategy list
dpb strategy explain tlsfrag:pos=snimid
```

`dpb run` points macOS at itself with a PAC file and `launchctl setenv`, and
reverts both on the way out — on Ctrl-C, on SIGTERM, on SIGHUP, and on a panic.
Every change is written to a journal and `fsync`ed *before* it is attempted, so
even a `kill -9` leaves a record of what to undo. PAC is the default mechanism
because macOS treats an unreachable auto-proxy URL as `DIRECT`: if dpb dies, the
machine fails **open**, not into an outage.

### When something is wrong

```sh
dpb why www.isbank.com.tr   # every rule that matched, with its provenance,
                            # and the verdict in force for that host
dpb status                  # running? which strategy? cache hit rate? DNS health?
dpb doctor                  # audit this machine; --repair puts back what a crash left
dpb panic                   # undo every system change and stop
```

### Running it in the background

```sh
dpb service install     # a LaunchAgent in your login session; no sudo
dpb service status
dpb service logs
dpb service uninstall
```

`--system` installs a LaunchDaemon in `/Library/LaunchDaemons` instead and needs
`sudo`. Prefer the user agent for proxy mode: `launchctl setenv` from a system
daemon sets the proxy variables in launchd's *system* domain, which GUI
applications do not inherit, so the daemon covers less of your machine than the
agent does.

Use one or the other, not `brew services` as well. Two supervisors running the
same binary race for the same port and for the same system proxy setting, and
the loser's cleanup undoes the winner's setup.

## What is and is not established

**Measured first-hand, and reproducible from this repository** — see
[`docs/measurements/`](docs/measurements) for the probe programs that produced
the numbers:

- The block is SNI-keyed RST injection on an otherwise reachable path: the same
  IP and port answers `cloudflare.com` and resets `discord.com`.
- The mechanism is a *rule*, not a magic number: the DPI parses only the first
  TLS record of a connection as a ClientHello, so a cut at any offset up to
  `sniEnd-1` passes and a cut at `sniEnd` or later does not. One predicate
  explains all 14 measured data points.
- DNS is poisoned per-QNAME, and TCP/53 is RST-filtered at every port tested —
  so dpb never falls back to plaintext TCP DNS, and a build gate fails the
  build if anyone adds it.
- Retrying a blocked connection with desync works immediately, 18/18, with no
  delay inserted. The DPI does not escalate to IP-level blocking and keeps no
  state between flows.

**Not established, and stated here because a user will otherwise assume it:**

- All of the above is **one ISP (Türk Telekom AS9121), one city (Kayseri), one
  day (2026-09-02), one target family**. Turkcell Superonline, Vodafone,
  Turknet and the mobile networks are entirely unmeasured. Turkish DPI
  configurations are documented to change on a months-scale cadence.
- The shipped profiles are therefore *starting points*, not guarantees.
  `dpb tune` exists so the tool never has to trust a single afternoon of
  measurement again — run it on your own line.
- The censor models in `internal/testcensor` are hypotheses about how the DPI
  works. The test suite proves the code matches the model. It cannot prove the
  model matches the middlebox.
- The Homebrew install has been exercised on exactly one machine, the one this
  was developed on. A clean machine and an older Homebrew that has no
  `brew trust` have not been tried. An Intel Mac has also not been tried, but
  is not expected to install anything — dpb ships arm64-only and the formula
  reports that rather than attempting a download.

## Development

```sh
make build       # -> ./dpb
make test        # go test ./...
make race        # go test ./... -race
make lint        # gofmt check + go vet
make cover-gate  # fails on any 0.0%-covered function in a gated package
make fuzz        # 60s per discovered fuzz target
make deps        # compile the dependency-pin package (tools/tools.go)
```

Three build gates run inside the normal test invocation and fail the build
rather than warn:

- **no bare goroutine** in `internal/front`, `internal/flow` or
  `internal/resolve`. Go runs only the panicking goroutine's deferred
  functions, so an unguarded goroutine in a connection path would turn one
  malformed input into a process death that strands the user's proxy settings.
  Every per-connection goroutine goes through `flow.Safe`.
- **no hostname dial** outside `internal/resolve`. The first run of the
  compatibility matrix scored every emitter 0/6 because Go's own resolver
  returned the ISP's sinkhole address. Every outbound dial resolves through the
  tool's own chain, and any new non-literal address argument has to be recorded
  with a written reason.
- **no plaintext TCP DNS**, anywhere. TCP/53 is RST-filtered on the measured
  line, so a truncation fallback would fail for exactly the names this tool
  exists to reach.

## Releasing

Cutting a release is one step — push a tag:

```sh
git tag -a v0.1.0 -m 'v0.1.0' && git push origin v0.1.0
```

`.github/workflows/release.yml` runs the race tests and the coverage gate, then
GoReleaser builds `darwin/arm64` (Apple Silicon only) and `windows/{amd64,arm64}`,
publishes the archives and `checksums.txt`, and updates `Formula/dpb.rb` in
`mumudevx/homebrew-tap`.

Two things have to exist once, before the first tag:

1. The repository `github.com/mumudevx/homebrew-tap` — empty is fine, GoReleaser
   creates `Formula/dpb.rb` inside it. The tap name in
   `brew tap mumudevx/tap` maps to that repository by Homebrew's convention.
2. A repository secret `HOMEBREW_TAP_TOKEN`: a fine-grained personal access
   token with *Contents: read and write* on the tap repository. The workflow's
   default `GITHUB_TOKEN` cannot write to another repository.

Without the secret, the release still publishes; only the tap push is skipped,
and [`Formula/dpb.rb`](Formula/dpb.rb) in this repository is the copy to fill
in by hand — its header says exactly which two values are missing and where to
get them.

## Documents

- [`docs/MEASUREMENTS.md`](docs/MEASUREMENTS.md) — the first-hand measurements
  everything here derives from. Where any other document disagrees with it, it
  wins.
- [`docs/measurements/`](docs/measurements) — the standalone probe programs that
  produced those numbers. Each is its own Go module and is not part of the main
  build.
- [`docs/PLAN.md`](docs/PLAN.md) — the implementation contract.
- [`docs/DOSSIER.md`](docs/DOSSIER.md) — background research.

## License

MIT — see [LICENSE](LICENSE).
