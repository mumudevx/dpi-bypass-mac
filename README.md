# dpb — macOS DPI bypass

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
> Türk Telekom line while the same probe with no strategy is reset. Intel has
> not been tried — the amd64 archive is built and published but nobody has run
> it. Check `dpb version` against the tag you expected.

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
git clone https://github.com/mumudevx/dpb
cd dpi-bypass-mac
make build        # -> ./dpb
```

Requires Go 1.26.4 on macOS. `make install` puts it in `$GOBIN`.

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
  was developed on. A clean machine, an Intel Mac, and an older Homebrew that
  has no `brew trust` have all not been tried.

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
GoReleaser builds `darwin/arm64` and `darwin/amd64`, publishes the archives and
`checksums.txt`, and updates `Formula/dpb.rb` in `mumudevx/homebrew-tap`.

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
