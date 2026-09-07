# dpb v2 — Implementation Plan

Synthesized 2026-09-02 from four independent architectures scored by three
independent judges. The winning design (`safety-first`) took first place on every
scorecard (41/43/42 of 50).

This plan is the contract. Package boundaries, exported interfaces and acceptance
criteria are binding; implementations may not renegotiate them unilaterally, because
milestones are built in parallel against these signatures.

Evidence base: `DOSSIER.md` (research) and `MEASUREMENTS.md` (first-hand measurement).
Where they disagree, MEASUREMENTS.md wins.

---

## Amendments — read these before the sections they amend

The plan below was written before wave 1 was implemented and reviewed. Building it
proved eight of its clauses wrong. Where an amendment here contradicts the body of
the plan, the amendment wins; where it contradicts `MEASUREMENTS.md`, the
measurement wins.

Amendments A1-A8 come from the wave 1 adversarial review. A9 records what wave 1
actually shipped.

**A1.** §3.4 / ladder tables: PLAN records chunk:size=4 as a 6/6 bypass, but MEASUREMENTS.md measured a chunk-everything emitter and the shipped op is capped at 16 segments. The plan must state the geometry a chunk parameter implies — 'the chunked prefix must extend past BodyOff+SNIEnd' — and drop sizes 1..8 from the tr and global ladders and from the probe-full sweep, or raise the chunk segment budget. As written it invites exactly the parameter-portability error §3.5 warns about.

**A2.** tune phase 3: the tlspad SNI sweep (300/600/1200/1500) is impossible for a byte relay — rewriting the ClientHello desynchronises the client's own TLS transcript, so every value returns failure regardless of the DPI. Respecify the inspection-depth probe as a low-TTL padded DECOY followed by the real unmodified hello, or delete it.

**A3.** §Phase 3 classifier: 'split:pos=snimid (2 TCP segments, hostname straddled)' assumes payload-absolute anchor semantics that the code does not implement. Either the plan states the coordinate system explicitly or the classifier's conclusion ('the DPI does not reassemble TCP') is unsound as written.

**A4.** Verification contract: PLAN.md:1501 row 2 specifies `launchctl getenv` as the verification for launchctl setenv, which contradicts manager.go:52's blanket 'Verify MUST read through a different subsystem'. Reconcile — either carve out an explicit, documented exception with the reason, or specify a real second observer.

**A5.** 'Every exit path' teardown table: the specified behaviour (teardown on a fresh context.Background() with a 10 s budget, reverse order, second Ctrl-C within 3 s force-exits and prints the journal path) is not implemented at all and the omission is undeclared. Either implement it in M11 or amend the table to say when it lands.

**A6.** §1836 killfuzz: the fuzzer's subject `dpb run --dry-run` does not exist until M11, so the journal's crash-durability guarantee has no evidence today. Mark the killfuzz-against-netstate step explicitly as M11 work rather than implying M6 satisfies it.

**A7.** quicfake / SegFakeRaw: the plan lists a UDP/QUIC desync capability, but M4 and M5 left the segment-kind contract unreconciled and the op cannot emit on any transport. Decide the contract in the plan (decoy datagrams are ordinary writes on a connected socket with a lowered hop limit, as byedpi does) before the UDP datapath is built.

**A8.** Verdict lifetime: the plan's 'plain works is self-revalidating at no cost' rationale is false once policy rewrites SrcLearnedPlain to ScopeDirect — the ladder is never invoked again, so it cannot revalidate. The plan should specify a TTL for learned-plain equal to the desync TTL, and specify that flow must refuse to record a plain win against a known sinkhole or a TLS alert, matching what probe already does.

**A10. Exit code 4 is "needs root" only.** The plan's CLI-surface table and M13's
acceptance clause both assign 4 to `dpb tune`'s "nothing is blocked here", which
collides with `dpb service install --system`'s "needs root" — observed in one
binary, and a script cannot branch on it. `ExitNothingBlocked` is 6. 4 keeps the
meaning the LaunchAgent already branches on.

**A11. The coverage gate covers `internal/cliapp`.** The plan's gated-package list
predates that package becoming the largest in the tree (~2700 statements), so
total coverage could fall while every gate stayed green. The Makefile's gated set
and floors are now the reference, not this document.

**A9. What wave 1 shipped, against what this plan specifies.**

- The TR ladder is four rungs, not five: `["", "tlsfrag:pos=snimid",
  "chunk:size=12", "oob:pos=1"]`. `global` is `["", "tlsfrag:pos=snimid",
  "tlsevery:period=64", "chunk:size=12"]`. `chunk:size=4` is refused by the
  emitter and is gone from both, per A1.
- `flow.LadderRunner` distinguishes the commit guard from the evidence guard.
  Any upstream byte still commits the connection; only a byte that is evidence
  of a working handshake feeds the verdict store. A TLS alert, bytes returned
  with a non-timeout error, or a peer in the sinkhole set are handed over and
  cached as nothing.
- A learned-plain verdict carries `LearnedPlainTTL`, equal to the desync TTL.
  The plan's rationale that it is "self-revalidating at no cost" is false, per A8.
- `probeChain` takes an optional ranker rather than ranking unconditionally, so
  the chain's composition can be asserted without a live network.
- Two build gates are stricter than the plan describes: the dial gate rejects
  `net.Resolver` and any non-literal address expression outside
  `internal/resolve` unless recorded with a written review, and the
  no-plaintext-TCP-DNS gate is scoped to the enclosing function rather than the
  file, so a plaintext stream client added beside an encrypted one is caught.


---

## Decision: what won, what was grafted, what was cut

**Winner: `safety-first` (Verdict — default-direct, learn-then-desync).** Unanimous across all three judges (41 / 43 / 42, first place on every scorecard). It is the only design whose *default connection policy* is, independently, the conclusion `MEASUREMENTS.md` §5.2 reaches: connect plain, escalate only on RST/EOF before any server byte reaches the client, cache both "this needs desync" and "plain works" per host. Given §5.1 — *"No emitter is both a bypass and universally safe"*, with 10 of 41 hosts (every Turkish bank and `.gov.tr` site tested) regressing under the winning emitter — that is not a safety nicety, it is the efficacy architecture. The shipped name stays `dpb` and the module stays `github.com/mumudevx/dpb`.

**The one thing no design had, which is now the centre of the plan.** All four judges flagged it: not one design encodes the measured mechanism. `MEASUREMENTS.md` §3.2 gives a *rule*, not a magic number — *"The DPI parses only the first TLS record of a connection as a ClientHello. If the SNI hostname is not complete within that first record, the flow is not matched and passes."* I checked this rule against all 14 measured data points and it explains every one, including the three that look like a different experiment:

- 2-record cuts: `sniStart-20`, `sniStart-1`, `sniStart`, `sniStart+1`, `sniMid`, `sniEnd-1` all pass 3/3 (first record ends ≤ 121); `sniEnd`, `+1`, `+20`, `+200` all blocked 0/3.
- `tlsrec-every-16` and `-every-64` pass (first record ends at 16 and 64, both ≤ 121); `tlsrec-every-256` fails (first record ends at 256 > 121).
- `tlsrec2-1seg` passes, so TCP framing is irrelevant.

One predicate — **`firstRecordEnd <= meta.SNIEnd - 1`** — covers all of it. It becomes `tlsmsg.Meta.MaxFirstRecordEnd()`, it is a *hard validator* inside the emitter (`strategy.ErrCutAfterSNI`), and the previous implementation's recorded failure ("it never verified the cut landed before `sniEnd`") becomes structurally impossible.

**Grafted in, with attribution:**

*From `probe-first` (Kalkan)* — the statistical hygiene of the prober, wholesale: control interleaved in every round with control-failed rounds **discarded** rather than scored; `VerdictLocalError` for our own downgrades, never attributed to a strategy; ranking by the **95% Wilson score lower bound** so three-target evidence outranks one-target evidence; elimination-only early exit. Also `ShapeIPBlock` as a stop condition (benign-SNI-to-the-same-IP first; if that fails, say "no desync can help" and stop), the padding-extension sweep for the inspection window, and `dpb apply '<spec>'` which imports a shared strategy and **re-verifies it locally** before writing it. Its `TargetFragile` class is kept but demoted from disqualifier to ranking input (see fatal flaws).

*From `unprivileged-first` (Ayar)* — the reproduced GT24 finding (`updater.node` is an in-process reqwest addon reading only `HTTP(S)_PROXY`/`NO_PROXY`), which turns `launchctl setenv` into a first-class coverage lever and demotes TUN to M15; `dpb coverage --watch`; the two fuzzed universal invariants (`FuzzPlanPreservesPayload`, `WriteCount() <= MaxSegments`) plus `TestParameterIsLive`, the byte-identical-output sweep over every numeric parameter that mechanically kills the `frag_window` class of defect; and `MSG_OOB` via `RawConn.Write` (whose callback returns a bool, so `EAGAIN` yields to the runtime poller) rather than `Control` + `Sendto`, which spins.

*From `netstack-first` (dpb2)* — the kqueue `EVFILT_PROC`/`NOTE_EXIT` janitor child (~120 lines, the only honest in-process answer to SIGKILL); `CheckIntegrity` as a table test across strategy × censor-model; and the capability validator that **refuses to load** a profile the selected transport cannot satisfy, instead of degrading silently.

*From all four* — an in-memory `Link`/`Device` pair so the entire gVisor stack, relay, UDP forwarder and in-process DNS run under `go test` with no root and no network. That is what converts the previous tree's 0.0%-covered region, where every confirmed defect lived, into ordinary unit tests.

**Removed from the winner** (judges 1 and 3 both flagged it as its one real efficacy gap): the shipped ladder ordered `plain, chunk(5), chunk(2), chunk(20), chunk(60), split(sni-1), tlsrec(sni)` with `--max-attempts 3`. `chunk-5` is **FAIL** in `MEASUREMENTS.md` §3.4 run A, every plain TCP split is 0/5, and `tlsrec` sat at rung 7 — beyond the retry budget. Replaced by §5.3's measured order. Also removed: **fake-IP**. Judges 2 and 3 called it a new failure surface (198.18.0.0/15 collisions, IP pinning, browser-DoH bypass) bought for an exclusion guarantee that §5.2 says is *not the answer anyway*. With default-direct, an unnamed TUN flow gets `ScopeWatch`, is judged by its own ClientHello, and is exactly as safe as everything else. `policy.ReverseMap` covers naming; `--capture=all` becomes the only TUN capture mode, which is now safe precisely because nothing is desynced without evidence.

---

## Package and file tree

```
cmd/dpb/main.go                          Entry: buildinfo, cliapp.Execute, exit codes, top-level recover→teardown→re-panic.

internal/buildinfo/buildinfo.go          Version/Commit/Date ldflags vars; UserAgent().
internal/observ/log.go                   Leveled logger; every warning carries a remediation string.
internal/observ/events.go                NDJSON event log with size-based rotation.
internal/observ/bus.go                   In-process event bus (ConnEvent, StateEvent, DriftEvent).
internal/observ/counters.go              Rolling per-host + global counters; escalation-rate drift detector.
internal/observ/control.go               Unix control-socket server (status/why/on/off/panic/reload).
internal/observ/client.go                Control-socket client used by the CLI.
internal/observ/redact.go                Hostname redaction for shareable diagnostics.
internal/paths/paths.go                  SUDO_USER-aware config/state/log/cache/journal paths.

# ── tlsmsg / httpmsg: pure parsers. No net, no os. Fuzzed. ──
internal/tlsmsg/tlsmsg.go                Meta, Proto, Classify, Parse, Need, MaxFirstRecordEnd (the measured rule).
internal/tlsmsg/clienthello.go           Bounds-checked ClientHello walk; body-relative SNI extent; GREASE tolerant.
internal/tlsmsg/record.go                Record header parse/build; SplitRecord(rec, cuts) → one byte string.
internal/tlsmsg/quic.go                  QUIC v1/v2 long-header Initial detect; DCID/token extents (read-only).
internal/tlsmsg/fuzz_test.go             FuzzParse, FuzzSplitRecord: no panic, no OOB read on truncated input.
internal/tlsmsg/testdata/                Captured 1601-byte X25519MLKEM768 hello + classic RSA + no-SNI hello.
internal/httpmsg/parse.go                Request-line detect; Host value offsets bounded to the header block.
internal/httpmsg/mangle.go               hostcase / hostdot / hostspell / hostpad, header-block scoped.
internal/httpmsg/idempotent.go           Whether a buffered plaintext request may be replayed on retry.

# ── strategy: specs are VALUES that compile to a Plan. Zero I/O. ──
internal/strategy/caps.go                Cap bitset + Has/Missing/String.
internal/strategy/pos.go                 Anchor + Pos: "12", "snistart-20", "snimid", "sniend-1", "bodymid".
internal/strategy/spec.go                Parse/String/canonicalise; ops sorted by (Kind,Name); "plain" == "".
internal/strategy/plan.go                Segment, Plan, Budget, DefaultBudget, Validate, StreamBytes.
internal/strategy/builder.go             Builder: ReframeFirstRecord, SplitAt, SetSegTTL, MarkOOB, Build.
internal/strategy/registry.go            Op registry; OpDoc incl. Determinism and Risk; Ladder(name).
internal/strategy/validate.go            One reframe op max; disorder⊕oob on darwin; cap satisfaction; budget.
internal/strategy/errors.go              ErrCutAfterSNI, ErrNeedComplete, ErrNeedSNI, ErrCapUnavailable, ErrBudget.
internal/strategy/ladder.go              Named ladders as DATA (tr, global, probe-full).
internal/strategy/golden_test.go         ~40 specs × 5 canned hellos → exact byte-for-byte plans.

# ── ops: the emitter set. tlsfrag is the primary; everything else is a rung. ──
internal/ops/tlsfrag.go                  PRIMARY. Reframe first record; HARD-refuses cut > sniEnd-1. One write.
internal/ops/tlsevery.go                 Periodic record reframing; refuses period > sniEnd-1.
internal/ops/chunk.go                    Fixed-size TCP write loop on a NODELAY socket. Ladder rungs 3-4.
internal/ops/oob.go                      MSG_OOB junk byte at a split point. Last rung; most destructive.
internal/ops/split.go                    Plain N-segment TCP split. Registered for the prober only; 0/5 on TT.
internal/ops/disorder.go                 Per-segment IP_TTL=1. Registered; NOT in the TR ladder (0/10 measured).
internal/ops/hostmangle.go               hostcase/hostdot/hostspell/hostpad mutators (port 80).
internal/ops/pad.go                      ClientHello padding-extension inflation — prober diagnostic only.
internal/ops/quicfake.go                 Low-TTL fake QUIC Initials on a connected UDP socket (CapUDPTTL).
internal/ops/unreachable.go              seqovl/fakedsplit/wssize/mss/dropsack: registered, always rejected, cited.
internal/ops/ops_test.go                 Per-op golden plans + the universal invariants.
internal/ops/fuzz_test.go                FuzzPlanPreservesPayload; TestParameterIsLive (byte-diff every numeric param).

# ── emit: the only impure code in the desync path. ──
internal/emit/transport.go               Transport interface + Governor + Sender.
internal/emit/sender.go                  Executes a Plan; TTL restore via defer; classifies errors into flow.Failure.
internal/emit/governor.go                Process-wide token bucket over small writes; COALESCES, never blocks.
internal/emit/socktransport.go           Kernel-socket Transport used by BOTH front-ends. No second impl to drift.
internal/emit/ttl_darwin.go              IP_TTL / IPV6_UNICAST_HOPS; DefaultTTL() reads sysctl net.inet.ip.ttl.
internal/emit/oob_darwin.go              MSG_OOB via RawConn.Write + unix.SendmsgN (poller-safe on EAGAIN).
internal/emit/udp.go                     Connected-UDP datagram transport for quicfake.
internal/emit/stub_other.go              Non-darwin: CapSockTTL/CapOOB withheld with a reason.

# ── policy: scoping and verdicts. ──
internal/policy/scope.go                 ScopeClass, Verdict, Source, Scope interface.
internal/policy/matcher.go               Label-anchored + wildcard + exact matching; IDNA/punycode normalisation.
internal/policy/ipset.go                 CIDR/bogon matching for IP-literal flows.
internal/policy/netid.go                 NetworkID fingerprint (kind/SSID/gateway/gw-MAC/resolver-set hash).
internal/policy/store.go                 Durable verdict store namespaced by NetworkID; atomic rename writes.
internal/policy/reverse.go               DNS-learned IP→name map with TTL (replaces fake-IP).
internal/policy/singleflight.go          Per-(network,host) ladder singleflight.
internal/policy/explain.go               Explanation assembly for `dpb why`.

# ── flow: the shared per-connection engine. ──
internal/flow/firstmsg.go                ReadFirstMessage: complete-message loop, server-first detect, Truncated flag.
internal/flow/ladder.go                  LadderRunner: default-direct, escalate-on-RST-before-response, cache.
internal/flow/classify.go                Failure classification; the "no upstream byte yet" commit guard.
internal/flow/relay.go                   Bidirectional pipe, half-close, idle deadlines, OnFirstByte hook.
internal/flow/rtt.go                     Per-destination RTT EWMA feeding the first-response wait.
internal/flow/safe.go                    flow.Safe: the ONLY sanctioned goroutine spawn. Enforced by a lint test.
internal/flow/dialer.go                  Dialer interface; uplink-bound impls; resolves ONLY through resolve.Chain.
internal/flow/nohostdial_test.go          Build gate: no net.Dial/DialContext with a hostname outside internal/resolve.

# ── resolve: DNS and the single funnel every dial must pass through. ──
internal/resolve/chain.go                Chain: ordered resolvers, positive+negative cache, poison hooks.
internal/resolve/doh.go                  RFC 8484 DoH; hardcoded bootstrap IPs; ID zeroing; no-proxy transport.
internal/resolve/dot.go                  DNS-over-TLS (853), dialled through the desyncing dial path.
internal/resolve/udp.go                  Plain UDP, alt-port aware. TCP fallback is structurally impossible.
internal/resolve/altport.go              77.88.8.8:1253 and 9.9.9.9:9953 with liveness ranking.
internal/resolve/poison.go               Sinkhole sentinels + zapret's reference-free uniqueness heuristic.
internal/resolve/aaaa.go                 Three-state AAAA policy; NAT64/DNS64 detection via ipv4only.arpa.
internal/resolve/server.go               Local DNS server (UDP + TCP); synthesises SERVFAIL, never returns an error.
internal/resolve/wire.go                 Minimal wire helpers: qname/qtype, rcode, section rewrite, SOA synthesis.
internal/resolve/bootstrap.go            Hardcoded DoH/DoT endpoint IPs (assume a censorable update channel).

# ── netstate: every macOS mutation. Journalled, independently verified. ──
internal/netstate/runner.go              Runner + Result + the known-liar table; Result.Failed().
internal/netstate/rib_darwin.go          AF_ROUTE reader via x/net/route. The independent route verifier.
internal/netstate/journal.go             Append-only NDJSON, fsync BEFORE apply; Pending(); Replay().
internal/netstate/manager.go             Do(Op): Begin→Apply→Verify→Commit, auto-rollback; UndoAll in reverse.
internal/netstate/adopt.go               Adopted detection: run Verify's reader BEFORE Apply; Revert becomes a no-op.
internal/netstate/op_proxy.go            PAC URL / web / secure / SOCKS ops; notSelf guard; scutil --proxy verify.
internal/netstate/op_launchenv.go        launchctl setenv/unsetenv HTTP(S)_PROXY/NO_PROXY.
internal/netstate/op_pacfile.go          PAC file write/remove; sha256 verify.
internal/netstate/op_dns.go              networksetup -setdnsservers; notSelf guard; scutil --dns verify.
internal/netstate/op_route_darwin.go     route add/delete; verified against the RIB, never the exit code.
internal/netstate/op_ifconfig_darwin.go  utun address/MTU/up; verified via net.Interfaces + RIB.
internal/netstate/facts_darwin.go        Uplink, gateway, MAC, v4/v6 globals, service list, VPN classification.
internal/netstate/scutil_darwin.go       scutil --proxy / --dns / --nc parsers (the independent verifiers).
internal/netstate/services_darwin.go     networksetup service enumeration; default-route→service mapping.
internal/netstate/lock.go                Pidfile + flock; ownerAlive(pid, startTime) via ps -o lstart=,comm=.
internal/netstate/testdata/              REAL captured outputs incl. route exit-0-with-failure, scutil, networksetup.

internal/janitor/janitor.go              Child: kqueue EVFILT_PROC/NOTE_EXIT on parent, then replay the journal.
internal/janitor/spawn_darwin.go         Spawns `dpb _janitor --parent-pid N --journal PATH`.

# ── netwatch: the laptop-reality layer. ──
internal/netwatch/watcher.go             Event kinds + Watcher interface + debounce.
internal/netwatch/route_darwin.go        PF_ROUTE socket reader (verified openable unprivileged).
internal/netwatch/sleep.go               Wall-vs-monotonic divergence detector. Advisory, never load-bearing.
internal/netwatch/portal.go              Captive-portal probe (204 canary + DNS-uniformity heuristic).
internal/netwatch/vpn_darwin.go          VPN classification: scutil --nc + RIB default-route ownership.

# ── front ends ──
internal/front/proxyfe/server.go         Listener, per-conn dispatch, protocol sniff (HTTP vs SOCKS5), drain.
internal/front/proxyfe/connect.go        HTTPS CONNECT → dial → 200 → ReadFirstMessage → LadderRunner.
internal/front/proxyfe/http.go           Plaintext HTTP: ReadRequest per request, dial per origin. No pooled bleed.
internal/front/proxyfe/socks5.go         SOCKS5 CONNECT, hostname-preserving (ATYP=domain).
internal/front/proxyfe/socks5udp.go      UDP ASSOCIATE; the unprivileged QUIC path.
internal/front/proxyfe/pac.go            GET /dpb.pac — DIRECT for bypassed hosts, no "; DIRECT" fallback.

internal/front/tunfe/link.go             Link interface + pipeLink (in-memory, no root, no utun).
internal/front/tunfe/link_darwin.go      Real utun via wireguard/tun. The ONLY untestable file in the tree.
internal/front/tunfe/endpoint.go         gVisor LinkEndpoint: offset-4 contract, View release, error surfacing.
internal/front/tunfe/stack.go            NIC, promiscuous+spoofing, v4+v6 routes, forwarder registration, teardown.
internal/front/tunfe/tcp.go              TCP forwarder → ReverseMap/SNI naming → LadderRunner. Pipe-first policy.
internal/front/tunfe/udp.go              Datagram-preserving relay, idle reaping, QUIC policy dispatch.
internal/front/tunfe/dns.go              UDP/53 and TCP/53 answered in-process from resolve.Chain.
internal/front/tunfe/icmp.go             ICMP port-unreachable for QUICRefuse (fast TCP fallback).

# ── probe: the prober, scored on TWO axes. ──
internal/probe/target.go                 Target/TargetKind; pinned Addr so a probe never uses the system resolver.
internal/probe/preflight.go              DNS transport matrix; stops if no clean resolver exists.
internal/probe/baseline.go               Which targets are actually blocked here; drops unblocked ones.
internal/probe/classify.go               ShapeIPBlock stop; first-record-limit binary search; padding sweep.
internal/probe/trial.go                  One attempt: full TLS handshake + cert-name check + block-page check.
internal/probe/runner.go                 Rounds, reps, interleaved controls, concurrency, cooldown, budget.
internal/probe/stats.go                  Wilson score interval; noise rate; confidence labelling.
internal/probe/rank.go                   The 7-key ranking that reproduces MEASUREMENTS §5.3 from data.
internal/probe/report.go                 Human table + JSON + tuned.toml write-back + `--export`.
internal/probe/candidates.go             Discrete sweep sets. Never binary-searches chunk size.

# ── testing infrastructure (non-test packages, shipped in the binary for selftest) ──
internal/testcensor/model.go             Model: RecordAware, FirstRecordOnly, ReassembleTCP, InspectBytes, MinTTL.
internal/testcensor/middlebox.go         In-process interposer; reads segments, injects RST / drops.
internal/testcensor/tt2026.go            The MEASURED rule as a fixture: matches only if SNI complete in record 1.
internal/testcensor/fragile.go           Fragile-terminator model: rejects a handshake spanning two records.
internal/testcensor/dns.go               Per-QNAME UDP drop, sinkhole answers, TCP/53 reset at any port.
internal/testcensor/origin.go            Minimal TLS+HTTP origin speaking a real ServerHello.
internal/testcensor/integrity.go         CheckIntegrity: reassembled bytes must equal the bytes written.
internal/testnet/scriptrunner.go         Fixture-driven netstate.Runner fake.
internal/testnet/ribfake.go              In-memory RIBReader.
internal/testnet/packetgen.go            Hand-built IPv4/IPv6 SYN + UDP datagrams for pipeLink.
internal/testnet/clock.go                Deterministic clock for deadline/TTL tests.
internal/testnet/killfuzz.go             Subprocess SIGKILL fuzzer for journal durability.

# ── config + cli ──
internal/config/config.go                Layered resolution: embedded → /etc → user → tuned → env → flags.
internal/config/schema.go                TOML decode with unknown-key REJECTION (kills the sni_match trap).
internal/config/tuned.go                 tuned.toml read/write; NetworkID match; expiry; confidence.
internal/config/excludes.go              Compiled-in mandatory bypass list; extendable, not removable.
internal/config/embed/global.toml        Conservative default: watch 443/80, ladder = tr, no forced strategy.
internal/config/embed/turkey.toml        TR: alt-port UDP + DoH chain, TR ladder, sinkhole sentinels, TR bypasses.
internal/config/embed/lab.toml           Profile used by selftest / censor-sim regression runs.

internal/cliapp/root.go                  Cobra root, global flags, signal context (INT/TERM/HUP/QUIT), panic barrier.
internal/cliapp/run.go                   `dpb run`; builds every subsystem; owns teardown ordering.
internal/cliapp/tune.go                  `dpb tune`.
internal/cliapp/probe.go                 `dpb probe` — one-shot verdict; also the FIRST runnable slice.
internal/cliapp/apply.go                 `dpb apply '<spec>'` — import a shared strategy, verify locally, write.
internal/cliapp/doctor.go                `dpb doctor [--repair|--full|--json]`.
internal/cliapp/why.go                   `dpb why <host>`.
internal/cliapp/status.go                `dpb status [--watch|--json]`.
internal/cliapp/onoff.go                 `dpb on | off | panic`.
internal/cliapp/coverage.go              `dpb coverage [--watch|--fix]`.
internal/cliapp/scope.go                 `dpb scope list|add|remove|bypass|unbypass|test`.
internal/cliapp/strategycmd.go           `dpb strategy list|explain|plan|validate`.
internal/cliapp/dnscmd.go                `dpb dns check|resolve --trace`.
internal/cliapp/selftest.go              `dpb selftest` — the censor-sim matrix, in the shipped binary.
internal/cliapp/service.go               `dpb service install|uninstall|start|stop|status|logs` (modern launchctl).
internal/cliapp/janitorcmd.go            Hidden `dpb _janitor`.
internal/cliapp/version.go               `dpb version [--json]`.
internal/cliapp/banner.go                Prints only VERIFIED facts, never intentions.

Formula/dpb.rb                           Homebrew formula for mumudevx/homebrew-tap (real sha256, real release).
.goreleaser.yaml                         darwin arm64+amd64, no codesign hook, checksums, tap publish.
Makefile                                 build/test/race/fuzz/lint/cover; `make cover-gate` fails on any 0.0% func.
```

---

## Exported interfaces and core types

```go
// ══════════════════════════ internal/tlsmsg ══════════════════════════
// Verified: `go vet` clean, `go build ./...` clean (go1.26.4 darwin/arm64).
package tlsmsg

import "errors"

type Proto uint8

const (
	ProtoUnknown Proto = iota
	ProtoTLS
	ProtoHTTP
	ProtoQUICInitial
)

func (p Proto) String() string { return [...]string{"unknown", "tls", "http", "quic"}[p] }

var ErrNoSNI = errors.New("tlsmsg: first message carries no server name")

// Meta is the parse of a client's first application message.
//
// For ProtoTLS, SNIStart/SNIEnd are offsets into the FIRST TLS record's BODY
// (relative to payload[BodyOff:]), because the measured DPI rule is expressed in
// record-body coordinates. For ProtoHTTP they are unused and HostStart/HostEnd
// are absolute offsets into the payload.
type Meta struct {
	Proto      Proto
	DstPort    int
	Complete   bool // the declared first message is fully buffered
	Truncated  bool // a deadline or size cap was hit first
	ServerName string

	RecHdr  [5]byte // the original record header, reused by reframers
	BodyOff int     // absolute offset of the first record's body (5 for TLS)
	BodyLen int     // declared length of the first record's body

	SNIStart int // body-relative; -1 when absent
	SNIEnd   int // body-relative, exclusive

	HostStart int // payload-absolute; -1 when absent
	HostEnd   int
	HeaderEnd int // end of the HTTP header block; -1 otherwise
}

func (m Meta) HasSNI() bool { return m.SNIStart >= 0 && m.SNIEnd > m.SNIStart }

// MaxFirstRecordEnd is the largest body offset at which the first TLS record may
// end while still hiding the hostname from the DPI.
//
// Measured 2026-09-02, Türk Telekom AS9121, 66 shuffled trials, both records in
// ONE TCP segment (MEASUREMENTS.md §3.2): every first-record end at sniEnd-1 or
// below passes 3/3 on discord.com and discord.gg; sniEnd, sniEnd+1, sniEnd+20 and
// sniEnd+200 are blocked 0/3. The same predicate explains §3's periodic results:
// tlsrec-every-16 and -every-64 pass (first record ends at 16 and 64, both <=
// sniEnd-1 = 121) while tlsrec-every-256 fails (256 > 121). One rule, 14 points.
func (m Meta) MaxFirstRecordEnd() (int, bool) {
	if !m.HasSNI() {
		return 0, false
	}
	return m.SNIEnd - 1, true
}

func Classify(b []byte, dstPort int) Proto { return ProtoUnknown }
func Parse(b []byte, dstPort int) Meta     { return Meta{} }

// Need reports how many more bytes are required before the first application
// message is complete. ok=false means the shape is unrecognisable and the caller
// must stop waiting rather than silently operating on a prefix.
func Need(b []byte, p Proto) (want int, ok bool) { return 0, false }

// SplitRecord reframes one TLS record into len(cuts)+1 structurally valid records
// carrying consecutive slices of the original body, concatenated into a single
// byte string that the caller writes with ONE Write. cuts are body-relative and
// strictly increasing.
func SplitRecord(rec []byte, cuts []int) ([]byte, error) { return nil, nil }

// ══════════════════════════ internal/strategy ══════════════════════════
package strategy

import (
	"errors"
	"time"

	"github.com/mumudevx/dpb/internal/tlsmsg"
)

type Cap uint32

const (
	CapStreamWrite Cap = 1 << iota
	CapNoDelay
	CapSockTTL
	CapOOB
	CapUDPTTL
	CapRawInject
	CapRawSeq // never granted in v1; see emit.Transport.SeqState
)

func (c Cap) Has(want Cap) bool    { return c&want == want }
func (c Cap) Missing(want Cap) Cap { return want &^ c }
func (c Cap) String() string       { return "" }

type Kind uint8

const (
	KindMutate   Kind = iota // rewrites payload bytes (host mangling)
	KindReframe              // rewrites the L5 record layer. At most ONE per spec.
	KindSchedule             // maps bytes onto ordered write ops. At most ONE per spec.
	KindSide                 // emits alongside (quicfake)
)

type Anchor uint8

const (
	AnchorAbs Anchor = iota
	AnchorSNIStart
	AnchorSNIMid
	AnchorSNIEnd
	AnchorBodyMid
	AnchorHostStart
	AnchorHostEnd
)

type Pos struct {
	Anchor Anchor
	Delta  int
}

func ParsePos(s string) (Pos, error)            { return Pos{}, nil }
func (p Pos) String() string                    { return "" }
func (p Pos) Resolve(m tlsmsg.Meta) (int, bool) { return 0, false }

type Args map[string]string

func (a Args) Int(k string, def int) (int, error)    { return def, nil }
func (a Args) Str(k, def string) string              { return def }
func (a Args) Bool(k string, def bool) (bool, error) { return def, nil }
func (a Args) Pos(k string, def Pos) (Pos, error)    { return def, nil }
func (a Args) Unknown(known ...string) []string      { return nil }

// Determinism separates an op whose correctness follows from a measured RULE
// (tlsfrag: cut anywhere <= sniEnd-1) from one whose parameter is an empirical
// constant (chunk: size=12 worked today). Ranking prefers rule-based ops.
type Determinism uint8

const (
	DetEmpirical Determinism = iota
	DetRuleBased
)

type ParamDoc struct {
	Name    string
	Default string
	Probe   []string // values the prober sweeps, in prior order
	Doc     string
}

type OpDoc struct {
	Name        string
	Kind        Kind
	Caps        Cap
	Determinism Determinism
	Params      []ParamDoc
	Summary     string
	Source      string // e.g. "MEASUREMENTS.md §3.2"
	Risk        int    // 0..100
	Rejected    string // non-empty if the op exists only to give an honest error
}

type SegKind uint8

const (
	SegStream SegKind = iota
	SegOOBByte
	SegFakeRaw
)

type Segment struct {
	Kind  SegKind
	Data  []byte
	TTL   int // 0 = leave the socket default
	Delay time.Duration
	Note  string
}

type Budget struct {
	MaxSegments   int
	MinSegment    int
	MaxTotalDelay time.Duration
	MaxPayload    int
}

func DefaultBudget() Budget {
	return Budget{MaxSegments: 16, MinSegment: 1,
		MaxTotalDelay: 250 * time.Millisecond, MaxPayload: 64 << 10}
}

// Plan is a pure value. Invariant, fuzzed on every build: concatenating every
// SegStream Data in emission order equals Payload.
type Plan struct {
	Spec     string
	Payload  []byte
	Segments []Segment
	Notes    []string
}

func (p Plan) Caps() Cap               { return 0 }
func (p Plan) StreamBytes() []byte     { return nil }
func (p Plan) WriteCount() int         { return len(p.Segments) }
func (p Plan) Validate(b Budget) error { return nil }
func (p Plan) String() string          { return p.Spec }

var (
	// ErrCutAfterSNI is the load-bearing validator. It fires when a reframing op
	// would leave the SNI hostname complete inside the first TLS record.
	ErrCutAfterSNI    = errors.New("strategy: first TLS record ends at or after sniEnd; the DPI would still match")
	ErrNeedComplete   = errors.New("strategy: op requires a complete first message")
	ErrNeedSNI        = errors.New("strategy: op requires a parsed server name")
	ErrCapUnavailable = errors.New("strategy: transport lacks a required capability")
	ErrBudget         = errors.New("strategy: plan exceeds the segment budget")
)

type Builder struct {
	Payload []byte
	Meta    tlsmsg.Meta
	Segs    []Segment
	Caps    Cap
	Budget  Budget
	Strict  bool // probe mode: any downgrade is an error, never a fallback
}

func (b *Builder) Reparse()                            {}
func (b *Builder) ReframeFirstRecord(cuts []int) error { return nil }
func (b *Builder) SplitAt(offsets ...int) error        { return nil }
func (b *Builder) SetSegTTL(i, ttl int) error          { return nil }
func (b *Builder) MarkOOB(i int, junk byte) error      { return nil }
func (b *Builder) Note(format string, a ...any)        {}
func (b *Builder) Build(spec string) (Plan, error)     { return Plan{}, nil }

type Op interface {
	Name() string
	Kind() Kind
	Caps() Cap
	Doc() OpDoc
	Compile(a Args) (Step, error)
}

type Step interface {
	Name() string
	Caps() Cap
	Apply(b *Builder) error
}

// Strategy is an ordered pipeline. Steps always execute in Kind order, never in
// typed order, so "chunk:size=12|hostcase" and "hostcase|chunk:size=12" are the
// same strategy and canonicalise identically.
type Strategy struct {
	Spec  string
	Steps []Step
}

func Parse(spec string) (Strategy, error)                     { return Strategy{}, nil }
func MustParse(spec string) Strategy                          { return Strategy{} }
func (s Strategy) String() string                             { return s.Spec }
func (s Strategy) Caps() Cap                                  { return 0 }
func (s Strategy) Determinism() Determinism                   { return DetEmpirical }
func (s Strategy) Explain() []string                          { return nil }
func (s Strategy) CheckAgainst(have Cap, m tlsmsg.Meta) error { return nil }
func (s Strategy) Build(payload []byte, m tlsmsg.Meta, have Cap, bud Budget) (Plan, error) {
	return Plan{}, nil
}

type Registry struct{ ops map[string]Op }

func NewRegistry() *Registry                               { return &Registry{} }
func (r *Registry) Register(o Op)                          {}
func (r *Registry) Get(spec string) (Strategy, error)      { return Strategy{}, nil }
func (r *Registry) Docs() []OpDoc                          { return nil }
func (r *Registry) Ladder(name string) ([]Strategy, error) { return nil, nil }

// ══════════════════════════ internal/emit ══════════════════════════
package emit

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/mumudevx/dpb/internal/strategy"
)

var ErrCapUnavailable = errors.New("emit: transport lacks a required capability")

type SeqState struct {
	ISN      uint32
	SndNxt   uint32
	RcvNxt   uint32
	WindowOK bool
}

// Transport is the seam between the emitter set and an interception mode. Proxy
// mode and TUN mode both dial an ordinary bound kernel socket and wrap it in the
// SAME SockTransport, so the two front-ends cannot drift apart.
type Transport interface {
	Caps() strategy.Cap
	Write(b []byte) (int, error)
	WriteOOB(b []byte) (int, error)
	SetTTL(ttl int) error
	ResetTTL() error
	InjectRaw(pkt []byte) error
	// SeqState reports the upstream sequence space. ok is ALWAYS false for a
	// kernel socket on Darwin: struct tcp_connection_info in netinet/tcp.h has no
	// snd_nxt field (verified against the macOS 26 SDK this session, 0 matches),
	// so CapRawSeq can never be granted and every seqovl/fakedsplit op fails
	// validation with a mechanical reason instead of emitting decoys out of
	// window. It lights up unchanged the day a netstack-owned endpoint exists.
	SeqState() (SeqState, bool)
	Local() netip.AddrPort
	Remote() netip.AddrPort
	Close() error
}

// Governor is a process-wide token bucket over small writes. The XNU
// `assertion failed: ifp->if_sndbyte_unsent >= 0` panic is a pre-existing Apple
// defect (public reports back to xnu-4570, 2017) provoked by high VOLUME of small
// writes, so the guard must be process-wide, not per-connection. It COALESCES
// adjacent small segments when short rather than blocking a write.
type Governor interface {
	Reserve(n int) int
	Stats() GovernorStats
}

type GovernorStats struct {
	Granted   uint64
	Coalesced uint64
}

func NewGovernor(perSecond, burst int) Governor { return nil }

type Sender struct {
	Gov  Governor
	Logf func(string, ...any)
}

func (s *Sender) Send(ctx context.Context, t Transport, p strategy.Plan) error { return nil }

type SockTransport struct{ c *net.TCPConn }

func NewSockTransport(c *net.TCPConn, inj RawInjector) (*SockTransport, error) { return nil, nil }

func (t *SockTransport) Caps() strategy.Cap             { return 0 }
func (t *SockTransport) Write(b []byte) (int, error)    { return 0, nil }
func (t *SockTransport) WriteOOB(b []byte) (int, error) { return 0, nil }
func (t *SockTransport) SetTTL(ttl int) error           { return nil }
func (t *SockTransport) ResetTTL() error                { return nil }
func (t *SockTransport) InjectRaw(pkt []byte) error     { return ErrCapUnavailable }
func (t *SockTransport) SeqState() (SeqState, bool)     { return SeqState{}, false }
func (t *SockTransport) Local() netip.AddrPort          { return netip.AddrPort{} }
func (t *SockTransport) Remote() netip.AddrPort         { return netip.AddrPort{} }
func (t *SockTransport) Close() error                   { return nil }

type RawInjector interface {
	Inject(pkt []byte) error
	Close() error
}

// DefaultTTL reads net.inet.ip.ttl (64 on the development machine, verified
// 2026-09-02) instead of hardcoding a value.
func DefaultTTL() (int, error) { return 0, nil }

// ══════════════════════════ internal/policy ══════════════════════════
package policy

import (
	"net/netip"
	"time"
)

type ScopeClass uint8

const (
	ScopeBypass ScopeClass = iota // hard veto: never buffered, never desynced
	ScopeDirect                   // relay immediately, no first-message buffering
	// ScopeWatch is the DEFAULT for every inspect port: buffer the complete first
	// message, send it UNMODIFIED, and escalate the ladder only on RST/EOF before
	// any upstream byte reaches the client. MEASUREMENTS.md §5.2 calls this a
	// correctness requirement, not an optimisation.
	ScopeWatch
	ScopeDesync // a cached or probed winner exists; apply it on attempt one
)

type Source uint8

const (
	SrcBuiltinBypass Source = iota
	SrcUserBypass
	SrcUserInclude
	SrcProbed
	SrcLearnedDesync
	SrcLearnedPlain
	SrcDefault
)

type Verdict struct {
	Class    ScopeClass
	Spec     string
	Ladder   []string
	Source   Source
	Reason   string
	RuleText string
	RuleFrom string // provenance, e.g. "compiled-in" or "~/.config/dpb/config.toml:31"
	Learned  time.Time
	Expires  time.Time // zero means never
	Wins     int
	Losses   int
}

func (v Verdict) Expired(now time.Time) bool {
	return !v.Expires.IsZero() && now.After(v.Expires)
}

type Rule struct {
	Pattern string
	Class   ScopeClass
	From    string
	Line    int
}

type ConnSummary struct {
	At       time.Time
	Spec     string
	Attempts int
	OK       bool
	Latency  time.Duration
}

type Explanation struct {
	Input     string
	Punycode  string
	Matched   []Rule
	Effective Verdict
	Recent    []ConnSummary
}

type Scope interface {
	ForName(host string, port int) Verdict
	ForAddr(ap netip.AddrPort) Verdict
	Explain(host string) Explanation
}

// Matcher anchors on a label boundary: "bank.com" matches bank.com and
// www.bank.com but never evilbank.com.
type Matcher struct{ rules []Rule }

func NewMatcher(rules []Rule) (*Matcher, error) { return nil, nil }
func (m *Matcher) Match(host string) []Rule     { return nil }
func MatchLabel(pattern, host string) bool      { return false }

// NetworkID namespaces every learned verdict so a home-WiFi result is never
// replayed on a cellular hotspot with a different censor.
type NetworkID struct {
	Kind        string // wifi | ethernet | cellular | vpn | unknown
	SSID        string
	Gateway     netip.Addr
	GatewayMAC  string
	ResolverSet string
}

func (n NetworkID) Key() string            { return "" }
func (n NetworkID) Equal(o NetworkID) bool { return n.Key() == o.Key() }

type Store interface {
	Get(net NetworkID, host string) (Verdict, bool)
	Put(net NetworkID, host string, v Verdict) error
	Demote(net NetworkID, host string) error
	ForEach(net NetworkID, fn func(host string, v Verdict) bool)
	Flush() error
	Close() error
}

func OpenStore(path string, now func() time.Time) (Store, error) { return nil, nil }

type ReverseMap interface {
	Learn(name string, ips []netip.Addr, ttl time.Duration)
	Lookup(ip netip.Addr) (string, bool)
}

func NewReverseMap(max int) ReverseMap { return nil }

// Singleflight collapses the parallel connections a browser opens to one host so
// the ladder is walked once per (network, host) rather than six times.
type Singleflight struct{}

func NewSingleflight() *Singleflight { return &Singleflight{} }
func (s *Singleflight) Do(key string, fn func() (Verdict, error)) (Verdict, error) {
	return Verdict{}, nil
}

// ══════════════════════════ internal/flow ══════════════════════════
package flow

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

type MsgKind uint8

const (
	MsgTLS MsgKind = iota
	MsgHTTP
	MsgOpaque
	MsgServerFirst // nothing arrived in FirstByteWait: relay now, buffer nothing
)

type FirstMsgOpts struct {
	FirstByteWait time.Duration
	CompleteWait  time.Duration
	Max           int
}

func DefaultFirstMsgOpts() FirstMsgOpts {
	return FirstMsgOpts{
		FirstByteWait: 250 * time.Millisecond,
		CompleteWait:  250 * time.Millisecond,
		Max:           64 << 10,
	}
}

// ReadFirstMessage loops until the DECLARED first application message is
// complete. It NEVER performs a single un-looped Read: a post-quantum
// ClientHello is ~1512-1601 bytes and spans two segments on a 1500-byte MTU, and
// silently operating on a prefix is how the previous implementation degraded a
// record split into a 1-byte TCP split.
func ReadFirstMessage(r io.Reader, port int, o FirstMsgOpts) (payload []byte, kind MsgKind, m tlsmsg.Meta, err error) {
	return nil, MsgOpaque, tlsmsg.Meta{}, nil
}

type Failure uint8

const (
	FailNone Failure = iota
	FailDial
	FailResetBeforeResponse   // censorship-shaped: retry
	FailTimeoutBeforeResponse // censorship-shaped: retry
	FailResetAfterResponse    // NOT censorship-shaped: never retry
	FailNotReplayable
	FailBudget
)

func (f Failure) Retryable() bool {
	return f == FailResetBeforeResponse || f == FailTimeoutBeforeResponse
}

type Attempt struct {
	Spec    string
	Class   Failure
	Err     error
	Latency time.Duration
}

type Outcome struct {
	Conn     net.Conn
	Spec     string
	Attempts []Attempt
	Pre      []byte // upstream bytes read while judging; replay to the client first
}

type Target struct {
	Name string
	Addr netip.AddrPort
	Port int
}

type Dialer interface {
	DialTCP(ctx context.Context, t Target) (net.Conn, error)
}

var (
	ErrLadderExhausted = errors.New("flow: every ladder rung failed")
	ErrNoUpstream      = errors.New("flow: upstream dial failed")
)

type RTTTracker struct{}

func NewRTTTracker() *RTTTracker                            { return &RTTTracker{} }
func (t *RTTTracker) Observe(a netip.Addr, d time.Duration) {}
func (t *RTTTracker) Wait(a netip.Addr) time.Duration       { return 0 }

type LadderRunner struct {
	Dial        Dialer
	Sender      *emit.Sender
	Registry    *strategy.Registry
	Store       policy.Store
	NetID       func() policy.NetworkID
	Single      *policy.Singleflight
	RTT         *RTTTracker
	Caps        strategy.Cap
	Budget      strategy.Budget
	MaxAttempts int
	TotalBudget time.Duration
	Now         func() time.Time
	OnOutcome   func(Target, policy.Verdict, Outcome)
	Logf        func(string, ...any)
}

// Run holds the buffered first message and tries rungs on FRESH upstream
// connections. Retry is safe for exactly this window because the ClientHello is
// the first thing on the wire: if the handshake fails, no application bytes have
// been delivered in either direction, so re-dialling is invisible to the client.
// Validated on the wire, MEASUREMENTS.md §6: 18/18 immediate retries succeeded.
func (l *LadderRunner) Run(ctx context.Context, t Target, v policy.Verdict,
	first []byte, m tlsmsg.Meta, extra []byte) (Outcome, error) {
	return Outcome{}, nil
}

type PipeOpts struct {
	Idle        time.Duration
	HalfClose   bool
	OnFirstByte func() // fires as the first upstream byte is about to reach the client
}

func Pipe(ctx context.Context, a, b net.Conn, o PipeOpts) error { return nil }

// Safe is the ONLY sanctioned goroutine spawn in per-connection code. A lint test
// fails the build on a bare `go ` in front/, flow/ and resolve/, because Go runs
// only the panicking goroutine's deferred functions.
func Safe(name string, logf func(string, ...any), fn func()) {}

// Replayable reports whether a buffered plaintext HTTP request may be re-sent on
// a fresh upstream connection (idempotent method, no body).
func Replayable(payload []byte, m tlsmsg.Meta) bool { return false }

// ══════════════════════════ internal/resolve ══════════════════════════
package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/mumudevx/dpb/internal/policy"
)

type Resolver interface {
	Label() string
	Transport() string // "doh" | "dot" | "udp" | "udp-alt"
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

// ErrTCPForbidden is returned if any code path attempts DNS over TCP. TCP/53 is
// RST-filtered at EVERY port on Türk Telekom (measured 2026-09-02: both
// `dig +tcp @8.8.8.8` and `dig +tcp -p 1253 @77.88.8.8` are connection-reset), so
// a truncation fallback to TCP breaks for exactly the names that matter.
var ErrTCPForbidden = errors.New("resolve: DNS over TCP is never attempted")

type AAAAMode uint8

const (
	AAAAAuto AAAAMode = iota // allow only with a verified v4 path and no NAT64
	AAAAAllow
	AAAASuppress // NOERROR + empty answer + SOA; never NXDOMAIN
)

type Signal struct {
	Poisoned bool
	Sinkhole bool
	Uniform  bool
	Detail   string
}

type Detector interface {
	Check(name string, addrs []netip.Addr) Signal
	Learn(name string, addrs []netip.Addr)
}

// NewDetector seeds the sinkhole sentinels. 195.175.254.2 is the BTK block page
// returned by the ISP resolver for every blocked name (measured 2026-09-02);
// 2a01:358:4014:a00::3 is its IPv6 counterpart, registered in RIPE with netname
// BTK. Uniform() is zapret's reference-free heuristic: several distinct blocked
// names resolving to one address is a censor, with no ground truth needed.
func NewDetector(sinkholes []netip.Addr, probes []string) Detector { return nil }

type Options struct {
	Resolvers []Resolver
	AAAA      AAAAMode
	Detector  Detector
	Reverse   policy.ReverseMap
	CacheTTL  time.Duration
	NegTTL    time.Duration
	Logf      func(string, ...any)
}

type Chain struct{}

func NewChain(o Options) *Chain { return nil }

// Exchange is the single DNS funnel. It rejects TCP, drops sinkhole answers and
// advances the chain, applies the AAAA policy, records the reverse mapping, and
// synthesises SERVFAIL rather than closing the session on chain exhaustion.
func (c *Chain) Exchange(ctx context.Context, query []byte) ([]byte, error)      { return nil, nil }
func (c *Chain) Resolve(ctx context.Context, host string) ([]netip.Addr, error)  { return nil, nil }
func (c *Chain) Labels() []string                                               { return nil }
func (c *Chain) Health() []Health                                               { return nil }

type Health struct {
	Label   string
	OK      bool
	Latency time.Duration
	Signal  Signal
	Err     error
}

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func NewDoH(endpoint string, bootstrap []netip.Addr, dial DialFunc) (Resolver, error) { return nil, nil }
func NewDoT(addr string, dial DialFunc) (Resolver, error)                             { return nil, nil }
func NewUDP(label, addr string, d *net.Dialer) (Resolver, error)                      { return nil, nil }

type Server struct{}

func NewServer(c *Chain, logf func(string, ...any)) *Server             { return nil }
func (s *Server) Answer(ctx context.Context, query []byte) []byte       { return nil }
func (s *Server) ServeUDP(ctx context.Context, pc net.PacketConn) error { return nil }
func (s *Server) ServeTCP(ctx context.Context, l net.Listener) error    { return nil }

// ══════════════════════════ internal/netstate ══════════════════════════
package netstate

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"
)

type Result struct {
	Argv     []string
	Combined string
	Code     int
	Err      error
	Duration time.Duration
}

// Failed is true on a non-zero exit OR on a match in the known-liar table.
// macOS route(8) has no failure exit path: Apple's route.c has newroute() as void
// and main() does `newroute(argc, argv); exit(0)`. Re-verified on this machine
// 2026-09-02: `route -n get -inet6 2001:db8::1` prints "route: writing to routing
// socket: not in table" and exits 0.
func (r Result) Failed() bool   { return false }
func (r Result) Reason() string { return "" }

type Runner interface {
	Run(ctx context.Context, name string, args ...string) Result
}

func NewExecRunner(logf func(string, ...any)) Runner { return nil }

type RouteEntry struct {
	Dst     netip.Prefix
	Gateway netip.Addr
	Iface   string
	Index   int
	Scoped  bool
}

// RIBReader reads the kernel routing table directly through an AF_ROUTE socket
// (golang.org/x/net/route). Verified openable unprivileged on this machine:
// FetchRIB returned 19808 bytes / 121 messages as uid 501. This is the
// independent verifier for every route mutation; parsing route(8)'s own stderr
// still trusts the tool that lies.
type RIBReader interface {
	Routes() ([]RouteEntry, error)
	Default() (RouteEntry, bool, error)
	ScopedDefault(iface string) (RouteEntry, bool, error)
	Exists(dst netip.Prefix, iface string) (bool, error)
}

func NewRIB() RIBReader { return nil }

type Env struct {
	Runner Runner
	RIB    RIBReader
	Facts  *Facts
	Logf   func(string, ...any)
	DryRun bool
}

type OpKind string

const (
	OpProxyPAC   OpKind = "proxy.pac"
	OpProxyHTTP  OpKind = "proxy.http"
	OpProxySOCKS OpKind = "proxy.socks"
	OpPACFile    OpKind = "proxy.pacfile"
	OpLaunchEnv  OpKind = "proxy.launchenv"
	OpDNSServers OpKind = "dns.servers"
	OpRoute      OpKind = "route"
	OpIfconfig   OpKind = "ifconfig"
)

// Op's contract: Verify MUST read through a different subsystem than Apply wrote
// through. Routes are written by route(8) and verified against the AF_ROUTE RIB;
// proxy settings are written by networksetup and verified with `scutil --proxy`;
// DNS likewise with `scutil --dns`; interfaces with net.Interfaces().
type Op interface {
	Kind() OpKind
	ID() string
	Describe() string
	Apply(ctx context.Context, e Env) error
	Verify(ctx context.Context, e Env) error
	Revert(ctx context.Context, e Env) error
	VerifyReverted(ctx context.Context, e Env) error
	Record() Record
}

type Record struct {
	Seq       uint64    `json:"seq"`
	Kind      OpKind    `json:"kind"`
	ID        string    `json:"id"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Applied   bool      `json:"applied"`
	Verified  bool      `json:"verified"`
	// Adopted marks state that already existed and that we did NOT create — a
	// VPN's -ifscope default, an admin-set PAC, a previous run's route. Revert is
	// a no-op for adopted records, which is what stops Ctrl-C from deleting a
	// VPN's routes.
	Adopted bool            `json:"adopted"`
	Revert  json.RawMessage `json:"revert"`
	Note    string          `json:"note"`
}

type Token uint64

type Journal interface {
	// Begin writes the revert record and fsyncs BEFORE the mutation is attempted,
	// so a SIGKILL between the two leaves an over-approximate journal — the safe
	// direction, since every Revert is idempotent and VerifyReverted tolerates
	// already-absent state.
	Begin(ctx context.Context, r Record) (Token, error)
	Commit(ctx context.Context, t Token, r Record) error
	Done(ctx context.Context, t Token) error
	Pending(ctx context.Context) ([]Record, error)
	Path() string
	Close() error
}

func OpenJournal(path string) (Journal, error) { return nil, nil }

type Manager struct{}

func NewManager(j Journal, e Env) *Manager             { return nil }
func (m *Manager) Do(ctx context.Context, op Op) error { return nil }
func (m *Manager) UndoAll(ctx context.Context) []error { return nil }
func (m *Manager) Applied() []Record                   { return nil }

type ReplayReport struct {
	Pending  []Record
	Reverted []Record
	Skipped  []Record
	Failed   []Record
}

func Replay(ctx context.Context, j Journal, e Env,
	ownerAlive func(pid int, started time.Time) bool) (ReplayReport, error) {
	return ReplayReport{}, nil
}

type VPNState struct {
	Present     bool
	FullTunnel  bool
	Iface       string
	ServiceName string
}

type Facts struct {
	Uplink      string
	Gateway     netip.Addr
	UplinkMAC   string
	V4Global    []netip.Addr
	V6Global    []netip.Addr
	Services    []string
	VPN         VPNState
	CollectedAt time.Time
}

func CollectFacts(ctx context.Context, e Env) (*Facts, error) { return nil, nil }

func NewPAC(r Runner, url string, services []string) Op                   { return nil }
func NewLaunchEnv(r Runner, httpsProxy string, noProxy []string) Op       { return nil }
func NewDNSServers(r Runner, servers []string, services []string) Op      { return nil }
func NewRoute(r Runner, dst netip.Prefix, gw netip.Addr, iface string) Op { return nil }
func NewIfconfig(r Runner, iface, local, peer string, mtu int) Op         { return nil }

// ══════════════════════════ internal/probe ══════════════════════════
package probe

import (
	"context"
	"io"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/resolve"
	"github.com/mumudevx/dpb/internal/strategy"
)

type TargetKind uint8

const (
	TargetBlocked TargetKind = iota // expected blocked; the thing a candidate must fix
	// TargetControl: expected reachable; distinguishes "strategy failed" from
	// "the network is down". Interleaved in EVERY round, not run once up front.
	TargetControl
	// TargetFragile: known to break under aggressive emitters. Scored as a
	// COMPATIBILITY axis feeding ranking — never as a hard disqualifier, because
	// MEASUREMENTS.md §5.1 shows no emitter is both a bypass and universally
	// safe, so disqualification would zero out every candidate.
	TargetFragile
)

type Target struct {
	Host string
	Port int
	Kind TargetKind
	// Addr pins the destination so a probe never resolves through the system
	// resolver. MEASUREMENTS.md §5.4: the first run of the compatibility matrix
	// scored every emitter 0/6 because Go's resolver returned the BTK sinkhole.
	Addr string
}

type Verdict uint8

const (
	VerdictUnknown Verdict = iota
	VerdictPass            // full TLS handshake AND a cert valid for the name
	VerdictReset
	VerdictTimeout
	VerdictBlockPage
	VerdictHandshakeFail // TLS alert / bad cert: server-side, discarded
	VerdictDialFail
	VerdictLocalError  // our own downgrade or bug: discarded, never scored
	VerdictControlDown // the interleaved control failed: round discarded
)

func (v Verdict) Scorable() bool {
	return v == VerdictPass || v == VerdictReset || v == VerdictTimeout || v == VerdictBlockPage
}

type Trial struct {
	Spec    string
	Target  Target
	Round   int
	Verdict Verdict
	Latency time.Duration
	Err     string
	At      time.Time
}

type Shape uint8

const (
	ShapeUnknown Shape = iota
	ShapeClean
	ShapeDNSOnly
	ShapeSNIReset
	ShapeSNIResetAndDNS
	// ShapeIPBlock: the path is unreachable even with a benign SNI. No desync can
	// help; say so and stop rather than burning a full ladder.
	ShapeIPBlock
)

type Evidence struct {
	Claim    string
	Method   string
	Observed string
	At       time.Time
}

type Classification struct {
	Shape Shape
	// FirstRecordLimit is the largest first-TLS-record end offset (body-relative)
	// at which the block stops firing, found by binary search over record cut
	// positions. On Türk Telekom this converges on sniEnd-1.
	FirstRecordLimit int
	// InspectBytes is the middlebox's apparent inspection window, measured by a
	// ClientHello padding-extension sweep.
	InspectBytes int
	RSTLatency   time.Duration
	DNS          []resolve.Health
	Evidence     []Evidence
}

type Score struct {
	Spec string

	BypassPass  int
	BypassTotal int
	WilsonLo    float64
	AllTargets  bool

	ControlPass  int
	ControlTotal int
	FragilePass  int
	FragileTotal int

	Determinism strategy.Determinism
	Segments    int
	Caps        strategy.Cap
	MedianRTT   time.Duration
	Discarded   int
}

// Wilson returns the 95% Wilson score interval for passes/trials, so a candidate
// measured across three targets automatically outranks one measured against a
// single target.
func Wilson(passes, trials int, z float64) (lo, hi float64) { return 0, 0 }

type Progress struct {
	Phase     string
	Done      int
	Total     int
	BestSoFar string
	Elapsed   time.Duration
	ETA       time.Duration
}

type Options struct {
	Targets     []Target
	Reps        int
	Concurrency int
	Cooldown    time.Duration
	Budget      time.Duration
	Registry    *strategy.Registry
	Chain       *resolve.Chain
	Dial        flow.Dialer
	Caps        strategy.Cap
	Now         func() time.Time
	OnProgress  func(Progress)
	Logf        func(string, ...any)
}

type Runner struct{}

func NewRunner(o Options) *Runner { return nil }

func (r *Runner) Preflight(ctx context.Context) ([]resolve.Health, error)  { return nil, nil }
func (r *Runner) Baseline(ctx context.Context) ([]Target, []Target, error) { return nil, nil, nil }
func (r *Runner) Classify(ctx context.Context) (Classification, error)     { return Classification{}, nil }
func (r *Runner) Evaluate(ctx context.Context, cands []strategy.Strategy) ([]Trial, error) {
	return nil, nil
}

// Rank orders candidates by, in strict precedence: control pass rate (does the
// ordinary internet still work), then bypass Wilson lower bound, then determinism
// (a rule beats a magic number), then fragile-host pass rate, then fewer
// segments, then median latency, then lexicographically for run-to-run stability.
// Applied to the measured data this reproduces MEASUREMENTS.md §5.3 exactly.
func Rank(ts []Trial, blocked []Target, docs []strategy.OpDoc) []Score { return nil }

type Report struct {
	CreatedAt   time.Time
	ToolVersion string
	NetworkKey  string
	Caps        string
	DNS         []resolve.Health
	Class       Classification
	Blocked     []string
	NotBlocked  []string
	Ranked      []Score
	Ladder      []string
	Confidence  string // "high" | "medium" | "low"
	NoiseRate   float64
	Elapsed     time.Duration
	Warnings    []string
}

func (r Report) WriteConfig(path string) error { return nil }
func (r Report) Text(w io.Writer) error        { return nil }
func (r Report) JSON(w io.Writer) error        { return nil }

// Candidates expands the sweep. It sweeps discrete measured points and never
// binary-searches over chunk size: MEASUREMENTS.md §3.4 records a curve that is
// non-monotonic and not explained by any simple model.
func Candidates(depth string, c Classification, caps strategy.Cap) []strategy.Strategy {
	return nil
}
```

---

## Data paths

## A. HTTPS CONNECT through proxy mode — the primary path

1. Browser holds a system PAC from `http://127.0.0.1:8080/dpb.pac`. The PAC does pure string matching against the **bypass** set only (no `dnsResolve`, which would leak the name to the poisoned system resolver). `isbank.com.tr` → `"DIRECT"`, so that traffic never enters the dpb process at all. Everything else → `"PROXY 127.0.0.1:8080"` with **no `; DIRECT` fallback**, so a transient dpb error cannot silently leak an unmodified ClientHello onto the wire.
2. `proxyfe.Server` accepts, sniffs the first byte (`0x05` → SOCKS5, else HTTP), reads `CONNECT discord.com:443 HTTP/1.1`. The name arrives from the client, so the app's own poisoned resolution is irrelevant — proxy mode defeats DNS censorship for free, with zero system-DNS mutation.
3. `policy.Scope.ForName("discord.com", 443)`. Compiled-in bypass rules (`.gov.tr`, `.com.tr`, banking list, RFC1918, `media.discordapp.net`, `discord.media`) are label-anchored, so `bank.com` never matches `evilbank.com`. Then `policy.Store.Get(NetworkID, host)`: a `SrcLearnedPlain` hit → `ScopeDirect`; a `SrcLearnedDesync` hit → `ScopeDesync` with the cached spec; a miss on an inspect port → **`ScopeWatch`**.
4. `resolve.Chain.Resolve` fires A and AAAA in parallel. DoH `cloudflare-dns.com` dialled at bootstrap `1.1.1.1`/`1.0.0.1` (TLS SNI still `cloudflare-dns.com`), then DoH `dns.google` at `8.8.8.8`/`8.8.4.4`, then DoT `9.9.9.9:853`, then UDP `77.88.8.8:1253`, then UDP `9.9.9.9:9953`. TCP is never attempted at any port. Every answer runs `Detector.Check`: a `195.175.254.2` or `2a01:358:4014:a00::/64` hit is a hard reject that advances the chain, not a fallback. Answers feed `policy.ReverseMap`.
5. Dial upstream through the uplink-bound dialer with `TCP_NODELAY` set in `Control`. Wrap in `emit.NewSockTransport` — `Caps = CapStreamWrite|CapNoDelay|CapSockTTL|CapOOB`, never `CapRawSeq`.
6. **Only after the dial succeeds** write `HTTP/1.1 200 Connection established`. A dial failure becomes a clean 502 the browser can render, not a half-open tunnel.
7. `flow.ReadFirstMessage(client, 443, DefaultFirstMsgOpts())`. Wait ≤250 ms for the first byte. `0x16` → TLS: read the 5-byte header, then **loop** until `5+recLen` bytes are buffered, ≤250 ms further and ≤64 KiB. A 1601-byte X25519MLKEM768 hello arriving in two segments is fully assembled here; `Meta.Complete = true`, `Meta.SNIStart/SNIEnd` are body-relative. Nothing at all within 250 ms → `MsgServerFirst`, and we pipe both directions immediately with zero bytes buffered.
8. **Attempt 1 is always `plain` under `ScopeWatch`.** `strategy.MustParse("")` produces a one-segment Plan carrying the payload verbatim. `emit.Sender.Send` writes it. Banks, `.gov.tr` and the 24% of Turkish hosts that are fragile succeed here and are **never desynced**.
9. `flow.Pipe` starts, but nothing from upstream is forwarded to the client until either the first upstream byte arrives or the response window elapses. That window is `max(300ms, min(3 × RTT_ewma, 2s))` — the measured RST latency on TT is ~22 ms, so 300 ms is ~13× headroom while still being invisible.
10. **Escalation.** RST/EOF inside that window, with zero upstream bytes delivered → `FailResetBeforeResponse`. Close upstream, advance one ladder rung, redial, replay the *same buffered first message* under the new spec. `policy.Singleflight` keyed on `(NetworkID, host)` collapses the six parallel connections a browser opens so the ladder is walked once. Rung 2 is `tlsfrag:pos=snimid`: reframe the first record into two structurally valid records cut inside the hostname, concatenate them, and emit **one** `Write`. Measured: 18/18 immediate retries succeed, ~23 ms to a completed handshake, ~45 ms total for the first visit.
11. On the first upstream byte, `Pipe` calls `OnFirstByte` → commit. `policy.Store.Put` records `SrcLearnedDesync{spec, expires:+7d}` or `SrcLearnedPlain{expires: zero}`. After commit a later RST is reported as negative evidence but **never retried**, because retrying would duplicate delivered bytes.
12. Ladder exhausted, or the 5 s budget spent → close the client connection with an attributable error and a `ConnEvent` listing every attempt. We never fall back to "send it plain and call it success".

## B. TCP flow through TUN mode

1. Packet arrives on `utunN`. `tunfe.Link.Read(bufs, sizes, 4)` — the 4-byte AF-prefix offset contract — → `endpoint.readLoop` → `DeliverNetworkPacket`, then `pb.DecRef` so gVisor's pooled Views are released. A read error is **logged and surfaced on a channel** to the supervisor, which tears the datapath down; the previous implementation's bare `return` turned a transient failure into a permanent silent IPv4 blackout while the capture routes still pointed at a dead device.
2. gVisor `tcp.Forwarder` → `handleForward` → `CreateEndpoint` → `gonet.TCPConn`, spawned via `flow.Safe`.
3. Naming, in order: `policy.ReverseMap.Lookup(dstIP)` (we served that answer, so we usually know) → the SNI in the first message → unknown. There is **no fake-IP layer**; an unnamed flow simply gets `ScopeWatch` on an inspect port and is judged by its own ClientHello, which is exactly as safe as everything else under default-direct.
4. `Scope.ForName` / `ForAddr`. **If the port is not an inspect port, or the target is bypassed, `flow.Pipe` starts both directions immediately with no first-message read at all.** That ordering is the fix for the unconditional un-deadlined `client.Read` that deadlocked SMTP, IMAP, POP3, FTP and MySQL.
5. Otherwise dial upstream with the `IP_BOUND_IF` dialer and wrap it in the **same** `emit.SockTransport` proxy mode uses. `Caps()` is identical, so the emitter set is identical and TUN adds coverage, not techniques.
6. From here it is steps 7–12 of path A verbatim, in the same `flow.LadderRunner`. Retry is strictly cleaner here: the client's connection lives in our netstack and has been told nothing, so re-dialling upstream is entirely invisible.

## C. DNS query in proxy mode

- **Primary path: applications never resolve.** The name travels inside `CONNECT` / SOCKS5 `ATYP=domain` and we resolve it internally. For browsers that is the entire DNS defence, with **zero system-DNS mutation** — the single biggest blast-radius reduction in the design.
- **Secondary path**, for apps that resolve for themselves: `resolve.Server` listens on `127.0.0.1:5353` for **UDP and TCP**, unprivileged. Off by default; `--set-dns` points the active service at it via `networksetup`, journalled, with the original resolvers retained as secondaries so a dead dpb degrades to plaintext rather than to no DNS at all. (This is a deliberate fail-*open* on DNS, paired with fail-open PAC — see the lifecycle section.)
- On `TC=1` from a UDP resolver we re-ask a DoH resolver, never TCP. `Chain.Exchange` synthesises `SERVFAIL` on chain exhaustion instead of closing the session and making the stub wait out its own timeout.
- `AAAAAuto` allows AAAA only when a v4 path is verified and no NAT64/DNS64 is detected (probe `ipv4only.arpa`); otherwise `AAAASuppress` answers `NOERROR` with an empty answer plus SOA — never `NXDOMAIN`, which would be cached as "this name does not exist".

## D. DNS query in TUN mode

- UDP/53 reaches the netstack UDP forwarder and is served **in-process** by the same `resolve.Server`. Relaying it would hand the ISP's resolver exactly the queries DoH exists to hide.
- **TCP/53 into the tunnel is also served locally.** An app that gets `TC=1` and retries over TCP works, even though upstream TCP/53 is RST at every port, because the retry never leaves the machine. No tool in the dossier does this.
- Every A/AAAA we serve feeds `policy.ReverseMap` before the reply goes out, so the TCP flow that follows already knows the hostname.
- Our own resolver traffic cannot loop: `resolve.DialFunc` binds to the uplink and runs the ladder on the DoH/DoT ClientHello, so the resolver's own SNI is protected without routing the query back through the tunnel.

## E. UDP / QUIC datagram

1. Datagram to `X:443/UDP` → `udp.Forwarder` → name via `ReverseMap` → `Scope.ForName(name, 443)`.
2. **`QUICRefuse` (default for in-scope names):** parse the QUIC long header; if it is an Initial, emit an **ICMP port-unreachable** back through the netstack. Chrome and Firefox mark the path QUIC-broken on the first unreachable and fall back to TCP within the same RTT, where the whole measured TCP ladder applies. Relaying UDP/443 verbatim — what the previous implementation did — is strictly *worse* than proxy mode, which forces TCP fallback by accident.
3. **`QUICRelay`** (bypassed and out-of-scope names): uplink-bound connected `net.UDPConn`, one `Read`/`Write` per datagram, never `io.Copy` (a stream copy merges or truncates datagrams), with an idle reaper at 60 s because UDP has no FIN.
4. **`QUICDesync`** (opt-in, only if `dpb tune` says it helps): `SetTTL(low)` on the connected socket, send N crafted Initials with the same DCID and a benign SNI, restore the hop limit, send the real datagram, then relay. Unprivileged — only TCP fakes are compiled out of byedpi on Darwin.
5. Proxy-mode UDP rides SOCKS5 `UDP ASSOCIATE` into the identical `flow` path; `QUICRefuse` is expressed as a SOCKS5 reply of `0x02`.

## F. TUN bring-up ordering (each step verified before the next)

`ifconfig utunN <v4local> <v4peer> mtu 1500 up` + v6 ULA, verified via `net.Interfaces()` and the RIB → `route add -net default <gw> -ifscope <uplink>` (v4 and v6), **verified by reading the AF_ROUTE RIB**, and journalled as `Adopted` if it already existed → start the netstack and forwarders → `route add -net 0.0.0.0/1 -interface utunN`, `128.0.0.0/1`, `::/1`, `8000::/1`, each verified in the RIB → `/32` and `/128` host routes for capturable nameservers → point the service's resolvers at the tunnel. Teardown is the exact reverse, with the utun closed **last**, because a `route delete` naming a closed interface fails.

---

## Strategy model

## Expression

One grammar used identically by the config file, `--strategy`, probe output, log lines and `dpb why`:

```
spec := [ op ( "|" op )* ]          # empty string == "plain"
op   := ident [ ":" k "=" v ( "," k "=" v )* ]
```

Live examples:

```
                                  # plain: send the first message unmodified
tlsfrag:pos=snimid                # PRIMARY. Cut the first TLS record inside the hostname.
tlsfrag:pos=sniend-1              # the boundary case; still passes
tlsfrag:pos=snistart-20           # hostname sits complete in record 2; also passes
tlsevery:period=64                # periodic reframing; first record ends at 64
chunk:size=12                     # ladder rung 3
chunk:size=4                      # ladder rung 4
oob:pos=1                         # ladder rung 5; most destructive
hostcase|hostdot|chunk:size=12    # port 80
quicfake:count=2,ttl=4            # UDP side channel
```

`pos` accepts an absolute integer or an anchored form: `snistart`, `snistart±N`, `snimid`, `sniend`, `sniend-1`, `bodymid`, `hoststart±N`. `Pos.Resolve` returns `(int, bool)` so an unresolvable anchor is an explicit failure, never a silent zero.

## Composition

Four `Kind`s, executed in `Kind` order regardless of typed order, so `chunk:size=12|hostcase` and `hostcase|chunk:size=12` are the same strategy and canonicalise identically (sorted by `(Kind, Name)`, args sorted, defaults elided):

- **`KindMutate`** rewrites payload bytes and forces `Builder.Reparse()` so every downstream offset stays valid: `hostcase`, `hostdot`, `hostspell`, `hostpad`, `tlspad`.
- **`KindReframe`** rewrites the L5 record layer: `tlsfrag`, `tlsevery`. **At most one per spec.** Requires `Meta.Complete`.
- **`KindSchedule`** maps the final bytes onto ordered write ops: `chunk`, `split`, `disorder`, `oob`. **At most one per spec.** Absent means one write.
- **`KindSide`** emits alongside: `quicfake`.

This is the generalisation the previous single-`Emitter` model could not express. `tlsfrag` is a *reframe*, so `tlsfrag:pos=snimid|chunk:size=12` composes properly — and that composition is exactly what the prober needs to test whether record fragmentation and chunking are independent axes on a given line.

## The primary emitter, and the rule it enforces

`tlsfrag` is the shipped rung-2 emitter and the reason this plan exists. It:

1. requires `Meta.Complete` and `Meta.HasSNI()`;
2. resolves `pos` against the **record body**, not the payload;
3. calls `Meta.MaxFirstRecordEnd()` and **hard-refuses** with `ErrCutAfterSNI` if the resulting first record would end at or after `SNIEnd`;
4. calls `tlsmsg.SplitRecord` to build two structurally valid records carrying consecutive halves of the body, reusing the original 3-byte type/version prefix and writing correct 2-byte lengths;
5. emits the concatenation as **one** `Segment`, i.e. one `Write`, one TCP segment.

That step 3 is the single most important line in the codebase. `MEASUREMENTS.md` §3.5 records that the previous implementation "never verified the cut landed before `sniEnd`", and its `frag_window` knob was inert. Here the predicate is a typed error, it is asserted in golden tests at `sniEnd-1` (pass) and `sniEnd` (refuse), and it is fuzzed.

Step 5 matters too: `tlsrec2-1seg` — two records in **one** TCP segment — passes 3/3, so the emitter needs no `TCP_NODELAY` timing, no socket options, no root, no multi-write behaviour, and is structurally immune to the XNU small-write panic. It is byte-identical in proxy mode and TUN mode, and its output is a pure function testable offline.

## Validation — four gates, all before a byte moves

1. **Parse-time.** Unknown op, unknown param, malformed `pos`, out-of-range value → an error naming the offending token and listing valid alternatives. `config` decodes TOML with **unknown-key rejection**, which kills the `sni_match`-declared-and-read-nowhere class of trap.
2. **Composition.** At most one `KindReframe`, at most one `KindSchedule`; `disorder` and `oob` are **mutually exclusive on Darwin** (zapret gates the pair to Linux because other kernels retransmit the OOB byte without URG and poison the stream; byedpi's `--disoob` measures 0/8 on macOS vs 8/8 for `--oob` alone); `tlsfrag`/`tlsevery` require `Complete`; any op reading `SNIStart` requires `HasSNI()`.
3. **Capability.** `Strategy.Caps()` unions the ops' caps and `CheckAgainst(have, meta)` rejects with `Missing()` named. **A profile naming a strategy the selected transport cannot satisfy refuses to load**, with a specific message and a suggested alternative — grafted from `netstack-first`, and the categorical fix for the previous implementation's flagship profile that demanded root and then silently shipped the SNI unfragmented.
4. **Budget.** `Plan.Validate` rejects >16 segments, sub-minimum segments, or >250 ms total delay.

Two invariants are asserted on every plan and fuzzed: `StreamBytes()` must equal `Payload` (a strategy can never corrupt a stream; the worst it can do is fail to help), and `WriteCount() <= MaxSegments`.

## Capabilities per mode

| Op | Needs | Proxy | TUN | Mechanism |
|---|---|---|---|---|
| `plain`, `tlsfrag`, `tlsevery`, `chunk`, `split`, host mutators | `CapStreamWrite\|CapNoDelay` | ✓ | ✓ | `Write` on a NODELAY socket |
| `disorder` | `+CapSockTTL` | ✓ | ✓ | `IP_TTL` / `IPV6_UNICAST_HOPS`; default read from `sysctl net.inet.ip.ttl` |
| `oob` | `+CapOOB` | ✓ | ✓ | `RawConn.Write` + `unix.SendmsgN(MSG_OOB)` — `Write`'s callback returns a bool so `EAGAIN` yields to the poller (grafted from Ayar) |
| `quicfake` | `CapUDPTTL` | SOCKS5 UDP only | ✓ | connected UDP socket, low hop limit, restore |
| `fake`, `seqovl`, `fakedsplit`, `hostfakesplit` | `CapRawSeq` | **never** | **never** | requires a real `snd_nxt`; `tcp_connection_info` has no such field |
| `wssize`, `mss`, `dropsack` | — | **never** | **never** | `SO_RCVBUF=1024` still advertises ~32 KB; `TCP_MAXSEG` returns `EINVAL`; macOS BPF is a device, not a socket filter |

The middle two columns being identical is the point: TUN adds *coverage*, never techniques. The bottom two rows are **registered and always rejected with a citation**, not absent — an honest error beats a missing feature, and `CapRawSeq` lights the whole family up unchanged the day a netstack-owned upstream endpoint exists.

## Ladders as data

`strategy.Ladder("tr")` returns, in order — lifted verbatim from `MEASUREMENTS.md` §5.3:

```
1. ""                    plain — always first
2. tlsfrag:pos=snimid    6/6 bypass, 8/8 controls, rule-based, one write
3. chunk:size=12         6/6 bypass, 8/8 controls, different mechanism
4. chunk:size=4          6/6 bypass, 6/8 controls — degrades, use if 2-3 fail
5. oob:pos=1             6/6 bypass, 6/8 controls, 0/20 fragile — last rung
```

`disorder` and `split` are registered ops with full test coverage but are **absent from the TR ladder** (0/10 and 0/5 measured). They remain in the prober's sweep because another ISP may differ and the prober measures rather than assumes.

---

## System-state lifecycle

## Complete enumeration of mutated macOS state

| # | State | When | Applied by | **Verified by (different subsystem)** | Survives SIGKILL? |
|---|---|---|---|---|---|
| 1 | Auto-proxy (PAC) URL + state | proxy mode, default | `networksetup -setautoproxyurl/-setautoproxystate` | `scutil --proxy` → `ProxyAutoConfigEnable` + `URLString` | no → journal |
| 2 | `launchctl setenv HTTPS_PROXY/HTTP_PROXY/NO_PROXY` | proxy mode, default | `launchctl setenv` | `launchctl getenv` | no → journal |
| 3 | Web + secure proxy | `--proxy-style=explicit` | `networksetup -setwebproxy` etc. | `scutil --proxy` → `HTTPEnable`/`HTTPProxy`/`HTTPPort` | no → journal |
| 4 | SOCKS proxy | `--socks` | `networksetup -setsocksfirewallproxy` | `scutil --proxy` → `SOCKSEnable` | no → journal |
| 5 | PAC file on disk | proxy mode | `os.WriteFile` | stat + SHA-256 | no → journal (harmless) |
| 6 | DNS servers per service | `--set-dns`, TUN | `networksetup -setdnsservers` | `scutil --dns` nameserver list | no → journal |
| 7 | utun device + addresses + MTU | TUN | wireguard/tun `ioctl`, then `ifconfig` | `net.Interfaces()` + RIB | **yes**, automatically |
| 8 | Capture routes (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`) | TUN | `route add -interface utunN` | **AF_ROUTE RIB read** | **yes** (interface-scoped) |
| 9 | Resolver `/32`+`/128` host routes | TUN | `route add` | RIB | **yes** |
| 10 | Scoped uplink default (`-ifscope en0`) | TUN | `route add -net default GW -ifscope en0` | RIB, checking `Scoped` + `Index` | no → journal |
| 11 | launchd agent/daemon | `dpb service install` | `launchctl bootstrap` | `launchctl print` | persists by design |

**Never touched, ever:** pf, sysctl (no `net.inet.tcp.blackhole` — that is a machine-wide behavioural change other applications would feel), the firewall, Keychain, `/etc/hosts`, `/etc/resolv.conf`, `networksetup -setv6off`.

## The runner that does not believe its tools

`Result.Failed()` is `Code != 0 || liarMatch`, against a table keyed by command:

- `route` — `writing to routing socket|not in table|File exists|Network is unreachable|No such process`
- `networksetup` — `(?i)^\s*\*\*\s*Error|is not a recognized network service|^Error:`
- `ifconfig` — `(?i)ioctl \(SIOC|does not exist|Invalid argument`
- `launchctl` — `(?i)^Bootstrap failed|Load failed|Operation not permitted`

Re-verified live this session: `route -n get -inet6 2001:db8::1` prints `route: writing to routing socket: not in table` and **exits 0**. Apple's `route.tproj/route.c` has `newroute()` as `void`, `main()` does `newroute(argc, argv); exit(0)`, and `rtmsg()` only `warnx()`es — there is no failure exit path to check.

**Stderr-parsing is only the first line of defence.** The hard rule, grafted from the winner and endorsed by all three judges: **`Verify` never uses the subsystem `Apply` wrote through.** Routes are written with `route(8)` and verified by reading the kernel RIB through an `AF_ROUTE` socket — verified openable unprivileged on this machine this session (19,808 bytes, 121 messages, uid 501). Proxy settings written with `networksetup` are verified with `scutil --proxy`; DNS with `scutil --dns`; interfaces with `net.Interfaces()`. A run under a full-tunnel VPN can no longer print "Ready" while capturing nothing, because the RIB read after `route add` returns `false`.

## The journal

`~/.local/state/dpb/journal.ndjson` (root: `/Library/Application Support/dpb/`), both **SUDO_USER-aware**. One JSON object per line, `O_APPEND`, **`fsync` before the mutation is attempted**, alongside a `run.lock` holding an advisory `flock` plus pid and process start time.

```
Manager.Do(op):
  runVerifyReader                → already present and not ours? Record{Adopted:true}; Revert is a no-op
  journal.Begin(record)          → fsync BEFORE any syscall
  op.Apply
  op.Verify                      ← independent subsystem
    ok      → journal.Commit(record{applied:true, verified:true})
    not ok  → op.Revert; op.VerifyReverted; journal.Done; return a specific error
```

A SIGKILL between `Begin` and `Apply` leaves an over-approximate journal, which is the safe direction: every `Revert` is idempotent and `VerifyReverted` tolerates already-absent state.

Two properties carried forward deliberately:

- **`Adopted`.** Run the verifier *before* applying. If the state already exists and we did not create it — a VPN's `-ifscope` default, an admin-set PAC, a previous run's route — record `Adopted:true` and make `Revert` a no-op. This is what stops Ctrl-C from deleting a VPN's routes, and it turns the previously-unreachable `File exists` adoption branch into a first-class tested state.
- **`notSelf`.** A captured proxy/DNS backup that already points at our own listener (leftover from a hard kill) is recorded as *off*, so `Restore` disables rather than pinning the user to a dead port forever.

## Every exit path

| Path | Mechanism |
|---|---|
| **SIGINT / SIGTERM / SIGHUP / SIGQUIT** | `signal.NotifyContext` covers all four — SIGHUP matters because closing the terminal sends HUP, not INT. Teardown runs on a **fresh `context.Background()`** with a 10 s budget, never the cancelled one, in reverse order: system settings → routes *while the utun still exists* → netstack → device. A second Ctrl-C within 3 s force-exits and prints the journal path. |
| **Panic in a connection goroutine** | Every per-connection goroutine is spawned by `flow.Safe`, which `recover()`s, emits a panic event with the stack, and kills that connection only. **A lint test fails the build on a bare `go ` in `front/`, `flow/` and `resolve/`** — Go runs only the panicking goroutine's defers, so this is the only thing that makes the restoration promise true. |
| **Panic on the main goroutine** | Top-level `defer func(){ if r := recover(); r != nil { teardown(); panic(r) } }()` — state is reverted before the stack dump. |
| **SIGKILL / power loss** | Four overlapping defences. (a) Interface-scoped routes vanish with the utun. (b) The **janitor child** — `dpb _janitor --parent-pid N --journal PATH` blocks on a kqueue `EVFILT_PROC`/`NOTE_EXIT` and replays the journal the moment the parent dies (~120 lines, grafted from `netstack-first`; the only in-process answer that does not wait for the next login). (c) A `RunAtLoad` LaunchAgent runs `dpb doctor --repair --quiet` at every login. (d) `Replay` reverts every pending record whose owning pid is not a live dpb, comparing pid **and** start time via `ps -o lstart=,comm=` so a healthy concurrent run is never clobbered. |
| **The residue itself is benign** | PAC is the default proxy mechanism *because* macOS treats an unfetchable auto-proxy URL as `DIRECT`. Process death fails **open**; an explicit web/secure proxy fails **closed** into a total outage. Same asymmetry for DNS: `--set-dns` writes `127.0.0.1` followed by the original resolvers, so a dead dpb degrades to plaintext DNS in ~1 RTT rather than to no DNS at all. |
| **Network change** | `netwatch` `PF_ROUTE` reader, 750 ms debounce → re-collect `Facts` → if `NetworkID` changed, quiesce (stop accepting, drain, swap the verdict namespace), **re-verify every applied Op against the RIB/scutil** (macOS flushes interface routes on link change), re-apply what went missing, re-run the portal probe, resume. If the uplink vanished, remove capture routes (fail open) and wait. |
| **Sleep / wake** | Primary signal is the `PF_ROUTE` churn on wake. Secondary is a 5 s ticker comparing wall-clock delta to Go's monotonic clock; a gap > 10 s means we slept. **Correctness does not depend on the secondary** — it only makes recovery faster. On wake: same revalidation, plus close all idle upstream sockets and drop negative DNS cache entries. |
| **Captive portal** | `netwatch.PortalWatcher` (204 canary + DNS-uniformity heuristic) → suspend: `Scope` returns `ScopeDirect` for everything, capture routes are removed, the PAC is regenerated to all-`DIRECT`. Resume when the canary clears. |
| **VPN appears underneath us** | Default-route change → re-scope. A pre-existing scoped default is `Adopted` and never deleted. A full-tunnel VPN we cannot scope past → stop with a clear message and exit code 5, rather than reporting success. |
| **`dpb off` / SIGUSR1** | Kill switch without process exit: everything goes `ScopeDirect`, routes removed, PAC all-`DIRECT`. `dpb on` restores. |
| **`dpb panic`** | Full `UndoAll` then `os.Exit(0)` — the "get me back to normal now" button. |

---

## Probing and runtime adaptation

## `dpb tune` — six phases, exhaustive by default, scored on two axes

**Phase 0 — environment.** `NetworkID`, uplink, gateway, MTU, v4/v6 reachability, VPN state, NAT64 detection, captive-portal check. If a portal is active or the network is unreachable, stop: no result taken behind a portal is trustworthy.

**Phase 1 — DNS transport matrix.** For each transport × {1 control name, 3 blocked names}, record answer / timeout / sinkhole / rcode. This re-derives GT2/GT3/GT4 on the user's own line rather than trusting them:

```
                        cloudflare.com   discord.com   discord.gg   roblox.com
  system resolver            ok           SINKHOLE      SINKHOLE       ok
  udp 8.8.8.8:53             ok           timeout       timeout        ok
  udp 77.88.8.8:1253         ok           ok            ok             ok
  udp 9.9.9.9:9953           ok           ok            ok             ok
  tcp 8.8.8.8:53             RESET        RESET         RESET        RESET
  dot 1.1.1.1:853            ok           ok            ok             ok
  doh cloudflare-dns.com     ok           ok            ok             ok
```

Output is a **reordered resolver chain** written into the tuned profile. No packet strategy fixes a poisoned resolver, so if DoH, DoT and both alt ports all fail, report and stop.

**Phase 2 — baseline and block-shape.** Every target is dialled **by pinned IP**, never by hostname — `MEASUREMENTS.md` §5.4 records that the first run of the compatibility matrix scored every emitter 0/6 because Go's resolver returned the BTK sinkhole and the connection reached the sinkhole rather than the origin.

1. Connect to the resolved IP with a **benign SNI** (the GT1 experiment). Failure → **`ShapeIPBlock`**: report honestly that no desync can help, and stop. Grafted from `probe-first`; it is the single most valuable honest output the tool can produce.
2. Connect with the real SNI, no strategy. Success → the target is **not blocked here**; drop it from the intersection and say so. GT20's reopening trend (Roblox unblocked after 680 days) makes this a live condition, not a formality.
3. Measure RST latency and whether the RST precedes or follows the server's ACK.

**Phase 3 — mechanism classification (~30 s).** Not brute force; an experiment where each outcome partitions the hypothesis space.

| Probe | If it passes |
|---|---|
| `tlsfrag:pos=snimid` | the DPI is first-record-only → record fragmentation is the axis |
| `split:pos=snimid` (2 TCP segments, hostname straddled) | the DPI does **not** reassemble TCP → segment splitting also works |
| binary search over `tlsfrag` cut position | yields `FirstRecordLimit`; on TT it converges on `sniEnd-1` |
| `tlsevery:period=N` sweep | confirms the limit is about the *first* record, not about record count |
| ClientHello padding sweep (SNI pushed to 300/600/1200/1500 B) | yields `InspectBytes`; a working pad near the MTU means the DPI is not reassembling |
| `chunk:size=1` | if even this fails, TCP-level shaping is not the axis at all |

The classification **narrows the search order**, never the search set, unless `--space` is passed explicitly.

**Phase 4 — the ladder run, on two axes.** Candidates come from `probe.Candidates`, sweeping **discrete measured points only** — never a binary search over chunk size, because §3.4's curve is non-monotonic and unexplained by any model:

- `chunk:size` ∈ `{1,2,3,4,5,8,12,20,35,40,60,120}` — exactly the points measured in runs A and B
- `tlsfrag:pos` ∈ `{snistart-20, snistart-1, snistart, snistart+1, snimid, sniend-1}`
- `tlsevery:period` ∈ `{16, 64, 128, 256}`
- `split:pos` ∈ `{1, 2, 3, 5, snimid}`, `disorder:pos` ∈ `{1, 3, snimid}`, `oob:pos` ∈ `{1, 3}`
- composites: `tlsfrag:pos=snimid|chunk:size=12`, `tlsevery:period=64|chunk:size=4`
- port-80 rungs: `hostcase|hostdot|chunk:size=12`, `hostpad` as a diagnostic

Each candidate runs against **every blocked target, every fragile target and every control**, `--reps 3` (the reps `MEASUREMENTS.md` used throughout), fresh 4-tuple per attempt, 400 ms cooldown, bounded concurrency 4, trials shuffled.

**Statistical hygiene, grafted wholesale from `probe-first`:**

- A control probe is interleaved in **every round**. Rounds where the control failed are **discarded and retried**, never scored as a strategy failure. `NoiseRate` = discarded ÷ attempted, and is reported.
- `VerdictLocalError` (a `Strict`-mode downgrade, a DNS failure, our own bug) is discarded, never attributed to a strategy. `VerdictHandshakeFail` (TLS alert, bad cert) likewise — that is a server condition.
- `VerdictPass` means the **TLS handshake completed and the certificate validates for the name** — not "TCP connected", not "bytes came back". This rules out a half-open connection and a transparent block page.
- Ranking key is the **95% Wilson score lower bound**, so 9/9 across three targets (~0.70) automatically outranks 3/3 against one (~0.44); the statistics themselves push toward the intersection.
- Elimination-only early exit: 0/2 on the first blocked target eliminates a candidate. **Never short-circuit on success** — blockcheck's own summary warns that greedy early exit makes the cross-domain intersection untrustworthy.

**Phase 5 — ranking.** `probe.Rank` orders by, in strict precedence:

1. **control pass rate** — does the ordinary internet still work;
2. bypass Wilson lower bound;
3. **determinism** — a rule (`tlsfrag`, whose correctness follows from `firstRecordEnd <= sniEnd-1`) beats an empirical constant (`chunk:size=12`, which worked today);
4. fragile-host pass rate;
5. fewer segments (latency, and the XNU write-volume guard);
6. median latency;
7. lexicographic, for run-to-run stability.

Applied to the measured data this reproduces `MEASUREMENTS.md` §5.3 exactly: `tlsfrag` and `chunk-12` tie on controls at 8/8, `tlsfrag` wins on determinism; `chunk-4` and `oob` fall to 6/8 controls and land below both.

**Fragile targets are scored, never disqualifying.** This is the correction to `probe-first`'s design: §5.1 shows *"No emitter is both a bypass and universally safe"*, so a hard disqualifier would eliminate every candidate and return nothing. The fragile axis is reported per-strategy, feeds ranking at key 4, and — critically — is *not* load-bearing at runtime, because default-direct means fragile hosts are never desynced in the first place.

**Phase 6 — write and act.** `~/.config/dpb/tuned.toml` carries the winner, the runner-up ladder, the reordered resolver chain, the `Classification`, the full trial matrix, the `NetworkID` and a `confidence` label (`high` = ≥3 blocked targets × ≥3 reps all passing, controls clean, noise < 5%). The command **terminates in a state, never in advice**: if nothing works it still writes the least-bad candidate, marks `confidence: low`, and offers exactly two next actions. `--json` emits the whole session; `--export` prints one pasteable line.

Targets are **data**: seeded `discord.com`, `discord.gg`, `cdn.discordapp.com` (all measured blocked), controls `cloudflare.com` pinned to `162.159.128.233` (same IP as `discord.com` — GT1's trick isolates the SNI variable from every routing variable), fragile set seeded with the 10 measured regressors. `media.discordapp.net` and `discord.media` are excluded from the blocked set: both reach the origin (401, 520).

## Runtime adaptation

`dpb tune` is a five-minute event; the ladder runs continuously and matters more.

- **Default `ScopeWatch` on inspect ports.** Attempt 1 is always `plain`. Escalate only on `FailResetBeforeResponse`/`FailTimeoutBeforeResponse` with **zero upstream bytes delivered to the client**. Validated on the wire: 18/18 immediate retries succeed with no delay inserted, ~45 ms total first visit, and the DPI does not escalate to IP-level blocking, does not penalise the source, and carries no state between flows (§6).
- **Cache both outcomes.** `SrcLearnedPlain` **never expires** — it is self-revalidating at zero cost, because a plain flow that later starts RSTing simply escalates. `SrcLearnedDesync` expires in **7 days**, well inside GT21's months-scale rot cadence, so a lifted block (GT20) is rediscovered. Namespaced by `NetworkID`, persisted atomically, LRU-capped at 4096.
- **Demote.** Three consecutive failures on a cached winner reset the host to unknown and re-walk **from `plain`**. Plus an opportunistic 1-in-20 demotion probe per host per 24 h.
- **Drift.** `observ.Counters` watches the escalation rate. When more than two thirds of in-scope hosts in a rolling window escalate past the persisted default, a `DriftReport` fires: `dpb status` shows *"your ISP's DPI likely changed — run `dpb tune` (~3 min)"* with the new winners listed. `--auto-tune` runs a single-flighted 45 s mini-tune in the background and hot-swaps the winner without dropping live connections.
- **`dpb apply '<spec>'`** (grafted from `probe-first`): import a strategy someone pasted in a forum or Telegram, validate it, **re-verify it locally against your own targets**, and only then write it. Zero infrastructure, zero privacy cost, and it matches how these communities already share.

---

## CLI surface

```
dpb run                          Start the bypass. No sudo unless --tun.
  --profile NAME                 global | turkey | tuned      (default: tuned if fresh, else turkey on TR locale)
  --config PATH                  ~/.config/dpb/config.toml
  --listen ADDR                  127.0.0.1
  --port N                       8080      (also serves /dpb.pac; 0 disables the HTTP listener)
  --socks-port N                 1080      (0 disables SOCKS5)
  --socks-udp                    true      SOCKS5 UDP ASSOCIATE — the unprivileged QUIC path
  --proxy-style pac|explicit|env|both|none     (default: both = pac + launchctl setenv)
  --set-dns off|on               (default: off in proxy mode, on in --tun)
  --dns-port N                   5353      (loopback resolver; 53 under root)
  --strategy SPEC                force one strategy for every in-scope host
  --ladder NAME|SPEC,SPEC,...    override the escalation ladder
  --mode watch|always|never      (default: watch — plain first, escalate on reset)
  --max-attempts N               5
  --attempt-budget DUR           5s
  --max-segments N               16        XNU small-write guard
  --inspect-ports 443,80
  --bypass HOST|CIDR[,...]       add to the hard-veto list (label-anchored)
  --bypass-file PATH
  --include HOST[,...]           if set, ONLY these names are ever escalated
  --dns-doh URL / --dns-udp ADDR prepend a resolver
  --ipv6 auto|allow|suppress     (default: auto)
  --quic refuse|relay|desync     (default: refuse for in-scope names)
  --tun                          also start the TUN front-end (requires root)
  --tun-name NAME / --mtu N      utun / 1500
  --allow-vpn                    proceed when a VPN owns the default route
  --no-learn                     disable the per-host verdict cache for this run
  --dry-run                      print every mutation that WOULD be applied; apply none
  -v / -vv / --log-json / --log-file PATH

dpb tune [target ...]            Measure this line and write a profile.
  --control HOST[,...]           default: cloudflare.com pinned to the first target's IP
  --fragile HOST[,...]           default: the 10 measured Turkish bank/gov regressors
  --reps N                       3
  --depth quick|full|paranoid    (default: full)
  --concurrency N / --cooldown DUR / --budget DUR      4 / 400ms / 8m
  --space full|record|chunk|'custom:...'
  --no-classify
  --write / --no-write           (default: --write, with a confirmation)
  --json / --export
  --dns-only                     run phase 1 and stop

dpb probe --host HOST            One-shot verdict. The debugging instrument and the FIRST runnable slice.
  --addr IP                      pin the destination; skip resolution
  --strategy SPEC                default: "" (plain)
  --reps N / --port N            5 / 443
  --json

dpb apply 'SPEC'                 Import a shared strategy: validate, RE-VERIFY locally, then write.

dpb why HOST [--port N] [--json]        Full decision chain: input, punycode, every rule that
                                        matched with file:line provenance, the effective verdict,
                                        and recent connection outcomes.
dpb status [--json] [--watch]           Running? mode? strategy? cache hit rate? last tune +
                                        confidence? DNS chain health? drift suspected?
dpb coverage [--watch DUR] [--fix]      Which proxy sources are set, and which processes actually
                                        connected (via lsof).
dpb doctor [--repair] [--full] [--json] Environment audit, capability report with reasons, poison
                                        preflight, journal drift; --repair replays the journal.

dpb on | dpb off | dpb panic            Kill switch / full restore-and-exit.
dpb reload

dpb scope list [--effective] | add HOST | remove HOST | bypass HOST|CIDR | unbypass HOST | test HOST
dpb strategy list | explain SPEC | plan SPEC --sample tls|http [--sni HOST] | validate SPEC
dpb dns check | resolve HOST [--trace]
dpb cache list | forget HOST | clear | export
dpb selftest [--model NAME]             Run the censor-simulator matrix in the shipped binary.
dpb service install [--system] | uninstall | start | stop | status | logs
                                        launchctl enable / bootout / bootstrap — never load -w.
dpb version [--json]
dpb _janitor --parent-pid N --journal PATH   (hidden)

exit codes: 0 ok · 1 error · 2 usage · 3 doctor check failed · 4 needs root ·
            5 refused for safety (VPN owns the default route, captive portal, IP-level block)
```

Three deliberate choices. **`--proxy-style` defaults to `both`** — the PAC covers CFNetwork and Chromium/Electron, `launchctl setenv` covers reqwest/curl/Go/Python/Node, which `otool`/`strings` on `updater.node` shows is what Discord's macOS updater actually reads. **`--set-dns` defaults to off in proxy mode**, because proxied clients hand us names; that keeps the unprivileged blast radius at two reversible mutations. **`--tun` is a flag on `run`, not a mode string**, because TUN is additive: `dpb run --tun` runs the proxy listeners *and* the tunnel, which is the shape of the architecture.

---

## Shipped defaults

Every value below is traceable to a first-hand measurement, a verified system fact, or an explicit dossier instruction. Where a number is *not* measurable, it is labelled unmeasured and given a structural justification.

## Shipped default configuration (`internal/config/embed/global.toml`)

| Setting | Value | Traced to |
|---|---|---|
| `mode` | `watch` (plain first, escalate on reset) | MEASUREMENTS §5.2: "Desync must **not** be applied unconditionally… This is byedpi's `--auto=torst` model; the measurements above show it is not an optimisation but a correctness requirement." |
| `inspect_ports` | `443, 80` | §1: the measured block is SNI-keyed on 443. Port 80 carries the `hostcase`/`hostdot` mutators. |
| `max_attempts` | `5` | §5.3 defines a five-rung ladder; the budget must reach the last rung. |
| `attempt_budget` | `5s` | §6: plain→RST ~22 ms, desync retry ~23 ms, total first visit ~45 ms. Five rungs ≈ 115 ms; 5 s is ~40× headroom and well under any browser CONNECT timeout. |
| `first_byte_wait` | `250ms` | DOSSIER §2's corrected relay: `readFirstMessage(client, 250*time.Millisecond, 64*1024)`. |
| `complete_wait` | `250ms` | Same source. A post-quantum hello spans two segments = one extra RTT; measured RTT to origin is ~22–29 ms, so 250 ms is ~10× margin. |
| `first_msg_max` | `64 KiB` | DOSSIER §2 (`64*1024`). |
| `response_wait` | `max(300ms, min(3×RTT_ewma, 2s))` | §6: RST arrives at ~22 ms, so 300 ms is ~13× headroom. The RTT term adapts on high-latency mobile; the 2 s cap bounds the worst case. |
| `max_segments` | `16` | DOSSIER §3: "Cap segments at 16." |
| `default_ttl` | read from `sysctl net.inet.ip.ttl` | DOSSIER §3: "read the real default TTL rather than hardcoding 64." **Verified on this machine: `net.inet.ip.ttl: 64`.** Read, never assumed. |
| `small_write_rate` | `512/s`, burst `64` — **UNMEASURED** | GT13 gives no threshold; no public report quantifies the XNU trip point. Structural justification: the primary emitter (`tlsfrag`) emits **exactly one write**, so it can never reach the governor; only ladder rungs 3–5 can, and they are reached only after `tlsfrag` fails. Configurable, coalescing rather than blocking. Honest status: a guard, not a calibration. |
| `verdict_ttl_plain` | never expires | Self-revalidating at zero cost: a `plain` flow that starts failing escalates on its own. |
| `verdict_ttl_desync` | `7d` | GT21: TR DPI rots on a months-scale cadence. GT20: Roblox was unblocked after 680 days, so a lifted block must be rediscovered. 7 days is comfortably inside the rot cadence. |
| `verdict_cache_cap` | `4096` LRU | Sizing choice, not a measurement. Stated as such. |
| `udp_idle` | `60s` | UDP has no FIN; an unreaped session leaks two goroutines and a socket. Sizing choice. |
| `quic` | `refuse` for in-scope names | GT18 / DOSSIER P2: "The working Discord recipe for Turkey requires manually passing `--disable-quic`"; relaying UDP/443 verbatim is worse than proxy mode. |
| `ipv6` | `auto` | GT19 (BTK-registered v6 sinkhole) plus the brief's Turkish-mobile requirement; blanket AAAA suppression on a 464XLAT carrier is a total outage, so suppression is gated on positive evidence and NAT64 detection. |
| `proxy_style` | `both` (PAC + `launchctl setenv`) | PAC because macOS treats an unfetchable auto-proxy URL as `DIRECT`, so process death fails open. `setenv` because `otool -L`/`strings` on `updater.node` shows an in-process reqwest addon whose only proxy sources are `HTTP(S)_PROXY`/`NO_PROXY`. |
| `set_dns` | `off` in proxy mode | Proxied clients hand us names inside CONNECT; this keeps the unprivileged blast radius at two reversible mutations. |

## The `turkey` profile (`internal/config/embed/turkey.toml`)

**Ladder** — lifted verbatim from `MEASUREMENTS.md` §5.3, each rung with its measured two-axis score:

| # | Spec | bypass | controls | fragile | Traced to |
|---|---|---|---|---|---|
| 1 | `""` (plain) | 0/6 | 8/8 | 20/20 | §5.1 — always first; banks and `.gov.tr` never leave this rung |
| 2 | `tlsfrag:pos=snimid` | **6/6** | 8/8 | 1/20 | §3.2 `sniMid` 3/3 × 2 targets; §5.1 `tlsrec-mid-sni`; §3.3 "strictly dominant cut position" — it satisfies the record rule *and* splits the hostname, so it also defeats a naive raw-stream matcher |
| 3 | `chunk:size=12` | **6/6** | 8/8 | 14/20 | §3.4 run A and run B both PASS at 12; §5.1 `chunk-12` |
| 4 | `chunk:size=4` | **6/6** | 6/8 | 13/20 | §3 `chunk-4` 3/3 × 3 targets; §3.4 run A and B both PASS at 4; §5.1 |
| 5 | `oob:pos=1` | **6/6** | 6/8 | 0/20 | §3 `oob-at-1` 3/3 × 3 targets; §5.1 — "powerful but the most destructive; last rung" |

**Not in the ladder, and why** — each is a registered, tested op available to the prober:

- `chunk:size=5` — **FAIL** in §3.4 run A. This is the number both `netstack-first` and `unprivileged-first` shipped as their default, imported from SpoofDPI; §3.5 warns "Strategy parameters are not portable between implementations."
- `chunk:size=40` — 0/3 × 3 targets (§3); FAIL in run B.
- `split:*` (any plain TCP split) — 0/5, including one cut inside the hostname (§3.1: "The DPI reassembles TCP").
- `disorder:*` — 0/10 (§3.5). The socket mechanism works on Darwin (GT11); it simply does not defeat this DPI.
- `tlsevery:period=256` — 0/3 (§3), consistent with the rule (first record ends at 256 > `sniEnd-1` = 121).
- `disorder` + `oob` together — rejected at validation on Darwin (GT12).

**DNS chain**, in order:

1. DoH `https://cloudflare-dns.com/dns-query`, bootstrap `1.1.1.1`, `1.0.0.1` — GT4, ~26k OONI measurements with 0 confirmed blocks, corroborated live.
2. DoH `https://dns.google/dns-query`, bootstrap `8.8.8.8`, `8.8.4.4` — GT4.
3. DoT `9.9.9.9:853` — GT4 ("DoT/853 connects").
4. UDP `77.88.8.8:1253` — §2: `dig -p 1253 @77.88.8.8 discord.com` → `162.159.128.233, 162.159.136.232`.
5. UDP `9.9.9.9:9953` — §2: → `162.159.135.232, 162.159.128.233`.

`allow_tcp53 = false`, structurally — §2: both `dig +tcp @8.8.8.8` and `dig +tcp -p 1253 @77.88.8.8` are connection-reset.

**Poison sentinels:** `195.175.254.2` (§2, the ISP resolver's answer for every blocked name) and `2a01:358:4014:a00::3` (GT19, RIPE netname BTK).

**Compiled-in bypass list** (hard veto, extendable but not removable): the 10 measured regressors (`akbank.com`, `isbank.com.tr`, `yapikredi.com.tr`, `ziraatbank.com.tr`, `vakifbank.com.tr`, `denizbank.com`, `turkiye.gov.tr`, `gib.gov.tr`, `mhrs.gov.tr`, `btk.gov.tr`) plus `.gov.tr`, `.com.tr`, `google.com`, `googleapis.com` (GT22, zapret-win-turkey's `excludelist.txt` verbatim), `discordapp.net` (GT22, desync corrupts large CDN transfers), and RFC1918 / loopback / link-local CIDRs. Note that under default-direct this list is a **belt-and-braces** layer, not the primary defence — §5.2: "a shipped exclusion list cannot be the answer — 24% of the tested hosts are fragile, and no hand-maintained list covers the Turkish long tail."

**Prober seeds:** blocked = `discord.com`, `discord.gg`, `cdn.discordapp.com` (§1, all confirmed blocked). Control = `cloudflare.com` pinned to `162.159.128.233` (§1 / GT1 — same IP, benign SNI, returns 301). Fragile = the 10 regressors. Explicitly **not** blocked targets: `media.discordapp.net` (401) and `discord.media` (520) — both reach the origin (§1), and shipping them as targets would make the prober chase a block that does not exist.

**Prober parameters:** `reps = 3` (the rep count used throughout `MEASUREMENTS.md`), `cooldown = 400ms` (§6 shows the DPI is stateless between flows, so this is anti-noise, not anti-escalation), `concurrency = 4`, chunk sweep = the exact set measured in runs A and B.

---

## Test strategy

The previous tree had 51.5% statement coverage with **every confirmed defect inside a 0.0%-covered function**: `tun.NewServer`, `handleForward`, `relay`, `applyDesync`, `pipe`, all of `rawinject_darwin.go`, all of `device_darwin.go`, and `proxy.handleHTTP`. Its only end-to-end test was behind `//go:build e2e` and excluded from the default run. That is a *design* failure, not a discipline failure: those paths were welded to root, to a kernel device, and to a censored network. Five structural decisions fix it.

**1. The technique layer is pure, so it is fully testable with zero I/O.** Every op is `(payload, Meta, params) → Plan`. Golden tests assert the exact segment list for ~40 specs × 5 canned hellos (classic RSA; TLS 1.3 minimal; the real 1601-byte X25519MLKEM768 hello; one with the SNI deliberately at a chunk boundary; one with no SNI). Three invariants run on **every** op and are fuzzed:

- `FuzzPlanPreservesPayload(payload, spec)` — `Plan.StreamBytes()` equals `Plan.Payload` (OOB junk excluded). Catches stream corruption categorically.
- `Plan.WriteCount() <= Budget.MaxSegments` — the XNU guard as an invariant, not a comment.
- `TestParameterIsLive` (grafted from Ayar) — sweep every numeric parameter of every op and assert the output bytes actually change. This mechanically kills the `frag_window` class of defect, where "the one knob you tell a Turkish user to reach for does nothing on the recommended emitter."

**2. The measured rule is a falsifiable test, and it is the centrepiece.** `TestTLSFragRefusesCutAtOrAfterSNIEnd` drives `tlsfrag` at every cut in `MEASUREMENTS.md` §3.2 against a `Meta` with `body=1497, sni at [112,122)` and asserts: `sniStart-20`, `sniStart-1`, `sniStart`, `sniStart+1`, `sniMid`, `sniEnd-1` all produce a valid two-record plan; `sniEnd`, `+1`, `+20`, `+200` all return `ErrCutAfterSNI`. `TestTLSEveryFirstRecordLimit` asserts `period=16` and `period=64` are accepted and `period=256` is refused. **Fourteen measured data points, one predicate, checked on every CI run.** Unlike `probe-first`'s fixture, this asserts *our validator against the measurement* — it cannot break because the network changed, only because the code regressed.

**3. `internal/testcensor` — a censor you can run in-process.** A `Middlebox` interposes on a loopback relay, reads segments as they arrive, applies a `Model`, and injects an RST or drops. The models are hypotheses with doc comments naming their source and confidence:

- `TT2026()` — `RecordAware: true, FirstRecordOnly: true, ReassembleTCP: true`. It matches only if the SNI is complete within the **first TLS record**, which is the §3.2 mechanism. Scenario tests then read as claims: `tlsfrag:pos=snimid` evades, `split:pos=snimid` does **not** (TCP reassembly), `chunk` results depend on where boundaries fall, `tlsrec2-1seg` evades (TCP framing irrelevant).
- `Fragile()` — a TLS terminator that rejects a handshake message spanning two records with `illegal parameter`, modelling `yapikredi.com.tr`. Asserts that `ScopeWatch` reaches it on rung 1 and **never escalates**.
- `DNSCensor()` — per-QNAME UDP drop, sinkhole answers from the ISP resolver, TCP/53 reset at every port.
- `testcensor.CheckIntegrity` (grafted from `netstack-first`) — across the full strategy × model cross product, the bytes the receiving TCP reassembles must equal the bytes the client wrote. A bypass tool that corrupts a stream is worse than no tool.

**4. `pipeLink` — the whole gVisor stack in `go test`, no root, no utun.** `Link` is an interface implementing exactly wireguard/tun's narrowed contract; `link_darwin.go` is the *only* untestable file, ~50 lines of `CreateTUN`/`Name`/`MTU`/`Close` with no logic. A test wires a second netstack as the client:

```
clientStack ──pipeLink── tunfe.Server ──fakeDialer── testcensor ── origin
```

Specific regressions pinned here: server-first protocols (SMTP/IMAP/POP3/FTP/MySQL greetings must reach the client within `FirstByteWait` with **zero** bytes buffered and `MsgServerFirst` returned); a ClientHello split across two injected segments must be fully reassembled before planning; `readLoop` errors must be logged and surfaced, not silently returned; `WritePackets` must release gVisor's pooled Views (asserted with a leak counter); `Events()` must be drained; half-close must propagate; a panic inside a relay goroutine kills the connection and not the process.

**5. `netstate` against captured reality, and a SIGKILL fuzzer.** `testnet.ScriptRunner` is driven by outputs captured from this machine — including the load-bearing one: `route` printing `writing to routing socket: not in table` and **exiting 0**, with a test asserting `Result.Failed() == true` despite `Code == 0`. `testnet.ribfake` implements `RIBReader` so `Verify` is testable in both directions. `testnet.killfuzz` runs `dpb run --dry-run` in a subprocess against the fake system, SIGKILLs it at 500 pseudo-random offsets, runs `Replay`, and asserts the fake system is byte-identical to baseline and the journal is empty. A chaos table injects a failure at each of Begin/Apply/Verify/Commit/Revert/VerifyReverted for every Op type and asserts no state leak, convergence after `Replay`, and that an `Adopted` record is **never** reverted (with a pre-seeded VPN scoped-default in the fake RIB).

**Additional gates.**

- `TestNoHostnameDial` — a build-gate AST walk asserting no `net.Dial`/`net.DialContext`/`tls.Dial` with a hostname argument exists outside `internal/resolve`. This is `MEASUREMENTS.md` §5.4 encoded: the compatibility matrix's first run scored every emitter 0/6 because Go's resolver returned the BTK sinkhole, and "every outbound dial in the implementation must resolve through the tool's own chain."
- `TestNoBareGoroutine` — an AST walk failing the build on a bare `go ` statement in `front/`, `flow/` and `resolve/`.
- Retry transparency: a censor that resets rungs 1 and 2 and accepts rung 3 must produce a client stream with **no duplicate and no missing bytes**, and `Outcome.Pre` replayed in order. A companion asserts a non-idempotent plaintext POST is never retried, and that a reset *after* the origin has sent data produces a visible error and no retry.
- Fuzzing: `FuzzParse`, `FuzzSplitRecord`, `FuzzParseHTTPHost`, `FuzzParseQUICInitial`, `FuzzSpecRoundTrip`, `FuzzMatchLabel` (pinning `bank.com` ≠ `evilbank.com`). 60 s per target in CI, longer nightly.
- Prober correctness: against `TT2026()` the search must converge on `tlsfrag`; against a no-censorship-plus-30%-loss model it must report "nothing is blocked here" (exit 4) and **not invent a winner**; `Rank` must refuse a candidate that passes target A and fails target B even when A was probed first.
- Everything under `-race`; a `-count=500` soak of the CONNECT path and of the escalation/commit state machine, whose race (first upstream byte vs. retry decision) gets a dedicated deterministic test with a controllable clock and a scripted upstream.
- **`make cover-gate` fails the build if any function in `flow`, `strategy`, `ops`, `emit`, `tlsmsg`, `front/proxyfe`, `front/tunfe`, `netstate`, `policy`, `resolve` or `probe` is at 0.0%**, and if per-package statement coverage drops below 85% (70% for `front/tunfe` and `netstate`, whose syscall leaves are covered by root-gated integration tests). Making 0% a build failure is the cheapest structural defence against repeating the previous tree's defining property.
- The `//go:build e2e` tag is **deleted**; those tests run in `go test ./...`.

**What is honestly untestable offline:** whether a strategy defeats real Turkish DPI. `testcensor` tests our *model* of the DPI, not the DPI. `dpb tune --json` is the field-report format, `go test -tags live` runs a small live suite for a maintainer on a Turkish line, and the README states the models are hypotheses. Likewise the XNU panic is destructive to test and needs a spare machine, so we test the *guard* (`MaxSegments`, the governor's coalescing under 200 concurrent `chunk:size=1` connections) rather than the panic.

---

## Milestones

### M0 — Foundation: module, logging, paths, goroutine discipline

**Depends on:** nothing

**Goal.** Stand up the skeleton every other milestone builds on: module layout, leveled logger with an NDJSON event sink, SUDO_USER-aware path resolution, buildinfo, flow.Safe, and the two AST build-gates (no bare goroutine, no hostname dial) so they fail on day one rather than being retrofitted.

**Files.**

- `cmd/dpb/main.go`
- `internal/buildinfo/buildinfo.go`
- `internal/observ/log.go`
- `internal/observ/events.go`
- `internal/observ/bus.go`
- `internal/observ/redact.go`
- `internal/paths/paths.go`
- `internal/flow/safe.go`
- `internal/flow/nohostdial_test.go`
- `Makefile`
- `.github/workflows/ci.yml`

**Done when.** `go build ./... && go vet ./... && go test ./... -race` all exit 0. `make cover-gate` runs and reports (vacuously passing). A deliberately-added bare `go func(){}()` in internal/flow makes `go test ./internal/flow/` fail with a message naming the file and line; a deliberately-added `net.Dial("tcp", "example.com:443")` outside internal/resolve does the same.

### M1 — Pure parsers: tlsmsg and httpmsg

**Depends on:** M0

**Goal.** Implement Meta, Classify, Parse, Need, SplitRecord and the HTTP header parser. The load-bearing deliverable is Meta.MaxFirstRecordEnd() plus body-relative SNIStart/SNIEnd, because every downstream correctness claim rests on them.

**Files.**

- `internal/tlsmsg/tlsmsg.go`
- `internal/tlsmsg/clienthello.go`
- `internal/tlsmsg/record.go`
- `internal/tlsmsg/quic.go`
- `internal/tlsmsg/fuzz_test.go`
- `internal/tlsmsg/testdata/pq_1601.bin`
- `internal/tlsmsg/testdata/classic.bin`
- `internal/tlsmsg/testdata/nosni.bin`
- `internal/httpmsg/parse.go`
- `internal/httpmsg/mangle.go`
- `internal/httpmsg/idempotent.go`

**Done when.** `go test ./internal/tlsmsg/ ./internal/httpmsg/ -race -cover` passes with >=90% statements. A table test parses the captured 1601-byte X25519MLKEM768 hello and asserts body=1497 with the SNI extent matching the ruleprobe observation, and asserts Complete flips from false to true at exactly the 5+recLen byte boundary when fed one byte at a time. `go test -fuzz=FuzzParse -fuzztime=60s ./internal/tlsmsg/` finds no panic and no out-of-range read.

### M2 — Strategy core: spec, plan, builder, registry, validator

**Depends on:** M1

**Goal.** Specs become canonical, round-tripping values that compile to a pure Plan. Includes the four validation gates, the Cap bitset, Pos anchors, Budget, and the typed errors. No ops yet beyond a no-op registration harness.

**Files.**

- `internal/strategy/caps.go`
- `internal/strategy/pos.go`
- `internal/strategy/spec.go`
- `internal/strategy/plan.go`
- `internal/strategy/builder.go`
- `internal/strategy/registry.go`
- `internal/strategy/validate.go`
- `internal/strategy/errors.go`
- `internal/strategy/ladder.go`

**Done when.** `go test ./internal/strategy/ -race -cover` >=90%. `go test -fuzz=FuzzSpecRoundTrip -fuzztime=60s` confirms Parse(String(Parse(s))) == Parse(s) and that canonicalisation is idempotent. Table tests assert: two KindReframe ops are rejected; `disorder|oob` is rejected on darwin with the zapret citation in the message; an unknown op and an unknown param each produce an error naming the token; a Plan with 17 segments fails Validate(DefaultBudget()).

### M3 — Censor simulator and test fakes

**Depends on:** M1

**Goal.** Build internal/testcensor (Model, Middlebox, TT2026, Fragile, DNSCensor, origin, CheckIntegrity) and internal/testnet (ScriptRunner, ribfake, packetgen, clock, killfuzz). This is infrastructure three later milestones depend on, so it is built in parallel with M2 rather than after it.

**Files.**

- `internal/testcensor/model.go`
- `internal/testcensor/middlebox.go`
- `internal/testcensor/tt2026.go`
- `internal/testcensor/fragile.go`
- `internal/testcensor/dns.go`
- `internal/testcensor/origin.go`
- `internal/testcensor/integrity.go`
- `internal/testnet/scriptrunner.go`
- `internal/testnet/ribfake.go`
- `internal/testnet/packetgen.go`
- `internal/testnet/clock.go`
- `internal/testnet/killfuzz.go`
- `internal/testnet/fixtures/route_exit0_fail.txt`
- `internal/testnet/fixtures/scutil_dns.txt`
- `internal/testnet/fixtures/scutil_proxy.txt`
- `internal/testnet/fixtures/networksetup_services.txt`

**Done when.** `go test ./internal/testcensor/ ./internal/testnet/ -race` passes. A self-test asserts TT2026() blocks a plain ClientHello for a listed name, passes the same hello when the SNI is not complete in the first record, and blocks it when two records are sent but the first ends at sniEnd. Fragile() rejects a two-record handshake with an `illegal parameter` alert. The captured route fixture is present verbatim and contains `writing to routing socket` alongside exit code 0.

### M4 — The emitter set, with tlsfrag as the primary

**Depends on:** M2, M3

**Goal.** Implement every op: tlsfrag (with the ErrCutAfterSNI validator), tlsevery, chunk, split, disorder, oob, host mutators, pad, quicfake, and the registered-but-rejected unreachable family. Includes the ladder data for `tr` and `global`.

**Files.**

- `internal/ops/tlsfrag.go`
- `internal/ops/tlsevery.go`
- `internal/ops/chunk.go`
- `internal/ops/oob.go`
- `internal/ops/split.go`
- `internal/ops/disorder.go`
- `internal/ops/hostmangle.go`
- `internal/ops/pad.go`
- `internal/ops/quicfake.go`
- `internal/ops/unreachable.go`
- `internal/ops/ops_test.go`
- `internal/ops/fuzz_test.go`
- `internal/strategy/golden_test.go`

**Done when.** `go test ./internal/ops/ ./internal/strategy/ -race -cover` >=90%. TestTLSFragRefusesCutAtOrAfterSNIEnd passes all ten §3.2 cut positions with the expected accept/refuse verdicts; TestTLSEveryFirstRecordLimit accepts period 16 and 64 and refuses 256. `go test -fuzz=FuzzPlanPreservesPayload -fuzztime=120s` finds no case where StreamBytes() != Payload. TestParameterIsLive fails if any numeric parameter of any op produces byte-identical output across its sweep. `dpb strategy plan 'tlsfrag:pos=snimid' --sample tls --sni discord.com` prints a one-segment plan containing two records.

### M5 — emit: transport, sender, governor, socket primitives

**Depends on:** M2

**Goal.** The only impure code in the desync path. SockTransport over *net.TCPConn shared by both front-ends; per-write TTL with defer-restore; MSG_OOB via RawConn.Write; the process-wide coalescing governor; DefaultTTL() reading sysctl.

**Files.**

- `internal/emit/transport.go`
- `internal/emit/sender.go`
- `internal/emit/governor.go`
- `internal/emit/socktransport.go`
- `internal/emit/ttl_darwin.go`
- `internal/emit/oob_darwin.go`
- `internal/emit/udp.go`
- `internal/emit/stub_other.go`

**Done when.** `go test ./internal/emit/ -race -cover` >=85%. A loopback test asserts an MSG_OOB junk byte is stripped from the peer's in-band stream (peer reads "abcde" for write("ab") + OOB('X') + write("cde")). A TTL test sets IP_TTL, reads it back, writes, and asserts the socket is restored to DefaultTTL() even when the write returns an error. A governor test with 200 concurrent chunk:size=1 plans asserts process-wide small-write rate stays under the cap and that plans are coalesced, never blocked. SeqState() returns ok=false unconditionally, with a test citing the SDK.

### M6 — netstate: runner, RIB, journal, manager, ops

**Depends on:** M0

**Goal.** Every macOS mutation, journalled fsync-before-apply and verified through a different subsystem than it was applied through. Includes the liar table, Adopted detection, notSelf guards, Replay, and the concrete proxy/PAC/launchenv/DNS/route/ifconfig ops. Runs fully in parallel with M1-M5.

**Files.**

- `internal/netstate/runner.go`
- `internal/netstate/rib_darwin.go`
- `internal/netstate/journal.go`
- `internal/netstate/manager.go`
- `internal/netstate/adopt.go`
- `internal/netstate/op_proxy.go`
- `internal/netstate/op_launchenv.go`
- `internal/netstate/op_pacfile.go`
- `internal/netstate/op_dns.go`
- `internal/netstate/op_route_darwin.go`
- `internal/netstate/op_ifconfig_darwin.go`
- `internal/netstate/facts_darwin.go`
- `internal/netstate/scutil_darwin.go`
- `internal/netstate/services_darwin.go`
- `internal/netstate/lock.go`

**Done when.** `go test ./internal/netstate/ -race -cover` >=85%. TestRouteExitZeroIsFailure feeds the captured fixture and asserts Result.Failed()==true with Code==0. TestAdoptedNeverReverted pre-seeds a VPN scoped default in ribfake and asserts UndoAll leaves it present. TestNotSelf discards a captured proxy entry pointing at our own listener. The chaos table injects a failure at each of the six Op lifecycle points for every Op type and asserts convergence to a clean fake system after Replay, and that a second Replay is a no-op. A standalone binary using rib_darwin.go reads the live RIB as a non-root uid and prints a non-zero route count.

### M7 — resolve: the DNS chain and the single dial funnel

**Depends on:** M0

**Goal.** DoH with bootstrap IPs, DoT, alt-port UDP, structurally-impossible TCP fallback, sinkhole and uniqueness poison detection, the three-state AAAA policy with NAT64 detection, the local UDP+TCP server with SERVFAIL synthesis, and the ReverseMap hookup. Parallel with M1-M6.

**Files.**

- `internal/resolve/chain.go`
- `internal/resolve/doh.go`
- `internal/resolve/dot.go`
- `internal/resolve/udp.go`
- `internal/resolve/altport.go`
- `internal/resolve/poison.go`
- `internal/resolve/aaaa.go`
- `internal/resolve/server.go`
- `internal/resolve/wire.go`
- `internal/resolve/bootstrap.go`

**Done when.** `go test ./internal/resolve/ -race -cover` >=85%. Against testcensor.DNSCensor(): a UDP/53 query for a blocked name times out and the chain advances; the alt-port resolver answers; a TCP attempt is never made (asserted by a listener that fails the test if connected to); a sinkhole answer of 195.175.254.2 is rejected and the chain advances; chain exhaustion returns a well-formed SERVFAIL carrying the caller's original message ID and question. `dpb dns check` against the fake censor reports the transport matrix.

### M8 — policy: scoping, verdicts, store, NetworkID

**Depends on:** M0

**Goal.** ScopeClass and Verdict types, the label-anchored matcher, CIDR matching, NetworkID fingerprinting, the durable NetworkID-namespaced verdict store with atomic writes, ReverseMap, Singleflight, and Explanation assembly. Parallel with M1-M7.

**Files.**

- `internal/policy/scope.go`
- `internal/policy/matcher.go`
- `internal/policy/ipset.go`
- `internal/policy/netid.go`
- `internal/policy/store.go`
- `internal/policy/reverse.go`
- `internal/policy/singleflight.go`
- `internal/policy/explain.go`

**Done when.** `go test ./internal/policy/ -race -cover` >=90%. `go test -fuzz=FuzzMatchLabel -fuzztime=60s` confirms MatchLabel("bank.com", x) is true for bank.com and www.bank.com and false for evilbank.com and bank.com.evil.tld. A store test writes a verdict under NetworkID A, changes to NetworkID B, and asserts Get returns not-found; a crash-during-write test (truncated temp file) asserts the previous store is intact after reopen. Singleflight collapses 6 concurrent Do calls on one key into 1 invocation.

### M9 — flow: the default-direct ladder engine

**Depends on:** M4, M5, M7, M8

**Goal.** ReadFirstMessage with the completeness loop and server-first detection; the LadderRunner implementing plain-first / escalate-on-reset-before-response / cache-both-outcomes; failure classification; the commit guard; half-close relay; RTT tracking; the bound dialer that resolves only through resolve.Chain.

**Files.**

- `internal/flow/firstmsg.go`
- `internal/flow/ladder.go`
- `internal/flow/classify.go`
- `internal/flow/relay.go`
- `internal/flow/rtt.go`
- `internal/flow/dialer.go`

**Done when.** `go test ./internal/flow/ -race -cover` >=85%. Against testcensor.TT2026(): a connection to a blocked name records exactly two attempts (plain then tlsfrag:pos=snimid), succeeds, writes a SrcLearnedDesync verdict, and the client observes one continuous stream with no duplicate or missing bytes. Against testcensor.Fragile(): the connection succeeds on attempt 1 and a SrcLearnedPlain verdict is written with a zero Expires; assert zero escalations. A server-first table (SMTP/IMAP/POP3/FTP/MySQL greetings) asserts the greeting reaches the client within FirstByteWait with zero bytes buffered. A reset-after-first-upstream-byte test asserts a visible error and zero retries. `go test -run TestLadder -count=500 -race` is stable.

### M10 — FIRST RUNNABLE SLICE: dpb probe

**Depends on:** M9

**Goal.** A single command that dials a real blocked host by pinned IP with a chosen strategy through the exact datapath the product will use, completes a real TLS handshake, validates the certificate against the name, and prints PASS / RESET / TIMEOUT with a latency. Needs no proxy, no TUN, no root, and mutates no system state. From here it is the integration harness for everything built afterwards.

**Files.**

- `internal/probe/target.go`
- `internal/probe/trial.go`
- `internal/cliapp/root.go`
- `internal/cliapp/probe.go`
- `internal/cliapp/strategycmd.go`
- `internal/cliapp/version.go`

**Done when.** On a Türk Telekom line: `dpb probe --host discord.com --addr 162.159.128.233 --strategy '' --reps 5` prints 0/5 PASS with verdict RESET, and `dpb probe --host discord.com --addr 162.159.128.233 --strategy 'tlsfrag:pos=snimid' --reps 5` prints 5/5 PASS. `dpb probe --host cloudflare.com --addr 162.159.128.233 --strategy '' --reps 5` prints 5/5 PASS (the same-IP benign-SNI control). Off a censored line, the same three commands run against testcensor via `--addr 127.0.0.1` with matching verdicts.

### M11 — Proxy front-end and full system lifecycle

**Depends on:** M6, M10

**Goal.** The shippable product: PAC generation and serving, HTTP CONNECT, per-request plaintext HTTP with per-origin dialing, SOCKS5 CONNECT, the system-proxy and launchenv mutations under the journal, signal-driven ordered teardown, and the config loader with unknown-key rejection.

**Files.**

- `internal/front/proxyfe/server.go`
- `internal/front/proxyfe/connect.go`
- `internal/front/proxyfe/http.go`
- `internal/front/proxyfe/socks5.go`
- `internal/front/proxyfe/pac.go`
- `internal/config/config.go`
- `internal/config/schema.go`
- `internal/config/excludes.go`
- `internal/config/embed/global.toml`
- `internal/config/embed/turkey.toml`
- `internal/cliapp/run.go`
- `internal/cliapp/banner.go`
- `internal/cliapp/scope.go`

**Done when.** On a Türk Telekom line, `dpb run --profile turkey` with no sudo, then `curl -x http://127.0.0.1:8080 -o /dev/null -w '%{http_code}' https://discord.com/` returns 200, and Discord loads in a browser. `curl -x http://127.0.0.1:8080 https://www.isbank.com.tr/` returns 200 on the first attempt with zero escalations in the log. Ctrl-C leaves `scutil --proxy` byte-identical to a snapshot taken before the run. An offline test asserts two pipelined plaintext requests to different origins reach different backends. A config file with an unknown key is rejected with an error naming the key.

### M12 — Observability, doctor, and the SIGKILL janitor

**Depends on:** M6, M8, M11

**Goal.** The control socket and the three commands that make the tool debuggable by its user: dpb why, dpb status, dpb coverage. Plus dpb doctor --repair, dpb on/off/panic, the kqueue janitor child, and the login repair LaunchAgent.

**Files.**

- `internal/observ/control.go`
- `internal/observ/client.go`
- `internal/observ/counters.go`
- `internal/janitor/janitor.go`
- `internal/janitor/spawn_darwin.go`
- `internal/cliapp/why.go`
- `internal/cliapp/status.go`
- `internal/cliapp/coverage.go`
- `internal/cliapp/doctor.go`
- `internal/cliapp/onoff.go`
- `internal/cliapp/janitorcmd.go`
- `internal/cliapp/selftest.go`

**Done when.** `dpb why www.isbank.com.tr` prints the matched compiled-in bypass rule with its provenance and the effective verdict. With dpb running, `kill -9 $(pgrep -x dpb)` is followed within 2 seconds by `scutil --proxy` returning to its pre-run state, and the journal file is empty — verified by the janitor, with the LaunchAgent path verified separately by removing the janitor and asserting recovery at next login. `dpb selftest` runs the full censor matrix and exits 0. `dpb coverage --watch 30s` lists the processes that connected.

### M13 — dpb tune: the two-axis prober

**Depends on:** M3, M9

**Goal.** Preflight DNS matrix, baseline with the ShapeIPBlock stop condition, mechanism classification including the first-record-limit binary search and the padding sweep, the discrete candidate sweep, interleaved controls with discarded rounds, Wilson scoring, the seven-key ranking, and tuned.toml write-back plus dpb apply.

**Files.**

- `internal/probe/preflight.go`
- `internal/probe/baseline.go`
- `internal/probe/classify.go`
- `internal/probe/runner.go`
- `internal/probe/stats.go`
- `internal/probe/rank.go`
- `internal/probe/report.go`
- `internal/probe/candidates.go`
- `internal/config/tuned.go`
- `internal/cliapp/tune.go`
- `internal/cliapp/apply.go`
- `internal/cliapp/dnscmd.go`
- `internal/cliapp/cachecmd.go`

**Done when.** Against testcensor.TT2026() plus testcensor.Fragile(), `dpb tune --json` converges on tlsfrag:pos=snimid as rank 1 with Classification.FirstRecordLimit equal to sniEnd-1, and ranks chunk-12 above chunk-4 and oob. Against a model with no censorship and 30% packet loss it reports 'nothing is blocked here', exits 4, and writes no winner. Against a model that blocks the benign-SNI control it reports ShapeIPBlock and stops. A unit test asserts a candidate passing target A and failing target B is not ranked first even when A was probed first, and that rounds with a failed control are excluded from the denominator. On a real line, `dpb tune` completes in under 8 minutes and writes tuned.toml with confidence: high.

### M14 — Distribution: tap, release, service install

**Depends on:** M11

**Goal.** Create mumudevx/homebrew-tap, cut v0.1.0 with a real sha256, and ship the privileged-helper service install with modern launchctl verbs. Deliberately early: the README's headline install command has 404'd since day one, so until this lands the tool has no users to be wrong for.

**Files.**

- `Formula/dpb.rb`
- `.goreleaser.yaml`
- `internal/cliapp/service.go`
- `README.md`

**Done when.** On a clean machine, `brew tap mumudevx/tap && brew install dpb && dpb version` prints the release version. `xattr -p com.apple.quarantine $(which dpb)` returns 'No such xattr'. `codesign -dv $(which dpb)` reports an ad-hoc signature with no codesign step in the pipeline. `sudo dpb service install --system && dpb service status` reports running, and `dpb service uninstall` leaves /Library/LaunchDaemons clean.

### M15 — netwatch: the laptop-reality layer

**Depends on:** M6, M11

**Goal.** PF_ROUTE watcher with debounce, the wall-vs-monotonic sleep detector, the captive-portal probe with automatic suspend and resume, and VPN classification with full- vs split-tunnel policy. Wired to quiesce, re-verify every applied Op, and swap the verdict namespace on NetworkID change.

**Files.**

- `internal/netwatch/watcher.go`
- `internal/netwatch/route_darwin.go`
- `internal/netwatch/sleep.go`
- `internal/netwatch/portal.go`
- `internal/netwatch/vpn_darwin.go`

**Done when.** `go test ./internal/netwatch/ -race` passes with a fake clock and a fake RIB. Manual acceptance, scripted in docs/accept-m15.md: switching from Wi-Fi to a phone hotspot mid-run produces a NetworkID change event within 2 seconds, quiesces, re-verifies, resumes, and the verdict store reports a different namespace via `dpb status --json`. Joining a network behind a captive portal produces PortalDetected and `dpb status` shows suspended with all-DIRECT PAC. Starting a full-tunnel VPN under a running dpb --tun produces a clean teardown with exit code 5 rather than a false 'Ready'.

### M16 — TUN front-end, built against pipeLink first

**Depends on:** M9, M15

**Goal.** Link and pipeLink, the gVisor endpoint with correct View release and error surfacing, the stack, the pipe-first TCP forwarder, the datagram-preserving UDP forwarder, in-process UDP/53 and TCP/53, and the verified route/ifconfig bring-up and teardown ordering. The real utun device is attached last.

**Files.**

- `internal/front/tunfe/link.go`
- `internal/front/tunfe/link_darwin.go`
- `internal/front/tunfe/endpoint.go`
- `internal/front/tunfe/stack.go`
- `internal/front/tunfe/tcp.go`
- `internal/front/tunfe/udp.go`
- `internal/front/tunfe/dns.go`
- `internal/front/tunfe/icmp.go`

**Done when.** `go test ./internal/front/tunfe/ -race -cover` >=70% with NO root and NO utun, driven entirely by pipeLink plus a client netstack. Tests assert: a server-first greeting reaches the client within FirstByteWait with zero bytes buffered; a hello split across two injected segments is reassembled before planning; readLoop errors are surfaced on the event channel; a View leak counter stays at zero; half-close propagates; UDP/53 and TCP/53 are answered in-process and never relayed. Then, under sudo on a real machine: `sudo dpb run --tun --profile turkey` followed by `curl -o /dev/null -w '%{http_code}' https://discord.com/` returns 200 with the system proxy OFF, and Ctrl-C leaves `netstat -rn` byte-identical to a pre-run snapshot.

### M17 — Remaining channels: QUIC, IPv6, SOCKS5 UDP

**Depends on:** M16

**Goal.** QUICRefuse via ICMP port-unreachable, QUICRelay and QUICDesync, SOCKS5 UDP ASSOCIATE as the unprivileged UDP path, and IPv6 end to end: ::/1 + 8000::/1 capture with RIB verification, a v6 address on the utun, IPV6_UNICAST_HOPS, and the auto AAAA policy with NAT64 detection.

**Files.**

- `internal/front/proxyfe/socks5udp.go`
- `internal/front/tunfe/icmp.go`
- `internal/ops/quicfake.go`
- `internal/resolve/aaaa.go`
- `internal/netstate/op_route_darwin.go`

**Done when.** `go test ./... -race` stays green. A pipeLink test asserts a QUIC Initial to an in-scope name produces an ICMP port-unreachable and no upstream datagram, and that a non-443 UDP datagram is relayed byte-for-byte with boundaries preserved. On a dual-stack line, `dpb dns resolve discord.com --trace` shows AAAA suppressed with NOERROR+SOA when v6 capture is unverified, and real AAAA answers plus a verified ::/1 route in the RIB when it is. On a NAT64 cellular line, AAAA passes through untouched and `curl -6 https://ipv6.google.com/` still succeeds.


---

## Explicitly rejected

- netstack-first's entire twin-gVisor-stack / BPF-ingress / raw-socket-egress / pf-anchor architecture. Its own thesis stakes M4 and M5 on unlocking `multidisorder:pos=2:seqovl=1`, i.e. TCP segment reordering and sequence overlap. MEASUREMENTS.md §3.1: 'Every two-segment TCP split fails, including one cut inside the SNI hostname. The DPI reassembles TCP,' and `tlsrec2-1seg` — two TLS records inside ONE TCP segment — passes 3/3. It is weeks of the hardest plumbing in the field aimed at a layer the measurements say is irrelevant. Rejected outright by all three judges.

- netstack-first's `--rst-suppress=blackhole` escape hatch (net.inet.tcp.blackhole). A global sysctl that changes how the entire machine answers traffic on closed ports, surviving a kill -9 until the journal is replayed. The design itself concedes 'other applications will hang where they used to fail fast'. Unacceptable on a banking laptop.

- Any use of pf. GT15's constraints are correctly stated by netstack-first, but the case where /etc/pf.conf has been replaced by an MDM profile, Little Snitch or LuLu produces an anchor that loads cleanly and is never evaluated — a silent failure whose only symptom is 'the uplink mysteriously never connects'. The IP_BOUND_IF + -ifscope design solves the recursion problem without excluding root, which is strictly better (DOSSIER D2).

- chunk-5 as the shipped default (netstack-first and unprivileged-first both ship it). Measured FAIL in MEASUREMENTS.md §3.4 run A. It is SpoofDPI's number, and §3.5 says explicitly: 'Strategy parameters are not portable between implementations — the prober must measure the emitters this tool actually ships, never import another tool's numbers.'

- disorder in any shipped ladder (netstack-first, unprivileged-first Tier 2, probe-first's classifier, safety-first's own registry ordering). 0/10 on Türk Telekom (§3.5). The op stays implemented and tested because GT11 shows the socket mechanism is sound on Darwin and another ISP may differ, but it never appears in the TR ladder.

- Plain TCP splitting as a bypass rung, and probe-first's H-align hypothesis that made split:at=sni-mid prior #1. `split2-in-sni` is 0/5 (§3). Splitting the hostname across TCP segments cannot help a middlebox that reassembles TCP.

- probe-first's TestTurkTelekomFixtureReproducesMeasuredCurve, which solves the straddle model against the chunk curve and 'fails loudly if the solution set is empty'. §3.4 says that curve is 'non-monotonic and not explained by any simple model'. It would enshrine a falsified model as a CI gate that breaks on day one. Replaced by TestTLSFragRefusesCutAtOrAfterSNIEnd, which asserts our validator against the measurement rather than asserting a model of the network.

- probe-first's rule that a candidate breaking any regression target is 'disqualified regardless of score'. §5.1: 'No emitter is both a bypass and universally safe. The correlation is close to perfect.' On a real line this disqualifies tlsrec, chunk and oob alike and returns nothing. Kept as a scored compatibility axis at ranking key 4, never as a filter.

- probe-first's fail-closed DNS (pointing the system resolver at the tunnel peer) shipped without a login repair agent. A kill -9 followed by closing the lid leaves a banking user with no DNS, no attributable error, and a recovery step they must find in documentation. Replaced by original-resolvers-as-secondary plus the janitor plus the RunAtLoad agent.

- safety-first's own shipped ladder ordering — plain, chunk(5), chunk(2), chunk(20), chunk(60), split(sni-1), tlsrec(sni) with --max-attempts 3. Of the rungs reachable within budget, every one is measured failing, and the only winning rung sat at position 7, beyond the retry budget. Replaced by §5.3's measured order.

- safety-first's fake-IP layer (deterministic hash allocation, 198.18.0.0/16 + fd70:d9b:f4ce::/48 pools, collision detection, Name/Alloc/Persist). Two judges flagged it as a new failure surface — IP pinning across restarts, browsers with built-in DoH bypassing it entirely, 198.18/15 VPN collisions, reverse-DNS checks — bought for an exclusion guarantee that §5.2 says is not the answer anyway. policy.ReverseMap plus SNI-peek plus ScopeDirect-on-unknown covers the naming need with a fraction of the risk.

- safety-first's --capture=names TUN mode and its dependent route machinery. With default-direct, capturing everything is safe because nothing is desynced without evidence, so the split-default pair is the only capture mode in v1.

- networksetup -setv6off / -setv6automatic as an IPv6 fallback. More invasive than filtering AAAA and leaves residue after a hard kill (DOSSIER D6).

- The fake-packet family as shipped code behind a build tag (netstack-first ships it in M5; unprivileged-first quarantines behind -tags dpb_rawfakes). Replaced by capability computation: the ops are registered and always fail validation with `CapRawSeq` named and the mechanical reason cited (struct tcp_connection_info has no snd_nxt — verified, 0 matches in the macOS 26 SDK header). No build tag, no dead profile, and the whole family lights up unchanged the day a netstack-owned upstream endpoint exists.

- turkey-superonline.toml, and per-ISP profile tables generally. GT21: profiles disagree across tools and rot on a months-scale cadence; §3.4 shows efficacy is non-monotonic within one ISP on one day. The prober running on the user's own line is the ISP-specific knowledge.

- Crowd-sourced strategy aggregation with a telemetry endpoint (probe-first designs it and correctly declines to ship it). The benefit is search-order only; the cost is an endpoint receiving 'someone on this network is running a circumvention tool' against a pending VPN Regulation proposal. `dpb tune --export` plus `dpb apply` gives the community the sharing it already practises, at zero infrastructure and zero privacy cost, with local re-verification before anything is trusted.

- Renaming the binary. probe-first proposed `kalkan` and safety-first proposed `Verdict`; the repo is mumudevx/dpi-bypass-mac with binary `dpb`, the module path is load-bearing in every import, and the rename buys nothing an alias could not.


---

## Risks

- The whole ladder rests on one afternoon on one Türk Telekom line in one city. §4 of MEASUREMENTS.md says so explicitly: Superonline, Vodafone, Turknet and every mobile network are unmeasured. The §3.2 record rule is a mechanism-level finding rather than a magic constant, which makes it far more likely to generalise than a chunk size — but 'more likely' is not 'measured'. The hedge is that `dpb tune` measures the emitters this tool actually ships, on the user's own line, and default-direct means a wrong ladder costs latency rather than breakage.

- The record rule could be an artefact of one DPI vendor's ClientHello parser rather than a property of Turkish DPI. If Türk Telekom deploys a middlebox that reassembles the TLS record layer, tlsfrag dies and the ladder falls through to chunk-12, whose parameter §3.4 shows is unstable. There is no third mechanism in the unprivileged envelope, and the fourth (seqovl / fakedsplit) needs CapRawSeq, which needs a netstack-owned upstream endpoint we have deliberately not built.

- Default-direct leaks one plain ClientHello per host per network before escalating. §6 measures that the DPI is stateless between flows, does not escalate to IP-level blackholing, and does not penalise the source — so today this is free. If Turkey adds per-source penalties or IP-blocking-after-detection, `mode=watch` becomes actively harmful and the correct default flips to `always` plus a seed list, at which point the fragile-host problem §5.1 documents returns in full.

- Removing fake-IP weakens the structural exclusion guarantee in TUN mode. An excluded name whose IP we never resolved, reached by IP literal on port 443, gets ScopeWatch and has its ClientHello buffered before the SNI-based bypass rule fires. It is still sent plain on attempt 1, so no desync touches it — but it does pass through our process, and a dpb crash mid-transfer kills that connection where a fake-IP-plus-capture=names design would never have seen it.

- The governor's rate limit is unmeasured. GT13 gives no threshold and the panic is destructive to reproduce. The primary emitter is structurally immune (one write), so the exposure is confined to ladder rungs 3-5 on a busy machine — but if the real threshold is far below 512 small writes per second, a user on chunk-4 under load can still panic their kernel, and we will find out from a bug report rather than a test.

- Two `SrcLearnedPlain` failure modes are silent by construction. A host that is blocked only intermittently gets cached as plain and stays that way until it fails again (self-correcting, but with a visible stall). And a host whose block is applied *after* the handshake — reset once server bytes have flowed — is classified FailResetAfterResponse and never retried, correctly, but also never surfaces as censorship in `dpb status`.

- PAC-as-default fails open on process death, which is the right asymmetry for a banking laptop and the wrong one for a censorship tool: between dpb dying and the janitor firing, a browser can send an unmodified ClientHello for a blocked name. The window is milliseconds and the alternative (explicit proxy) is a total outage, but it is a real leak and should be stated in the README rather than discovered.

- The AF_ROUTE RIB verifier is only as good as its parser. golang.org/x/net/route is an unversioned x/ package parsing an undocumented kernel structure; a macOS release that changes the routing-message layout would make Verify fail closed, which would refuse to bring up TUN mode rather than corrupt state — safe, but it turns an OS update into an outage. Pin the version and cover it with a live smoke test in CI on a macOS runner.

- TUN mode's justification remains GT24, which unprivileged-first's otool/strings work substantially refutes on macOS: updater.node is an in-process reqwest addon honouring HTTP(S)_PROXY. The residual gap is applications that read neither the proxy pane nor the environment and resolve for themselves. M16 is 1.5 weeks of the plan's most complex work for a population we have not sized, and the 15-minute reproduction (launch Discord under pane-only, then under setenv, watching Discord_updater_rCURRENT.log and lsof) must be run before M16 starts.

- Judges disagreed on whether the plan should optimise for time-to-first-user, and two of three said unprivileged-first would ship sooner. This plan builds M0-M9 before anything forwards a byte, and `dpb probe` at M10 is a measurement instrument rather than a bypass. If the schedule slips, the mitigation is to cut M6 down to the proxy/PAC ops only and defer routes to M15, which pulls M11 forward by roughly a week.

- No telemetry means no visibility into real efficacy across Turkish ISPs, which is the exact data that would most improve the product. `dpb tune --export` produces a shareable line and `--json` a full report, but both require a user to act. Given the pending VPN Regulation proposal, collecting the data would be a liability; the cost is that the ladder's ordering beyond rung 2 stays justified by n=1.

- GT20's trend is toward reopening, and Discord may be unblocked during the build. The design absorbs this better than a static tool — the prober reports 'not blocked' and drops the target, `SrcLearnedPlain` records it, demotion probes rediscover it — but the honest statement is that the addressable problem may be shrinking, and the ladder's value would then rest entirely on targets nobody has measured.
