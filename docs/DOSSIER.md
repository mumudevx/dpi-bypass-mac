# DPI Bypass for Turkey — Research Dossier

Generated 2026-09-02 by a 17-agent research + adversarial-verification workflow.
Live measurements were taken from a Türk Telekom line (AS9121, Kayseri) on 2026-09-02.

> Every claim below survived an independent adversarial fact-checking pass. Where a
> challenger corrected a researcher, the corrected version is what appears here.

---

## 1. Ground truth

### GT1 — (high confidence)

The Turkish block on HTTPS is SNI-keyed RST injection on an otherwise-reachable path, not IP blocking. Measured directly from a Türk Telekom line (AS9121, Kayseri) on 2026-09-02: `curl --resolve discord.com:443:162.159.128.233` → 'Recv failure: Connection reset by peer', while `curl --resolve cloudflare.com:443:162.159.128.233` — the SAME IP with a benign SNI — returns HTTP 301. Same shape for www.roblox.com → 128.116.5.3.

*Source:* trfork challenger, live curl from AS9121 on 2026-09-02. Corroborated by OONI raw measurements showing tcp_connect succeeding to real Cloudflare IPs followed by connection_reset on AS9121/AS34984/AS12444.

### GT2 — (high confidence)

DNS censorship is a per-QNAME drop of the query, NOT a transparent port-53 redirect. On TT today, UDP/53 to 8.8.8.8, 1.1.1.1, 9.9.9.9 and 77.88.8.8 all time out for discord.com and roblox.com, while google.com and wikipedia.org through the same resolver on the same port answer normally. The ISP resolver itself (192.168.0.1) returns the BTK block page 195.175.254.2. This CORRECTS the widespread 'Turkish ISPs hijack port 53' folklore repeated in the GoodbyeDPI-Turkey lineage.

*Source:* trfork challenger, live dig from AS9121 2026-09-02. The challenger explicitly overrides the recon's hijack/redirect mechanism claim.

### GT3 — (high confidence)

Alternate-port plaintext UDP DNS still works; TCP DNS is filtered at every port. Verified live on TT: `dig -p 1253 @77.88.8.8 discord.com` and `dig -p 9953 @9.9.9.9 discord.com` both resolve correctly; `dig +tcp @8.8.8.8 discord.com` AND `dig +tcp -p 1253 @77.88.8.8 discord.com` are both connection-reset. Any resolver that falls back to TCP on truncation breaks for exactly the names that matter.

*Source:* trfork challenger, live dig 2026-09-02. The TCP-filtering finding is new and appears in no tool's documentation.

### GT4 — (high confidence)

DoH is not blocked in Turkey and is the cleanest defeat of layer 1. ~26,000 OONI measurements since May 2026 show cloudflare-dns.com 12,406 accessible / 0 confirmed blocks, dns.google 12,298 / 0, mozilla.cloudflare-dns.com 1,035 / 0. Independently confirmed live on TT: Cloudflare and Google DoH JSON both return real Discord IPs; DoT/853 connects.

*Source:* OONI aggregation (isp-reality recon) — note the OONI API was quota-blocked for the fact-checker, so the counts are single-session and unreplicated. But the live TT measurement corroborates the direction independently.

### GT5 — (high confidence)

ClientHello fragmentation still works on Türk Telekom, but efficacy is a non-monotonic function of chunk size. Upstream SpoofDPI v1.5.x on TT, discord.com ×3 each, fully reproducible: chunk=1 → 200, chunk=5 → 200, chunk=20 → 200, chunk=60 → 200, chunk=35 (upstream's own default) → 000, chunk=120 → 000, split-mode=sni (upstream's default) → 000, split-mode=first-byte → 000, split-mode=random → 200.

*Source:* trfork challenger, live sweep from AS9121 2026-09-02. This is the single most actionable measurement in the entire dossier.

### GT6 — (high confidence)

The claim 'plain ClientHello fragmentation is dead on Türk Telekom' is NOT established and is contradicted by better evidence. Its sole source is rothilion26/discord-dpi-bypass-macos — an anonymous repo with 0 stars, 3 commits, whose own README says it was verified on exactly one hardware/network configuration, and whose stated justification is a non-sequitur (it argues the destination server reassembles, which is true of all fragmentation and irrelevant to the middlebox). The live chunk sweep above refutes it directly.

*Source:* isp-reality challenger verdict on F6; trfork challenger's live chunk sweep. Challenger wins over recon.

### GT7 — (medium confidence)

Fake packets are not needed to beat the current TR block. Both community-verified working SpoofDPI configurations for Turkey in issue #403 omit --https-fake-count entirely. Measured on TT, unprivileged chunking alone beats the block. Upstream also ships FakeCount:0 and Disorder:false as defaults.

*Source:* SpoofDPI issue #403 (CemKutlar 2026-07-15, mruchann 2026-08-24); upstream challenger's runtime confirmation of `fake; count=0`. Medium because 'not needed for Discord on TT today' does not generalise to Superonline or to future DPI updates.

### GT8 — (medium confidence)

Every field-verified Turkish strategy that goes beyond plain splitting pairs the split with an out-of-order, out-of-band, or sequence-overlap component. The canonical ByeDPI Turkey string is `--split 1 --disorder 3+s --mod-http=h,d --auto=torst --tlsrec 1+s`; zapret2's flagship TT and Superonline profile is `multidisorder:pos=2:seqovl=1`; the one macOS-on-TT recipe reported working is `--split-pos=1 --oob`. Not one working profile uses an in-order split alone.

*Source:* SplitWire-Turkey service_install.bat:11; zapret-win-turkey.au3:559-565; rothilion26 discord-bypass.sh:52. Medium: the ByeDPI string's 'independent corroboration' collapsed on inspection (the second source is a 6-day-old 0-star repo copying it), and the macOS recipe is n=1.

### GT9 — (high confidence)

macOS has no divert socket mechanism, so an nfqws/winws-style kernel packet datapath is structurally impossible. Verified: `strings /sbin/pfctl | grep -ci divert` → 0; `man 5 pf.conf | grep -ci divert` → 0; `nm -gU /System/Library/Kernels/kernel | grep -c div_` → 0; net/pfvar.h absent from the current SDK (so DIOCNATLOOK needs vendored undocumented structs). IPPROTO_DIVERT 254 survives only as a vestigial constant.

*Source:* techniques recon + challenger, both reproduced first-hand on Darwin 25.3.0. zapret's own docs/bsd.md agrees.

### GT10 — (high confidence)

Raw packet injection IS available on macOS as root and is NOT the blocker people assume. AF_INET/SOCK_RAW/IPPROTO_RAW + IP_HDRINCL works; `man 4 ip` confirms ip_len and ip_off must be in host byte order on the send path, and XNU's rip_output validates ip_len in host order. The real blocker for a proxy-mode fake is that the kernel owns the upstream socket's sequence space, not that packet access is missing. dpb already implements the injector correctly at the byte level.

*Source:* audit-b challenger, verified against apple-oss-distributions/xnu raw_ip.c and ip_output.c; dpb internal/sysnet/rawinject_darwin.go read directly.

### GT11 — (high confidence)

Socket-level disorder (per-segment setsockopt IP_TTL=1) works on macOS and is race-free with TCP_NODELAY. Measured on Darwin 25.3.0: after send(40) with TTL=1, txpackets=1/txbytes=40 immediately; after restore + send(24), txpackets=2; at 50ms, txpackets=3 with txretransmitbytes=40 — i.e. ONLY the lost segment is retransmitted, Linux-like, not the FreeBSD whole-message behaviour. MSG_OOB (0x1) also exists in the SDK.

*Source:* techniques recon and challenger, both ran the probe on this machine.

### GT12 — (high confidence)

Disorder and OOB must never be combined on Darwin. zapret's blockcheck.sh gates the pair to Linux with an explicit comment: 'simultaneous oob and disorder works properly only in linux. other systems retransmit oob byte without URG tcp flag and poison tcp stream.' Empirically, byedpi's --disoob is 0/8 on macOS across three hosts while --oob alone is 8/8.

*Source:* blockcheck.sh:1634-1636; techniques challenger's controlled reruns after eliminating a port-reuse false positive.

### GT13 — (high confidence)

The XNU panic `assertion failed: ifp->if_sndbyte_unsent >= 0` is a pre-existing Apple kernel defect, not a SpoofDPI bug. Public reports date to xnu-4570 (2017, keybase/client#9091) and xnu-7195 (2021) against unrelated software. High-volume small TCP writes provoke it. SpoofDPI issue #386 reproduced it from Turkey on macOS Tahoe 26.4.1 with chunk-size=1 + disorder; never fixed.

*Source:* upstream challenger, which traced the assertion to prior public reports. This broadens the risk to ANY macOS tool doing many small writes, including dpb.

### GT14 — (high confidence)

macOS route(8) never exits non-zero on a routing-socket failure. Apple's network_cmds route.tproj/route.c has newroute() as void with `newroute(argc, argv); exit(0);` in main; rtmsg() only warnx()es. Verified: `route -n get -inet6 2001:db8::1` prints 'route: writing to routing socket: not in table' and returns 0. Any tool that shells out to route and checks only the exit status treats every failure as success.

*Source:* audit-b challenger, verified on macOS 26.3.1 against Apple's open-source route.c. Confirmed applicable to dpb: internal/sysnet/runner.go returns only exec's error.

### GT15 — (high confidence)

A pf anchor not referenced from the main ruleset loads cleanly and is never evaluated. /etc/pf.conf on macOS 26.3.1 references only `com.apple/*` anchors. The wildcard is non-recursive: pf.conf(5) states it 'will not descend to evaluate anchors recursively', so `com.apple/dpb` is evaluated but `com.apple/dpb/sub` is not. macOS pf enable/disable is reference-counted via -E/-X; using -e/-d can tear down another app's firewall.

*Source:* ux-dist recon and challenger, /etc/pf.conf and pf.conf(5) read on this machine. Note the challenger corrected one detail: an unreferenced anchor does NOT appear in `pfctl -s rules` — you need `pfctl -s Anchors`.

### GT16 — (high confidence)

Homebrew-installed CLI binaries are never Gatekeeper-evaluated, because Homebrew downloads with curl and curl does not set com.apple.quarantine. Verified on macOS 26.3.1 / Homebrew 6.0.18: brew-installed binaries and cached bottles carry only com.apple.provenance. The September 2026 cask delisting applies to homebrew-cask only; formulae and bottles are unaffected. SpoofDPI proves it at 5,006 stars in homebrew-core with zero Apple signing or notarization.

*Source:* ux-dist challenger, xattr checks run first-hand; Homebrew/brew#20755; homebrew-core Formula/s/spoofdpi.rb.

### GT17 — (high confidence)

Go's linker already ad-hoc signs every darwin/arm64 binary host-independently — `NeedCodeSign() { return ctxt.IsDarwin() && ctxt.IsARM64() }` with no host check — and lipo preserves the signature. Apple Silicon's SIGKILL-on-unsigned requirement is therefore satisfied without any codesign step. SpoofDPI's .goreleaser.yaml has no codesign hook at all.

*Source:* ux-dist challenger, verified against go1.26.4 src/cmd/link/internal/ld/lib.go:301 and by building/stripping/running test binaries.

### GT18 — (high confidence)

No QUIC-aware bypass exists in any of the reviewed tools. SpoofDPI has zero QUIC code (grep confirms); its UDP handling is blind low-TTL fake-datagram injection. The working Discord recipe for Turkey requires manually passing --disable-quic. byedpi on Darwin DOES retain --udp-fake with a settable TTL (desync_udp is ungated), so QUIC fake-Initial is reachable on macOS without root — but nobody parses QUIC Initials or fragments the CRYPTO frame.

*Source:* upstream recon+challenger (grep over the whole tree); trfork challenger's flag probe of a Darwin byedpi build; SpoofDPI issue #403.

### GT19 — (high confidence)

IPv6 is a real and unaddressed censorship channel. The IPv6 sinkhole 2a01:358:4014:a00::3 is registered in RIPE with netname BTK — the telecom regulator itself. On a dual-stack Turkish connection, AAAA poisoning bypasses any IPv4-only tool entirely.

*Source:* isp-reality challenger, RIPE whois on the sinkhole address.

### GT20 — (medium confidence)

Discord is the benchmark target and remains blocked, but the policy trend is toward reopening, not hardening. Roblox was unblocked 18 June 2026 after a 680-day ban following compliance work; the Turkish Transport & Infrastructure Minister has publicly said Discord had 'largely complied' and would likely be reopened. OONI's 'confirmed blocks rising through August 2026' framing is not supported — raw counts track measurement volume, and no monthly denominators were given.

*Source:* isp-reality challenger; Türkiye Today and ShiftDelete on the Roblox reopening; Cumhuriyet/Webtekno on the Discord statements.

### GT21 — (high confidence)

Turkish DPI configurations rot on a months-scale cadence, and per-ISP profiles disagree across tools. zapret-win-turkey's Superonline v1 profile uses md5sig with no TTL; Keenetic's superonline_fiber uses TTL=6; the Android presets use --ttl 3 with a fake SNI. Every serious Turkish tool ships a blockcheck/auto-tune path as a first-class feature precisely because fixed profiles decay.

*Source:* isp-reality challenger's cross-tool comparison; zapret-win-turkey.au3; keenetic_zapret2_manager.sh; the presence of blockcheck automation in every major TR fork.

### GT22 — (high confidence)

Aggressive desync breaks legitimate traffic and needs an exclusion list, not just an inclusion list. zapret-win-turkey ships excludelist.txt = com.tr, gov.tr, google.com, googleapis.com. GoodbyeDPI-Turkey issue #142 reports that over-aggressive fake TTLs break devlet (government), bankacılık (banking) and kick.com. The macOS Discord tool deliberately excludes *.discordapp.net because desync corrupts large downloads from that CDN.

*Source:* zapret-win-turkey config/excludelist.txt (verified verbatim); GoodbyeDPI-Turkey issue #142 (verified verbatim via gh api); rothilion26 discord-bypass.sh comments.

### GT23 — (low confidence)

No evidence of JA3/JA4 TLS fingerprinting, active probing, or ECH blocking in Turkey. Turkey is absent from the published lists of ECH-blocking countries (Russia Nov 2024, Iran, China, Uzbekistan), and no Turkish tool implements uTLS or fingerprint randomisation — which they would if fingerprinting were a live threat. This is absence of evidence, not evidence of absence.

*Source:* isp-reality recon+challenger, negative result across OONI, FOCI 2025, and the codebases of six Turkish tools.

### GT24 — (low confidence)

Proxy-unaware native binaries are a genuine coverage gap that only packet-level interception closes. Discord's macOS updater is reported to be a separate binary that ignores system proxy settings, so no proxy-based tool sees its traffic. This is the strongest justification for TUN mode — but it is currently single-sourced from one anonymous repo and has not been independently reproduced.

*Source:* rothilion26/discord-dpi-bypass-macos README. isp-reality challenger flagged it as unverified folklore; the proposed 15-minute reproduction (watch Discord_updater_rCURRENT.log) has not been run.


---

## 2. Technique ranking

| P | Technique | TR efficacy | macOS | root |
|---|---|---|---|---|
| P0 | Encrypted DNS (DoH) with hardcoded bootstrap IPs | proven | easy | no |
| P0 | Alternate-port plaintext UDP DNS (77.88.8.8:1253, 9.9.9.9:9953) as fallback | proven | easy | no |
| P0 | Chunked ClientHello splitting with a probed chunk size | proven | easy | no |
| P0 | Complete-ClientHello read loop before choosing an emitter | proven | easy | no |
| P0 | Per-domain exclusion list (.gov.tr, .com.tr, google.com, CDNs) | proven | easy | no |
| P1 | On-device strategy prober (`dpb tune`, blockcheck-shaped) | likely | moderate | no |
| P1 | Disorder — per-segment setsockopt(IP_TTL=1) so the earlier segment is retransmitted after the later one | likely | easy | no |
| P1 | OOB byte injection (MSG_OOB / TCP urgent pointer) | likely | moderate | no |
| P1 | Runtime auto-retry on RST/timeout with per-host strategy cache (byedpi --auto=torst) | likely | moderate | no |
| P1 | TLS record fragmentation (dpb's current default) | unknown | easy | no |
| P1 | IPv6 handling — capture v6 or filter AAAA | proven | moderate | yes |
| P2 | HTTP header tampering (host-case, host-dot, hostspell, hostpad) | likely | easy | no |
| P2 | QUIC / UDP-443 policy — block to blocked names to force TCP fallback | likely | moderate | yes |
| P2 | QUIC fake-Initial with low TTL (unprivileged, via connected UDP socket) | unknown | easy | no |
| P3 | Fake TCP packets with correct sequence number and low TTL (GoodbyeDPI/zapret family) | unknown | hard | yes |
| P3 | Auto-TTL by hop-count learning (BPF SYN/ACK sniffing) | unknown | hard | yes |
| P3 | Sequence overlap (seqovl), fakedsplit, hostfakesplit, wssize, md5sig fooling | unknown | hard | yes |
| P3 | pf rdr transparent mode (as an alternative to TUN) | likely | hard | yes |
| P3 | drop-sack (BPF socket filter suppressing server SACKs) | unknown | impossible | no |
| P3 | nfqws/dvtws-style kernel packet interception | proven | impossible | yes |
| P3 | ECH (Encrypted Client Hello) | unknown | impossible | no |

### [P0] Encrypted DNS (DoH) with hardcoded bootstrap IPs

TR=proven · macOS=easy · root=False

Defeats layer 1 outright. ~26k OONI measurements since May 2026 show 0 confirmed blocks of cloudflare-dns.com / dns.google in TR, and Cloudflare + Google DoH were confirmed working live on Türk Telekom on 2026-09-02. Already implemented correctly in dpb (internal/dns) with bootstrap IPs, RFC 8484 ID-zeroing and a no-Proxy transport. The bootstrap map is essential, not optional — SpoofDPI's DoH resolves its own endpoint through the poisoned system resolver, which is a single point of failure dpb already beats.

### [P0] Alternate-port plaintext UDP DNS (77.88.8.8:1253, 9.9.9.9:9953) as fallback

TR=proven · macOS=easy · root=False

Verified live on TT 2026-09-02: both resolve blocked names correctly, while UDP/53 to the same servers times out per-QNAME. Change turkey.toml's `77.88.8.8:53` to `:1253` and add Quad9 on 9953 — as shipped, that fallback is dead weight that also risks accepting a censor's answer. CRITICAL: never fall back to TCP DNS; TCP/53 is RST-filtered at every port, including 1253.

### [P0] Chunked ClientHello splitting with a probed chunk size

TR=proven · macOS=easy · root=False

The core finding of the whole dossier. Measured x3 on TT: chunk 1/5/20/60 → HTTP 200; chunk 35 (SpoofDPI's own default) and 120 → failure; split-mode=sni (SpoofDPI's default) and first-byte → failure. dpb has no chunk emitter at all — add `chunk-N` alongside the existing multi-split. Note this REFUTES the 'fragmentation is dead on TT' claim, whose only source is an anonymous 0-star repo with an n=1 test and a non-sequitur justification.

### [P0] Complete-ClientHello read loop before choosing an emitter

TR=proven · macOS=easy · root=False

Not a bypass technique but a prerequisite for every one of them. Both dpb front-ends take the first payload from a single un-looped Read; a post-quantum ClientHello (X25519MLKEM768, ~1512-1601 bytes, now >54% of requests per Cloudflare) spans two segments on a 1500-MTU utun, so tls-record-frag silently falls back to a 1-2 byte plain TCP split — the exact shape measured as failing on TT. Intermittent, timing-dependent, unlogged: the worst failure mode to debug.

### [P0] Per-domain exclusion list (.gov.tr, .com.tr, google.com, CDNs)

TR=proven · macOS=easy · root=False

Ship an exclude list, not just an include list. zapret-win-turkey excludes com.tr/gov.tr/google.com/googleapis.com; GoodbyeDPI-Turkey #142 documents desync breaking banking and government sites; the macOS Discord tool excludes *.discordapp.net because desync corrupts large downloads. dpb wires sni_skip only into proxy mode — tun.Options has no SkipHost field, so exclusions silently vanish under sudo — and matches with bare HasSuffix, so `bank.com` also matches `evilbank.com`.

### [P1] On-device strategy prober (`dpb tune`, blockcheck-shaped)

TR=likely · macOS=moderate · root=False

The single clearest differentiator: no macOS-native tool in this space has auto-tuning. SpoofDPI has none; zapret's blockcheck.sh is a 2349-line interactive shell script. Justified directly by the measurements — efficacy is non-monotonic in chunk size WITHIN one ISP, so no static per-ISP table can be right. Steal blockcheck's design (DNS preflight first, unblocked control domain, cross-target intersection) but run exhaustively by default: blockcheck's own summary warns its greedy early-exit makes the intersection untrustworthy.

### [P1] Disorder — per-segment setsockopt(IP_TTL=1) so the earlier segment is retransmitted after the later one

TR=likely · macOS=easy · root=False

Every field-verified Turkish profile pairs a split with disorder, OOB, or seqovl; the canonical ByeDPI Turkey string is `--split 1 --disorder 3+s ... --tlsrec 1+s`, and zapret2's TT/Superonline flagship is multidisorder:seqovl=1. Measured race-free on macOS: with TCP_NODELAY and an empty send queue the TTL=1 segment leaves immediately and only that segment is retransmitted (Linux-like, not FreeBSD). dpb's Conn.SetTTL already exists on both front-ends and is called by nothing. MUST bound the segment count — the XNU if_sndbyte_unsent panic is provoked by high-volume small writes.

### [P1] OOB byte injection (MSG_OOB / TCP urgent pointer)

TR=likely · macOS=moderate · root=False

Appears in the one macOS-on-TT recipe reported working (`--split-pos=1 --oob`, Aug 2026) and in zapret's tpws ladder. MSG_OOB=0x1 exists in the SDK and byedpi's --oob scores 8/8 on macOS. Two hard constraints: Go's net.TCPConn exposes no MSG_OOB path, so it needs syscall.RawConn.Control + unix.Sendto (awkward with the runtime poller); and it must NEVER be combined with disorder on Darwin — zapret gates that pair to Linux because other kernels retransmit the OOB byte without URG and poison the stream (byedpi's --disoob measured 0/8 on macOS).

### [P1] Runtime auto-retry on RST/timeout with per-host strategy cache (byedpi --auto=torst)

TR=likely · macOS=moderate · root=False

Complements the one-shot prober: apply nothing until you actually see an RST, then walk the ladder and cache the winner per destination with a TTL. Keeps you off the slow path for the 99% of hosts that aren't blocked, and self-heals when the ISP changes tactics — which the field data says is normal (Superonline configs reportedly broke in Feb 2026; profiles disagree across tools today). dpb applies desync unconditionally to every flow, which is both slower and riskier on large CDN transfers.

### [P1] TLS record fragmentation (dpb's current default)

TR=unknown · macOS=easy · root=False

Verified byte-correct in dpb — two structurally valid records splitting the SNI at 'blocked-si|te.example' — but never measured against Turkish DPI. The repo's 'verified against a live Turkish ISP' claim has no capture, ISP name, date or methodology anywhere in the tree. It is a genuinely different mechanism from TCP-segment splitting (record layer vs segment boundaries) so the chunk-sweep results do not transfer either way. Keep it in the ladder; do not keep it as the unexamined default.

### [P1] IPv6 handling — capture v6 or filter AAAA

TR=proven · macOS=moderate · root=True

The IPv6 sinkhole 2a01:358:4014:a00::3 is registered in RIPE to BTK itself, so AAAA poisoning is half of layer 1. dpb captures only 0.0.0.0/1 + 128.0.0.0/1 and assigns no v6 address — yet its TUN DNS path forwards AAAA queries verbatim and returns real AAAA records, actively handing apps addresses for traffic it cannot see. Filtering AAAA in the resolver chain is a few lines and fails closed; full ::/1 + 8000::/1 capture is the right end state.

### [P2] HTTP header tampering (host-case, host-dot, hostspell, hostpad)

TR=likely · macOS=easy · root=False

Cheap, already implemented in dpb (host-case, host-dot verified working), zero privileges, and a real differentiator against SpoofDPI which does no plaintext-HTTP evasion at all. Diminishing value in 2026 since most traffic is HTTPS. One latent bug: mangleHeaderName searches the whole payload rather than stopping at the header block, unlike parseHTTPHost. --hostpad is worth adding as a diagnostic — zapret notes that if the minimum working pad size approaches the MTU, the DPI is not reassembling and a plain split is the better fix.

### [P2] QUIC / UDP-443 policy — block to blocked names to force TCP fallback

TR=likely · macOS=moderate · root=True

The working Discord recipe for Turkey requires manually passing --disable-quic, which is direct evidence QUIC is what breaks Electron apps. No tool in the dossier parses QUIC Initials. GoodbyeDPI's -q (block QUIC) is part of its default -9 preset precisely to force browsers back onto the path the TCP strategies cover. dpb's TUN mode relays UDP/443 verbatim, which is WORSE than proxy mode for an HTTP/3 browser — proxy mode at least forces TCP fallback. Dropping UDP/443 for blocked hostnames is far cheaper than decrypting and re-fragmenting QUIC Initials.

### [P2] QUIC fake-Initial with low TTL (unprivileged, via connected UDP socket)

TR=unknown · macOS=easy · root=False

A genuine free win nobody has noticed: byedpi's desync_udp is UNGATED on macOS and does setttl(sfd, ttl) then sends N fake datagrams before the real one — so QUIC fake-Initial works on Darwin with no privileges, provided you see the datagrams (SOCKS5 UDP ASSOCIATE, or a utun). This refutes the blanket 'fake+low-TTL is unavailable on macOS' claim; only TCP fakes are compiled out. Efficacy against TR DPI is unmeasured.

### [P3] Fake TCP packets with correct sequence number and low TTL (GoodbyeDPI/zapret family)

TR=unknown · macOS=hard · root=True

Currently triply broken in dpb: BaseSeq hardcoded to 0 (decoys land ~4GB out of window with ack=0), the raw socket has no IP_BOUND_IF so the decoy is routed back into dpb's own utun by the 0.0.0.0/1 capture route, and the real ClientHello is written unfragmented so the profile is worse than the default. Fixing it needs a netstack-owned upstream endpoint to get a real ISN. And the payoff is unproven: both community-verified working SpoofDPI configs for Turkey omit fake packets entirely, and upstream ships FakeCount:0 by default. Do not start this before the prober says fakes help.

### [P3] Auto-TTL by hop-count learning (BPF SYN/ACK sniffing)

TR=unknown · macOS=hard · root=True

The right way to do fake-packet TTL if you do fakes at all — measure per-destination rather than guess. SpoofDPI's design (snap the inbound SYN/ACK TTL to 64/128/255, subtract, cache in a sharded LRU, use max(hops,2)-1) is worth copying wholesale, and is strictly better than a hardcoded value. Note its cache-miss path hardcodes 255 and returns TTL 254, a silent fail-open where the fake reaches the origin. GoodbyeDPI-Turkey #142 claims TT has DPI only in the first ~3 hops, but that is one unverified community report. Blocked behind the fake-packet fix; needs root for /dev/bpf.

### [P3] Sequence overlap (seqovl), fakedsplit, hostfakesplit, wssize, md5sig fooling

TR=unknown · macOS=hard · root=True

The 2026 state of the art in zapret/zapret2, and seqovl in particular is strong structural evidence that TR DPI reassembles (it appears in the flagship profile for both TT and Superonline). But all of it requires emitting packets with sequence numbers the kernel would not choose, which is unreachable until dpb owns the upstream TCP endpoint. wssize is additionally unreachable in userspace on macOS — measured: SO_RCVBUF=1024 still yields a ~32KB advertised window with wscale 3. Also note --mss is unavailable: setsockopt(TCP_MAXSEG) returns EINVAL on macOS both before and after connect.

### [P3] pf rdr transparent mode (as an alternative to TUN)

TR=likely · macOS=hard · root=True

Looks cheaper than TUN but is not. net/pfvar.h is absent from the current SDK so DIOCNATLOOK original-destination recovery needs vendored undocumented struct layouts (exactly what SonicDPI got wrong with an 'approximate' ioctl number). zapret's recipe requires `user { >root }`, meaning a root-run dpb could not desync its own traffic — dpb's existing IP_BOUND_IF + -ifscope design avoids that. And it is TCP-only. If ever added, the anchor MUST be named `com.apple/dpb`: anchors outside com.apple/* load, appear in `pfctl -s Anchors`, and are never evaluated, and the wildcard is non-recursive.

### [P3] drop-sack (BPF socket filter suppressing server SACKs)

TR=unknown · macOS=impossible · root=False

byedpi installs a 7-instruction classic BPF program via SO_ATTACH_FILTER on the TCP socket. macOS BPF is a device, not a socket filter — there is no SO_ATTACH_FILTER equivalent. Document as a known permanent gap rather than attempting to emulate it.

### [P3] nfqws/dvtws-style kernel packet interception

TR=proven · macOS=impossible · root=True

Dead on macOS, permanently. Verified first-hand: pfctl contains zero 'divert' strings, `man 5 pf.conf` has zero divert mentions, the kernel exports zero div_* symbols. IPPROTO_DIVERT 254 survives only as a vestigial constant in netinet/in.h. zapret's own docs say dvtws 'compiles but is useless'. The design space on macOS is exactly two options — userspace proxy (optionally behind pf rdr) or a TUN device — and there will never be a third.

### [P3] ECH (Encrypted Client Hello)

TR=unknown · macOS=impossible · root=False

Not a technique a bypass tool can apply to someone else's traffic — you cannot add ECH to an application's ClientHello without terminating and re-originating TLS. Censors already block it directly elsewhere (Russia's TSPU drops ClientHellos carrying the ECH extension since Nov 2024). No evidence either way for Turkey. The one useful adjacent action is what dpb already does: ship a DoH resolver so browsers that DO support ECH can fetch the HTTPS/SVCB record.


---

## 3. Architecture recommendation (from the rebuild-core synthesis)

> NOTE: the user has since chosen a FULL FROM-SCRATCH rewrite. This section is retained
> because its technical content (defect analysis, interfaces, measured constraints) is
> what the new design must satisfy — not because its keep/rewrite verdict is binding.

## 0. What the architecture has to be shaped by

Three measured facts drive everything:

1. **The block is SNI-keyed RST injection on a reachable path.** Same Cloudflare IP, benign SNI → HTTP 301; blocked SNI → RST. So the job is *hide the SNI from the middlebox*, not *find another route*. IP allowlists, IP-scoped routing, and "route everything through a tunnel" are all wasted work.
2. **DNS is a separate, per-QNAME drop — not a port-53 redirect.** `dig @8.8.8.8 discord.com` times out; `dig @8.8.8.8 google.com` answers. Encrypted transport or a non-53 UDP port both escape it; TCP/53 does not, at any port.
3. **The winning ClientHello shape is empirical and non-monotonic.** chunk 1/5/20/60 → 200, chunk 35/120 → 000, split-at-SNI → 000. No static profile survives this. The architecture must contain a *prober*, not a table.

---

## 1. Package map (target state)

```
cmd/dpb/                      (move main.go here)
internal/
  config/                     KEEP + extend
    profile.go                + [strategy] ladder, [filter] exclude, alt-port DNS
    embed/                    global.toml, turkey.toml  (delete turkey-superonline.toml)
  dns/                        KEEP nearly as-is  ★ strongest package
    resolver.go doh.go udp.go exchange.go
    + altport.go              NEW: UDP resolver pinned to :1253 / :9953
    + poison.go               NEW: sinkhole + uniqueness detector
  desync/                     REBUILD the emitter set
    engine.go strategy.go clienthello.go http.go   KEEP
    split.go tlsrecord.go hostmangle.go            KEEP
    + chunk.go                NEW  chunk-N emitter (P0)
    + disorder.go             NEW  TTL=1 per-segment (P1)
    + oob.go                  NEW  MSG_OOB byte (P1)
    packet.go fakepacket.go   QUARANTINE behind a build tag until seq is real
  probe/                      NEW PACKAGE  ★ the differentiator
    ladder.go  runner.go  verdict.go  cache.go
  proxy/                      REWRITE handler.go, keep server.go/conn.go/adapt.go
  tun/                        KEEP netstack; REWRITE relay policy in stack_darwin.go
    endpoint_darwin.go device_darwin.go udp_darwin.go   KEEP (udp is excellent)
  sysnet/                     KEEP; fix runner.go + add IP_BOUND_IF
    runner.go                 FIX: parse stderr, route(8) always exits 0
    rawinject_darwin.go       FIX: IP_BOUND_IF, or quarantine with fakepacket
  cli/
    run.go runtun_darwin.go doctor.go service.go       KEEP
    + tune.go                 NEW  `dpb tune`
```

---

## 2. Interception layer — keep both, change the default

**Proxy mode (no root) stays the primary shipped path.** The measured evidence says an unprivileged chunking proxy already beats the TT block today; the fake-packet path costs root and has zero measured gain. Keep `--mode proxy` as the default and the one you tell non-technical users about.

**TUN mode (root) stays, for proxy-unaware binaries only** — Discord's updater, Electron helpers, anything that ignores `networksetup`. The gVisor + wireguard/tun + link-endpoint plumbing is correct and hard-won; do not throw it away.

**Do not add pf-rdr as a third mode.** It looks cheaper but: `net/pfvar.h` is gone from the SDK so `DIOCNATLOOK` original-destination recovery needs vendored undocumented structs; zapret's recipe requires `user { >root }`, which means a root-run dpb cannot desync its own traffic; and it is TCP-only. dpb's existing `IP_BOUND_IF` + `-ifscope` design already solves the recursion problem *without* excluding root, which is strictly better. If you ever do add pf, the anchor name must be `com.apple/dpb` — anchors outside `com.apple/*` load, appear in `pfctl -s Anchors`, and are never evaluated (and `com.apple/dpb/sub` is *also* never evaluated; the wildcard is one level, non-recursive).

### The TUN relay, corrected

Today `relay()` does an unconditional `client.Read(buf)` before `pipe()`. Fix:

```go
func (srv *Server) relay(client *gonet.TCPConn, dstIP net.IP, dstPort int) {
    up := dial(...)
    if !srv.opt.DesyncPorts[dstPort] || srv.opt.SkipHostIP(dstIP) {
        pipe(client, up)          // start both directions immediately
        return
    }
    // Only on desync ports: bounded wait for a complete first message.
    first, err := readFirstMessage(client, 250*time.Millisecond, 64*1024)
    if err == errNoClientData {   // server-speaks-first protocol
        pipe(client, up); return
    }
    srv.applyDesync(up, first, dstPort)
    pipe(client, up)
}
```

`readFirstMessage` is the other half of the fix: loop until the declared TLS record length is satisfied, capped by deadline and size. A post-quantum ClientHello is ~1512–1601 bytes and spans two 1460-byte segments on the utun, so today `tls-record-frag` silently degrades to a 1–2 byte plain TCP split — the exact shape measured as *failing* on TT.

---

## 3. Desync engine — interfaces

Keep the existing shape, it is good. Extend it in two places.

```go
// strategy.go — add a capability declaration so the injector isn't opened for
// emitters that never use it (today a raw socket is opened per connection even
// for tls-record-frag).
type Emitter interface {
    Name() string
    Emit(ctx context.Context, conn Conn, data []byte, meta *Meta) error
    Needs() Capability          // NEW: CapNone | CapRawInject | CapSockTTL | CapOOB
}
```

New emitters:

| Emitter | Mechanism | Privilege |
|---|---|---|
| `chunk-N` | fixed-size `Write` loop on a `TCP_NODELAY` socket | none |
| `disorder` | per-segment `SetTTL(1)` → `Write` → `SetTTL(default)` | none |
| `oob` | `RawConn.Control` + `unix.Sendto(fd, buf[:pos+1], MSG_OOB)` | none |

`Conn.SetTTL` already exists on both `proxyConn` and `tunConn` and is currently called by nothing — `disorder` is the consumer it was built for.

Two hard rules for `disorder`:

* **Never combine `disorder` with `oob` on Darwin.** zapret gates that combination to Linux with an explicit comment: other kernels retransmit the OOB byte without the URG flag and poison the stream. Reject the pair at config-validation time.
* **Bound the segment count.** The XNU `assertion failed: ifp->if_sndbyte_unsent >= 0` panic is a *pre-existing Apple defect* (public reports back to xnu-4570, 2017) provoked by high volumes of small writes — not a SpoofDPI bug. Any tool that emits hundreds of tiny writes per connection can trip it. Cap segments at 16 and read the real default TTL rather than hardcoding 64.

---

## 4. Fake-packet path — quarantine, don't ship

Three independent defects, each fatal on its own:

1. `runtun_darwin.go:106` passes literal `0` as `BaseSeq`. Fakes carry seq `0x00000000` / `0xFFFF0000`, ack `0`. Any DPI that reassembles enough to see an SNI discards a segment 4 GB out of window before parsing it.
2. `rawinject_darwin.go` sets only `IP_HDRINCL` — no `IP_BOUND_IF`. `unix.Sendto` does an unscoped route lookup; `0.0.0.0/1 → utun` is more specific than the `-ifscope en0` default, so the decoy is written back into dpb's own tun device.
3. `fakeTTL.Emit` writes the real ClientHello with a single unfragmented `conn.Write`. In TUN mode with root the injector *is* non-nil, so the `tlsRecordFrag` fallback never fires — `turkey-superonline` ships the SNI intact in one segment.

The parts that are *right* and worth preserving verbatim: `buildIPv4TCP` (correct IP + TCP-pseudo-header checksums), and the macOS `IP_HDRINCL` byte-order fixup swapping `ip_len`/`ip_off` — `man 4 ip` on Darwin says "the ip_off and ip_len fields are in host byte order", and XNU's `rip_output` validates `ip_len` in host order, so a network-order value would `EINVAL`. Same page confirms `ip_id = 0` means "kernel sets appropriate value", so the all-zero IP ID is not a fingerprint.

Move `packet.go` + `fakepacket.go` behind `//go:build dpb_fakes`, keep the tests, and revisit only after a netstack-owned upstream endpoint gives you a real ISN.

---

## 5. DNS — small changes, large effect

The resolver chain is the best code in the repo (bootstrap IPs, RFC 8484 ID-zeroing, NXDOMAIN-vs-SERVFAIL, no self-proxy loop). Four fixes:

1. **Replace `77.88.8.8:53` with `77.88.8.8:1253`** in `turkey.toml`, add `9.9.9.9:9953`. Measured on TT today: `:53` to any public resolver is dropped per-QNAME for blocked names; UDP `:1253` and `:9953` answer correctly. TCP/53 is RST at any port — never fall back to TCP DNS.
2. **Add `poison.go`.** Two detectors, both cheap: (a) sinkhole sentinel — treat `195.175.254.2` or `2a01:358:4014:a00::3` in any answer as a positive censorship signal; (b) zapret's reference-free uniqueness heuristic — if the system resolver returns the *same* address for several different blocked names, it is a censor. Surface both in `dpb doctor` and in the `dpb tune` preflight.
3. **Ask AAAA.** All three resolvers hardcode `dns.TypeA`; the `*dns.AAAA` branch in `extractA` is dead. Fire A and AAAA in parallel.
4. **Synthesise SERVFAIL in `serveDNS`** instead of returning on the first chain error, which today closes the UDP session and makes the stub resolver wait out its own timeout.

---

## 6. `dpb tune` — the actual differentiator

No macOS-native tool in this space has auto-tuning. SpoofDPI has none. zapret's `blockcheck.sh` is a 2349-line interactive shell script.

```go
package probe

type Candidate struct{ Emitter string; Params desync.Spec }
type Result struct{ Cand Candidate; Domain string; OK bool; Latency time.Duration }

type Ladder []Candidate      // ordered by prior probability of success
func (l Ladder) Run(ctx, targets []string, control string, opt Options) []Result
func Intersect(rs []Result, nTargets int) []Candidate  // works for ALL targets
```

Design, lifted from blockcheck and corrected for what was measured:

* **Preflight DNS first.** No packet strategy fixes a poisoned resolver; report and stop if the chain itself is compromised.
* **Control domain.** Probe a known-unblocked host each round to distinguish "strategy failed" from "network is down".
* **Sweep chunk size non-monotonically.** The measured curve is 1 ✓, 5 ✓, 20 ✓, 35 ✗, 60 ✓, 120 ✗. A binary search or a "smaller is better" assumption gets the wrong answer. Sweep the discrete set `{1, 2, 5, 10, 20, 40, 60}` plus record-frag and disorder/oob variants.
* **Intersect across ≥3 targets, exhaustively by default.** blockcheck's own summary warns that its greedy early-exit makes the intersection untrustworthy; a first-match-wins result is a config that works for whichever domain happened to be tested first. Slow-with-a-progress-bar beats fast-and-wrong for this audience.
* **Write the winner into `~/.config/dpb/profile.toml` and offer to restart the service.** Do not print a paragraph of caveats and exit — that is the zapret failure mode.
* **Turkish targets, not `rutracker.org`.** Seed from `discord.com`, `discord.gg`, `discord.media`, plus 2–3 currently-blocked names; treat the list as data, refreshable, not a constant.

Complement it with runtime adaptation (byedpi's `--auto=torst`): on `ECONNRESET`/timeout for a host, advance one rung on the ladder, cache the winner per host with a TTL, persist across restarts. Together these mean the tool self-heals when the ISP changes tactics — which the field data says is the normal state.

---

## 7. Scoping and safety

**Ship an exclude list, not just an include list.** zapret-win-turkey excludes `com.tr`, `gov.tr`, `google.com`, `googleapis.com` precisely because aggressive desync breaks banking and government sites; GoodbyeDPI-Turkey issue #142 reports the same. Also exclude CDNs where desync corrupts large transfers (`discordapp.net` is the documented case).

Two fixes required to make this real:

* `sni_skip` is wired **only** into `proxy.Options.SkipHost` (`run.go:99`). `tun.Options` has no `SkipHost` field — a user who excludes their bank loses that exclusion the moment they run `--mode tun` under sudo. Add IP-level skip to the TUN relay.
* `skipHostFunc` uses bare `strings.HasSuffix`, so `sni_skip = ["bank.com"]` also matches `evilbank.com`. Anchor on a label boundary.
* `sni_match` is declared in `profile.go:62` and read nowhere. Implement it or delete it — a silently ignored key in a per-ISP tuning file is a trap.

**Fix `sysnet/runner.go`.** macOS `route(8)` has no failure exit path (`newroute()` is `void`; `main()` does `newroute(...); exit(0)`), so every route failure in dpb is currently invisible: `AddRoute` and `ScopeUplink` treat them as success. Consequences: a run under a full-tunnel VPN prints "Ready. Capture all TCP + UDP" while capturing nothing; the journal records deletes for routes dpb never created and removes the VPN's routes on Ctrl-C; the `File exists` adoption branch is unreachable dead code. Parse combined output for `writing to routing socket` rather than trusting the exit status.

**Persist the route journal to disk** alongside the proxy/DNS backups, and have `dpb doctor` replay it. The `-ifscope` default route is attached to the physical uplink and does not vanish with the utun; today the README tells users to `sudo route delete` it by hand.

**Add a route-change watcher.** A `PF_ROUTE` monitor that re-derives uplink + gateway and rebuilds the bound dialer, or at minimum tears everything down on a default-route change. Laptop users switch networks constantly; "it broke my internet" is the outcome today.

**Add `recover()` per connection goroutine** — the README promises restoration on panic, and Go runs only the panicking goroutine's defers.

---

## 8. IPv6

`CaptureAll` installs `0.0.0.0/1` + `128.0.0.0/1` only; `ifconfig` assigns v4 addresses only; `buildIPv4TCP` is v4-only. Meanwhile TUN-mode DNS forwards the client's raw query through `Chain.Exchange`, which **answers AAAA queries with real AAAA records** — so dpb hands applications IPv6 addresses for traffic it then cannot see. The IPv6 sinkhole `2a01:358:4014:a00::3` is registered to *BTK itself*, so AAAA poisoning is half the block.

Pick one and do it in v1: add `::/1` + `8000::/1` capture with a v6 address on the utun, or filter AAAA out of the DNS path and disable IPv6 on the service for the run. Silent fail-open is the worst option for a censorship tool.

---

## 9. Distribution

`brew tap mumudevx/tap && brew install dpb` — the README's headline instruction — cannot work: `mumudevx/homebrew-tap` does not exist, there are zero releases, and `Formula/dpb.rb` still has `REPLACE_WITH_RELEASE_SHA256`. This is the cheapest high-value fix in the whole report.

Once it exists, the distribution story is genuinely free: Homebrew downloads with curl, curl does not set `com.apple.quarantine`, so Gatekeeper never evaluates a brew-installed CLI. SpoofDPI proves it at 5k stars with no Apple account. No $99, no notarization.

Two corrections to current assumptions: the `codesign -s -` hooks in `.goreleaser.yaml` are belt-and-braces, not load-bearing — Go's internal linker already ad-hoc signs every `darwin/arm64` binary host-independently, and `lipo` preserves it. And homebrew-core is not a near-term goal: self-submission requires 225 stars (dpb has 0), and the formula would have to build from source.

For TUN mode, `dpb service install --system` should follow the clash-verge-service pattern: root-owned binary in `/Library/PrivilegedHelperTools`, a `/Library/LaunchDaemons` plist, `launchctl enable system/… ; bootout system … ; bootstrap system …`. One admin prompt at install, never again. Replace the deprecated `launchctl load -w` calls in `service.go` with the modern verbs. `SMAppService` is not an option — it requires an `.app` bundle.

---

## 4. Audit of the previous implementation (defects the rewrite must not repeat)

**Verdict:** Genuinely good infrastructure code wrapped around a desync engine whose flagship technique is a no-op — keep about 70% of it, rebuild the emitter set and the relay policy, and delete the turkey-superonline profile today because it ships the SNI in one unfragmented segment.

**Build status:** Clean on go1.26.4 darwin/arm64 as of 2026-09-02: `go build ./...` exit 0, `go vet ./...` no diagnostics, `go test ./...` 73 tests passing across 9 packages, `go test -race` also green. 6,171 lines of Go. Total statement coverage 51.5%, but badly skewed: internal/tun/stack_darwin.go (NewServer, handleForward, relay, applyDesync, pipe), all of internal/sysnet/rawinject_darwin.go, all of internal/tun/device_darwin.go, and internal/proxy/handler.go handleHTTP are ALL at 0.0%. Every confirmed defect lives in a 0%-covered function. There is no automated evidence that TCP works through the netstack at all; proxy mode does have an end-to-end CONNECT test, but it is behind `//go:build e2e` and excluded from the default run.

### Code that was CORRECT (patterns to re-derive, not to copy blindly)

- internal/dns/ (resolver.go, doh.go, udp.go, exchange.go) — the best package in the repo. Genuine RFC 8484 DoH with bootstrap IPs for four known hosts, wire-ID zeroing with caller-ID restore, no-Proxy transport so it can't self-loop, NXDOMAIN-as-final vs SERVFAIL-as-failure. This solves the DNS-poisoning half of the Turkish threat model correctly. Needs only alt-port fallbacks, AAAA, and a poison detector.

- internal/sysnet/ lifecycle (proxymode.go, dnsmode.go, tunmode_darwin.go, dnsroute_darwin.go) — production-grade. On-disk JSON backups, idempotent restore, `notSelf` guards that discard a captured state pointing at dpb's own listener (the bug most such tools ship with), a route journal replayed in reverse, restore on a fresh context.Background() rather than the cancelled one, SIGHUP handled so closing the terminal still tears down. Copy this design verbatim into any rewrite.

- internal/tun/endpoint_darwin.go + device_darwin.go — the gVisor link endpoint is correct for macOS utun. linkOffset=4 exactly matches wireguard/tun's Darwin contract (Read fills bufs[0][offset-4:] and strips 4; Write puts the AF prefix in buf[offset-4:offset]), Capabilities()=0 so gVisor computes checksums itself. The hard architectural work — utun + userspace stack + no kext — is done and done right.

- internal/tun/udp_darwin.go — excellent. Real udp.NewForwarder, port 53 answered in-process from the resolver chain instead of relayed in the clear, per-datagram copy that deliberately avoids io.Copy because stream re-framing would merge/truncate datagrams (with the reasoning in the comment), idle reaping via deadlines. serveUDP 100% / relayUDP 100% / copyDatagrams 90% covered.

- internal/desync/ scaffolding (engine.go, strategy.go, clienthello.go, http.go, split.go, tlsrecord.go, hostmangle.go) — the Emitter/Transformer/Conn abstraction is the right shape, and the engine correctly re-parses Meta after any transformer runs so emitter offsets stay valid. tls-record-frag itself is verified byte-correct: two structurally valid records splitting the SNI at 'blocked-si|te.example'.

- internal/desync/packet.go buildIPv4TCP + the macOS IP_HDRINCL byte-order fixup in rawinject_darwin.go — correct per Darwin's own `man 4 ip` ('the ip_off and ip_len fields are in host byte order') and XNU's rip_output, which validates ip_len in host order. Preserve verbatim even while the fake-packet emitters are quarantined.

- Test quality in internal/sysnet and internal/dns — tests encode *why* a behaviour matters, several citing live measurements (e.g. 'Measured on a live run: with the /32 installed, route -n get 192.168.0.1 still reported en0'). These survive refactoring.

### Code that was WRONG (defects to avoid)

- internal/tun/stack_darwin.go relay() — the unconditional `client.Read(buf)` at line 140 precedes both the DesyncPorts gate and pipe(), with no deadline, on every captured port. Deadlocks SMTP/IMAP/POP3/FTP/MySQL and any server-greets-first protocol. Start piping immediately; intercept only on desync ports with a bounded wait.

- First-payload reads in both front-ends (stack_darwin.go:140, proxy/handler.go:48) — single un-looped Read. A post-quantum ClientHello is ~1512-1601 bytes and spans two segments on a 1500-MTU utun, so tls-record-frag silently degrades to a 1-2 byte plain TCP split, which is the shape measured as FAILING on Türk Telekom. Loop until the declared TLS record is complete, bounded by deadline and size cap, and log the fallback.

- internal/desync/tlsrecord.go frag_window handling — `off := s.window` is unconditionally overwritten by the SNI midpoint whenever meta.SNIOffset > 5, i.e. for every parseable ClientHello. Verified by sweep: window 0/1/2/5/20/60 all produce byte-identical output. The banner prints window=%d and the README's tuning recipe is `--frag-window 3`. The one knob you tell a Turkish user to reach for does nothing on the recommended emitter — and it is non-deterministically alive on the no-SNI path, which is worse than dead for A/B testing.

- internal/desync/fakepacket.go — three independent fatal defects. (1) BaseSeq is literal 0 at runtun_darwin.go:106, so decoys carry seq 0x00000000 / 0xFFFF0000 and ack 0. (2) The raw socket sets only IP_HDRINCL, never IP_BOUND_IF, so an unscoped route lookup matches dpb's own 0.0.0.0/1 → utun capture route and the decoy is written back into the tunnel. (3) The real ClientHello goes out via a single unfragmented conn.Write, and the tlsRecordFrag fallback only fires when the injector is nil — which never happens in TUN mode under root. Quarantine behind a build tag until a netstack-owned upstream supplies a real ISN.

- internal/proxy/handler.go handleHTTP — dials one upstream for the first request's host then blindly tunnels the rest of the client connection into it. Reproduced: request 2 addressed to backend B was delivered to backend A. Go's http.Transport clears targetAddr from the pool key for http-scheme targets through an http proxy, so one pooled connection serves every plaintext origin. 0.0% covered. Loop http.ReadRequest and dial per-request, or force Connection: close.

- internal/sysnet/runner.go — only checks exec's error. macOS route(8) has no failure exit path (newroute() is void; main() does newroute(...); exit(0)), so every route failure is silently treated as success. A run under a full-tunnel VPN prints 'Ready. Capture all TCP + UDP' while capturing nothing, and the journal then deletes the VPN's routes on Ctrl-C. Parse combined output for 'writing to routing socket'.

- internal/tun/endpoint_darwin.go readLoop — `if err != nil { return }` with no log, no retry, no signal to the main goroutine. wireguard/tun surfaces route-socket errors through a buffered channel, so a transient failure becomes a permanent silent total IPv4 blackout while the split-default routes still point at a dead device. Also: dev.Events() is never drained (cap 10), and WritePackets leaks gVisor's pooled Views (pb.ToView() with no Release) plus copies every packet twice.

- internal/cli/run.go skipHostFunc — bare strings.HasSuffix, so sni_skip=["bank.com"] matches evilbank.com. And SkipHost reaches only proxy.Options; tun.Options has no such field, so exclusions silently stop working under sudo — the mode where they matter most.

### Code that was DEAD or HARMFUL

- internal/config/embed/turkey-superonline.toml — as shipped it is worse than doing nothing. It demands root + TUN, then in exactly that configuration emits a decoy that never leaves the machine and writes the real ClientHello in one unfragmented segment with the SNI intact. Strictly weaker than the default `turkey` profile. Delete it now; reintroduce only after the fake path has a real sequence number and a bound socket, and only if probing shows fakes actually help on TR (both community-verified working SpoofDPI configs for Turkey omit fake packets entirely).

- internal/config/profile.go:62 `SNIMatch` — declared and referenced nowhere in the repo. Validate() does not reject it either, so a user who writes sni_match=["youtube.com"] to scope desync silently gets global desync. Implement or remove.

- internal/desync/packet.go badChecksum + tcpFlagFIN/SYN/RST — implemented and unit-tested, wired to no emitter. Keep the code only if fake packets come back (it is the one fooling primitive that genuinely works on a macOS raw send, since nothing sets CSUM_TCP for IP_HDRINCL); otherwise it is dead weight advertising a capability that does not exist.

- Formula/dpb.rb as the documented install path — it points at releases that do not exist, with `sha256 "REPLACE_WITH_RELEASE_SHA256"`, in a tap (mumudevx/homebrew-tap) that returns 404. Either create the tap and cut a release, or delete the brew instructions from the README. Shipping a headline install command that 404s is worse than shipping none.

- The `codesign -s -` hooks in .goreleaser.yaml (optional) — Go's internal linker already ad-hoc signs darwin/arm64 host-independently and lipo preserves it. Harmless, but they create a false belief that a Linux runner would break the build.


---

## 5. Open decisions

### D1. What to do with the fake-packet family (fake-ttl / fake-seq / turkey-superonline) right now

- Delete the code and the profile entirely — the technique is unproven for TR and costs root
- Quarantine behind a `//go:build dpb_fakes` tag, delete the profile, keep buildIPv4TCP and the byte-order fixup; revisit only if the prober shows fakes help
- Fix it properly now: add IP_BOUND_IF, move the upstream endpoint into gVisor to get a real ISN, and compose the fake with a stream-level emitter instead of replacing it

**Recommended:** Quarantine behind a build tag and delete turkey-superonline.toml this week. The profile as shipped is actively harmful — it demands sudo and then sends the SNI in one unfragmented segment. But buildIPv4TCP and the macOS IP_HDRINCL byte-order fixup are correct and hard to rediscover (verified against `man 4 ip` and XNU's rip_output), so keep the code compiling behind a tag with its tests. Full fix is a P2/P3 item: it requires re-architecting the TUN relay to own the sequence space, and both community-verified working Turkey configs omit fake packets, so the payoff is speculative.

### D2. Which interception mode is the primary, supported path

- Proxy mode (no root) as primary, TUN as an opt-in for proxy-unaware apps
- TUN mode as primary — it captures everything
- Add pf-rdr as a third, cheaper transparent mode

**Recommended:** Proxy mode as primary; TUN opt-in. The measured evidence says unprivileged chunking already beats the current TT block, and the fake path costs root for zero measured gain. Reject pf-rdr: net/pfvar.h is gone from the SDK so DIOCNATLOOK needs vendored undocumented structs (exactly what SonicDPI got wrong), zapret's recipe requires excluding root's own traffic — which dpb's IP_BOUND_IF design avoids — and it is TCP-only. Keep TUN for the proxy-unaware-binary case, but reproduce the Discord-updater claim before investing further in it.

### D3. Default emitter for the `turkey` profile

- Keep tls-record-frag (record-layer split, untested against TT)
- Switch to chunk-5 (measured working on TT, matches the community-verified SpoofDPI recipe)
- Ship chunk-5 as default and make tls-record-frag a probed alternative

**Recommended:** Ship chunk-5 as the default and keep tls-record-frag in the ladder. TLS-record fragmentation is a genuinely different mechanism from TCP-segment chunking and may well work — but it has never been measured against Türk Telekom, whereas chunk-5 has been, three times, and matches the working config in SpoofDPI issue #403. Do not let the repo's unsourced 'verified against a live Turkish ISP' README claim carry the default; there is no capture, ISP name, date or methodology behind it anywhere in the tree.

### D4. Plaintext DNS fallbacks in the Turkey profile

- Remove plaintext UDP fallbacks entirely — DoH only
- Keep 77.88.8.8 but move it to :1253, and add 9.9.9.9:9953
- Keep :53 as-is and add poison detection so a hijacked answer is rejected

**Recommended:** Move to alternate ports and add poison detection. Measured on TT: UDP/53 to every public resolver is dropped per-QNAME for blocked names, so `77.88.8.8:53` in turkey.toml is dead weight that also risks accepting a censor's answer; UDP/1253 and UDP/9953 both work today. Ship both alt-port fallbacks AND the sinkhole sentinel (195.175.254.2 / 2a01:358:4014:a00::3) plus zapret's reference-free uniqueness heuristic. Never fall back to TCP DNS — it is filtered at every port.

### D5. How ambitious `dpb tune` should be in v1

- Chunk-size sweep only against one target, write the winner (~2 days)
- Full ladder (chunk sizes × record-frag × disorder × oob) across 3+ targets with a control and cross-target intersection (~1-2 weeks)
- Ship a static per-ISP profile table instead and defer probing

**Recommended:** Full ladder with intersection. This is the differentiator — no macOS-native tool has auto-tuning, SpoofDPI has none, and zapret's blockcheck is a 2349-line interactive shell script no non-technical user will run. The static-table option is refuted by the measurements: efficacy is non-monotonic in chunk size within a single ISP, so a per-ISP table is the wrong abstraction. Heed blockcheck's own warning and run exhaustively by default — its greedy early-exit makes the cross-domain intersection untrustworthy, and 'a strategy that fixes one site and breaks another' is worse than useless.

### D6. IPv6 policy

- Add ::/1 + 8000::/1 capture, a v6 address on the utun, and an IPv6 desync path
- Filter AAAA out of the DNS path so apps never get v6 addresses for traffic dpb can't see
- Disable IPv6 on the service for the duration of the run
- Leave as-is and document it

**Recommended:** Filter AAAA in v1, full v6 capture later. Leaving it as-is is not acceptable: the IPv6 sinkhole is registered to BTK itself, so AAAA poisoning is half of layer 1, and dpb currently makes it worse by answering AAAA queries with real records for traffic it then cannot capture. Filtering AAAA in the resolver chain is a few lines and fails closed. Disabling IPv6 on the interface is more invasive and leaves residue after a hard kill. Full v6 capture is the right end state but is a larger change touching routes, ifconfig, and buildIPv6TCP.

### D7. Whether to add disorder and OOB emitters, given the macOS constraints

- Add both, mutually exclusive on Darwin, bounded to ≤16 segments
- Add disorder only — it is cheap (SetTTL already exists on both Conn impls) and lower-risk
- Add neither; chunking alone is measured sufficient on TT

**Recommended:** Add both, mutually exclusive, bounded. Every field-verified Turkish profile that goes beyond plain splitting pairs it with disorder, OOB, or seqovl, and the one macOS-on-TT recipe reported working is `--split-pos=1 --oob`. Disorder is nearly free — `Conn.SetTTL` is already implemented on proxyConn and tunConn and called by nothing. Enforce the exclusion at config-validation time (zapret gates the pair to Linux because other kernels retransmit the OOB byte without URG and poison the stream), and cap segments to stay clear of the XNU write-volume panic. Budget real time for OOB: Go's net package exposes no MSG_OOB path, so it needs RawConn.Control + unix.Sendto.

### D8. Distribution: what to fix first

- Create mumudevx/homebrew-tap, cut a v0.1.0 release, fill in the real sha256
- Pursue homebrew-core with a source-building formula
- Add a curl|sh installer as the primary path
- Notarize with a $99 Apple Developer account

**Recommended:** Create the tap and cut a release — today, before any technique work. The README's headline install command currently 404s, so the tool has no users at all. Homebrew-core is not reachable: self-submission requires 225 stars and dpb has 0. Notarization buys nothing — brew installs carry no quarantine, and Go's linker already ad-hoc signs darwin/arm64 host-independently, so Apple Silicon's SIGKILL requirement is already satisfied. A curl|sh installer is a reasonable secondary path (it also skips quarantine); a browser-downloaded .tar.gz already extracts without quarantine via `tar xzf`, so the README's `xattr -dr` advice is aimed at the wrong path.


---

## 6. Risks

- THE HEADLINE RISK: the whole product rests on one afternoon of measurement from one Türk Telekom line in Kayseri on 2026-09-02. The chunk-size curve (1/5/20/60 pass, 35/120 fail), the per-QNAME DNS drop, the TCP/53 filtering, the SNI-RST proof — all of it is n=1 ISP, n=1 city, n=1 day, one target domain family. Turkish DPI demonstrably varies by ISP (Superonline profiles disagree across tools; Vodafone needs a different split position) and rots on a months-scale cadence. Build the prober precisely so you never have to trust a measurement this thin again — but do not ship a profile that hardcodes these numbers as if they were laws.

- The XNU `if_sndbyte_unsent` panic is a pre-existing Apple defect provoked by high-volume small TCP writes, and it is reachable from dpb regardless of design. A chunk-1 emitter over a busy connection produces exactly the write pattern that tripped it for a Turkish user on macOS Tahoe. Cap segment counts, prefer larger working chunk sizes over smaller ones when the prober finds several, and treat 'chunk-1 works' as a diagnostic result rather than a shipping default. Testing this is inherently destructive and needs a spare machine.

- OONI is the evidentiary backbone of the censorship-landscape half of this report, and none of it could be independently reproduced — every request from the fact-checker returned `{"error":"quota exceeded"}` from both api.ooni.io and api.ooni.org, across two endpoint families and six attempts. The aggregate DNS-vs-SNI split, the per-ASN breakdowns, the DoH-accessibility counts, and the Discord/Roblox block trends all trace to a single unreplicated session with no archived payloads. Treat them as directionally useful, not as numbers to quote.

- The Discord-updater justification for TUN mode is single-sourced from an anonymous 0-star, 3-commit repo, and it is load-bearing for the most expensive piece of the architecture. Reproduce it in 15 minutes before investing further: run proxy mode, launch Discord, and watch `~/Library/Application Support/discord/logs/Discord_updater_rCURRENT.log`. If the updater honours the system proxy after all, the case for TUN weakens considerably and proxy mode plus a QUIC-blocking story may be the whole product.

- Fixing the fake-packet path requires owning the upstream TCP sequence space, which means terminating the upstream connection inside gVisor rather than using a kernel socket. That is a substantial re-architecture of the TUN relay, it invalidates the current BoundNetDialer/IP_BOUND_IF recursion fix, and the payoff is unproven — both community-verified working Turkey configurations omit fake packets entirely. High cost, speculative benefit; do not start it before the prober tells you fakes help.

- MSG_OOB in Go is not free. `net.TCPConn` exposes no way to send it; you need `syscall.RawConn.Control` plus `unix.Sendto` with the MSG_OOB flag on the raw fd, which interacts awkwardly with Go's runtime poller. Since `--oob` appears in the only macOS-on-TT recipe reported working, this cost lands on a P1 item, not a nice-to-have.

- Turkey's VPN Regulation proposal (İfade Özgürlüğü Derneği, 2026-04-20) would amend Law 5809 to define 'sanal ağ hizmet sağlayıcı', require BTK authorization via a Turkish representative, and authorise fines of 1M-30M TL plus bandwidth throttling up to 95%. It is a teklif, not enacted. It does not obviously cover a local serverless tool — but the definitional boundary is untested, and a Turkish-authored, Turkish-audience circumvention tool sits closer to it than a generic library does.

- Circumvention-tool domains are themselves partially blocked in Turkey (psiphon.ca, protonvpn.com, nordvpn.com all show anomalies). Any update endpoint, strategy-list fetch, or telemetry destination may be unreachable from the network the tool is meant to fix. Bootstrap everything over DoH and assume the update channel can be censored.

- Aggressive desync applied indiscriminately breaks banking, government and large CDN downloads — this is documented across three independent Turkish tools and is the most common reason users uninstall. dpb currently captures ALL TCP+UDP in TUN mode and does not apply `sni_skip` there at all. Shipping the prober without shipping the exclusion list first means the first thing a user notices is that their bank stopped working.

- macOS route(8) silently succeeding turns several correctness bugs into invisible ones simultaneously: a run under a full-tunnel VPN reports 'Ready. Capture all TCP + UDP' while capturing nothing; the teardown journal deletes routes dpb never created, including the VPN's; and the `File exists` adoption branch is unreachable dead code. Until runner.go parses stderr, every route-related diagnosis you make about this tool is unreliable.

- Distribution is currently broken in a way that makes all of the above moot: `mumudevx/homebrew-tap` returns 404, there are zero GitHub releases, and the formula carries a placeholder sha256. The README's headline install command cannot work for anyone. Fix this before any technique work, or the tool has no users to be wrong for.

- IPv6 is a silent fail-open. TUN mode captures only IPv4 while dpb's own DNS path forwards AAAA queries verbatim and returns real AAAA records — so the tool actively hands applications addresses for traffic it then cannot see, on a network whose IPv6 sinkhole is registered to BTK. For a censorship tool this is worse than failing closed, and it is currently disclosed only in a README limitations section.


---

## 7. Superseding first-hand measurements

See `MEASUREMENTS.md` in the same directory. It was measured after this dossier was
written, on the same Türk Telekom line, and it CORRECTS this document in several
places — most importantly the P0 technique choice and the efficacy of `disorder`.
Where the two disagree, MEASUREMENTS.md wins: it is first-hand, shuffled, and
controlled.
