# First-hand DPI measurements — Türk Telekom (AS9121, Kayseri), 2026-09-02

All numbers below were measured directly from the development machine, not taken
from any tool's documentation. Every run interleaved a benign-SNI control against
the *same* destination IP; the control passed 100% in every run, so no result here
is explained by the network being down.

Probe sources: `scratchpad/{chunkprobe,emitprobe,mechprobe,ruleprobe}`.

## 1. The block

SNI-keyed RST injection on an otherwise-reachable path.

```
curl --resolve discord.com:443:162.159.128.233     -> 000 (connection reset)
curl --resolve cloudflare.com:443:162.159.128.233  -> 301
```

Same IP, same port, same TCP handshake. Only the SNI differs.

Blocked targets confirmed: `discord.com`, `discord.gg`, `gateway.discord.gg`,
`cdn.discordapp.com`, `updates.discord.com`.
NOT blocked: `media.discordapp.net` (401), `discord.media` (520) — both reach the
origin, so they must be excluded from desync rather than fixed by it.

## 2. DNS

Per-QNAME drop, **not** a transparent port-53 redirect.

```
dig @8.8.8.8 google.com          -> NOERROR, ANSWER: 1
dig @8.8.8.8 discord.com         -> timeout
dig @1.1.1.1 / @9.9.9.9 / @77.88.8.8, same split
dig -p 1253 @77.88.8.8 discord.com -> 162.159.128.233, 162.159.136.232
dig -p 9953 @9.9.9.9  discord.com  -> 162.159.135.232, 162.159.128.233
dig +tcp @8.8.8.8 discord.com          -> connection reset
dig +tcp -p 1253 @77.88.8.8 discord.com -> connection reset
system resolver (192.168.0.1) discord.com -> 195.175.254.2   (BTK sinkhole)
system resolver (192.168.0.1) google.com  -> 172.217.18.174  (genuine)
```

Consequences for the resolver design:
- Alternate-port plaintext UDP is a working fallback; `:53` is not.
- **Never fall back to TCP DNS.** It is RST-filtered at every port tested.
- The sinkhole address `195.175.254.2` is a reliable positive censorship signal.

## 3. What defeats the block

129 shuffled trials, 14 emitters x 3 blocked targets x 3 reps.

| Emitter | discord.com | discord.gg | cdn.discordapp.com | |
|---|---|---|---|---|
| baseline (no desync) | 0/3 | 0/3 | 0/3 | blocked |
| `split2-at-{1,2,3,5,64}` (2 TCP segments) | 0/5 | — | — | blocked |
| `split2-in-sni` (2 TCP segments, cut inside hostname) | 0/5 | — | — | blocked |
| `disorder-at-3`, `disorder-in-sni` (IP_TTL=1 head) | 0/5 | — | — | blocked |
| `chunk-40` | 0/3 | 0/3 | 0/3 | blocked |
| `chunk-4` | 3/3 | 3/3 | 3/3 | **through** |
| `tlsrec2-at-{1,5,20,100}` | 3/3 | 3/3 | 3/3 | **through** |
| `tlsrec2-in-sni` | 3/3 | 3/3 | 3/3 | **through** |
| `tlsrec-every-{16,64}` | 3/3 | 3/3 | 3/3 | **through** |
| `tlsrec2-at-400`, `tlsrec-every-256` | 0/3 | 0/3 | 0/3 | blocked |
| `tlsrec2-1seg` (two records, ONE TCP segment) | 3/3 | 3/3 | 3/3 | **through** |
| `oob-at-1`, `oob-at-3` (MSG_OOB) | 3/3 | 3/3 | 3/3 | **through** |

### 3.1 TCP segmentation is not the mechanism

Every two-segment TCP split fails, including one cut inside the SNI hostname.
The DPI reassembles TCP.

Conversely `tlsrec2-1seg` — two TLS records inside a **single** TCP segment —
goes through on all three targets. TCP framing is therefore irrelevant to the
bypass; the TLS record layer is where it happens.

### 3.2 The exact rule

66 shuffled trials, cut position expressed relative to the SNI hostname's
position inside the ClientHello record body (`body=1497, sni at [112,122)`),
with both records emitted in one TCP segment:

| Cut | discord.com | discord.gg | |
|---|---|---|---|
| none | 0/3 | 0/3 | blocked |
| `sniStart-20` | 3/3 | 3/3 | **through** |
| `sniStart-1` | 3/3 | 3/3 | **through** |
| `sniStart` | 3/3 | 3/3 | **through** |
| `sniStart+1` | 3/3 | 3/3 | **through** |
| `sniMid` | 3/3 | 3/3 | **through** |
| `sniEnd-1` | 3/3 | 3/3 | **through** |
| `sniEnd` | 0/3 | 0/3 | blocked |
| `sniEnd+1` | 0/3 | 0/3 | blocked |
| `sniEnd+20` | 0/3 | 0/3 | blocked |
| `sniEnd+200` | 0/3 | 0/3 | blocked |

The boundary is exactly at `sniEnd`. That `sniStart-20` also passes — where the
hostname sits complete and contiguous in the *second* record — establishes the
mechanism:

> **The DPI parses only the first TLS record of a connection as a ClientHello.
> If the SNI hostname is not complete within that first record, the flow is not
> matched and passes.**

### 3.3 Why this is the right primary emitter

- **Deterministic.** A rule, not a magic number: cut at any offset `<= sniEnd-1`.
- **No kernel dependency.** Pure byte reframing before `write()`. No socket
  options, no timing, no raw sockets, no root — identical in proxy and TUN mode.
- **Testable offline.** The output is a byte string; correctness is a unit test,
  not a network experiment. This is the code path that sat at 0% coverage before.
- **Strictly dominant cut position:** inside the hostname (`sniMid`). That
  satisfies the record rule *and* splits the hostname itself, so it also defeats a
  naive DPI that string-matches across the raw stream without record awareness.

### 3.4 Chunking is real but unreliable — do not default to it

Two independent shuffled sweeps of fixed-size TCP chunking of the ClientHello:

```
run A (5 reps):  1 PASS  2 PASS  3 PASS  4 PASS  5 FAIL  8 FAIL  12 PASS
                 20 FAIL  35 FAIL  60 FAIL  120 FAIL
run B (3 reps):  4 PASS  12 PASS  40 FAIL
```

Non-monotonic and not explained by any simple model, while every result in §3.2
is explained by one rule. Chunking belongs in the probe ladder as a fallback, not
as the shipped default.

**Important caveat on these numbers.** The harness above chunks the *entire*
ClientHello. An implementation that caps its segment count — as `internal/ops`
does, at 16 segments, to stay clear of the XNU `if_sndbyte_unsent` panic — emits
a different shape under the same label, and measures differently:

```
chunk:size=       2      4      8      9     12     20
shipped op     RESET  RESET  RESET   PASS   PASS  RESET
this harness    PASS   PASS   FAIL      -    PASS   FAIL
```

The shipped op's results are explained by a necessary condition: with 15
boundaries available, the chunked prefix covers `15 x size` bytes, and it must
extend past the SNI (`5 + sniEnd` = 127 here) for the bypass to occur.
`9 x 15 = 135 > 127` passes; `8 x 15 = 120 < 127` does not. It is necessary but
not sufficient — `size=20` covers 300 bytes and still fails.

This is the same lesson as §3.5, sharper: **a chunk size is meaningless without
the write geometry it was measured under.** Quote a size only together with the
segment budget, and never carry a size from one implementation to another.

### 3.5 Corrections to the research dossier

- The dossier's P0 recommendation — "chunked ClientHello splitting with a probed
  chunk size" — is superseded. Chunking works but is unstable; record
  fragmentation works by a rule and is stable.
- The dossier rated `disorder` (per-segment `IP_TTL=1`) as P1 / "likely" on the
  strength of Turkish ByeDPI and zapret strategy strings. Measured here it is
  **0/10 on Türk Telekom**. The socket mechanism itself works on Darwin; it simply
  does not defeat this DPI, which is consistent with §3.1 — reordering TCP
  segments cannot help against a middlebox that reassembles TCP.
- The dossier reported the chunk curve as `1 ok, 5 ok, 20 ok, 35 fail, 60 ok,
  120 fail`, measured through SpoofDPI. Measured here through a direct
  implementation the working set is different (§3.4). **Strategy parameters are
  not portable between implementations** — the prober must measure the emitters
  this tool actually ships, never import another tool's numbers.
- `tls-record-frag` — the previous implementation's default, whose "verified
  against a live Turkish ISP" claim had no evidence anywhere in the repository —
  turns out to have been the right choice of mechanism. Its `frag_window` knob
  was still inert, and it never verified the cut landed before `sniEnd`.

## 4. Scope of these measurements

One ISP (Türk Telekom AS9121), one city (Kayseri), one day (2026-09-02), one
target family (Discord behind Cloudflare, plus a Cloudflare control). Turkcell
Superonline, Vodafone, Turknet and the mobile networks are **unmeasured**, and
Turkish DPI configurations are documented to rot on a months-scale cadence.

The rule in §3.2 is a strong, mechanism-level first rung for the ladder. It is not
a law, and the prober exists precisely so the tool never has to trust a single
afternoon of measurement again.

---

## 5. Compatibility — the finding that decides the architecture

A bypass that breaks online banking is worse than no bypass. Every candidate
emitter was therefore scored on **both** axes at once: does it get through the
DPI, and does it leave ordinary sites working.

41 hosts were first probed plain vs record-split (full handshake + `GET /`).
**10 of 41 regressed under record splitting — and all ten are Turkish banks and
`.gov.tr` sites:**

```
www.akbank.com          handshake: EOF
www.isbank.com.tr       handshake: connection reset by peer
www.yapikredi.com.tr    handshake: remote error: tls: illegal parameter
www.ziraatbank.com.tr   handshake: EOF
www.vakifbank.com.tr    handshake: connection reset by peer
www.denizbank.com       handshake: connection reset by peer
www.turkiye.gov.tr      handshake: EOF
www.gib.gov.tr          handshake: EOF
www.mhrs.gov.tr         handshake: EOF
www.btk.gov.tr          handshake: EOF
```

`yapikredi.com.tr` returns an explicit TLS alert (`illegal parameter`), so this is
the server side rejecting a handshake message spanning two records — legal per RFC
8446 §5.1, but not universally implemented. Not blocked: `garantibbva.com.tr`,
`qnbfinansbank.com`, `teb.com.tr`, `nvi.gov.tr`.

### 5.1 The two-axis matrix

3 blocked hosts, 10 fragile hosts, 4 ordinary controls, 2 reps each:

| emitter | bypass | fragile hosts | controls | |
|---|---|---|---|---|
| `plain` | 0/6 | 20/20 | 8/8 | safe, no bypass |
| `tcpsplit-in-sni` | 0/6 | 20/20 | 8/8 | safe, no bypass |
| `tlsrec-mid-sni` | **6/6** | 1/20 | 8/8 | bypasses, breaks banks |
| `tlsrec-at-1` | **6/6** | 1/20 | 8/8 | bypasses, breaks banks |
| `chunk-12` | **6/6** | 14/20 | 8/8 | bypasses, breaks banks |
| `chunk-2` | **6/6** | 14/20 | 6/8 | bypasses, breaks banks |
| `chunk-4` | **6/6** | 13/20 | 6/8 | bypasses, breaks banks |
| `oob-at-1` | **6/6** | 0/20 | 6/8 | bypasses, breaks everything fragile |
| `oob-at-3` | **6/6** | 0/20 | 6/8 | bypasses, breaks everything fragile |

**No emitter is both a bypass and universally safe.** The correlation is close to
perfect: whatever confuses the DPI's ClientHello parser also confuses a fragile
TLS terminator.

### 5.2 What this forces

Desync must **not** be applied unconditionally, and a shipped exclusion list cannot
be the answer — 24% of the tested hosts are fragile, and no hand-maintained list
covers the Turkish long tail.

The default policy must be:

1. Connect with **no desync**.
2. If the TLS handshake fails with RST / EOF **before any server bytes have
   reached the client**, retry the connection walking the strategy ladder.
3. Cache the winning strategy per hostname, with a TTL, persisted across restarts.
4. Cache "plain works" just as durably, so a bank is desynced at most once, ever.

Banks and government sites succeed on step 1 and are never desynced. Blocked hosts
cost one extra round trip on first visit. This is byedpi's `--auto=torst` model;
the measurements above show it is not an optimisation but a correctness
requirement.

Retry is safe for exactly this case because the ClientHello is the first thing on
the wire — if the handshake fails, no application bytes have been delivered in
either direction, so re-dialling is transparent to the client.

### 5.3 Ladder order implied by the data

1. `plain` — always first.
2. `tlsrec` cut inside the SNI hostname — best bypass/compatibility ratio
   (8/8 controls), deterministic, no kernel dependency.
3. `chunk-12` — different mechanism, 8/8 controls, useful when record splitting
   is rejected by the origin.
4. `chunk-2` / `chunk-4` — degrade controls, use only if the above fail.
5. `oob` — powerful but the most destructive; last rung, and never combined with
   disorder on Darwin.

### 5.4 A resolver bug worth recording

The first run of this matrix scored every emitter 0/6 on bypass. The cause was
that the probe dialled by hostname, so Go's resolver used the **system** resolver,
which returns the BTK sinkhole `195.175.254.2` for every blocked name. The
connection then went to the sinkhole rather than to the origin, and no desync
strategy can help with that.

This is the failure mode a user will hit if the tool's own resolver chain is
bypassed anywhere — including by a library that calls `net.Dial` with a hostname.
Every outbound dial in the implementation must resolve through the tool's own
chain, never through the system resolver.

---

## 6. The retry model is validated on the wire

The policy in §5.2 only works if a desync retry succeeds *immediately* after the
DPI has just reset a plain attempt to the same host. Measured, 6 rounds x 3
blocked targets, no delay inserted between the two attempts:

```
retry success: 18/18
plain attempt:       ~22 ms to RST
desync retry:        ~23 ms to completed handshake
total first visit:   ~45 ms
```

Escalation check — 15 back-to-back blocked attempts to the same host, then:

```
desync attempt after the burst:            success, 23 ms
benign SNI to the same IP after the burst: success, 24 ms
```

The DPI does not escalate to IP-level blackholing, does not penalise the source,
and does not carry state between flows. Blocking is per-flow and stateless.

Cost on the common path — a host that was never blocked:

```
www.google.com   plain: success, 29 ms   (no retry)
www.akbank.com   plain: success, 22 ms   (no retry)
```

So the fail-first design costs one extra ~23 ms round trip on the **first** visit
to a blocked host and nothing at all thereafter or anywhere else. Combined with
§5.1 — where every bypassing emitter broke Turkish banking — this is not a
trade-off. Fail-first is both the safer and the cheaper design.
