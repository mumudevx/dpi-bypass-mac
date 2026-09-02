# tlsmsg testdata

Real ClientHellos, captured 2026-09-02 on darwin/arm64 with go1.26.4 by recording
the first `Write` of a `crypto/tls` client handshaking against a live host
(104.16.132.229:443). No bytes were synthesised or hand-edited.

| file | bytes | record body | SNI extent (body-relative) | server name |
|---|---|---|---|---|
| `pq_1601.bin` | 1502 | 1497 | `[112,122)` | `discord.gg` |
| `classic.bin` | 224 | 219 | `[106,120)` | `cloudflare.com` |
| `nosni.bin` | 1483 | 1478 | — | — |

`pq_1601.bin` is the Go 1.26 default hello: TLS 1.3 with an `X25519MLKEM768` key
share, which is what makes it 1.5 KB and therefore what makes it span two
segments on a 1500-byte MTU. Its geometry — **body = 1497, SNI at [112,122)** — is
byte-for-byte the hello the `ruleprobe` run in `MEASUREMENTS.md` §3.2 measured
against, so every cut position in that table (`sniStart-20` … `sniEnd+200`) maps
onto these offsets directly.

`classic.bin` is the same client pinned to `MaxVersion: TLS 1.2` and P-256, i.e. a
pre-post-quantum hello with no 1216-byte key share.

`nosni.bin` is the same Go 1.26 default hello with no `ServerName` set, so the
`server_name` extension is absent entirely.

**Naming note.** `docs/PLAN.md` calls this capture "the 1601-byte hello"; the
filename keeps that label so downstream milestones referencing the plan's path
resolve. The capture is 1502 bytes. The number the plan's acceptance criterion
actually turns on — `body = 1497` with the SNI extent matching the ruleprobe
observation — reproduces exactly.

The handshake for `pq_1601.bin` was reset by the DPI mid-flight
(`read: connection reset by peer`), which is the block in `MEASUREMENTS.md` §1
reproducing itself during the capture. The recorded bytes are the client's, so
the reset does not affect them.
