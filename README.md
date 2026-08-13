# dpb — macOS DPI Bypass CLI

A macOS-first **Deep Packet Inspection (DPI) bypass** tool that works both in
**Turkey** and **globally**. It runs a local proxy that fragments the TLS
ClientHello and resolves names over encrypted DNS, defeating the two most common
censorship techniques: passive **SNI inspection** and **DNS poisoning**.

Inspired by [SpoofDPI](https://github.com/xvzc/SpoofDPI) (cross-platform, Go) and
[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) (Windows-only), `dpb`
combines fragmentation strategies with region profiles in a single static binary
— no kernel extension, no Apple Developer account, and (in proxy mode) no root.

> **Honesty note.** This tool changes *how* packets are framed to slip past DPI;
> it is **not a VPN** and provides no encryption or anonymity beyond what HTTPS
> already gives you. Whether a given strategy defeats a specific ISP's DPI can
> only be confirmed on that network. The shipped profiles are **starting
> points** — see [Tuning](#tuning).

## How it works

| Layer | Technique | Defeats |
|-------|-----------|---------|
| TLS   | ClientHello fragmentation (split inside the SNI, multi-split, TLS record fragmentation) | passive SNI blocking |
| DNS   | DNS-over-HTTPS / DoT with a fallback chain and bootstrap IPs; in TUN mode UDP 53 is answered from that chain instead of the ISP's resolver | DNS poisoning & hijacking |
| HTTP  | `Host` header case/dot tricks | plaintext HTTP keyword filters |

The proxy never decrypts your traffic — for HTTPS it tunnels via `CONNECT` and
only re-frames the first (plaintext) ClientHello bytes.

## Install

### Homebrew (recommended)

```sh
brew tap mumudevx/tap
brew install dpb
```

### From source

```sh
brew install go            # Go 1.24+
git clone https://github.com/mumudevx/dpi-bypass-mac
cd dpi-bypass-mac
go build -o dpb .
```

A manually-downloaded binary is quarantined by Gatekeeper; clear it with:

```sh
xattr -dr com.apple.quarantine ./dpb
```

## Usage

```sh
# Turkey profile, auto-configures the system proxy, restores on Ctrl-C
dpb run --profile turkey

# Global default
dpb run --profile global

# Transparent mode: capture ALL TCP + UDP (even apps that ignore the proxy) — root
sudo dpb run --mode tun --profile turkey

# Don't touch system settings — point your browser at 127.0.0.1:8080 yourself
dpb run --profile global --no-set-proxy

# Override the strategy for a stubborn ISP
dpb run --profile turkey --emitter tls-record-frag --frag-window 3

# Inspect / list profiles
dpb profiles list
dpb profiles show turkey

# Run in the background via launchd
dpb service install --profile turkey
dpb service status
dpb service uninstall

# Diagnose & recover after a crash (restores leftover proxy and DNS settings)
dpb doctor
```

When started without `--no-set-proxy`, `dpb` detects the active network service
(the one carrying the default route), points its HTTP/HTTPS proxy at the local
listener, and **restores the previous settings on exit** (Ctrl-C, SIGTERM, or
panic). If the process is killed with `kill -9`, run `dpb doctor` to restore.

## Profiles

| Profile  | DNS                                   | Strategy                         |
|----------|---------------------------------------|----------------------------------|
| `global` | Cloudflare DoH (+UDP)                 | `tls-record-frag`                |
| `turkey` | Cloudflare DoH → Yandex UDP → Google  | `host-case` → `tls-record-frag`  |
| `turkey-superonline` | Cloudflare DoH → Yandex UDP | `fake-ttl` (needs `--mode tun`); falls back to record fragmentation in proxy mode |

> **Why `tls-record-frag` is the default:** verified against a live Turkish ISP,
> plain TCP-segment splitting (`split-at-sni`) is defeated — the DPI reassembles
> TCP. Fragmenting the ClientHello across **multiple TLS records** is not
> reassembled and gets through (DNS poisoning is handled separately by DoH).

Create your own by copying a built-in into `~/.config/dpb/config.toml`:

```toml
[profiles.my-isp]
name = "my-isp"
[profiles.my-isp.dns]
cache_ttl = "5m"
[[profiles.my-isp.dns.resolvers]]
type = "doh"
url  = "https://dns.quad9.net/dns-query"
name = "quad9"
[profiles.my-isp.strategy]
emitter     = "multi-split"
split_sizes = [1, 2, 3]
[profiles.my-isp.filter]
ports = [443, 80]
```

Then `dpb run --profile my-isp`.

## Tuning

Different ISPs respond to different strategies. A/B test against a known-blocked
domain:

```sh
dpb run --profile turkey --emitter split-at-sni      # try one
dpb run --profile turkey --emitter tls-record-frag   # then another
```

Available emitters: `split-at-sni`, `split-at-offset`, `multi-split`,
`tls-record-frag`, and (TUN-only) `fake-ttl`, `fake-seq`. Available
transformers: `host-case`, `host-dot`.

## Verifying it works

The bypass not breaking normal TLS is testable on any network:

```sh
dpb run --no-set-proxy --port 8080 &
curl -x http://127.0.0.1:8080 https://example.com -o /dev/null -w "%{http_code}\n"
```

To confirm the ClientHello is actually fragmented on the wire (needs sudo):

```sh
sudo tcpdump -i en0 -n 'tcp port 443 and host <server-ip>'
# look for the ClientHello arriving as 2+ TCP segments
```

## Modes

| Mode | Scope | Privileges | Fake-packet desync |
|------|-------|------------|--------------------|
| `proxy` (default) | apps that honour the system/manual proxy | none | no (degrades to SNI split) |
| `tun` | **all** TCP + UDP, incl. apps that ignore the proxy | root (`sudo`) | yes |

`tun` mode brings up a `utun` device fed into a userspace TCP/IP stack
(gVisor), captures all TCP and UDP via a split-default route, relays each flow
to its real destination bound to the physical uplink (`IP_BOUND_IF`, no loop),
and applies the same desync engine — plus packet-level fake-packet emitters.
Routes are torn down on exit; closing the utun also drops them, so a hard kill
self-heals (run `dpb doctor` to be sure).

UDP is relayed datagram-for-datagram with a 60-second idle reaper, which is what
keeps QUIC, WebRTC/voice and game traffic alive for apps that bypass the proxy
(Discord's updater and voice, for example). Port 53 is the exception: queries are
answered in-process from the profile's resolver chain instead of being relayed,
so TUN mode defeats DNS poisoning the same way proxy mode does.

Two details make that work in practice:

- **An interface-scoped default route** (`route add -net default <gw> -ifscope
  en0`) is installed before the capture routes. `IP_BOUND_IF` constrains route
  lookup rather than bypassing it, so once `0.0.0.0/1` points at the utun the
  relay's own sockets have nothing to fall back to and every upstream connection
  fails with `ENETUNREACH`. An existing scoped route is adopted, not replaced.
- **The system resolver is redirected** to `1.1.1.1` for the duration of the
  run, and restored on exit. A DHCP-provided resolver cannot be captured by
  routing — it is on-link, where the LAN's subnet route wins, and it is usually
  the default gateway, whose next hop has to keep working. The redirect target
  is a real public resolver on purpose: if `dpb` is killed with `-9`, resolution
  degrades to plaintext DNS rather than failing outright, and `dpb doctor`
  restores the saved list. Static resolvers that are *not* the gateway are
  captured with a host route instead, leaving the setting untouched.

`dpb`'s own plaintext fallback queries dial through the uplink so they are not
pulled back into the tunnel and re-answered by the chain that issued them. DoH
keeps the default path on purpose — its connection travels through the desync
engine, and the DoH endpoint's SNI is itself a censorship target.

## Limitations & roadmap

- **Proxy scope.** In proxy mode, only traffic that honours the system proxy is
  affected. Use `--mode tun` to catch everything.
- **Fake-packet desync is experimental.** The `fake-ttl` / `fake-seq` emitters
  craft and inject decoy packets via a raw socket in TUN mode. The packet
  building and emitter logic are unit-tested, but on-wire efficacy depends on
  the ISP's DPI and on macOS NIC offload (which may "fix" a deliberately bad
  checksum); validate on the target network. The exact-sequence fake (mirroring
  GoodbyeDPI autottl precisely) needs a netstack-owned upstream and is a
  follow-up.
- **UDP is relayed, not desynced.** The desync engine reframes a TCP stream, so
  it does not apply to QUIC. If an ISP blocks a name over QUIC specifically, the
  practical workaround is still to disable QUIC in the client so it falls back to
  TCP, where the strategies do apply.
- **IPv4 only.** Both the capture routes and fake-packet crafting are IPv4;
  IPv6 flows leave on the physical uplink untouched, and an IPv6-only nameserver
  is not intercepted. Disable IPv6 on the interface if your ISP poisons it.
- **A hard kill leaves the scoped default route behind.** Interface-scoped
  routes on the utun vanish with the device, but the `-ifscope` route for the
  uplink does not. The next run adopts it, so it is harmless on the same
  network; delete it by hand (`sudo route delete -net default <gw> -ifscope
  en0`) if you move to a network with a different gateway.

## Development

```sh
go test ./...                       # unit + integration tests
go test -tags e2e ./internal/proxy  # live HTTPS-through-proxy smoke test
go vet ./...
```

## License

MIT — see [LICENSE](LICENSE).
