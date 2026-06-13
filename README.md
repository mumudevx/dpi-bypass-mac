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
| DNS   | DNS-over-HTTPS / DoT with a fallback chain and bootstrap IPs | DNS poisoning & hijacking |
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

# Transparent mode: capture ALL TCP (even apps that ignore the proxy) — root
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

# Diagnose & recover after a crash (restores leftover proxy settings)
dpb doctor
```

When started without `--no-set-proxy`, `dpb` detects the active network service
(the one carrying the default route), points its HTTP/HTTPS proxy at the local
listener, and **restores the previous settings on exit** (Ctrl-C, SIGTERM, or
panic). If the process is killed with `kill -9`, run `dpb doctor` to restore.

## Profiles

| Profile  | DNS                                   | Strategy                         |
|----------|---------------------------------------|----------------------------------|
| `global` | Cloudflare DoH (+UDP)                 | `split-at-sni`, window 1         |
| `turkey` | Cloudflare DoH → Yandex UDP → Google  | `host-case` → `split-at-sni`, window 2 |
| `turkey-superonline` | Cloudflare DoH → Yandex UDP | `fake-ttl` (needs `--mode tun`); falls back to SNI split in proxy mode |

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
| `tun` | **all** TCP, incl. apps that ignore the proxy | root (`sudo`) | yes |

`tun` mode brings up a `utun` device fed into a userspace TCP/IP stack
(gVisor), captures all TCP via a split-default route, relays each flow to its
real destination bound to the physical uplink (`IP_BOUND_IF`, no loop), and
applies the same desync engine — plus packet-level fake-packet emitters. Routes
are torn down on exit; closing the utun also drops them, so a hard kill
self-heals (run `dpb doctor` to be sure).

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
- **TUN DNS.** In TUN mode the app does its own DNS, so pair it with an
  encrypted-DNS setting (or proxy mode) to also defeat DNS poisoning;
  intercepting UDP 53 inside the tunnel is a planned enhancement.
- **IPv4 fakes.** Fake-packet crafting is IPv4-only; IPv6 flows fall back to an
  SNI split.

## Development

```sh
go test ./...                       # unit + integration tests
go test -tags e2e ./internal/proxy  # live HTTPS-through-proxy smoke test
go vet ./...
```

## License

MIT — see [LICENSE](LICENSE).
