# M15 manual acceptance — netwatch on a real laptop

Nothing in this file has been run. Every step needs a second network, a captive portal or
a VPN, and none of the automated work on this project was permitted to mutate a real
machine's network state. The automated evidence that stands in its place — a scripted
routing source, a movable fact collector, and assertions made through the live control
socket — is recorded at the bottom.

Run it deliberately, on a machine you can afford to disturb.

Run every step with `-v`; the watcher's decisions are debug-level lines prefixed
`netwatch:`.

---

## Setup

```sh
go build -o /tmp/dpb ./cmd/dpb
# Snapshot the machine's routing table so step 5 can diff it.
netstat -rn > /tmp/rn.before
```

---

## 1. A network change swaps the verdict namespace (the central clause)

Two networks are needed: the Wi-Fi you are on, and a phone hotspot.

```sh
# terminal 1 — on Wi-Fi
/tmp/dpb run --profile turkey -v 2>&1 | tee /tmp/m15.log
```

```sh
# terminal 2 — record the starting namespace, then make dpb learn something
/tmp/dpb status --json | jq -r .network_id          # → e.g. wifi-9b2590814e6c31ad
curl -sS -o /dev/null -w '%{http_code}\n' https://discord.com/
/tmp/dpb status --json | jq '.cache'                # → at least one host cached
```

Now switch the Wi-Fi to the phone hotspot (System Settings → Wi-Fi → the hotspot),
and within two seconds of association run:

```sh
/tmp/dpb status --json | jq -r '.network_id, .suspended, .suspend_reason'
```

**PASS when:**

- `network_id` differs from the value recorded above **within 2 s** of the association.
- `/tmp/m15.log` contains, in this order:
  `netwatch: suspending: the network changed`, `netwatch: network-change: the verdict
  namespace moved from <old> to <new>`, `run: resumed on <new>`,
  `netwatch: lifting: the network changed`.
- `suspended` is back to `false` once the log shows `resumed`.
- `jq '.cache'` reports **0 hosts** on the new namespace — the Wi-Fi's verdicts are not
  visible here. This is the whole point: MEASUREMENTS.md is explicit that Turkish DPI
  differs by ISP, and a `tlsfrag` verdict learned on Türk Telekom is not evidence about a
  mobile carrier.
- `curl https://www.isbank.com.tr/` still returns 200 throughout, including during the
  settle. The datapath fails OPEN; only the judging stops.

Switch back to Wi-Fi and confirm `network_id` returns to the FIRST value and
`jq '.cache'` shows the earlier hosts again. A namespace that is not stable across a
round trip is a cache that is thrown away on every commute.

**FAIL shapes to look for:** the namespace changing but the cache still reporting the old
network's hosts (the store was not re-keyed); `suspended` stuck true (an unbalanced hold);
a connection failing during the settle (the datapath was suspended in the wrong sense).

---

## 2. Sleep and wake

```sh
# with dpb running, close the lid for at least 60 seconds, then open it
grep -E 'netwatch: (wake|network-change|route-change)' /tmp/m15.log
```

**PASS when:** a `netwatch: wake: the wall clock ran <n> further than the monotonic
clock` line appears with `<n>` roughly the time the lid was closed, OR a `route-change`
arrives first and the wake line does not (both are correct — the routing churn is the
primary signal and the sleep detector only makes recovery faster when the churn is late).
In both cases a re-verify must follow, and `curl https://discord.com/` must work on the
first attempt after wake, not the second.

`sudo pmset sleepnow` reproduces this without the lid.

---

## 3. Captive portal

Needs a network with a portal (most hotels, airports, many cafés). Join it with dpb
running.

```sh
/tmp/dpb status | head -5
```

**PASS when:**

- `mode: watch (SUSPENDED: everything relays direct) — a captive portal is intercepting
  this network`.
- `curl -s http://127.0.0.1:<port>/dpb.pac` returns the all-`DIRECT` script with no
  `PROXY` line in it.
- The portal's own login page loads in a browser. This is the acceptance criterion that
  matters: a tool that makes a hotel network unusable gets uninstalled.
- After completing the login, within ~15 s (the poll interval), `dpb status` reports
  `mode: watch` with no SUSPENDED marker, and `/tmp/m15.log` shows
  `netwatch: portal-detected` followed later by `netwatch: portal-cleared`.

**FAIL shape:** a portal declared on a network that has none. If `dpb status` ever
reports a portal on your ordinary Wi-Fi, capture `/tmp/m15.log` — the probe requires two
intercepted canaries with no clean one, so a false positive means the canary set needs
re-choosing, not that the quorum needs lowering.

---

## 4. A VPN appears underneath a running dpb

### 4a. Split tunnel (proxy mode) — nothing should happen

Connect a split-tunnel VPN (a corporate profile that routes only some prefixes).

**PASS when:** `dpb status` is unchanged, `netstat -rn` still shows the VPN's routes after
`Ctrl-C` on dpb, and `/tmp/m15.log` shows at most a `split-tunnel VPN ... is left alone`
line. Deleting a coexisting VPN's routes on teardown is a defect this project has already
had once.

### 4b. Full tunnel, proxy mode — reported, not fatal

Connect a full-tunnel VPN (wg-quick, Tailscale `--accept-routes`, Mullvad).

**PASS when:** dpb keeps running and `/tmp/m15.log` says
`a full-tunnel VPN (<name>) owns the default route; the proxy still works, but every
verdict learned now describes the VPN's exit network`. A proxy on loopback is reached
without consulting the default route, so refusing here would be a safety gate firing on a
configuration that is fine.

### 4c. Full tunnel, TUN mode — exit 5

**This step cannot pass until M16 lands `--tun`.** `requiresCapture()` in
`internal/cliapp/netwatchrun.go` returns false for every run today; M16 flips that one
line. Once it does:

```sh
sudo /tmp/dpb run --tun --profile turkey -v
# ...then start a full-tunnel VPN
echo $?    # → 5
```

**PASS when:** the exit code is 5 (refused for safety), stderr names the tunnel interface
and says dpb is stopping rather than reporting success while capturing nothing, and
`netstat -rn > /tmp/rn.after; diff /tmp/rn.before /tmp/rn.after` shows only the VPN's own
routes — dpb's capture routes are gone and the VPN's are untouched.

---

## 5. The uplink vanishes

```sh
# with dpb running, turn Wi-Fi off entirely
networksetup -setairportpower en0 off
/tmp/dpb status | head -5      # → SUSPENDED: there is no uplink
networksetup -setairportpower en0 on
/tmp/dpb status | head -5      # → back to watch within ~2 s of association
```

**PASS when:** the suspension appears and then lifts on its own, and dpb never has to be
restarted.

---

## What was actually run by the implementing lane

- `go test ./... -race` — 2099 tests, 21 packages, clean.
- `make cover-gate` — pass; `internal/netwatch` is now a gated package at 94.5%.
- `internal/netwatch` alone: 85 tests, race clean, driven entirely by a fake clock with
  independent wall and monotonic axes, a fake routing source, a fake fact collector and a
  scripted portal prober. No test touches the network.
- Two live, read-only checks on this machine (uid 501, no sudo): the PF_ROUTE socket
  opens and the reader stops within 2 s of cancellation.
- `dpb run --proxy-style none --port 18443 -v` on the live Türk Telekom line with the
  watcher running: `curl -x` returned 200 for `discord.com`
  (`scope=desync strategy=tlsfrag:pos=snimid attempts=1`) and 200 for `www.isbank.com.tr`
  (`scope=bypass plain attempts=0`). `dpb status` reported the namespace and the cache;
  Ctrl-C tore down with `stop the network watcher` ahead of the listeners.
- Steps 1-5 above were NOT run. They need a second network, a portal, or a VPN, and the
  lane was forbidden from changing this machine's network state.
