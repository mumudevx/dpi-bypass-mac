# Exercising TUN mode as root

TUN mode has never been run as root, by anyone. Every `--tun` assertion in the
test suite runs over `tunfe.NewPipe`, an in-memory device, against a recording
sequencer — which is why `OpenDevice` sits at 62.5% function coverage. The
packet path, the capture routes and the DNS interception are unproven on real
hardware.

This file is the procedure for changing that. It was written for one specific
machine and reviewed for safety by an agent whose only job was to ask "what
happens if a step fails halfway". Read it all before typing anything.

Proxy mode needs none of this: it is unprivileged, it changes no routing, and
it is the mode the measurements in `MEASUREMENTS.md` were taken through.

---

EXERCISING TUN MODE AS ROOT ON THIS MACHINE — safety-reviewed procedure.

Read the whole thing before typing anything. It is written for this specific machine: uplink en0, gateway 192.168.0.1, resolver 192.168.0.1 (DHCP-supplied), services "Thunderbolt Bridge" / "Wi-Fi" / "iPhone USB", utun0..utun7 already in use, no IPv6 default route. If any of that has changed, stop and re-read the plan with `--dry-run` first.

=== THE ONE FACT THAT MAKES THIS SAFE ===

With `--set-dns off`, every single change dpb makes is IN-KERNEL AND NON-PERSISTENT:
  - the utun device is a file descriptor; the kernel destroys the interface when dpb's process exits, by any means including `kill -9`
  - macOS `route` changes live only in the running kernel; nothing writes them to disk
So the worst case, if everything goes wrong and you cannot type anything, is: hold the power button, reboot, and the machine comes back exactly as it is now. Nothing you are about to do can survive a reboot.

That is only true with `--set-dns off`. `networksetup -setdnsservers` (the 6th op, which `--set-dns on` adds) writes to /Library/Preferences/SystemConfiguration/preferences.plist and DOES survive a reboot. Do the first run without it.

=== STEP 0 — confirm nothing else holds the lock ===

  $ pgrep -fl 'dpb run'          # must print nothing
  $ dpb doctor                   # must report 0 failed

If a run lock is held by a process that is gone, `dpb doctor` says so and
`dpb doctor --repair` clears it.

=== STEP 1 — do this at the physical keyboard ===

Not over SSH, not over Screen Sharing, not over a Remote Desktop session. The capture routes rewrite the whole address space; your own subnet route survives, but the gateway's /32 does not, and you do not want to discover the exception list with your only input channel on the other side of it. Close anything you would mind dropping (VPN clients especially — dpb will refuse to start if a full-tunnel VPN is already up, but a VPN that comes up later is not something this run is designed to survive).

=== STEP 2 — snapshot the "before", so you can prove the revert ===

  $ mkdir -p ~/dpb-tun-check && cd ~/dpb-tun-check
  $ netstat -rn -f inet > routes.before
  $ ifconfig -l > ifaces.before
  $ scutil --dns > dns.before
  $ for s in "Wi-Fi" "Thunderbolt Bridge" "iPhone USB"; do echo "== $s"; networksetup -getdnsservers "$s"; done > dnsservers.before
  $ cat dnsservers.before

Expected output of that last command, on this machine, right now:
  == Wi-Fi
  There aren't any DNS Servers set on Wi-Fi.
  == Thunderbolt Bridge
  There aren't any DNS Servers set on Thunderbolt Bridge.
  == iPhone USB
  There aren't any DNS Servers set on iPhone USB.

IF IT SAYS ANYTHING ELSE, STOP. The recovery script in step 3 restores DNS to "Empty" (= back to DHCP), which is only correct because that is the current state. If real servers are listed, edit recover.sh to set those exact addresses instead.

Changes to the system: none, all four commands are read-only.

=== STEP 3 — write the recovery script BEFORE you need it ===

Write it now, while DNS and the network still work, so that recovering never depends on either. Every binary it calls is local.

  $ cat > ~/dpb-tun-check/recover.sh <<'EOF'
  #!/bin/sh
  # Escalating recovery. Run with: sudo sh ~/dpb-tun-check/recover.sh
  echo "--- 1. asking dpb to revert itself"
  pkill -INT -f 'dpb run' 2>/dev/null
  sleep 8
  pkill -KILL -f 'dpb run' 2>/dev/null
  sleep 2
  echo "--- 2. routing table now"
  netstat -rn -f inet | head -12
  echo "--- 3. removing any capture route that is still there"
  for p in 0.0.0.0/1 128.0.0.0/1 192.168.0.1/32; do
      route -n delete -inet -net "$p" 2>&1
  done
  route -n delete -inet default 192.168.0.1 -ifscope en0 2>&1
  echo "--- 4. restoring DNS to DHCP (correct only if dnsservers.before said 'There aren't any')"
  for s in "Wi-Fi" "Thunderbolt Bridge" "iPhone USB"; do
      networksetup -setdnsservers "$s" Empty
  done
  dscacheutil -flushcache
  killall -HUP mDNSResponder
  echo "--- 5. final routing table"
  netstat -rn -f inet | head -12
  EOF
  $ chmod +x ~/dpb-tun-check/recover.sh

Note on step 3 of that script: "not in table" errors are the EXPECTED and GOOD case — the utun vanished with the process and the kernel already purged every route naming it. Only run recover.sh if something is actually wrong.

Changes to the system: one file in your home directory. Revert: `rm ~/dpb-tun-check/recover.sh`.

=== STEP 4 — read the plan with no privileges and no mutation ===

  $ cd /Users/muhsin/Documents/GitHub/mumudevx/dpi-bypass-mac
  $ make build
  $ ./dpb run --tun --dry-run --set-dns off --proxy-style none --port 18490 --socks-port 18491

Expected (I ran exactly this): the banner, then

  system settings that WOULD be applied — none of them was:
    - configure utun 10.255.90.1 -> 10.255.90.2 mtu 1500 up
    - add route 0.0.0.0/0 via 192.168.0.1 scoped to en0
    - add route 0.0.0.0/1 via interface utun
    - add route 128.0.0.0/1 via interface utun
    - add route 192.168.0.1/32 via interface utun
  ...
  Nothing was changed and nothing was journalled, so there is nothing to revert.

Five ops, no DNS op. Ctrl-C to stop it — it is a run, it does not exit on its own.
Changes to the system: NONE. `--dry-run` needs no root, opens no device and applies no Op; that is enforced in netstate/manager.go, which returns from Do before any journal write when DryRun is set. Revert: none needed.

=== STEP 5 — the real run, time-boxed so it cannot outlive you ===

This is the only step that changes anything. It is shaped so that the run stops by itself after 120 seconds even if your terminal becomes unusable:

  $ sudo -v
  $ sudo /bin/sh -c './dpb run --tun --set-dns off --proxy-style none --port 18490 --socks-port 18491 -v & D=$!; (sleep 120; kill -INT $D) & W=$!; wait $D; kill $W 2>/dev/null'

Use `sudo`, NEVER `sudo -i` or `su -`. Under plain `sudo`, dpb's paths layout resolves to the INVOKING user's directories (~/.local/state/dpb) and chowns what it creates; under a root login shell it switches to /Library/Application Support/dpb, and a later `sudo dpb doctor --repair` from your normal shell would look in the wrong place and find nothing to repair.

Expected: the banner, this time headed `system settings applied and verified:` over the same five ops with `utun` replaced by the real device (utun8 or higher — utun0..7 are already taken; read the name off the banner, do not assume). Then `Ctrl-C reverts every change above.` and a journal path.

What changes: one new utun interface; four kernel routes (an en0-scoped default via 192.168.0.1, the two capture halves 0.0.0.0/1 and 128.0.0.0/1 pointed at the utun, and 192.168.0.1/32 pointed at the utun); and a journal file with those five records. No persistent file outside the journal. No DNS change.

Each op is applied AND independently verified by reading the kernel routing table back before dpb prints it, so anything on that list is a change that really landed.

=== STEP 6 — confirm it works, in a SECOND terminal, quickly ===

You have 120 seconds. Have these ready to paste:

  $ netstat -rn -f inet | head -12          # expect 0.0.0.0/1 and 128.0.0.0/1 on the new utun
  $ ifconfig -l | tr ' ' '\n' | grep utun   # expect one more utun than ifaces.before
  $ curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 15 https://discord.com/
  $ dig +short +time=3 discord.com

The curl is the actual test: with no proxy environment variables set, that request is being captured by the routes and carried by dpb's ladder. Expect 200. In proxy mode I measured the same host at 0.301s after one escalation to tlsfrag:pos=snimid.

=== STEP 7 — the revert ===

Ctrl-C in the first terminal (or just wait for the 120s watchdog). Expected:

  dpb: interrupt; reverting system changes (up to 10s). Press Ctrl-C again to give up immediately.

Then verify, in this exact order:

  $ netstat -rn -f inet > ~/dpb-tun-check/routes.after
  $ diff ~/dpb-tun-check/routes.before ~/dpb-tun-check/routes.after && echo "ROUTES IDENTICAL"
  $ ifconfig -l > ~/dpb-tun-check/ifaces.after
  $ diff ~/dpb-tun-check/ifaces.before ~/dpb-tun-check/ifaces.after && echo "INTERFACES IDENTICAL"
  $ ls -l ~/.local/state/dpb/journal.ndjson
  $ for s in "Wi-Fi" "Thunderbolt Bridge" "iPhone USB"; do networksetup -getdnsservers "$s"; done
  $ curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 https://example.com/

The revert succeeded if and only if: both diffs print IDENTICAL, journal.ndjson is 0 bytes (it is truncated once nothing is pending — that is the designed signal, not an error), the DNS listing still says "There aren't any DNS Servers set", and the curl returns 200. In my proxy-mode run the equivalent teardown drained the whole stack in 11ms and left a 0-byte journal.

=== IF A STEP FAILS HALFWAY AND THE NETWORK IS GONE ===

Escalate in this order. Do not skip ahead.

  1. Ctrl-C again. A second Ctrl-C within 3 seconds force-exits; the kernel then destroys the utun on process death and purges every route naming it. This alone fixes the three utun routes.

  2. In any terminal:  sudo pkill -INT -f 'dpb run'    then wait 10 seconds and re-check `netstat -rn -f inet | head`.

  3. If dpb was `kill -9`ed rather than interrupted, the SIGKILL janitor (a child process watching your pid via kqueue — the Y1 fix is what makes it exist under `--tun --proxy-style none` at all) replays the journal for you within a second or so. Check `netstat -rn -f inet | head` before doing anything more.

  4.  cd /Users/muhsin/Documents/GitHub/mumudevx/dpi-bypass-mac && sudo ./dpb doctor --repair
      Plain `sudo`, from your own shell, for the paths reason in step 5. Run it only after dpb is dead: records owned by a live dpb are deliberately skipped and left pending.

  5.  sudo sh ~/dpb-tun-check/recover.sh
      This is the blunt instrument and it is written to be safe to run twice.

  6. Reboot. Because you used `--set-dns off`, this is guaranteed to restore the machine completely: not one of the five ops writes anything to disk.

There is no step where you are stuck. Step 6 always works.

=== WHAT `dpb doctor --repair` WILL FIX ===

- Every journalled op, reverted in reverse order on a fresh context, each with the revert payload recorded at apply time: `route delete` for each of the four routes (with the same `-ifscope en0` / `-interface utunN` spelling that added them), the ifconfig, and — if you ever run with `--set-dns on` — `networksetup -setdnsservers <service> <the exact previous list>`, or `... Empty` when there was no previous list, which is this machine's case.
- Residue from a PREVIOUS crashed run, not just this one. It reads the journal from disk, so it sees what another process wrote.
- A journal whose final line was torn by a SIGKILL mid-write: everything before the torn line is still replayed.
- It also audits and reports system proxy settings, the PAC file, launchd proxy environment variables, the run lock and the control socket. On a clean machine it prints "10 check(s), 0 failed, 0 warning(s)" — I ran it this session.

=== WHAT IT WILL NOT FIX ===

- A route the kernel says is not ours. routeOp.Revert reads the RIB first and, if 0.0.0.0/1 is owned by a different interface (another tunnel that grabbed it after dpb died), it logs and leaves it alone by design — `route delete -net 0.0.0.0/1 -interface X` would otherwise delete whoever owns that prefix, not us. Correct behaviour, but it means repair can report success while the prefix is still captured by something else. Check `netstat -rn` yourself; do not trust the summary alone.
- Anything not in the journal. If you run dpb under a different XDG_STATE_HOME, or as a different user, or via `sudo -i`, the journal it writes and the journal repair reads are different files. Same shell, plain `sudo`, both times.
- The utun interface. It cannot destroy one and does not need to — the interface is owned by the dead process's file descriptor and is gone before repair runs.
- A machine broken by something that is not dpb. It replays dpb's journal; it is not a general network repair tool.
- Anything, if you run it without root — the route and networksetup calls will fail and it will report them as failures.
- Note also: a CLEAN exit truncates the journal to zero bytes, so `doctor --repair` after a successful Ctrl-C correctly finds nothing to do. An empty journal is the success signal, not a missing one.

=== TWO RISKS I COULD NOT TEST, AND YOU SHOULD WATCH FOR ===

1. NOBODY HAS EVER RUN THIS AS ROOT. Every `--tun` assertion in the tree is against an in-memory pipe device and a recording sequencer. Your step 5 is the first time the real utun_control open, the real `ifconfig`, the real `route add` and the real routing-table read-back run together. This is why it is time-boxed to 120 seconds.

2. On this machine the resolver and the gateway are the SAME address, 192.168.0.1, so op 5 installs `192.168.0.1/32 -interface utunN` — a /32 that is more specific than en0's on-link 192.168.0.0/24 route to the gateway. dpb's own upstream sockets bind to en0 directly (IP_BOUND_IF), so they should be unaffected; that binding is precisely the Y2 uplink pin, and I verified by sabotage that removing it is caught. But anything ELSE on the machine that talks to 192.168.0.1 — a DHCP lease renewal, the router's web UI, mDNS to the router — is routed into the tunnel for the duration, and whether dpb's UDP relay carries all of it has never been observed on real hardware. If the run goes past a couple of minutes and the Wi-Fi lease renews, that is the interaction to suspect. Keep it short.