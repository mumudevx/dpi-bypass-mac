# Windows Parity, Plan 6: Make It Run, Ship It, Measure It

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the Windows code for the first time, fix what that reveals, settle the distribution decisions, and write down exactly what a measurement session does when a Windows machine on a censored line exists.

**Architecture:** Task 1 is the pivot of the entire six-plan effort — a `windows-latest` CI job turns five plans of *"it compiles and was reviewed"* into *"it executes"*. Task 2 fixes what that finds. Everything after is distribution and protocol.

**Tech Stack:** Go 1.26.4, GitHub Actions, goreleaser 2.18, winget/scoop manifests. **No new module dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-07-windows-parity-design.md` (§8 tier 2, §9, §10)

## Global Constraints

- Module path `github.com/mumudevx/dpb`. Go floor `1.26.4`.
- **No new module dependencies.** `go mod tidy` byte-identical; never hand-edit `go.mod`.
- **No behaviour change on macOS.** The darwin suite must stay green with an unchanged test count unless a task adds tests. `brew install dpb` must keep working for the macOS users who have it today — that is a live install path, not a hypothetical.
- **No test body may be edited.** Five plans have held this with zero assertions weakened. Test files may gain build tags; a test written *within this branch* may be corrected if it encodes a defect — say which and why.
- Coverage floors: `tunfe` 70, `cliapp` 83, everything else **85**. Never lower one.
- `gofmt -l cmd internal tools` empty. `GOOS=windows go build ./...` exit 0.
- **Never publish or tag.** Cutting a release is the user's action. Prepare the config, verify it with `--snapshot`, and report the command.
- Comments explain WHY and cite evidence.

---

## The honest state, before this plan

Five plans built Windows support. **Not one line of it has ever executed.** Every claim so far is "it compiles, its test binaries link, and it was reviewed by reading."

That review has been productive — it caught **nine defects** across two classes:

*Compiles, looks right, always fails:* `syscall.Sendto` returns `EWINDOWS`; `internal/poll`'s Windows `RawWrite` returns `EWINDOWS` on a false callback; `os.Process.Signal` handles only `Kill`; two bare `go` statements tripping a project-wide gate.

*"Could not look" reported as a definite answer:* a `ProcessStart` returning "dead" on any query failure; an `envCtl.Get` reading a failed read as "unset"; a `Configured` turning DHCP DNS into permanent static DNS; a proxy revert leaving `ProxyEnable=1` on a machine that had it off; a liveness check that counted the process asking the question; a verifier that read a directory standard users cannot read, and deleted a good install over the denial.

**Reading found all nine. Running will find a different set.** That is what Task 1 is for, and Task 2 should be expected to be substantial.

---

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `.github/workflows/ci.yml` (modified) | the `windows-latest` job |
| `docs/MEASUREMENTS-windows.md` (rewritten) | the measurement protocol, then its results |
| `internal/cliapp/devtool.go` | `dpb devtool capture-sysconf` |
| `packaging/winget/` | the winget manifest set |
| `packaging/scoop/dpb.json` | the scoop manifest |

**Modified:** `.goreleaser.yaml`, `Formula/dpb.rb`, `README.md`.

---

## Task 1: run the Windows code for the first time

**Files:** modify `.github/workflows/ci.yml`.

**This is the most valuable task in the remaining effort.** Everything else in this plan is packaging.

- [ ] **Step 1: add the job**

A second job alongside `build`, on `runs-on: windows-latest`, mirroring the macOS job's steps where they apply: `gofmt` check, `go build ./...`, `go vet ./...`, `go test ./...`.

Reuse the existing `GO_VERSION` env var and `actions/setup-go` with caching, matching the macOS job's shape — read it first.

- [ ] **Step 2: decide what the job may skip, and say why in the YAML**

Some things genuinely cannot run there and the job must not pretend otherwise:

- `internal/sysconf/scdarwin` is darwin-only by design; its test imports `golang.org/x/net/route`, which has no Windows files. Exclude it **by name, with the reason in a comment.**
- `make cover-gate` measures darwin coverage against floors calibrated on darwin. Running it on Windows would compare different numbers to the same floors. Decide whether to run it, and if not, say why rather than silently omitting it.
- The root-gated integration tests do not run on macOS CI either. Check what the macOS job actually does about them and match.

**A CI job that reports green by skipping everything it does not understand is worse than no job.** That standard has been applied six times in this effort; apply it to the job itself.

- [ ] **Step 3: expect failures, and capture them precisely**

Windows tests have never run. Some will fail. **Do not fix them in this task** — the job's first purpose is to produce a list.

Run the equivalent locally as far as possible (`GOOS=windows go vet ./...` is clean today, which means everything at least compiles), then report: which packages' tests you expect to run, and which you cannot predict.

- [ ] **Step 4: commit the job**

Commit it even if it is red. A red CI job that names a real failure is the deliverable; a green one achieved by exclusion is not.

---

## Task 2: fix what Task 1 found

**Files:** wherever the failures are.

- [ ] **Step 1: get the actual failure list**

Push the branch and read the Windows job's output. If it cannot be run, say so plainly and stop — do not invent a list.

- [ ] **Step 2: triage before fixing**

For each failure decide: is this a **real defect in the Windows implementation**, a **test that encodes a macOS assumption** and should be build-tagged with a stated reason, or a **CI environment limitation** (no console, no interactive session, no admin)?

The three need different treatment, and the third is the one that invites dishonesty — "it fails on CI" is not a reason to delete a test, only to tag it with what CI cannot provide.

- [ ] **Step 3: fix, with the project's rules intact**

No test body edited. "Could not look" never reported as "no". Anything you cannot fix honestly, report.

- [ ] **Step 4: report what you learned**

Add to `docs/MEASUREMENTS-windows.md` a short section: **what running the code for the first time revealed**, and what remains unverified because CI is not a real desktop (no interactive session, no wintun driver, no admin, no censored network).

---

## Task 3: the distribution decisions

**Files:** modify `.goreleaser.yaml`, `Formula/dpb.rb`, `README.md`.

Three decisions have been deferred to this plan. Make them deliberately.

- [ ] **Decision 1: `brews` is deprecated.**

`goreleaser check` fails on it. goreleaser 2.18 prefers `homebrew_casks`. **But a formula and a cask are different Homebrew concepts**, and `brew install dpb` works for macOS users today — this is a live path.

Establish what actually changes for a user: does `brew install dpb` still work, does the tap layout change, does an existing installation upgrade cleanly? Then decide. **If migrating risks breaking existing installs, the honest answer may be to stay on `brews` until goreleaser removes it and say so in a comment** — a deprecation warning is not a bug. Whatever you choose, `goreleaser release --snapshot` must still produce a working darwin formula.

- [ ] **Decision 2: the formula's Intel URL points at an archive that has never existed.**

`Formula/dpb.rb`'s `on_intel` block references `dpb_<v>_darwin_amd64.tar.gz`, and goreleaser has always been arm64-only by policy. So `brew install dpb` on an Intel Mac **404s**.

Options: drop the `on_intel` block so Homebrew reports an unsupported platform cleanly; or build darwin/amd64 and change the policy. The policy is deliberate — `.goreleaser.yaml` has an `ignore` for darwin/amd64 — so dropping the block is probably right. Either way the user must get a clear message instead of a download failure.

Note `internal/cliapp/dist_test.go`'s `TestFormulaURLsMatchTheArchivesTheReleaseWillPublish` asserts **exactly two** URL stanzas. If you drop one, that test's expectation changes — and it is a **pre-existing** test, so you may not edit it. Resolve that properly: either the test's shape is wrong and should be reported rather than edited, or the fix must keep two stanzas. Do not quietly weaken it.

- [ ] **Decision 3: `wintun.dll`.**

Spec §9 records its redistribution terms as **unverified**. Verify them now — read the actual licence at the wintun source — and then either bundle it in the Windows archives, or document where a user gets it and confirm the README already says so.

**Do not guess.** If the terms are unclear, say so and leave it unbundled; that is the safe direction, and `tunfe` already reports a missing driver plainly.

---

## Task 4: winget and scoop

**Files:** create `packaging/winget/`, `packaging/scoop/dpb.json`; modify `README.md`.

The macOS install path is a Homebrew tap. These are the Windows equivalents, and spec §9 chose them over code signing.

- [ ] **Step 1: scoop**

A scoop bucket needs a JSON manifest with the archive URL, hash, and the binary to shim. It goes in its own repository (`mumudevx/scoop-dpb`) the way the Homebrew tap does, but the manifest belongs here so it is version-controlled with the code that produces it.

Derive the URL and filename from what `goreleaser release --snapshot` actually produces — do not assume the naming. The archives are `dpb_<version>_windows_<arch>.zip`; confirm.

- [ ] **Step 2: winget**

A winget submission is a set of YAML manifests (version, installer, locale) against a schema. Write them for the zip installer. They are submitted as a PR to `microsoft/winget-pkgs` — **do not submit anything**; produce the manifests and report what submitting would involve.

- [ ] **Step 3: SmartScreen, stated once more where it matters**

Neither scoop nor winget suppresses SmartScreen for an unsigned binary. The README says this already for the direct download; make sure the package-manager sections do not accidentally imply otherwise.

- [ ] **Step 4: README**

Add the two install methods to the Windows section, next to the direct download.

---

## Task 5: the capture tool and the measurement protocol

**Files:** create `internal/cliapp/devtool.go`; rewrite `docs/MEASUREMENTS-windows.md`.

- [ ] **Step 1: `dpb devtool capture-sysconf`**

Plan 4 deferred this because there was no machine to capture from. There still is not — but CI is now a Windows machine, and the tool is what turns a future session into fixtures.

It should serialise what `scwindows` reads — `MibIpForwardTable2` rows, `IpAdapterAddresses` blocks, the `WINHTTP_CURRENT_USER_IE_PROXY_CONFIG` values — as JSON into `internal/testwin/fixtures/`.

The reason is in `internal/testnet`'s package comment: the macOS fakes are driven by output captured from a real machine, so a test asserts against what the machine actually produced rather than what the author assumed. API returns cannot be captured as text, so they are captured as structs. **This keeps that guarantee.**

Hide it behind a hidden/dev command so it does not appear in normal help.

- [ ] **Step 2: the measurement protocol**

Rewrite `docs/MEASUREMENTS-windows.md` from "no measurement exists" into **the exact protocol a measurement session follows**, so that when a Windows machine on a censored line exists, the session is a matter of following steps rather than re-deriving method.

It must state:
- the setup: Windows 11 on a censored line, bridged so the machine has its own address on that line
- the commands: `dpb probe` per rung, `dpb tune`, with reps and cooldown matching what `MEASUREMENTS.md` used so the numbers are comparable
- **what would make the result invalid** — the trap `MEASUREMENTS.md` §5.4 records, where a whole compatibility matrix was invalidated because the system resolver answered blocked names with the ISP sinkhole and every emitter was scored against a blackhole. `--addr` pinning exists for that reason.
- that the macOS numbers do **not** transfer: Windows has a different TCP stack, and `turkey.toml`'s ladder was measured on macOS
- that a `tr-windows` ladder is only created **if** measurement shows one is needed — no second ladder is invented in advance

- [ ] **Step 3: verify and commit**

---

## Phase gate

Every item names a file in this plan's File Structure.

- [ ] darwin `go build ./... && go vet ./... && go test ./... -race` green
- [ ] `gofmt -l cmd internal tools` empty
- [ ] `make cover-gate` passes, no floor lowered
- [ ] `go mod tidy` byte-identical
- [ ] `GOOS=windows go build ./...` exit 0
- [ ] **the `windows-latest` CI job exists and its result is reported honestly** — green, or red with a named failure list and a triage for each
- [ ] `goreleaser release --snapshot` produces 3 archives and a darwin-only formula
- [ ] `brew install dpb` path unchanged for macOS users, or the change stated explicitly
- [ ] `Formula/dpb.rb` no longer points at an archive that does not exist
- [ ] `docs/MEASUREMENTS-windows.md` contains a protocol a person could follow, and states plainly that no Windows measurement exists yet
- [ ] `dpb probe --host discord.com --reps 3 --strategy tlsfrag:pos=snimid` still 3/3 PASS on the development machine

**What this plan cannot do:** measure the ladder. That needs Windows 11 on a censored line, and CI is in a datacentre. The protocol is the deliverable; the numbers are the session after it.
