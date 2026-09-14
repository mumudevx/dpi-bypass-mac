# Homebrew formula for dpb.
#
# The canonical copy lives in mumudevx/homebrew-tap and is written there by
# GoReleaser (see .goreleaser.yaml) whenever a tag is pushed. This copy is the
# manual fallback and the reviewable reference: if the tap push ever fails, or
# a release is cut by hand, fill in the checksum below and commit this file
# to the tap as Formula/dpb.rb.
#
# FILLING IN THE CHECKSUM
#
#   Every release publishes a checksums.txt alongside the archives. The value
#   below is the sha256 line for the one darwin archive dpb ships
#   (darwin/arm64 — see the ARM64-ONLY note below):
#
#     curl -sL https://github.com/mumudevx/dpi-bypass-mac/releases/download/v0.1.0/checksums.txt
#
#   or compute it from the file itself:
#
#     shasum -a 256 dpb_0.1.0_darwin_arm64.tar.gz
#
#   It must be filled in before this formula is published. Homebrew refuses to
#   install a formula whose sha256 does not match, so a placeholder left in
#   place fails loudly at install time rather than silently installing
#   something unverified — which is the right direction, but it is still a
#   broken install command, and a broken install command is what this milestone
#   exists to end.
#
# ARM64-ONLY, ON PURPOSE, AND THE on_intel BLOCK REFLECTS THAT
#
#   .goreleaser.yaml's builds.ignore excludes darwin/amd64: dpb ships for
#   Apple Silicon only, and no darwin/amd64 archive has ever been published.
#   An earlier version of this formula had an on_intel block whose url pointed
#   at "dpb_<v>_darwin_amd64.tar.gz" — an archive `goreleaser release
#   --snapshot` never produces, so `brew install dpb` on an Intel Mac 404'd.
#   on_intel below calls `odie` instead: verified with a local tap and
#   `brew fetch --arch=intel`, which prints the odie message and exits, no
#   download attempted. That is Homebrew's own on_arm/on_intel DSL working as
#   designed; it is not what GoReleaser's generated formula does for the same
#   case. GoReleaser 2.18 has no macOS archive for amd64 to reason about, so it
#   wraps the lone url in a bare `if Hardware::CPU.arm?` with no fallback —
#   verified by running `goreleaser release --snapshot` and forcing that
#   branch closed on an arm64 host: Homebrew fails with "formula requires at
#   least a URL" and a full backtrace asking the user to file a bug. No field
#   in `brews:` (url_template, custom_block, dependencies) changes that. This
#   manual copy is the only place, today, that gives an Intel user a clean
#   message instead of a crash or a 404.
#
# NO CODESIGN, NO NOTARIZATION, AND THAT IS CORRECT
#
#   Homebrew downloads with curl, and curl sets no com.apple.quarantine
#   attribute, so a formula-installed CLI is never evaluated by Gatekeeper.
#   Verified on macOS 26.3.1 / Homebrew 6.0.18: brew-installed binaries carry
#   only com.apple.provenance, and `xattr -p com.apple.quarantine` on one
#   answers "No such xattr". Apple Silicon's refusal to run a wholly unsigned
#   binary is satisfied by Go's own linker, which ad-hoc signs every
#   darwin/arm64 binary host-independently: `codesign -dv` on a plain
#   `go build` of this tree reports flags=0x20002(adhoc,linker-signed).
#
# NO service BLOCK
#
#   dpb installs its own launchd job (`dpb service install`, label
#   com.mumudevx.dpb). A `brew services` job would be a second supervisor for
#   the same binary, racing for the same port and for the same system proxy
#   setting; the loser's teardown would restore the proxy the winner had just
#   set. One supervisor only.
class Dpb < Formula
  desc "macOS DPI bypass: connects plain first, desyncs only on evidence"
  homepage "https://github.com/mumudevx/dpi-bypass-mac"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/mumudevx/dpi-bypass-mac/releases/download/v0.1.0/dpb_0.1.0_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_ARM64_SHA256" # from checksums.txt; see the header
    end
    on_intel do
      # See "ARM64-ONLY, ON PURPOSE" above: there is no darwin/amd64 archive
      # to point at, so this reports the platform as unsupported instead of
      # attempting a download that would 404.
      odie "dpb ships an Apple Silicon (arm64) build only; there is no " \
           "darwin/amd64 archive to install. See " \
           "https://github.com/mumudevx/dpi-bypass-mac for status."
    end
  end

  def install
    bin.install "dpb"
  end

  def caveats
    <<~EOS
      dpb needs no root in proxy mode. Start it in the foreground with:

        dpb run

      To keep it running across logins:

        dpb service install
        dpb service status

      The shipped profiles come from measurements taken on one ISP, in one city,
      on one day. Measure your own line before trusting them:

        dpb tune
    EOS
  end

  test do
    # `dpb version` prints "dpb <version> (<commit>) <platform>". Asserting on
    # the version rather than on the word "dpb" is what makes this test able to
    # fail: a formula that shipped last release's bottle would still print the
    # binary's name.
    assert_match version.to_s, shell_output("#{bin}/dpb version")

    # `dpb strategy list` runs the whole registry and touches no network, no
    # system setting and no privileged interface, so it is safe in a sandbox
    # and still proves the binary does more than print its own name.
    assert_match "tlsfrag", shell_output("#{bin}/dpb strategy list")
  end
end
