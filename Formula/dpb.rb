# Homebrew formula for dpb.
#
# The canonical copy lives in mumudevx/homebrew-tap and is written there by
# GoReleaser (see .goreleaser.yaml) whenever a tag is pushed. This copy is the
# manual fallback and the reviewable reference: if the tap push ever fails, or
# a release is cut by hand, fill in the two checksums below and commit this file
# to the tap as Formula/dpb.rb.
#
# FILLING IN THE CHECKSUMS
#
#   Every release publishes a checksums.txt alongside the archives. The two
#   values below are the sha256 lines for the darwin archives:
#
#     curl -sL https://github.com/mumudevx/dpi-bypass-mac/releases/download/v0.1.0/checksums.txt
#
#   or compute them from the files themselves:
#
#     shasum -a 256 dpb_0.1.0_darwin_arm64.tar.gz dpb_0.1.0_darwin_amd64.tar.gz
#
#   Both must be filled in before this formula is published. Homebrew refuses to
#   install a formula whose sha256 does not match, so a placeholder left in
#   place fails loudly at install time rather than silently installing
#   something unverified — which is the right direction, but it is still a
#   broken install command, and a broken install command is what this milestone
#   exists to end.
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
      url "https://github.com/mumudevx/dpi-bypass-mac/releases/download/v0.1.0/dpb_0.1.0_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_AMD64_SHA256" # from checksums.txt; see the header
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
