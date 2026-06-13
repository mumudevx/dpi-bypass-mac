# This formula is generated/updated by GoReleaser in the mumudevx/homebrew-tap
# repository. It is mirrored here for reference. Install with:
#   brew tap mumudevx/tap
#   brew install dpb
class Dpb < Formula
  desc "macOS DPI bypass CLI (Turkey + global)"
  homepage "https://github.com/mumudevx/dpi-bypass-mac"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/mumudevx/dpi-bypass-mac/releases/download/v0.1.0/dpb_0.1.0_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
    on_intel do
      url "https://github.com/mumudevx/dpi-bypass-mac/releases/download/v0.1.0/dpb_0.1.0_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  def install
    bin.install "dpb"
  end

  service do
    run [opt_bin/"dpb", "run", "--profile", "turkey"]
    keep_alive true
    log_path var/"log/dpb.log"
    error_log_path var/"log/dpb.err.log"
  end

  test do
    assert_match "dpb", shell_output("#{bin}/dpb version")
  end
end
