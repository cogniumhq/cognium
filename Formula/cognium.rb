class Cognium < Formula
  desc "AI-powered static analysis CLI for detecting security vulnerabilities"
  homepage "https://cognium.dev"
  url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-arm64"
  sha256 "" # TODO: Add SHA256 hash after first release
  version "1.0.0"
  license "MIT"

  # Supports macOS (Darwin) on both Intel and Apple Silicon
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-arm64"
      sha256 "" # TODO: Add SHA256 for ARM64
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-x64"
      sha256 "" # TODO: Add SHA256 for x64
    end
  end

  # Linux support
  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-arm64"
      sha256 "" # TODO: Add SHA256 for ARM64
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-x64"
      sha256 "" # TODO: Add SHA256 for x64
    end
  end

  def install
    # The downloaded file is the standalone binary
    bin.install Dir["*"].first => "cognium"
  end

  test do
    # Test that the binary runs and outputs version
    assert_match "cognium v#{version}", shell_output("#{bin}/cognium version")
  end
end
