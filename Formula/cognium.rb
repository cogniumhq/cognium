class Cognium < Formula
  desc "AI-powered static analysis CLI for detecting security vulnerabilities"
  homepage "https://cognium.dev"
  url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-arm64"
  sha256 "b3c98e0ba3916b9d29a67ed6fdbcbbaa20212f32d05a4427e9bd7529a7131e84" # TODO: Add SHA256 hash after first release
  version "1.0.5"
  license "MIT"

  # Supports macOS (Darwin) on both Intel and Apple Silicon
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-arm64"
      sha256 "b3c98e0ba3916b9d29a67ed6fdbcbbaa20212f32d05a4427e9bd7529a7131e84" # TODO: Add SHA256 for ARM64
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-x64"
      sha256 "2220d23c7b4eab14ed60cc568bbec82d4748c6a3881bf805a227ab86fc87c3e3" # TODO: Add SHA256 for x64
    end
  end

  # Linux support
  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-arm64"
      sha256 "be95331c8355ccdc9a06f8effa249acbfe201e24eb1aed59b3e6b5713e36e389" # TODO: Add SHA256 for ARM64
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-x64"
      sha256 "6911c2610e0ac8c4cac9f11949c12c02e73443a343e7ba266f1abccd356a111a" # TODO: Add SHA256 for x64
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
