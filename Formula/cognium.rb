class Cognium < Formula
  desc "AI-powered static analysis CLI for detecting security vulnerabilities"
  homepage "https://cognium.dev"
  url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-arm64"
  sha256 "3e4230513f8cafbb886b0db4b7c8df8af62dd43ed5fa9b96d41b24094b8137a0" # TODO: Add SHA256 hash after first release
  version "1.0.4"
  license "MIT"

  # Supports macOS (Darwin) on both Intel and Apple Silicon
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-arm64"
      sha256 "3e4230513f8cafbb886b0db4b7c8df8af62dd43ed5fa9b96d41b24094b8137a0" # TODO: Add SHA256 for ARM64
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-x64"
      sha256 "90a0f90cc8d29c9aca956f2429905de1b219cb60562d16e5c9e5ffd9e0f751bc" # TODO: Add SHA256 for x64
    end
  end

  # Linux support
  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-arm64"
      sha256 "d5adce258bfc77b8abff403cfbaa6c075b9f56b1d8e29f76905415abaac8124e" # TODO: Add SHA256 for ARM64
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-x64"
      sha256 "3fed619f20c38e1aeb16eafbe36a36716abe6396322c59f989ee8a3e1dd3440b" # TODO: Add SHA256 for x64
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
