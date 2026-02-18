# Homebrew Distribution Guide

This guide explains how to set up and maintain the Homebrew tap for Cognium.

## Overview

Cognium is distributed via Homebrew using a custom tap at `cogniumhq/tap`.

Users install with:
```bash
brew install cogniumhq/tap/cognium
```

## Repository Structure

### Main Repository (cogniumhq/cognium)
- Contains the source code and builds standalone binaries
- `Formula/cognium.rb` - Homebrew formula (for reference/development)

### Tap Repository (cogniumhq/homebrew-tap)
- Separate repository: `https://github.com/cogniumhq/homebrew-tap`
- Contains only the formula file: `cognium.rb` or `Formula/cognium.rb`
- Homebrew automatically discovers it when users run `brew install cogniumhq/tap/cognium`

## Initial Tap Setup

### 1. Create Tap Repository

```bash
# Create a new repository on GitHub
# Name: homebrew-tap
# Owner: cogniumhq
# URL: https://github.com/cogniumhq/homebrew-tap

# Clone it locally
git clone https://github.com/cogniumhq/homebrew-tap.git
cd homebrew-tap

# Create Formula directory (optional but recommended)
mkdir -p Formula

# Copy the formula
cp /path/to/cognium/Formula/cognium.rb Formula/cognium.rb
# OR place it in the root as cognium.rb

# Commit and push
git add .
git commit -m "Initial formula for cognium"
git push origin main
```

### 2. Formula File Location

Homebrew accepts two structures:
- `Formula/cognium.rb` (recommended for multiple formulas)
- `cognium.rb` (acceptable for single formula)

## Release Process

When releasing a new version of Cognium:

### 1. Build Binaries for All Platforms

```bash
# macOS ARM64 (Apple Silicon)
bun build src/cli.ts --compile --target=bun-darwin-arm64 --outfile cognium-darwin-arm64

# macOS x64 (Intel)
bun build src/cli.ts --compile --target=bun-darwin-x64 --outfile cognium-darwin-x64

# Linux x64
bun build src/cli.ts --compile --target=bun-linux-x64 --outfile cognium-linux-x64

# Linux ARM64
bun build src/cli.ts --compile --target=bun-linux-arm64 --outfile cognium-linux-arm64
```

Note: Cross-compilation may require building on native platforms or CI/CD.

### 2. Generate SHA256 Hashes

```bash
shasum -a 256 cognium-darwin-arm64
shasum -a 256 cognium-darwin-x64
shasum -a 256 cognium-linux-x64
shasum -a 256 cognium-linux-arm64
```

### 3. Create GitHub Release

```bash
# Tag the release
git tag v1.0.0
git push origin v1.0.0

# Create release on GitHub and upload binaries:
# - cognium-darwin-arm64
# - cognium-darwin-x64
# - cognium-linux-x64
# - cognium-linux-arm64
```

Or use GitHub CLI:
```bash
gh release create v1.0.0 \
  cognium-darwin-arm64 \
  cognium-darwin-x64 \
  cognium-linux-x64 \
  cognium-linux-arm64 \
  --title "v1.0.0" \
  --notes "Release notes here"
```

### 4. Update Homebrew Formula

```bash
cd homebrew-tap

# Edit Formula/cognium.rb or cognium.rb
# Update:
# - version number
# - URL with new version tag
# - SHA256 hashes for each platform

git add .
git commit -m "Update cognium to v1.0.0"
git push origin main
```

### 5. Test Installation

```bash
# Test locally first
brew install --build-from-source cogniumhq/tap/cognium

# Or test specific version
brew install cogniumhq/tap/cognium@1.0.0

# Verify
cognium version

# Uninstall after testing
brew uninstall cognium
```

## Formula Template

The formula in `Formula/cognium.rb` should follow this structure:

```ruby
class Cognium < Formula
  desc "AI-powered static analysis CLI for detecting security vulnerabilities"
  homepage "https://cognium.dev"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-arm64"
      sha256 "abc123..." # ARM64 SHA256
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-darwin-x64"
      sha256 "def456..." # x64 SHA256
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-arm64"
      sha256 "ghi789..." # ARM64 SHA256
    else
      url "https://github.com/cogniumhq/cognium/releases/download/v1.0.0/cognium-linux-x64"
      sha256 "jkl012..." # x64 SHA256
    end
  end

  def install
    bin.install Dir["*"].first => "cognium"
  end

  test do
    assert_match "cognium v#{version}", shell_output("#{bin}/cognium version")
  end
end
```

## Automated Release with GitHub Actions

Consider creating `.github/workflows/release.yml` in the main repository:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: macos-latest
            target: darwin-arm64
          - os: macos-latest
            target: darwin-x64
          - os: ubuntu-latest
            target: linux-x64
          - os: ubuntu-latest
            target: linux-arm64

    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4

      - uses: oven-sh/setup-bun@v1

      - run: bun install

      - name: Build binary
        run: bun build src/cli.ts --compile --target=bun-${{ matrix.target }} --outfile cognium-${{ matrix.target }}

      - name: Generate SHA256
        run: shasum -a 256 cognium-${{ matrix.target }} > cognium-${{ matrix.target }}.sha256

      - uses: softprops/action-gh-release@v1
        with:
          files: |
            cognium-${{ matrix.target }}
            cognium-${{ matrix.target }}.sha256

  update-homebrew:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Update Homebrew formula
        # Use homebrew/bump-formula-pr action or custom script
        # to automatically update the formula in homebrew-tap
```

## Troubleshooting

### Formula Not Found
```bash
# Make sure tap is added
brew tap cogniumhq/tap

# Or use full name
brew install cogniumhq/tap/cognium
```

### SHA256 Mismatch
- Regenerate SHA256 for the binary
- Ensure you're hashing the correct file
- Update formula with correct hash

### Binary Not Executable
- Ensure file is named correctly in releases
- Check file permissions on download

## Resources

- [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Homebrew Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae)
- [How to Create and Maintain a Tap](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap)
