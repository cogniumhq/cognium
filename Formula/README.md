# Homebrew Formula

This directory contains the Homebrew formula for Cognium.

## Purpose

The `cognium.rb` file in this directory is a **reference/template** formula. It serves as:
1. A template for the formula maintained in the separate `homebrew-tap` repository
2. A reference for development and testing

## Actual Distribution

The **live formula** that users install from is maintained in a separate repository:
- Repository: https://github.com/cogniumhq/homebrew-tap
- Location: `Formula/cognium.rb` or `cognium.rb`

Users install with:
```bash
brew install cogniumhq/tap/cognium
```

## Updating the Formula

When releasing a new version:
1. Build binaries for all platforms (see RELEASE.md)
2. Generate SHA256 hashes
3. Update version and SHA256s in `cognium.rb`
4. Copy updated formula to the homebrew-tap repository
5. Commit and push to homebrew-tap

See HOMEBREW.md for complete instructions.

## Testing Locally

To test the formula before publishing:

```bash
# Install from local formula
brew install --build-from-source ./Formula/cognium.rb

# Or audit the formula
brew audit --strict ./Formula/cognium.rb

# Uninstall after testing
brew uninstall cognium
```
