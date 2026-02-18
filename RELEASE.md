# Release Checklist

This document provides a step-by-step checklist for releasing a new version of Cognium.

## Pre-Release

- [ ] All changes committed and pushed
- [ ] All tests passing (when tests exist)
- [ ] `bun run typecheck` passes without errors
- [ ] Manual testing completed for all commands
- [ ] CHANGELOG.md updated with release notes

## Version Update

```bash
# Bump version (pick one) — automatically updates package.json and src/version.ts
npm version patch   # e.g. 1.0.0 → 1.0.1
npm version minor   # e.g. 1.0.0 → 1.1.0
npm version major   # e.g. 1.0.0 → 2.0.0
```

- [ ] Run `npm version <patch|minor|major>` (updates `package.json` + `src/version.ts` + creates git tag)
- [ ] Update `CHANGELOG.md` with release date and notes
- [ ] Update version in `Formula/cognium.rb` (reference formula)

## Build Verification

### npm Build
```bash
bun run build
```
- [ ] Build completes without errors
- [ ] `dist/` directory contains cli.js, index.js, and .d.ts files
- [ ] Test with: `node dist/cli.js version`

### Standalone Binary Build (Local Platform)
```bash
bun run build:standalone
```
- [ ] Build completes without errors
- [ ] Binary is executable: `./cognium version`
- [ ] Binary size is reasonable (~60MB)

## Cross-Platform Builds

Build binaries for all supported platforms:

### macOS ARM64 (Apple Silicon)
```bash
bun build src/cli.ts --compile --target=bun-darwin-arm64 --outfile cognium-darwin-arm64
```
- [ ] Binary created successfully
- [ ] Test if on ARM Mac: `./cognium-darwin-arm64 version`

### macOS x64 (Intel)
```bash
bun build src/cli.ts --compile --target=bun-darwin-x64 --outfile cognium-darwin-x64
```
- [ ] Binary created successfully
- [ ] Test if on Intel Mac: `./cognium-darwin-x64 version`

### Linux x64
```bash
bun build src/cli.ts --compile --target=bun-linux-x64 --outfile cognium-linux-x64
```
- [ ] Binary created successfully

### Linux ARM64
```bash
bun build src/cli.ts --compile --target=bun-linux-arm64 --outfile cognium-linux-arm64
```
- [ ] Binary created successfully

**Note**: Cross-compilation may not work for all targets. Consider using CI/CD (GitHub Actions) or building on native platforms.

## Generate SHA256 Hashes

```bash
shasum -a 256 cognium-darwin-arm64 > cognium-darwin-arm64.sha256
shasum -a 256 cognium-darwin-x64 > cognium-darwin-x64.sha256
shasum -a 256 cognium-linux-x64 > cognium-linux-x64.sha256
shasum -a 256 cognium-linux-arm64 > cognium-linux-arm64.sha256

# Or all at once
shasum -a 256 cognium-* > SHA256SUMS
```

- [ ] SHA256 hashes generated for all binaries
- [ ] Hashes saved to file(s)

## Git Tag

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```
- [ ] Tag created locally
- [ ] Tag pushed to GitHub

## GitHub Release

### Using GitHub Web UI
1. Go to https://github.com/cogniumhq/cognium/releases/new
2. Select the tag: vX.Y.Z
3. Set title: vX.Y.Z
4. Copy release notes from CHANGELOG.md
5. Upload binaries:
   - cognium-darwin-arm64
   - cognium-darwin-x64
   - cognium-linux-x64
   - cognium-linux-arm64
   - SHA256SUMS (optional)
6. Publish release

### Using GitHub CLI
```bash
gh release create vX.Y.Z \
  cognium-darwin-arm64 \
  cognium-darwin-x64 \
  cognium-linux-x64 \
  cognium-linux-arm64 \
  SHA256SUMS \
  --title "vX.Y.Z" \
  --notes-file CHANGELOG.md
```

- [ ] GitHub release created
- [ ] All binaries uploaded
- [ ] Release notes included
- [ ] Release published (not draft)

## npm Publication

```bash
# Dry run first
npm publish --dry-run

# Actual publish
npm publish
```

- [ ] npm dry-run successful
- [ ] npm publish successful
- [ ] Package visible at https://www.npmjs.com/package/cognium
- [ ] Test install: `npm install -g cognium`

## Homebrew Formula Update

### 1. Clone homebrew-tap repository
```bash
git clone https://github.com/cogniumhq/homebrew-tap.git
cd homebrew-tap
```

### 2. Update Formula/cognium.rb

Extract SHA256 hashes from the files you created:
```bash
cat cognium-darwin-arm64.sha256
cat cognium-darwin-x64.sha256
cat cognium-linux-x64.sha256
cat cognium-linux-arm64.sha256
```

Edit `Formula/cognium.rb` (or `cognium.rb`):
- [ ] Update `version` to "X.Y.Z"
- [ ] Update URL tags from `vX.Y.Z-OLD` to `vX.Y.Z`
- [ ] Update SHA256 hash for darwin-arm64
- [ ] Update SHA256 hash for darwin-x64
- [ ] Update SHA256 hash for linux-arm64
- [ ] Update SHA256 hash for linux-x64

### 3. Commit and Push
```bash
git add Formula/cognium.rb  # or cognium.rb
git commit -m "Update cognium to vX.Y.Z"
git push origin main
```

- [ ] Formula updated and pushed

### 4. Test Homebrew Installation

```bash
# Uninstall old version if present
brew uninstall cognium

# Install from tap
brew install cogniumhq/tap/cognium

# Verify
cognium version

# Should output: cognium vX.Y.Z
```

- [ ] Homebrew installation successful
- [ ] Correct version displayed
- [ ] Binary runs without errors

## Post-Release Verification

- [ ] npm package: `npm view cognium version` shows new version
- [ ] Homebrew: `brew info cogniumhq/tap/cognium` shows new version
- [ ] GitHub release visible and complete
- [ ] Test fresh install: `npx cognium version`
- [ ] Test Homebrew install: `brew install cogniumhq/tap/cognium`

## Communication

- [ ] Announce on Discord (if applicable)
- [ ] Tweet about release (if applicable)
- [ ] Update documentation site (if applicable)
- [ ] Notify users of breaking changes (if any)

## Troubleshooting

### Cross-compilation fails
- Use GitHub Actions for multi-platform builds
- Build on native machines/VMs
- See HOMEBREW.md for GitHub Actions example

### SHA256 mismatch in Homebrew
- Verify you're using the correct binary file
- Regenerate SHA256: `shasum -a 256 <file>`
- Ensure formula URLs point to correct release

### npm publish fails
- Check you're logged in: `npm whoami`
- Verify package name availability
- Check npm registry status: https://status.npmjs.org/

### Homebrew installation fails
- Wait a few minutes for GitHub CDN to propagate
- Check formula syntax: `brew audit --strict Formula/cognium.rb`
- Verify release binaries are publicly accessible
- Check release URLs in formula match GitHub release

## Automation (Future)

Consider implementing GitHub Actions for:
- Automatic cross-platform builds on tag push
- Automatic GitHub release creation
- Automatic Homebrew formula PR
- Automatic npm publication

See HOMEBREW.md for example GitHub Actions workflow.
