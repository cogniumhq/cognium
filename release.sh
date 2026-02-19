#!/usr/bin/env bash
# release.sh — Automates the full Cognium release process
# Usage: ./release.sh <patch|minor|major>

set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────────────────
BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${BLUE}→${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}!${NC} $1"; }
die()     { echo -e "${RED}✗${NC} $1"; exit 1; }
confirm() { read -p "$1 [y/N] " -n 1 -r; echo; [[ $REPLY =~ ^[Yy]$ ]]; }

# ── Argument ────────────────────────────────────────────────────────────────────
if [[ $# -ne 1 ]] || [[ ! "$1" =~ ^(patch|minor|major)$ ]]; then
  echo "Usage: ./release.sh <patch|minor|major>"
  exit 1
fi
BUMP=$1

# ── Prerequisites ───────────────────────────────────────────────────────────────
info "Checking prerequisites..."
command -v bun  >/dev/null 2>&1 || die "bun not found"
command -v node >/dev/null 2>&1 || die "node not found"
command -v npm  >/dev/null 2>&1 || die "npm not found"
command -v gh   >/dev/null 2>&1 || die "GitHub CLI (gh) not found — brew install gh"
gh auth status  >/dev/null 2>&1 || die "Not authenticated with GitHub CLI — run: gh auth login"
npm whoami      >/dev/null 2>&1 || die "Not logged in to npm — run: npm login"
success "Prerequisites OK"

# ── Clean working tree ──────────────────────────────────────────────────────────
if [[ -n $(git status --porcelain) ]]; then
  warn "Uncommitted changes detected:"
  git status --short
  confirm "Continue anyway?" || exit 1
fi

# ── Typecheck ───────────────────────────────────────────────────────────────────
info "Running type check..."
bun run typecheck
success "Type check passed"

# ── Bump version ────────────────────────────────────────────────────────────────
OLD_VERSION=$(node -p "require('./package.json').version")
info "Bumping version ($BUMP): $OLD_VERSION → ..."
# --no-git-tag-version: we'll commit everything (changelog, formula) together
npm version "$BUMP" --no-git-tag-version
NEW_VERSION=$(node -p "require('./package.json').version")
TAG="v$NEW_VERSION"
success "Version bumped to $NEW_VERSION"

# ── CHANGELOG ───────────────────────────────────────────────────────────────────
TODAY=$(date +%Y-%m-%d)
# Build changelog entry from commits since last tag
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [[ -n "$LAST_TAG" ]]; then
  COMMITS=$(git log "$LAST_TAG"..HEAD --pretty=format:"- %s" --no-merges)
else
  COMMITS=$(git log --pretty=format:"- %s" --no-merges | head -20)
fi

ENTRY="## [$NEW_VERSION] - $TODAY

### Changes

${COMMITS:-"- (no commits since last release)"}

[$NEW_VERSION]: https://github.com/cogniumhq/cognium/compare/v$OLD_VERSION...v$NEW_VERSION"

ENTRY_FILE=$(mktemp)
printf '%s\n' "$ENTRY" > "$ENTRY_FILE"
TMPFILE=$(mktemp)
awk -v entry_file="$ENTRY_FILE" '
  /^## \[/ && !inserted {
    while ((getline line < entry_file) > 0) print line
    print ""
    inserted=1
  }
  { print }
' CHANGELOG.md > "$TMPFILE"
mv "$TMPFILE" CHANGELOG.md
rm "$ENTRY_FILE"

info "CHANGELOG.md pre-populated from git commits. Opening for review..."
${EDITOR:-vi} CHANGELOG.md
success "CHANGELOG.md updated"

# ── npm build ───────────────────────────────────────────────────────────────────
info "Building npm package..."
bun run build
node dist/cli.js version | grep -q "$NEW_VERSION" || die "Built CLI reports wrong version"
success "npm build OK"

# ── Cross-platform binaries ─────────────────────────────────────────────────────
info "Building cross-platform binaries..."
bun build src/cli.ts --compile --target=bun-darwin-arm64 --outfile cognium-darwin-arm64
bun build src/cli.ts --compile --target=bun-darwin-x64   --outfile cognium-darwin-x64
bun build src/cli.ts --compile --target=bun-linux-x64    --outfile cognium-linux-x64
bun build src/cli.ts --compile --target=bun-linux-arm64  --outfile cognium-linux-arm64
success "Binaries built"

# ── SHA256 ──────────────────────────────────────────────────────────────────────
info "Generating SHA256 hashes..."
shasum -a 256 cognium-darwin-arm64 cognium-darwin-x64 cognium-linux-x64 cognium-linux-arm64 > SHA256SUMS
cat SHA256SUMS
SHA_DARWIN_ARM64=$(awk '/cognium-darwin-arm64/{print $1}' SHA256SUMS)
SHA_DARWIN_X64=$(awk '/cognium-darwin-x64/{print $1}'   SHA256SUMS)
SHA_LINUX_X64=$(awk '/cognium-linux-x64/{print $1}'     SHA256SUMS)
SHA_LINUX_ARM64=$(awk '/cognium-linux-arm64/{print $1}' SHA256SUMS)
success "SHA256SUMS generated"

# ── Update local Formula/cognium.rb ─────────────────────────────────────────────
info "Updating Formula/cognium.rb..."
python3 - <<PYEOF
import re

with open('Formula/cognium.rb', 'r') as f:
    content = f.read()

# Replace version string
content = re.sub(r'version "[^"]+"', f'version "$NEW_VERSION"', content)

# Replace all URLs (old version tag → new)
content = content.replace(f'v$OLD_VERSION', f'v$NEW_VERSION')

# Replace sha256 values in order: top-level, darwin-arm64, darwin-x64, linux-arm64, linux-x64
# Strategy: replace each sha256 line by finding its surrounding context
def replace_sha(text, platform, new_hash):
    # Match sha256 line near a url containing the platform name
    pattern = r'(url "[^"]*' + platform + r'[^"]*"\\n\\s*sha256 ")[^"]*(")'
    return re.sub(pattern, r'\\g<1>' + new_hash + r'\\g<2>', text)

content = replace_sha(content, 'darwin-arm64', '$SHA_DARWIN_ARM64')
content = replace_sha(content, 'darwin-x64',   '$SHA_DARWIN_X64')
content = replace_sha(content, 'linux-arm64',  '$SHA_LINUX_ARM64')
content = replace_sha(content, 'linux-x64',    '$SHA_LINUX_X64')

with open('Formula/cognium.rb', 'w') as f:
    f.write(content)
PYEOF
success "Formula/cognium.rb updated"

# ── Git commit, tag, push ────────────────────────────────────────────────────────
info "Committing release $TAG..."
git add -A
git commit -m "Release $TAG"
git tag "$TAG"
git push origin main
git push origin "$TAG"
success "Pushed $TAG to GitHub"

# ── GitHub release ───────────────────────────────────────────────────────────────
info "Creating GitHub release $TAG..."
# Extract release notes for this version from CHANGELOG.md
RELEASE_NOTES=$(awk "/^## \[$NEW_VERSION\]/{found=1; next} found && /^## \[/{exit} found{print}" CHANGELOG.md)
gh release create "$TAG" \
  cognium-darwin-arm64 \
  cognium-darwin-x64 \
  cognium-linux-x64 \
  cognium-linux-arm64 \
  SHA256SUMS \
  --title "$TAG" \
  --notes "$RELEASE_NOTES"
success "GitHub release created: https://github.com/cogniumhq/cognium/releases/tag/$TAG"

# ── npm publish ──────────────────────────────────────────────────────────────────
info "Running npm publish dry-run..."
npm publish --dry-run
echo ""
if confirm "Publish $TAG to npm?"; then
  npm publish
  success "Published to npm: https://www.npmjs.com/package/cognium"
else
  warn "Skipped npm publish — run 'npm publish' manually when ready"
fi

# ── Homebrew tap ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Homebrew tap update (cogniumhq/homebrew-tap):${NC}"
echo ""

HOMEBREW_TAP_DIR="${HOMEBREW_TAP_DIR:-}"
if [[ -n "$HOMEBREW_TAP_DIR" ]] && [[ -d "$HOMEBREW_TAP_DIR" ]]; then
  info "Updating Homebrew tap at $HOMEBREW_TAP_DIR..."
  cp Formula/cognium.rb "$HOMEBREW_TAP_DIR/Formula/cognium.rb"
  pushd "$HOMEBREW_TAP_DIR" > /dev/null
  git add Formula/cognium.rb
  git commit -m "Update cognium to $TAG"
  git push origin main
  popd > /dev/null
  success "Homebrew tap updated"
else
  warn "Set HOMEBREW_TAP_DIR to auto-update, or run these commands manually:"
  echo ""
  echo "  git clone https://github.com/cogniumhq/homebrew-tap.git"
  echo "  cp Formula/cognium.rb homebrew-tap/Formula/cognium.rb"
  echo "  cd homebrew-tap"
  echo "  git add Formula/cognium.rb"
  echo "  git commit -m \"Update cognium to $TAG\""
  echo "  git push origin main"
fi

# ── Done ─────────────────────────────────────────────────────────────────────────
echo ""
success "Release $TAG complete!"
echo ""
echo "  npm:      https://www.npmjs.com/package/cognium"
echo "  GitHub:   https://github.com/cogniumhq/cognium/releases/tag/$TAG"
echo "  Homebrew: brew install cogniumhq/tap/cognium"
