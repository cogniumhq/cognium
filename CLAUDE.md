# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

`cognium` is the user-facing CLI for the Cognium static analysis platform. It provides a simple command-line interface for scanning code for security vulnerabilities.

## Architecture

```
cognium (CLI)
    └── circle-ir (core SAST library)
```

The CLI is a thin wrapper around `circle-ir` that provides:
- Command-line argument parsing (Commander.js)
- Progress indicators (ora)
- Colored output (chalk)
- Multiple output formats (text, JSON, SARIF)

## TypeScript Configuration

**STRICTLY TYPESCRIPT** - This project enforces strict TypeScript with the following guarantees:

- **Strict mode enabled**: All strict TypeScript checks are active
- **No unused code**: `noUnusedLocals` and `noUnusedParameters` enabled
- **Complete coverage**: `noImplicitReturns` and `noFallthroughCasesInSwitch` enabled
- **ESM only**: Pure ES modules (`"type": "module"`)
- **Module resolution**: `bundler` mode for modern tooling
- **Target**: ES2022 for modern JavaScript features
- **Declaration files**: `.d.ts` files are generated for all builds

See `tsconfig.json` for complete configuration. Type checking is enforced via `bun run typecheck`.

## Build System

**BUN-BASED BUILDS** - All builds use Bun, not tsc:

### npm Distribution Build
```bash
bun run build
```
- Outputs to `dist/` directory
- Generates ESM modules for Node.js
- Includes TypeScript declarations (.d.ts)
- Used by `prepublishOnly` hook for npm publishing
- Entry point: `dist/cli.js` (specified in package.json bin)

### Standalone Binary Build
```bash
bun run build:standalone
```
- Uses `bun build --compile` to create self-contained executable
- Outputs single binary file: `./cognium`
- No Node.js runtime required
- Used for Homebrew distribution
- Bundles all dependencies including circle-ir

### Development
```bash
bun run dev          # Run CLI in development mode
bun run typecheck    # TypeScript validation only (no build)
```

## Testing

**CRITICAL: NO TESTS CURRENTLY EXIST**

The project has `bun test` configured but zero test files. When adding tests:
- Use Bun's built-in test runner
- Name tests: `*.test.ts` or `*.spec.ts`
- Place in `src/` directory or separate `test/` directory
- Test the CLI commands, formatters, and file collection logic
- Mock `circle-ir` for unit tests

## Project Structure

```
src/
├── cli.ts         # Main CLI entry point
│                  # - Command definitions (scan, init, version)
│                  # - File collection and scanning logic
│                  # - Progress indicators with ora
│                  # - Exit code handling (0=clean, 1=vulns, 2=error)
│
├── formatters.ts  # Output formatters
│                  # - formatResults(): colored text output
│                  # - formatJSON(): structured JSON
│                  # - formatSARIF(): SARIF 2.1.0 for CI/CD
│
├── version.ts     # Version constant (must be manually updated)
│
└── index.ts       # Programmatic API exports
                   # - Re-exports circle-ir types
                   # - Allows use as library (not just CLI)
```

## Distribution Channels

### 1. npm Registry
- Package name: `cognium`
- Main: `dist/index.js` (programmatic API)
- Bin: `dist/cli.js` (CLI command)
- Types: `dist/index.d.ts`
- Requires Node.js >= 18.0.0
- Built with `bun run build`

### 2. Homebrew
- Standalone binary: `./cognium`
- No runtime dependencies
- Built with `bun run build:standalone`
- Tap: `cogniumhq/tap/cognium`

### 3. GitHub Releases
- Standalone binaries for multiple platforms
- Source code archives

## Key Dependencies

**Runtime**:
- `circle-ir@^3.1.0`: Core SAST engine (our library)
- `commander@^13.0.0`: CLI argument parsing
- `chalk@^5.4.0`: Terminal colors (ESM only)
- `ora@^8.0.0`: Spinners/progress indicators

**Development**:
- `typescript@^5.7.0`: Type checking only (not used for builds)
- `@types/node@^22.0.0`: Node.js types
- `bun-types@^1.2.0`: Bun runtime types

## Documentation

### README.md (User-Facing)
Comprehensive end-user documentation including:
- Installation instructions (npm, Homebrew, standalone)
- Command reference with examples
- Configuration options
- CI/CD integration examples
- Supported languages and vulnerability types
- Benchmark results

**DO NOT modify README.md** without explicit user request - it's customer-facing documentation.

### CLAUDE.md (This File)
Developer guidance for Claude Code when working on this codebase.

### CHANGELOG.md
Keep a Changelog format tracking all releases.

### HOMEBREW.md
Complete guide for setting up and maintaining the Homebrew tap distribution.

## Homebrew Distribution

Cognium is distributed via Homebrew through a custom tap at `cogniumhq/homebrew-tap`.

**Tap Repository**: Separate GitHub repository containing only the formula file:
- Repository: `https://github.com/cogniumhq/homebrew-tap`
- Formula: `Formula/cognium.rb` or `cognium.rb`
- Users install with: `brew install cogniumhq/tap/cognium`

**Formula Location in This Repo**: `Formula/cognium.rb`
- This is a reference/template formula
- The actual formula is maintained in the separate homebrew-tap repository
- Must be updated with SHA256 hashes after each release

**See HOMEBREW.md** for complete setup instructions, release process, and automation.

## Development Workflow

1. **Making Changes**:
   - Edit TypeScript files in `src/`
   - Run `bun run typecheck` to verify types
   - Run `bun run dev scan <path>` to test CLI

2. **Before Committing**:
   - Ensure `bun run typecheck` passes
   - Manually test CLI commands
   - Update version.ts if needed

3. **Release Process**:
   - Update version in package.json, version.ts, and CHANGELOG.md
   - Run `bun run build` to verify npm build
   - Run `bun run build:standalone` to verify binary build
   - Build binaries for all platforms (macOS arm64/x64, Linux arm64/x64)
   - Generate SHA256 hashes for all binaries
   - Create GitHub release with tag and upload binaries
   - Update Homebrew formula in homebrew-tap repository with new SHA256s
   - Publish to npm with `npm publish`
   - See HOMEBREW.md for detailed Homebrew release steps

## Code Style Notes

- Use `async/await` for asynchronous operations
- Prefer functional array methods (map, filter, reduce)
- Error handling: try/catch with appropriate exit codes
- Use chalk for all colored output
- Use ora spinners for long-running operations
- File paths: use Node.js path module for cross-platform compatibility
- Avoid process.exit() except in CLI entry point
