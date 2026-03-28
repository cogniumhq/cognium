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
- Command-line argument parsing (zero-dependency native parser)
- Progress indicators (zero-dependency spinner utility)
- Colored output (zero-dependency ANSI color utilities)
- Multiple output formats (text, JSON, SARIF)
- Helpful vulnerability descriptions and remediation guidance

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
│                  # - Command parsing and routing
│                  # - File collection and scanning logic
│                  # - Auto-detects directory → analyzeProject(), file → analyze()
│                  # - scanProject(): wraps analyzeProject() for directory scans
│                  # - Progress indicators
│                  # - Exit code handling (0=clean, 1=vulns or cross-file paths, 2=error)
│                  # - Severity filtering (minimum or exact match, applied to taint paths too)
│
├── formatters.ts  # Output formatters
│                  # - formatResults(): colored text output with help text + cross-file section
│                  # - formatJSON(): structured JSON with cross_file_taint_paths + cross_file_calls
│                  # - formatSARIF(): SARIF 2.1.0 with relatedLocations for cross-file paths
│                  # - formatCrossFilePaths(): renders hop chain, source/sink, confidence, fix hint
│                  # - Vulnerability help text with descriptions and fixes
│
├── version.ts     # Version constant (updated via npm version)
│
├── index.ts       # Programmatic API exports
│                  # - Re-exports circle-ir types
│                  # - Allows use as library (not just CLI)
│
└── utils/
    ├── colors.ts  # Zero-dependency ANSI color utilities
    │              # - Bright colors for better terminal visibility
    │              # - Simple escape sequences
    │
    ├── spinner.ts # Zero-dependency spinner utility
    │              # - Unicode spinner frames
    │              # - Cursor management
    │              # - Success/fail/warn indicators
    │
    └── args.ts    # Zero-dependency argument parser
                   # - Parses CLI arguments
                   # - Help text generation
                   # - Version display
```

## Distribution Channels

### 1. npm Registry
- Package name: `cognium`
- Main: `dist/index.js` (programmatic API)
- Bin: `dist/cli.js` (CLI command)
- Types: `dist/index.d.ts`
- Requires Node.js >= 18.0.0
- Built with `bun run build`

### 2. GitHub Releases
- Standalone binaries for multiple platforms
- Built with `bun run build:standalone`
- No runtime dependencies
- Source code archives

## Circle-IR Integration

### Directory vs Single-File Auto-Detection

`cognium scan <path>` auto-detects whether `<path>` is a directory or file:

- **Directory** → calls `analyzeProject()` via `scanProject()` in `cli.ts`
  - All files in the directory are passed together for cross-file taint analysis
  - Returns `ProjectAnalysis` with `taint_paths: TaintPath[]` (cross-file) + per-file `files: FileAnalysis[]`
  - Cross-file taint paths appear as an additional section in all output formats (text, JSON, SARIF)

- **Single file** → calls `analyze()` per-file (original behavior, unchanged)

No new CLI flags or commands — behavior is purely automatic based on the input path.

### Key Types from circle-ir (v3.9.1)

```typescript
// Per-file result (from analyze())
CircleIR.findings?: SastFinding[]   // quality + reliability findings from 11-pass pipeline

// SastFinding interface (SARIF 2.1.0-aligned)
interface SastFinding {
  id: string;           // e.g. "dead-code-42"
  rule_id: string;      // e.g. "dead-code" | "missing-await" | "n-plus-one"
  category: PassCategory; // 'security' | 'reliability' | 'performance' | 'maintainability'
  severity: string;     // 'critical' | 'high' | 'medium' | 'low'
  level: SarifLevel;    // 'error' | 'warning' | 'note'
  message: string;
  file: string;
  line: number;
  cwe?: string;         // e.g. "CWE-561"
  fix?: string;         // instance-specific remediation hint
}

// Cross-file result (from analyzeProject())
ProjectAnalysis.taint_paths: TaintPath[]     // cross-file taint flows
ProjectAnalysis.cross_file_calls: CrossFileCall[]  // resolved inter-file method calls

// CrossFileData (cognium internal, passed through cli.ts → formatters.ts)
interface CrossFileData {
  taintPaths: TaintPath[];
  crossFileCalls: CrossFileCall[];
}
```

### Output Format Additions (cross-file)

- **Text**: `formatCrossFilePaths()` appended after per-file section
- **JSON**: `cross_file_taint_paths`, `cross_file_calls`, `summary.crossFileTaintPaths` added
- **SARIF**: cross-file rules (`cross-file-{sink_type}`) + results with `relatedLocations` pointing to source file

### `SINK_SEVERITY` Duplication

`cli.ts` and `formatters.ts` each maintain their own `SINK_SEVERITY: Record<SinkType, string>` map. This is intentional — `cli.ts` doesn't export it and the module boundary is clean.

---

## Key Dependencies

**Runtime**:
- `circle-ir@^3.11.0`: Core SAST engine — 36-pass taint + quality analysis pipeline, 24 software quality metrics

**Development**:
- `typescript@^6.0.2`: Type checking only (not used for builds)
- `@types/node@^25.5.0`: Node.js types
- `bun-types@^1.3.11`: Bun runtime types

**Zero Dependencies for UI/UX**:
- All CLI features (colors, spinners, argument parsing) use custom zero-dependency utilities
- Located in `src/utils/`: `colors.ts`, `spinner.ts`, `args.ts`
- Reduces attack surface and bundle size
- No external dependencies can break the CLI

## Documentation

### README.md (User-Facing)
Comprehensive end-user documentation including:
- Installation instructions (npm, standalone binary)
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
   - Publish to npm with `npm publish`

## Code Style Notes

- Use `async/await` for asynchronous operations
- Prefer functional array methods (map, filter, reduce)
- Error handling: try/catch with appropriate exit codes
- Use zero-dependency color utilities from `src/utils/colors.ts` for all colored output
- Use zero-dependency spinner from `src/utils/spinner.ts` for long-running operations
- File paths: use Node.js path module for cross-platform compatibility
- Avoid process.exit() except in CLI entry point
