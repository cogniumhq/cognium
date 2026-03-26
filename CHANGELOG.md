# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-03-25

### Added

- **17 new SAST detection passes** (via circle-ir 3.9.0–3.9.4):
  - **Reliability**: `null-deref` (CWE-476), `resource-leak` (CWE-772),
    `unchecked-return` (CWE-252), `dead-code` (CWE-561),
    `variable-shadowing` (CWE-1109), `leaked-global` (CWE-1109),
    `unused-variable` (CWE-561)
  - **Performance**: `missing-await` (CWE-252), `n-plus-one` (CWE-1049),
    `sync-io-async` (CWE-1050), `string-concat-loop` (CWE-1046)
  - **Architecture**: `circular-dependency` (CWE-1047), `orphan-module`,
    `dependency-fan-out`, `stale-doc-ref`
  - **Maintainability**: `missing-public-doc`, `todo-in-prod`
- **Software metrics engine** (via circle-ir 3.9.5): every scan now populates
  `ir.metrics` with 24 quality metrics — cyclomatic complexity (v(G)/WMC),
  Halstead suite, size (LOC/NLOC), CK coupling (CBO/RFC), inheritance (DIT/NOC),
  cohesion (LCOM), doc_coverage, and four composite scores
  (maintainability_index, code_quality_index, bug_hotspot_score, refactoring_roi).

### Changed

- **circle-ir upgraded** from 3.8.x → 3.9.5

[1.1.0]: https://github.com/cogniumhq/cognium/compare/v1.0.9...v1.1.0

## [1.0.9] - 2026-03-17

### Fixed

- **WASM Path Resolution**: Enhanced standalone binary to search for WASM files in multiple locations:
  - Next to the binary executable
  - Current working directory
  - Parent directory of binary
- **Better Error Messages**: Added detailed error message when WASM files cannot be found, showing all searched locations
- Fixes "ENOENT: no such file or directory, open 'wasm/tree-sitter-*.wasm'" errors when running binary from different directories

### Changed

- Version output now shows "Powered by Cognium Labs" instead of "Powered by circle-ir"

[1.0.9]: https://github.com/cogniumhq/cognium/compare/v1.0.8...v1.0.9

## [1.0.8] - 2026-03-17

### Added

- **Bash Support**: Added support for scanning Bash scripts (.sh, .bash files)
- **GitHub Actions Workflow**: Automated binary builds for macOS (arm64/x64) and Linux (x64) on release
- All WASM language parsers now included: bash, java, javascript, python, rust

### Changed

- Updated help text to include bash in supported languages

[1.0.8]: https://github.com/cogniumhq/cognium/compare/v1.0.7...v1.0.8

## [1.0.7] - 2026-03-17

### Fixed

- **WASM Path Resolution**: Fixed standalone binary WASM file loading by using `process.execPath` instead of `import.meta.url` to locate the binary directory
- Resolves "ENOENT: no such file or directory, open 'wasm/tree-sitter-*.wasm'" errors

[1.0.7]: https://github.com/cogniumhq/cognium/compare/v1.0.6...v1.0.7

## [1.0.6] - 2026-03-17

### Added

- **CWE Exclusion**: New `--exclude-cwe` option to filter out specific CWE types
  - Supports single CWE: `--exclude-cwe CWE-330`
  - Supports multiple CWEs: `--exclude-cwe CWE-330,CWE-327,CWE-20`
  - Can be combined with `--severity` filtering

### Changed

- Updated help text with `--exclude-cwe` examples

[1.0.6]: https://github.com/cogniumhq/cognium/compare/v1.0.5...v1.0.6

## [1.0.5] - 2026-02-18

### Changes

- circle-ir upgrade + --ai removal

[1.0.5]: https://github.com/cogniumhq/cognium/compare/v1.0.4...v1.0.5

## [1.0.4] - 2026-02-17

### Changes

- Patched
  * upgrade circle-ir to latest

[1.0.4]: https://github.com/cogniumhq/cognium/compare/v1.0.3...v1.0.4

## [1.0.0] - 2025-02-11

### Added

- **Initial Release**: AI-powered static analysis CLI
- **Multi-language Support**: Java, JavaScript, TypeScript, Python, Rust
- **Vulnerability Detection**: SQL Injection, XSS, Command Injection, Path Traversal, and more
- **Output Formats**: Text, JSON, SARIF for CI/CD integration
- **Configuration**: Project-level `cognium.config.json` support
- **Parallel Analysis**: Multi-threaded scanning for large codebases
- **Severity Filtering**: Filter results by severity level

### Technical

- Built with Bun for fast startup and standalone binary support
- Powered by circle-ir for accurate taint analysis
- SARIF output for GitHub/GitLab integration

[1.0.0]: https://github.com/cogniumhq/cognium/releases/tag/v1.0.0
