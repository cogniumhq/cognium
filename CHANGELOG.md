# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.5] - 2026-04-07

### Changed

- **circle-ir upgraded 3.16.5 -> 3.16.7** — n-plus-one false positive fix:
  - `n-plus-one` no longer flags `Map.get()` / `Map.has()` calls on in-memory
    collections (e.g. `rpoIndex.get()` in graph algorithms). Added receiver
    exclusions for `*Index`, `*Map`, `*Lookup`, `*Dict`, `*By*` suffixes and
    bare-name collections like `idom`, `seen`, `visited`, `memo`, `cache`,
    `registry`.

[1.4.5]: https://github.com/cogniumhq/cognium/compare/v1.4.4...v1.4.5

## [1.4.3] - 2026-04-05

### Added

- **125-test suite** — 94 unit tests (formatters, args parsing, config loading, scan/metrics
  command logic) + 31 e2e tests (CLI subprocess via `Bun.spawn` covering text/json/sarif output,
  exit codes, severity/category/CWE filtering, directory mode, metrics, config integration)
- **`npm run dogfood`** — scans cognium's own `src/` directory with the project config; exits
  non-zero on findings, suitable for CI gating

### Changed

- **circle-ir upgraded 3.16.4 -> 3.16.5** — false positive fixes in 4 analysis passes:
  - `naming-convention`: skip synthetic names (`<module>`, `<anonymous>`)
  - `redundant-loop-computation`: don't flag `.length` in JS/TS (O(1) property access)
  - `unhandled-exception`: source-level try/catch detection fallback when CFG builder
    misses exception edges
  - `unbounded-collection`: skip bounded loops (`for...of`, `for...in`, `.forEach()`)
- **Re-enabled 4 passes** in `cognium.config.json` that were previously disabled due to
  false positives now fixed in circle-ir 3.16.5: `naming-convention`,
  `redundant-loop-computation`, `unhandled-exception`, `unbounded-collection`
- **Release script** now gracefully skips Homebrew formula update when `Formula/cognium.rb`
  is not present

[1.4.3]: https://github.com/cogniumhq/cognium/compare/v1.4.2...v1.4.3

## [1.4.0] - 2026-03-29

### Changed

- **circle-ir upgraded 3.14.0 → 3.15.0** — improved accuracy for three high-impact passes:
  - **`null-deref`** — now recognizes Java assertion guards (`assert x != null`), `Objects.requireNonNull()`, Guava `Preconditions.checkNotNull()`, Spring `Assert.notNull()`, and JUnit/TestNG `assertNotNull()` — reducing false positives when developers use assertion-based or utility-method null checks
  - **`n-plus-one`** — expanded medium-confidence receiver detection with suffix matching (`*Repository`, `*Repo`, `*Dao`, `*Service`, `*Client`, `*Store`, `*Cache`, `*Gateway`, `*Mapper`, etc.) — catches `userRepository.find()` and similar custom repository patterns that were previously missed
  - **`sink-filter` (XSS)** — added sanitizer detection (DOMPurify, sanitizeHtml, escapeHtml, validator.escape, Angular bypassSecurityTrust), string literal suppression (`.innerHTML = "static"` no longer flagged), and constant propagation integration — reducing false positives on safe DOM assignments

### Release notes

Version 1.4.0 brings improved pass accuracy from circle-ir 3.15.0, reducing both false positives and false negatives across null-deref, N+1 query, and XSS detection.

[1.4.0]: https://github.com/cogniumhq/cognium/compare/v1.3.2...v1.4.0

## [1.3.2] - 2026-03-28

### Added

- **6 new analysis passes** via circle-ir 3.13.0 — all surface findings during `cognium scan`:
  - **`blocking-main-thread`** (CWE-1050, warning) — synchronous crypto/hashing operations
    (`pbkdf2Sync`, `scryptSync`, `generateKeyPairSync`) and `*Sync` I/O calls inside HTTP request
    handlers (NestJS decorators, Express `(req, res)`, handler method names); JS/TS only
  - **`excessive-allocation`** (CWE-770, warning) — collection or object allocation inside loop
    bodies (`new Map()`, `new ArrayList<>()`, `list()`, `Vec::new()`); all languages except Bash
  - **`missing-stream`** (performance, note) — whole-file reads without streaming:
    `readFileSync`/`response.text()` (JS/TS), `Files.readAllBytes`/`BufferedReader` (Java),
    `f.read()` (Python); skips methods already using `.pipe()`/`createReadStream`/`for await`
  - **`god-class`** (CWE-1060, warning) — class exceeding 2 of 3 CK metric thresholds:
    WMC > 47, LCOM2 > 0.8, CBO > 14; Java/TS/Python
  - **`naming-convention`** (maintainability, note) — PascalCase classes, camelCase methods,
    UPPER_SNAKE_CASE constants (Java/TS), snake_case methods (Python/Bash/Rust); capped at 20
    findings per file

### Changed

- **circle-ir upgraded 3.12.0 → 3.14.0**

- **`missing-guard-dom` removed from the default scan pipeline** — this pass (added in v1.3.0)
  produced high-severity false positives on any Java codebase using framework-level authorization
  (Spring Security annotations, filter chains, servlet filters). Those guards are not visible as
  intra-method call nodes in the CFG, so every sensitive operation was reported as unguarded
  regardless of actual protection. The underlying analysis is being re-implemented in
  circle-ir-ai with LLM-identified auth guards. `cognium scan` output is unaffected for
  codebases not using that pass; users who were acting on `missing-guard-dom` findings should
  treat prior results with caution.

- **`feature-envy` removed from the default scan pipeline** — the call-count heuristic fired on
  legitimate delegation patterns (facades, controllers, service orchestrators). Requires design
  intent reasoning to distinguish from genuine feature envy; reserved for circle-ir-ai.

- **`serial-await` fix hint is now advisory** — the suggestion no longer prescribes
  `Promise.all()` directly; it reads "verify ordering requirements before parallelising" to
  prevent incorrect refactors where the operations have semantic ordering constraints.

[1.3.2]: https://github.com/cogniumhq/cognium/compare/v1.3.1...v1.3.2

## [1.3.1] - 2026-03-28

### Changed

- **circle-ir upgraded 3.11.0 → 3.12.0** — internal improvements to Java receiver-type
  resolution and test coverage:
  - `JavaPlugin.getReceiverType()` now resolves identifier receivers by walking the parse tree
    once and caching the result (`WeakMap<Tree, Map<string, string>>`). Generic types are stripped
    (`List<String>` → `List`). This improves polymorphic sink matching for Java code that
    declares a variable with a concrete type and later calls methods on it (e.g.
    `PreparedStatement ps = …; ps.executeQuery(q)`).
  - No API changes; all existing cognium commands and output formats are unaffected.

[1.3.1]: https://github.com/cogniumhq/cognium/compare/v1.3.0...v1.3.1

## [1.3.0] - 2026-03-28

### Added

- **Phase 4 analysis passes** via circle-ir 3.11.0 — four new passes now surface findings during
  `cognium scan`:
  - **`missing-guard-dom`** (CWE-285, error) — sensitive operations (delete, drop, executeUpdate,
    grantRole, etc.) not dominated by an authentication/authorization check on all CFG paths (Java)
  - **`cleanup-verify`** (CWE-772, warning) — resource cleanup does not post-dominate acquisition;
    resource is left open on at least one CFG path (Java, Python, JS/TS)
  - **`missing-override`** (warning) — method matches a parent class signature without `@Override`
    annotation; typos in method names go undetected at compile time (Java)
  - **`unused-interface-method`** (note) — interface method never called in this file; potential
    dead API surface (Java, TypeScript)
- **Rich help text for 15 additional passes** — `formatResults` now displays descriptions and
  fix hints for all passes introduced since v1.2.3:
  `infinite-loop`, `double-close`, `use-after-close`, `unhandled-exception`, `broad-catch`,
  `swallowed-exception`, `redundant-loop-computation`, `unbounded-collection`, `serial-await`,
  `react-inline-jsx`, `deep-inheritance`, `missing-guard-dom`, `cleanup-verify`,
  `missing-override`, `unused-interface-method`
- **TypeHierarchy wired into taint matching** (circle-ir 3.11.0) — `PreparedStatement.executeQuery()`
  now correctly matches `Statement`-level sink configs; reduces false negatives in polymorphic
  call chains

### Changed

- **circle-ir upgraded 3.9.8 → 3.11.0** — picks up all reliability, performance, and architecture
  passes from v3.9.9 through v3.11.0, plus OWASP command injection fixes from v3.9.10/v3.10.0
- **TypeScript upgraded 5.7 → 6.0.2** — uses latest type-checker; all strict checks remain clean
- **`@types/node` upgraded 22 → 25**, **`bun-types` upgraded 1.2 → 1.3**

[1.3.0]: https://github.com/cogniumhq/cognium/compare/v1.2.3...v1.3.0

## [1.2.3] - 2026-03-26

### Added

- **`cognium metrics <path>` command** — new subcommand that reports software quality metrics for
  files or directories. Supports all languages supported by `scan`. Metrics include cyclomatic
  complexity, Halstead suite, WMC, LOC/NLOC, comment density, CBO, RFC, DIT, NOC, LCOM, doc
  coverage, and four composite scores (maintainability index, code quality index, bug hotspot
  score, refactoring ROI).
  - `--format text|json` — human-readable grouped output (default) or machine-readable JSON
  - `--category <cats>` — filter to specific metric categories (`complexity`, `size`, `coupling`,
    `inheritance`, `cohesion`, `documentation`, `duplication`); comma-separated
  - `--language <lang>` — analyze only files for the given language
  - `--exclude-tests` — skip test files and directories
  - `-o, --output <file>` — write results to a file instead of stdout
  - `-q, --quiet` — suppress per-file progress output
- **Updated help text** (`cognium --help`) — METRICS section added with all options and examples

[1.2.3]: https://github.com/cogniumhq/cognium/compare/v1.2.2...v1.2.3

## [1.2.2] - 2026-03-26

### Fixed

- **`--language` filter now correctly filters files by extension** — previously `--language typescript`
  collected all supported file types (Java, Python, etc.) because the language flag was used as a
  hint rather than a filter. Now only files matching the requested language extension are collected.
- **Standalone binary detection simplified** — removed the `|| !import.meta.url.includes('node_modules')`
  condition from `isStandalone` that could incorrectly activate standalone WASM search when running
  `node dist/cli.js` in environments where the path doesn't include `node_modules`.
- **Spinner no longer emits control characters in CI** — spinner is now disabled when stdout is not a
  TTY (piped output, CI environments), preventing garbled escape sequences in logs.
- **Per-file progress in spinner** — spinner now shows the current file being scanned and a
  `(N/total)` counter, giving better feedback on large codebases.
- **Async file I/O in file collection** — `collectFiles()` now uses non-blocking `fs/promises`
  (`stat`, `readdir`) instead of synchronous `statSync`/`readdirSync`.

[1.2.2]: https://github.com/cogniumhq/cognium/compare/v1.2.1...v1.2.2

## [1.2.1] - 2026-03-26

### Fixed

- **Zero false positives on TypeScript/library code** — circle-ir upgraded to 3.9.7, which
  eliminates all remaining false positives when scanning TypeScript projects:
  1,542 cross-file `sql_injection`, 8 cross-file `log_injection`, and 4 `external_taint_escape`.
  Root causes: a `matchesSourcePattern` bug that allowed bare `get()` calls to match all
  class-qualified source patterns (Map/HashMap/Properties/Request), and `interprocedural_param`
  sources leaking into cross-file and Scenario-B analyses where they don't belong.
  See [circle-ir CHANGELOG](https://github.com/cogniumhq/circle-ir/blob/main/CHANGELOG.md) for details.

[1.2.1]: https://github.com/cogniumhq/cognium/compare/v1.2.0...v1.2.1

## [1.2.0] - 2026-03-26

### Added

- **`--category` filter** — filter findings by ISO 25010 category. Valid values (comma-separated): `security`, `reliability`, `performance`, `maintainability`, `architecture`. Examples: `--category security` (security findings only), `--category reliability,performance` (both categories). Cross-file taint paths (always `security`) are automatically excluded when `security` is not in the requested categories.

- **Category tags in text output** — non-security findings now show their category in brackets (e.g. `[maintainability]`, `[reliability]`) next to the finding type, making it easy to distinguish code quality issues from security vulnerabilities at a glance.

- **Category-aware summary** — the end-of-scan summary now reports security and code quality findings separately:
  - `Found N security finding(s) in M file(s)` (red)
  - `Found/Also found N code quality finding(s) in M file(s)` (yellow)

### Changed

- **Exit code semantics** — the CLI now exits with code `1` only when security findings are present, and exits `0` for quality-only scans. This allows CI pipelines to gate on security vulnerabilities without being blocked by documentation or style findings.

- **circle-ir upgraded** from 3.9.5 → 3.9.6, which eliminates false positives in `variable-shadowing`, `leaked-global`, and `external_taint_escape` passes (see [circle-ir CHANGELOG](https://github.com/cogniumhq/circle-ir/blob/main/CHANGELOG.md) for details).

[1.2.0]: https://github.com/cogniumhq/cognium/compare/v1.1.0...v1.2.0

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
