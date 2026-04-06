# cognium

[![npm version](https://img.shields.io/npm/v/cognium.svg)](https://www.npmjs.com/package/cognium)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/cogniumhq/cognium/blob/main/LICENSE)
[![OWASP Benchmark](https://img.shields.io/badge/OWASP%20Benchmark-100%25%20TPR%2C%200%25%20FPR-brightgreen)](https://github.com/cogniumhq/cognium#benchmark-results)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-available-blue?logo=github)](https://github.com/marketplace/actions/cognium-security-scan)

Semantic static analysis engine for detecting security vulnerabilities via taint tracking.

## Installation

### npm (recommended)

```bash
npm install -g cognium
```

### Standalone binary

Download from [GitHub Releases](https://github.com/cogniumhq/cognium/releases).

**Note:** When using the standalone binary, place the `wasm/` directory in the same location as the binary.

## Quick Start

```bash
# Scan a single file
cognium scan src/app.java

# Scan a directory
cognium scan ./src

# Scan with specific language
cognium scan api.py --language python

# Output as JSON
cognium scan ./src --format json

# Show only critical vulnerabilities
cognium scan ./src --severity critical

# Security findings only (skip quality/reliability passes)
cognium scan ./src --category security

# Exclude specific CWEs (e.g. weak crypto noise)
cognium scan ./src --exclude-cwe CWE-327,CWE-330

# Exclude test files
cognium scan ./src --exclude-tests

# Software quality metrics
cognium metrics ./src
cognium metrics ./src --category complexity,coupling --format json
```

## Commands

### `cognium scan <path>`

Scan files or directories for security vulnerabilities.

```bash
cognium scan <path> [options]

Options:
  -l, --language <lang>      Force language (java|javascript|typescript|python|rust|bash)
  -f, --format <format>      Output format (text|json|sarif) [default: text]
  --threads <n>              Parallel analysis threads [default: 4]
  --severity <level>         Filter by severity:
                               - Single level: minimum severity (e.g., "high" shows high+critical)
                               - Multiple levels: exact match (e.g., "critical,high" shows only those)
                               - Valid levels: low, medium, high, critical
  --category <cats>          Filter by ISO 25010 category (comma-separated):
                               security, reliability, performance, maintainability, architecture
  --exclude-cwe <cwes>       Exclude specific CWEs (comma-separated, e.g. CWE-330,CWE-327)
  --exclude-tests            Exclude test files and directories
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress progress output
  -v, --verbose              Show detailed output
```

**Examples:**

```bash
# Scan entire project
cognium scan ./src

# Show only critical and high severity issues
cognium scan ./src --severity critical,high

# Exclude test files and show only critical issues
cognium scan ./src --exclude-tests --severity critical

# Security findings only (skip quality/reliability passes)
cognium scan ./src --category security

# Reliability + performance findings only
cognium scan ./src --category reliability,performance

# Exclude weak-crypto and weak-random findings
cognium scan ./src --exclude-cwe CWE-327,CWE-330

# Generate SARIF report for CI/CD
cognium scan ./src --format sarif --output results.sarif

# Scan with verbose output
cognium scan ./src -v

# Quiet mode (no progress, only results)
cognium scan ./src -q
```

### `cognium init`

Initialize a configuration file in your project.

```bash
cognium init
```

Creates a `cognium.config.json` with customizable rules.

### `cognium metrics <path>`

Report software quality metrics for files or directories.

```bash
cognium metrics <path> [options]

Options:
  -l, --language <lang>      Analyze only files for the given language
  -f, --format <format>      Output format (text|json) [default: text]
  --category <cats>          Filter metric categories (comma-separated):
                               complexity, size, coupling, inheritance,
                               cohesion, documentation, duplication
  --exclude-tests            Skip test files and directories
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress per-file progress output
```

**Examples:**

```bash
# Show all metrics for a directory
cognium metrics ./src

# Complexity and coupling metrics only
cognium metrics ./src --category complexity,coupling

# JSON output for tooling integration
cognium metrics ./src --format json --output metrics.json

# Java files only, skip tests
cognium metrics ./src --language java --exclude-tests
```

**Sample output:**

```
src/UserController.java
  Complexity
    cyclomatic_complexity : 8.2
    WMC                   : 41
    halstead_volume       : 3820.4

  Size
    LOC                   : 182
    NLOC                  : 156
    function_count        : 9

  Coupling
    CBO                   : 6
    RFC                   : 22

  Composite Scores
    maintainability_index : 68.4 / 100
    code_quality_index    : 71.2 / 100
    bug_hotspot_score     : 32.1 / 100
    refactoring_roi       : 45.0 / 100
```

Available metrics: `cyclomatic_complexity`, `WMC`, `halstead_volume`, `halstead_difficulty`, `halstead_effort`, `halstead_bugs`, `LOC`, `NLOC`, `comment_density`, `function_count`, `CBO`, `RFC`, `DIT`, `NOC`, `LCOM`, `doc_coverage`, `maintainability_index`, `code_quality_index`, `bug_hotspot_score`, `refactoring_roi`.

### `cognium version`

Display version information.

```bash
cognium version
```

## Output Format

Cognium provides helpful, actionable output for each vulnerability found:

```
/path/to/VulnerableApp.java
  [!!!] sql_injection (Critical) [CWE-89]
      Line 45: sql_injection vulnerability: tainted data flows from line 42 to line 45
      User input is used in SQL query without sanitization
      → Fix: Use PreparedStatement with parameterized queries instead of string concatenation
  [!!] xss (High) [CWE-79]
      Line 78: xss vulnerability: tainted data flows from line 76 to line 78
      User input is rendered in HTML without proper encoding
      → Fix: Use HTML encoding/escaping functions before rendering user input in web pages

Found 2 vulnerability(ies) in 1 file(s)
```

**Clean code = silent output:** When no vulnerabilities are found, cognium stays quiet (Unix philosophy: no news is good news).

Use `-v` flag to see all scanned files including clean ones.

## Detected Vulnerabilities

| Type | CWE | Severity | Description |
|------|-----|----------|-------------|
| SQL Injection | CWE-89 | Critical | User input in SQL queries |
| Command Injection | CWE-78 | Critical | User input in system commands |
| Deserialization | CWE-502 | Critical | Untrusted deserialization |
| XXE | CWE-611 | Critical | XML external entity injection |
| Cross-Site Scripting (XSS) | CWE-79 | High | User input in HTML output |
| Path Traversal | CWE-22 | High | User input in file paths |
| SSRF | CWE-918 | High | Server-side request forgery |
| LDAP Injection | CWE-90 | High | User input in LDAP queries |
| XPath Injection | CWE-643 | High | User input in XPath queries |
| NoSQL Injection | CWE-943 | High | User input in NoSQL queries |
| Code Injection | CWE-94 | Critical | Dynamic code execution |
| Open Redirect | CWE-601 | Medium | User controls redirect destination |
| Log Injection | CWE-117 | Medium | User input in logs |
| Trust Boundary | CWE-501 | Medium | Data crosses trust boundary |
| External Taint Escape | CWE-20 | Medium | External input reaches sensitive sink |
| Weak Random | CWE-330 | Low | Weak random number generator |
| Weak Hash | CWE-327 | Low | Weak hashing algorithm |
| Weak Crypto | CWE-327 | Low | Weak cryptographic algorithm |
| Insecure Cookie | CWE-614 | Low | Cookie without security flags |

## Code Quality Analysis

In addition to security vulnerabilities, `cognium scan` runs 17 code quality passes and reports findings in five ISO 25010 categories:

| Category | Rule IDs | Example Issues |
|----------|----------|----------------|
| **Reliability** | `null-deref`, `resource-leak`, `unchecked-return`, `dead-code`, `variable-shadowing`, `leaked-global`, `unused-variable`, `infinite-loop`, `double-close`, `use-after-close`, `unhandled-exception`, `broad-catch`, `swallowed-exception`, `missing-guard-dom`, `cleanup-verify` | Null pointer dereferences, unclosed streams, swallowed exceptions |
| **Performance** | `n-plus-one`, `redundant-loop-computation`, `unbounded-collection`, `serial-await`, `react-inline-jsx` | N+1 DB queries, unnecessary work inside loops |
| **Maintainability** | `missing-public-doc`, `todo-in-prod`, `stale-doc-ref` | Missing Javadoc/JSDoc, TODO comments in production code |
| **Architecture** | `circular-dependency`, `orphan-module`, `dependency-fan-out`, `deep-inheritance`, `missing-override`, `unused-interface-method` | Circular imports, overly deep class hierarchies |

Quality findings appear alongside security findings in text output with their category tag:

```
src/UserService.java
  [!!] sql_injection (Critical) [CWE-89]
      ...
  [!] null-deref [reliability] (High) [CWE-476]
      Line 34: Return value of findById() is dereferenced without a null check
      → Fix: Check for null before dereferencing or use Optional<T>
  [i] missing-public-doc [maintainability] (Low)
      Line 12: Public method processRequest() has no Javadoc

Found 1 security finding(s) in 1 file(s)
Also found 2 code quality finding(s) in 1 file(s)
```

**Exit codes:** The CLI exits `1` only when **security** findings are present (so CI pipelines gate on vulnerabilities without being blocked by documentation or style findings). Quality-only scans exit `0`.

Filter to security findings only: `cognium scan ./src --category security`

## Supported Languages

| Language | Extensions | Frameworks |
|----------|------------|------------|
| Java | `.java` | Spring, JAX-RS, Servlet |
| JavaScript | `.js`, `.mjs` | Express, Fastify, Node.js |
| TypeScript | `.ts`, `.tsx` | Express, Fastify, Node.js |
| Python | `.py` | Flask, Django, FastAPI |
| Rust | `.rs` | Actix-web, Rocket, Axum |
| Bash | `.sh`, `.bash` | Shell scripts |

## Configuration

Create `cognium.config.json` in your project root:

```json
{
  "include": ["src/**/*.java", "src/**/*.ts"],
  "exclude": ["**/test/**", "**/node_modules/**"],
  "severity": "medium",
  "rules": {
    "sql-injection": "error",
    "xss": "error",
    "command-injection": "error",
    "path-traversal": "warn"
  }
}
```

## Severity Filtering

Cognium supports flexible severity filtering to focus on what matters:

### Minimum Severity (Single Value)

Shows vulnerabilities at or above the specified level:

```bash
# Show only critical
cognium scan ./src --severity critical

# Show high and critical
cognium scan ./src --severity high

# Show medium, high, and critical
cognium scan ./src --severity medium
```

### Exact Severity Match (Comma-Separated)

Shows only the specified severity levels:

```bash
# Show only critical and high
cognium scan ./src --severity critical,high

# Show only medium
cognium scan ./src --severity medium

# Show low and medium
cognium scan ./src --severity low,medium
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install cognium
        run: npm install -g cognium
      - name: Run security scan
        run: cognium scan ./src --format sarif --output results.sarif --severity high
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: node:20
  script:
    - npm install -g cognium
    - cognium scan ./src --format json --output gl-sast-report.json --severity high
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Pre-commit Hook

Prevent commits with critical vulnerabilities:

```bash
#!/bin/sh
# .git/hooks/pre-commit

if ! cognium scan . --severity critical --quiet; then
  echo "❌ Commit blocked: Critical security vulnerabilities found"
  exit 1
fi
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No security findings (quality-only findings do not trigger exit 1) |
| 1 | One or more security vulnerabilities found |
| 2 | Error during analysis |

Use exit codes in CI/CD to fail builds when security vulnerabilities are detected:

```bash
# Fail build on any security finding
cognium scan ./src || exit 1

# Fail build only on critical/high security findings
cognium scan ./src --severity high || exit 1

# Fail build only on critical security findings
cognium scan ./src --severity critical || exit 1

# Never fail on quality-only issues (always exit 0 for docs/style findings)
cognium scan ./src --category reliability,performance,maintainability,architecture; echo "Quality scan done (exit $?)"
```

## Performance

Cognium is built for speed:

- **Parallel analysis**: Process multiple files concurrently (configurable with `--threads`)
- **Zero dependencies**: Only one runtime dependency (`circle-ir`)
- **Native performance**: Powered by tree-sitter WASM parsers
- **Lean binary**: ~58MB standalone binary includes all dependencies

## Architecture

- **CLI**: Lightweight wrapper with zero-dependency utilities
- **Core Engine**: [circle-ir](https://github.com/cogniumhq/circle-ir) - High-performance SAST library
- **Dependencies**: Only 1 runtime dependency (circle-ir)

## LLM Enhancement (Optional)

The core static analysis engine runs deterministically without any LLM. Optionally, you can enable LLM-based discovery modes for enhanced detection:

- **Discovery Mode**: LLM reads source code to locate vulnerable methods from scratch
- **Verification Mode**: Confirms whether static findings are actually exploitable
- **Semantic Extraction**: Extracts design intent for automated gap analysis

For details on LLM integration and benchmark improvements (42.5% → 78.3% on CWE-Bench with Claude Opus), visit [cognium.net](https://cognium.net).

## Benchmark Results

**All scores below are from the static analysis engine** — fully deterministic, no LLM required:

| Benchmark | Score | Details |
|-----------|-------|---------|
| OWASP Benchmark | +100% | TPR 100%, FPR 0% (1415 test cases) |
| Juliet Test Suite | +100% | 156/156 test cases, 9 CWEs |
| SecuriBench Micro | 97.7% TPR | 105/108 vulns detected, 6.7% FPR |
| CWE-Bench-Java | 42.5% | 51/120 real-world CVEs |

### Reproducing Benchmarks

The benchmark scores are verifiable and reproducible:

```bash
# Install cognium
npm install -g cognium

# Clone benchmark repositories
git clone https://github.com/OWASP-Benchmark/BenchmarkJava
git clone https://github.com/juliet-test-suite/juliet-test-suite-for-java
git clone https://github.com/CWE-Bench/cwe-bench-java

# Run scans
cognium scan BenchmarkJava/src --format json -o owasp-results.json
cognium scan juliet-test-suite-for-java --format json -o juliet-results.json
cognium scan cwe-bench-java --format json -o cwe-bench-results.json
```

For detailed benchmark methodology and comparison with other tools, see [cognium.dev](https://cognium.dev).

## Links

- [GitHub](https://github.com/cogniumhq/cognium)
- [circle-ir (Core Engine)](https://github.com/cogniumhq/circle-ir)
- [Website](https://cognium.dev)

## License

MIT
