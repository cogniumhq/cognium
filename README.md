# cognium

AI-powered static analysis CLI for detecting security vulnerabilities in your code.

## Installation

### npm (recommended)

```bash
npm install -g cognium
```

### Homebrew (macOS/Linux)

```bash
brew install cogniumhq/tap/cognium
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

# Exclude test files
cognium scan ./src --exclude-tests
```

## Commands

### `cognium scan <path>`

Scan files or directories for security vulnerabilities.

```bash
cognium scan <path> [options]

Options:
  -l, --language <lang>      Force language (java|javascript|typescript|python|rust)
  -f, --format <format>      Output format (text|json|sarif) [default: text]
  --threads <n>              Parallel analysis threads [default: 4]
  --severity <level>         Filter by severity:
                               - Single level: minimum severity (e.g., "high" shows high+critical)
                               - Multiple levels: exact match (e.g., "critical,high" shows only those)
                               - Valid levels: low, medium, high, critical
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
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found |
| 2 | Error during analysis |

Use exit codes in CI/CD to fail builds when vulnerabilities are detected:

```bash
# Fail build on any vulnerability
cognium scan ./src || exit 1

# Fail build only on critical/high
cognium scan ./src --severity high || exit 1

# Fail build only on critical
cognium scan ./src --severity critical || exit 1
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

## Benchmark Results

All scores below are for circle-ir static analysis (no LLM):

| Benchmark | Score | Details |
|-----------|-------|---------|
| OWASP Benchmark | +100% | TPR 100%, FPR 0% (1415 test cases) |
| Juliet Test Suite | +100% | 156/156 test cases, 9 CWEs |
| SecuriBench Micro | 97.7% TPR | 105/108 vulns detected, 6.7% FPR |
| CWE-Bench-Java | 42.5% | 51/120 real-world CVEs |

## Links

- [GitHub](https://github.com/cogniumhq/cognium)
- [circle-ir (Core Engine)](https://github.com/cogniumhq/circle-ir)
- [Website](https://cognium.dev)

## License

MIT
