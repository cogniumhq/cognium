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

# Enable AI verification (requires API key)
cognium scan ./src --ai
```

## Commands

### `cognium scan <path>`

Scan files or directories for security vulnerabilities.

```bash
cognium scan <path> [options]

Options:
  -l, --language <lang>  Force language (java|javascript|typescript|python|rust)
  -f, --format <format>  Output format (text|json|sarif) [default: text]
  --ai                   Enable AI-powered verification
  --threads <n>          Parallel analysis threads [default: 4]
  --severity <level>     Minimum severity (low|medium|high|critical)
  -o, --output <file>    Write results to file
  -q, --quiet            Suppress progress output
  -v, --verbose          Show detailed output
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

## Detected Vulnerabilities

| Type | CWE | Description |
|------|-----|-------------|
| SQL Injection | CWE-89 | User input in SQL queries |
| Command Injection | CWE-78 | User input in system commands |
| Cross-Site Scripting (XSS) | CWE-79 | User input in HTML output |
| Path Traversal | CWE-22 | User input in file paths |
| LDAP Injection | CWE-90 | User input in LDAP queries |
| XPath Injection | CWE-643 | User input in XPath queries |
| Deserialization | CWE-502 | Untrusted deserialization |
| SSRF | CWE-918 | Server-side request forgery |
| Code Injection | CWE-94 | Dynamic code execution |
| XXE | CWE-611 | XML external entity injection |

## Supported Languages

| Language | Extensions | Frameworks |
|----------|------------|------------|
| Java | `.java` | Spring, JAX-RS, Servlet |
| JavaScript | `.js`, `.mjs` | Express, Fastify, Node.js |
| TypeScript | `.ts`, `.tsx` | Express, Fastify, Node.js |
| Python | `.py` | Flask, Django, FastAPI |
| Rust | `.rs` | Actix-web, Rocket, Axum |

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

## AI Verification

Enable AI-powered verification to reduce false positives:

```bash
# Set your API key
export COGNIUM_API_KEY=your-api-key

# Run with AI verification
cognium scan ./src --ai
```

AI verification analyzes each finding to confirm exploitability and provides detailed remediation guidance.

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
        run: cognium scan ./src --format sarif --output results.sarif
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
    - cognium scan ./src --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Benchmark Results

| Benchmark | Score | Details |
|-----------|-------|---------|
| OWASP Benchmark | +100% | 1415/1415 test cases |
| Juliet Test Suite | +100% | 156/156 test cases |
| SecuriBench Micro | 98.1% TPR | 6.7% FPR |
| CWE-Bench-Java | 65.5% | 509/777 real-world CVEs |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found |
| 2 | Error during analysis |

## Links

- [Documentation](https://docs.cognium.dev)
- [GitHub](https://github.com/cogniumhq/cognium)
- [Discord](https://discord.gg/cognium)
- [Twitter](https://twitter.com/cogniumdev)

## License

MIT
