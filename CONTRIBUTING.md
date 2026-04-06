# Contributing to Cognium

Thank you for your interest in contributing! This guide covers how to get started.

## Getting Started

### Prerequisites

- [Bun](https://bun.sh) >= 1.0.0
- Node.js >= 18.0.0 (for npm distribution testing)

### Setup

```bash
git clone https://github.com/cogniumhq/cognium.git
cd cognium
bun install
```

### Development

```bash
bun run dev scan <path>     # Run CLI locally
bun run typecheck           # TypeScript validation
bun run build               # Build npm distribution (dist/)
bun run build:standalone    # Build self-contained binary
```

## How to Contribute

### Reporting Bugs

Open an issue at [github.com/cogniumhq/cognium/issues](https://github.com/cogniumhq/cognium/issues) with:

- Cognium version (`cognium version`)
- Operating system and Node.js/Bun version
- Minimal reproduction case (code snippet + command that triggers the issue)
- Actual vs. expected output

### Suggesting Features

Open a [feature request issue](https://github.com/cogniumhq/cognium/issues/new) describing:

- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes in `src/`
3. Run `bun run typecheck` — it must pass with zero errors
4. Test manually: `bun run dev scan <some-path>`
5. Update `CHANGELOG.md` under `[Unreleased]` describing your change
6. Open a PR with a clear description of what changed and why

#### PR checklist

- [ ] `bun run typecheck` passes
- [ ] No new `any` types introduced
- [ ] Output formats (text, JSON, SARIF) still work if formatters changed
- [ ] CHANGELOG.md updated
- [ ] README.md updated if user-facing behavior changed

## Project Structure

```
src/
├── cli.ts          # Main entry point — command parsing, scanning logic
├── formatters.ts   # Output formatters (text, JSON, SARIF)
├── index.ts        # Programmatic API exports
├── version.ts      # Version constant (kept in sync with package.json)
└── utils/
    ├── args.ts     # Zero-dependency argument parser
    ├── colors.ts   # Zero-dependency ANSI color utilities
    └── spinner.ts  # Zero-dependency progress spinner
```

Key constraint: **zero UI dependencies** — all CLI utilities (`colors.ts`, `spinner.ts`, `args.ts`) must remain dependency-free. Do not add npm packages for terminal output.

## Code Style

- Strict TypeScript — no `any`, no `// @ts-ignore`
- `async/await` over raw Promises
- Functional array methods (`map`, `filter`, `reduce`) over imperative loops where idiomatic
- `process.exit()` only in `cli.ts`, never in library code
- ANSI colors via `src/utils/colors.ts` — no third-party color libraries

## Commit Messages

Use conventional commits style:

```
feat: add --exclude-path flag to scan command
fix: correct severity filter when comma-separated values passed
docs: update CI/CD integration examples
chore: bump circle-ir to 3.16.3
```

## Versioning

Versions are managed via `npm version`. Do not edit `package.json` or `src/version.ts` manually:

```bash
npm version patch   # 1.4.2 → 1.4.3
npm version minor   # 1.4.2 → 1.5.0
npm version major   # 1.4.2 → 2.0.0
```

The `version` npm lifecycle script keeps `src/version.ts` in sync automatically.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
