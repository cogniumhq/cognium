/**
 * Lightweight argument parser
 * Replaces commander dependency with zero-dependency alternative
 */

export interface ParsedArgs {
  command?: string;
  args: string[];
  options: Record<string, string | boolean>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const args: string[] = [];
  const options: Record<string, string | boolean> = {};
  let command: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg.startsWith('--')) {
      // Long option
      const key = arg.slice(2);
      if (key.includes('=')) {
        const [k, v] = key.split('=', 2);
        options[k] = v;
      } else {
        const nextArg = argv[i + 1];
        if (nextArg && !nextArg.startsWith('-')) {
          options[key] = nextArg;
          i++;
        } else {
          options[key] = true;
        }
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      // Short option
      const key = arg.slice(1);
      const nextArg = argv[i + 1];
      if (nextArg && !nextArg.startsWith('-')) {
        options[key] = nextArg;
        i++;
      } else {
        options[key] = true;
      }
    } else {
      // Positional argument
      if (!command) {
        command = arg;
      } else {
        args.push(arg);
      }
    }
  }

  return { command, args, options };
}

export function showHelp(): void {
  console.log(`
cognium - Semantic static analysis CLI for detecting security vulnerabilities

USAGE:
  cognium <command> [options]

COMMANDS:
  scan <path>          Scan files or directories for security vulnerabilities
  metrics <path>       Report software quality metrics for files or directories
  list-passes [cat]    List all analysis passes (optionally filter by category)
  init                 Initialize a configuration file in your project
  version              Display version information

SCAN OPTIONS:
  -l, --language <lang>      Scan only files for language (bash|java|javascript|typescript|python|rust)
  -f, --format <format>      Output format (text|json|sarif|owasp-benchmark) [default: text]
  --threads <n>              Parallel analysis threads [default: 4]
  --severity <level>         Filter by severity:
                               - Single level: minimum severity (e.g., "high" shows high+critical)
                               - Multiple levels: exact match (e.g., "critical,high" shows only those)
                               - Valid levels: low, medium, high, critical
  --category <cats>          Filter by finding category (comma-separated):
                               - Valid categories: security, reliability, performance,
                                 maintainability, architecture
  --exclude-cwe <cwes>       Exclude specific CWEs (comma-separated, e.g., "CWE-330,CWE-327")
  --disable-pass <passes>    Disable specific passes (comma-separated, e.g., "naming-convention,todo-in-prod")
  --exclude-tests            Exclude test files and directories
  --profile <file>           Load config from file [default: cognium.config.json]
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress progress output
  -v, --verbose              Show detailed output

METRICS OPTIONS:
  -l, --language <lang>      Analyze only files for language (bash|java|javascript|typescript|python|rust)
  -f, --format <format>      Output format (text|json) [default: text]
  --category <cats>          Filter by metric category (comma-separated):
                               - Valid categories: complexity, size, coupling,
                                 inheritance, cohesion, documentation, duplication
  --exclude-tests            Exclude test files and directories
  --profile <file>           Load config from file [default: cognium.config.json]
  -o, --output <file>        Write results to file
  -q, --quiet                Suppress progress output

EXAMPLES:
  cognium scan src/
  cognium scan app.java -f json -o results.json
  cognium scan . --exclude-tests --severity high
  cognium scan . --severity critical,high
  cognium scan . --category security
  cognium scan . --category reliability,performance
  cognium scan . --exclude-cwe CWE-330,CWE-327
  cognium scan . --disable-pass naming-convention,todo-in-prod
  cognium scan . --profile custom-config.json
  cognium scan BenchmarkJava/src/ -f owasp-benchmark -o cognium_results.csv
  cognium metrics src/
  cognium metrics src/ --category complexity
  cognium metrics src/ --format json --profile custom-config.json
  cognium list-passes
  cognium list-passes reliability
  cognium init

For more information, visit: https://cognium.dev
`);
}

export function showVersion(version: string): void {
  console.log(`cognium v${version}`);
  console.log(`Powered by Cognium Labs`);
}
