#!/usr/bin/env node
/**
 * cognium CLI - AI-powered static analysis for security vulnerabilities
 */

import { readFileSync, existsSync, statSync, readdirSync } from 'fs';
import { join, extname, resolve, basename } from 'path';
import { initAnalyzer, analyze, type SinkType } from 'circle-ir';
import { formatResults, formatJSON, formatSARIF } from './formatters.js';
import { version } from './version.js';
import { parseArgs, showHelp, showVersion } from './utils/args.js';
import { spinner } from './utils/spinner.js';
import { colors } from './utils/colors.js';
import { createProgressReporter, formatProgressBar } from './utils/prograss_tarcker.js';

// Test file/directory patterns to exclude
const TEST_PATTERNS = [
  /[\/\\]test[\/\\]/i,
  /[\/\\]tests[\/\\]/i,
  /[\/\\]__tests__[\/\\]/i,
  /[\/\\]spec[\/\\]/i,
  /[\/\\]__mocks__[\/\\]/i,
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /Test\.java$/,
  /Tests\.java$/,
  /IT\.java$/,           // Integration tests
  /_test\.py$/,
  /_tests\.py$/,
  /test_.*\.py$/,
  /_test\.rs$/,
];

function isTestFile(filePath: string): boolean {
  return TEST_PATTERNS.some(pattern => pattern.test(filePath));
}

// Language detection by extension
const LANG_MAP: Record<string, string> = {
  '.java': 'java',
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.rs': 'rust',
  '.sh': 'bash',
  '.bash': 'bash',
};

interface ScanOptions {
  language?: string;
  format: 'text' | 'json' | 'sarif';
  threads: number;
  severity?: string;
  output?: string;
  quiet?: boolean;
  verbose?: boolean;
  excludeTests?: boolean;
  excludeCwe?: string;
}

interface ScanResult {
  file: string;
  vulnerabilities: Array<{
    type: string;
    severity: string;
    message: string;
    line: number;
    cwe?: string;
  }>;
  error?: string;
}

const SINK_SEVERITY: Record<SinkType, string> = {
  sql_injection: 'critical',
  nosql_injection: 'high',
  command_injection: 'critical',
  path_traversal: 'high',
  xss: 'high',
  xxe: 'critical',
  deserialization: 'critical',
  ldap_injection: 'high',
  xpath_injection: 'high',
  ssrf: 'high',
  open_redirect: 'medium',
  code_injection: 'critical',
  log_injection: 'medium',
  weak_random: 'low',
  weak_hash: 'low',
  weak_crypto: 'low',
  insecure_cookie: 'low',
  trust_boundary: 'medium',
  external_taint_escape: 'medium',
};

const SINK_CWE: Record<SinkType, string> = {
  sql_injection: 'CWE-89',
  nosql_injection: 'CWE-943',
  command_injection: 'CWE-78',
  path_traversal: 'CWE-22',
  xss: 'CWE-79',
  xxe: 'CWE-611',
  deserialization: 'CWE-502',
  ldap_injection: 'CWE-90',
  xpath_injection: 'CWE-643',
  ssrf: 'CWE-918',
  open_redirect: 'CWE-601',
  code_injection: 'CWE-94',
  log_injection: 'CWE-117',
  weak_random: 'CWE-330',
  weak_hash: 'CWE-327',
  weak_crypto: 'CWE-327',
  insecure_cookie: 'CWE-614',
  trust_boundary: 'CWE-501',
  external_taint_escape: 'CWE-20',
};

function detectLanguage(filePath: string): string | null {
  const ext = extname(filePath).toLowerCase();
  return LANG_MAP[ext] || null;
}

function collectFiles(targetPath: string, language?: string, excludeTests = false): string[] {
  const files: string[] = [];
  const stat = statSync(targetPath);

  if (stat.isFile()) {
    // Skip test files if excludeTests is enabled
    if (excludeTests && isTestFile(targetPath)) {
      return files;
    }
    const lang = language || detectLanguage(targetPath);
    if (lang) {
      files.push(targetPath);
    }
  } else if (stat.isDirectory()) {
    const entries = readdirSync(targetPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
      // Skip test directories if excludeTests is enabled
      if (excludeTests && /^(test|tests|__tests__|spec|__mocks__)$/i.test(entry.name)) continue;
      const fullPath = join(targetPath, entry.name);
      files.push(...collectFiles(fullPath, language, excludeTests));
    }
  }

  return files;
}

async function scanFile(filePath: string, language: string): Promise<ScanResult> {
  try {
    const code = readFileSync(filePath, 'utf-8');
    const result = await analyze(code, filePath, language as any);

    const vulnerabilities = (result.taint.flows || []).map(flow => ({
      type: flow.sink_type,
      severity: SINK_SEVERITY[flow.sink_type] ?? 'high',
      message: `${flow.sink_type} vulnerability: tainted data flows from line ${flow.source_line} to line ${flow.sink_line}`,
      line: flow.sink_line,
      cwe: SINK_CWE[flow.sink_type],
    }));

    return { file: filePath, vulnerabilities };
  } catch (error) {
    return {
      file: filePath,
      vulnerabilities: [],
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

async function runScan(targetPath: string, options: ScanOptions): Promise<void> {
  // When output is structured (JSON/SARIF) or written to a file, keep stdout clean:
  // show progress on stderr instead of stdout to avoid corrupting machine-readable output.
  const progressOnStderr = options.format !== 'text' || Boolean(options.output);

  const spin =
    options.quiet || progressOnStderr || !process.stdout.isTTY
      ? null
      : spinner('Initializing analyzer...').start();

  const reportProgress = createProgressReporter({ quiet: options.quiet, spinner: spin });

  try {
    // Initialize circle-ir with appropriate WASM paths
    // Detect if we're running as a standalone binary (compiled with bun --compile)
    // Note: `node dist/cli.js` is *not* standalone; it should load WASM from `node_modules/`.
    // Bun-compiled binaries embed code under `/$bunfs/` and need an external `wasm/` directory.
    const isStandalone = import.meta.url.includes('/$bunfs/');

    if (isStandalone) {
      // Standalone binary: look for wasm/ directory in multiple locations
      const { dirname, join } = await import('path');
      const binaryDir = dirname(process.execPath);
      const cwd = process.cwd();

      // Try multiple locations for wasm directory
      const wasmLocations = [
        join(binaryDir, 'wasm'),           // Next to binary
        join(cwd, 'wasm'),                 // Current directory
        join(binaryDir, '..', 'wasm'),     // Parent of binary directory
      ];

      let wasmDir: string | null = null;
      for (const location of wasmLocations) {
        if (existsSync(location) && existsSync(join(location, 'web-tree-sitter.wasm'))) {
          wasmDir = location;
          break;
        }
      }

      if (wasmDir) {
        await initAnalyzer({
          wasmPath: join(wasmDir, 'web-tree-sitter.wasm'),
          languagePaths: {
            bash: join(wasmDir, 'tree-sitter-bash.wasm'),
            java: join(wasmDir, 'tree-sitter-java.wasm'),
            javascript: join(wasmDir, 'tree-sitter-javascript.wasm'),
            // circle-ir currently uses the JavaScript parser for TypeScript
            typescript: join(wasmDir, 'tree-sitter-javascript.wasm'),
            python: join(wasmDir, 'tree-sitter-python.wasm'),
            rust: join(wasmDir, 'tree-sitter-rust.wasm'),
          }
        });
      } else {
        // WASM files not found
        if (spin) spin.fail('WASM files not found');
        console.error(colors.red('\nError: WASM files not found'));
        console.error('The cognium binary requires WASM files to be present in a "wasm/" directory.');
        console.error('\nExpected locations (searched in order):');
        for (const loc of wasmLocations) {
          console.error(`  - ${loc}`);
        }
        console.error('\nPlease ensure the wasm/ directory is located next to the binary or in your current directory.');
        console.error('Download from: https://github.com/cogniumhq/cognium/releases');
        process.exit(2);
      }
    } else {
      // Development mode: use node_modules
      const wasmBasePath = new URL('../node_modules/circle-ir/dist/wasm/', import.meta.url).pathname;
      await initAnalyzer({
        wasmPath: wasmBasePath + 'web-tree-sitter.wasm',
        languagePaths: {
          bash: wasmBasePath + 'tree-sitter-bash.wasm',
          java: wasmBasePath + 'tree-sitter-java.wasm',
          javascript: wasmBasePath + 'tree-sitter-javascript.wasm',
          // circle-ir currently uses the JavaScript parser for TypeScript
          typescript: wasmBasePath + 'tree-sitter-javascript.wasm',
          python: wasmBasePath + 'tree-sitter-python.wasm',
          rust: wasmBasePath + 'tree-sitter-rust.wasm',
        }
      });
    }

    reportProgress('Collecting files...');

    const absPath = resolve(targetPath);
    if (!existsSync(absPath)) {
      if (spin) spin.fail(`Path not found: ${absPath}`);
      process.exit(2);
    }

    const files = collectFiles(absPath, options.language, options.excludeTests);

    if (files.length === 0) {
      if (spin) spin.warn('No supported files found');
      return;
    }

    reportProgress(`Scanning ${files.length} file(s)...`);

    const results: ScanResult[] = [];
    let processed = 0;

    // Process files with concurrency
    const concurrency = options.threads;
    for (let i = 0; i < files.length; i += concurrency) {
      const batch = files.slice(i, i + concurrency);
      const batchResults = await Promise.all(
        batch.map(async (file) => {
          const lang = options.language || detectLanguage(file);
          if (!lang) return null;
          return scanFile(file, lang);
        })
      );

      for (const result of batchResults) {
        if (result) results.push(result);
      }

      processed += batch.length;
      const pct = Math.floor((processed / files.length) * 100);
      const bar = formatProgressBar(processed, files.length);
      const remaining = files.length - processed;
      const last = batch.length > 0 ? basename(batch[batch.length - 1]!) : '';
      reportProgress(
        `Scanning ${bar} ${processed}/${files.length} (${pct}%) - ${remaining} left${last ? ` • ${last}` : ''}`
      );
    }

    if (spin) {
      spin.succeed(`Scanned ${files.length} file(s)`);
    } else {
      reportProgress(`Scanned ${files.length} file(s)`, true);
    }

    // Filter by severity if specified
    const severityOrder = ['low', 'medium', 'high', 'critical'];

    if (options.severity) {
      // Check if multiple severities are specified (comma-separated)
      if (options.severity.includes(',')) {
        const allowedSeverities = options.severity.split(',').map(s => s.trim().toLowerCase());
        for (const result of results) {
          result.vulnerabilities = result.vulnerabilities.filter(v =>
            allowedSeverities.includes(v.severity.toLowerCase())
          );
        }
      } else {
        // Single severity: treat as minimum level
        const minSeverityIndex = severityOrder.indexOf(options.severity.toLowerCase());
        if (minSeverityIndex === -1) {
          throw new Error(`Invalid severity level: ${options.severity}. Must be one of: low, medium, high, critical`);
        }
        for (const result of results) {
          result.vulnerabilities = result.vulnerabilities.filter(v =>
            severityOrder.indexOf(v.severity) >= minSeverityIndex
          );
        }
      }
    }

    // Filter by excluded CWEs if specified
    if (options.excludeCwe) {
      const excludedCwes = options.excludeCwe.split(',').map(c => c.trim().toUpperCase());
      for (const result of results) {
        result.vulnerabilities = result.vulnerabilities.filter(v => {
          if (!v.cwe) return true; // Keep vulnerabilities without CWE
          const cweNumber = v.cwe.toUpperCase();
          return !excludedCwes.includes(cweNumber);
        });
      }
    }

    // Count total vulnerabilities
    const totalVulns = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    const errors = results.filter(r => r.error).length;

    // Only output if there are vulnerabilities, errors, or verbose/output file requested
    // Always output for JSON/SARIF formats (structured output expected)
    const shouldOutput = totalVulns > 0 || errors > 0 || options.verbose || options.output || options.format !== 'text';

    if (shouldOutput) {
      // Output results
      let output: string;
      switch (options.format) {
        case 'json':
          output = formatJSON(results);
          break;
        case 'sarif':
          output = formatSARIF(results);
          break;
        default:
          output = formatResults(results, options.verbose);
      }

      if (options.output) {
        const { writeFileSync } = await import('fs');
        writeFileSync(options.output, output);
        console.log(colors.green(`Results written to ${options.output}`));
      } else if (output.trim()) {
        console.log(output);
      }

      // Summary
      if (!options.quiet && options.format === 'text') {
        console.log();
        if (totalVulns > 0) {
          console.log(colors.red(`Found ${totalVulns} vulnerability(ies) in ${files.length} file(s)`));
        } else if (options.verbose) {
          console.log(colors.green(`No vulnerabilities found in ${files.length} file(s)`));
        }
        if (errors > 0) {
          console.log(colors.yellow(`${errors} file(s) had errors during analysis`));
        }
      }
    }

    // Exit code
    process.exit(totalVulns > 0 ? 1 : 0);

  } catch (error) {
    if (spin) spin.fail('Analysis failed');
    console.error(colors.red(error instanceof Error ? error.message : 'Unknown error'));
    process.exit(2);
  }
}

// Init command handler
async function handleInit(): Promise<void> {
  const configPath = 'cognium.config.json';
  if (existsSync(configPath)) {
    console.log(colors.yellow('Configuration file already exists'));
    return;
  }

  const config = {
    include: ['src/**/*.java', 'src/**/*.ts', 'src/**/*.py'],
    exclude: ['**/test/**', '**/node_modules/**', '**/dist/**'],
    severity: 'medium',
    rules: {
      'sql-injection': 'error',
      'command-injection': 'error',
      'xss': 'error',
      'path-traversal': 'error',
      'ssrf': 'warn',
      'deserialization': 'warn',
    },
  };

  const { writeFileSync } = await import('fs');
  writeFileSync(configPath, JSON.stringify(config, null, 2));
  console.log(colors.green(`Created ${configPath}`));
}

// Main entry point
async function main(): Promise<void> {
  const { command, args, options } = parseArgs(process.argv.slice(2));

  // Handle help flag
  if (options.help || options.h) {
    showHelp();
    return;
  }

  // Handle version command or flag
  if (command === 'version' || options.version || options.V) {
    showVersion(version);
    return;
  }

  // Handle init command
  if (command === 'init') {
    await handleInit();
    return;
  }

  // Handle scan command
  if (command === 'scan') {
    if (args.length === 0) {
      console.error(colors.red('Error: scan command requires a path argument'));
      console.log('\nUsage: cognium scan <path> [options]');
      process.exit(1);
    }

    const targetPath = args[0];
    const scanOptions: ScanOptions = {
      language: (options.language || options.l) as string | undefined,
      format: (options.format || options.f || 'text') as 'text' | 'json' | 'sarif',
      threads: parseInt((options.threads as string) || '4', 10),
      severity: (options.severity) as string | undefined,
      output: (options.output || options.o) as string | undefined,
      quiet: options.quiet === true || options.q === true,
      verbose: options.verbose === true || options.v === true,
      excludeTests: options['exclude-tests'] === true,
      excludeCwe: (options['exclude-cwe']) as string | undefined,
    };

    await runScan(targetPath, scanOptions);
    return;
  }

  // No command or unknown command
  if (!command) {
    showHelp();
  } else {
    console.error(colors.red(`Error: Unknown command '${command}'`));
    console.log('\nRun \'cognium --help\' for usage information');
    process.exit(1);
  }
}

// Run the CLI
main().catch((error) => {
  console.error(colors.red('Fatal error:'), error.message);
  process.exit(2);
});
