#!/usr/bin/env node
/**
 * cognium CLI - AI-powered static analysis for security vulnerabilities
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { readFileSync, existsSync, statSync, readdirSync } from 'fs';
import { join, extname, resolve } from 'path';
import { initAnalyzer, analyze, type CircleIR } from 'circle-ir';
import { formatResults, formatJSON, formatSARIF } from './formatters.js';
import { version } from './version.js';

const program = new Command();

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
};

interface ScanOptions {
  language?: string;
  format: 'text' | 'json' | 'sarif';
  ai?: boolean;
  threads: number;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  output?: string;
  quiet?: boolean;
  verbose?: boolean;
  excludeTests?: boolean;
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
      severity: flow.severity || 'high',
      message: `${flow.sink_type} vulnerability: tainted data flows from line ${flow.source_line} to line ${flow.sink_line}`,
      line: flow.sink_line,
      cwe: flow.cwe,
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
  const spinner = options.quiet ? null : ora('Initializing analyzer...').start();

  try {
    // Initialize circle-ir
    await initAnalyzer();

    if (spinner) spinner.text = 'Collecting files...';

    const absPath = resolve(targetPath);
    if (!existsSync(absPath)) {
      if (spinner) spinner.fail(`Path not found: ${absPath}`);
      process.exit(2);
    }

    const files = collectFiles(absPath, options.language, options.excludeTests);

    if (files.length === 0) {
      if (spinner) spinner.warn('No supported files found');
      return;
    }

    if (spinner) spinner.text = `Scanning ${files.length} file(s)...`;

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
      if (spinner) spinner.text = `Scanning... (${processed}/${files.length})`;
    }

    if (spinner) spinner.succeed(`Scanned ${files.length} file(s)`);

    // Filter by severity if specified
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const minSeverityIndex = options.severity ? severityOrder.indexOf(options.severity) : 0;

    for (const result of results) {
      result.vulnerabilities = result.vulnerabilities.filter(v =>
        severityOrder.indexOf(v.severity) >= minSeverityIndex
      );
    }

    // Count total vulnerabilities
    const totalVulns = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    const errors = results.filter(r => r.error).length;

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
      console.log(chalk.green(`Results written to ${options.output}`));
    } else {
      console.log(output);
    }

    // Summary
    if (!options.quiet && options.format === 'text') {
      console.log();
      if (totalVulns > 0) {
        console.log(chalk.red(`Found ${totalVulns} vulnerability(ies) in ${files.length} file(s)`));
      } else {
        console.log(chalk.green(`No vulnerabilities found in ${files.length} file(s)`));
      }
      if (errors > 0) {
        console.log(chalk.yellow(`${errors} file(s) had errors during analysis`));
      }
    }

    // Exit code
    process.exit(totalVulns > 0 ? 1 : 0);

  } catch (error) {
    if (spinner) spinner.fail('Analysis failed');
    console.error(chalk.red(error instanceof Error ? error.message : 'Unknown error'));
    process.exit(2);
  }
}

// Main program
program
  .name('cognium')
  .description('AI-powered static analysis CLI for detecting security vulnerabilities')
  .version(version);

program
  .command('scan <path>')
  .description('Scan files or directories for security vulnerabilities')
  .option('-l, --language <lang>', 'Force language (java|javascript|typescript|python|rust)')
  .option('-f, --format <format>', 'Output format (text|json|sarif)', 'text')
  .option('--ai', 'Enable AI-powered verification')
  .option('--threads <n>', 'Parallel analysis threads', '4')
  .option('--severity <level>', 'Minimum severity (low|medium|high|critical)')
  .option('--exclude-tests', 'Exclude test files and directories')
  .option('-o, --output <file>', 'Write results to file')
  .option('-q, --quiet', 'Suppress progress output')
  .option('-v, --verbose', 'Show detailed output')
  .action(async (targetPath: string, options: any) => {
    await runScan(targetPath, {
      ...options,
      threads: parseInt(options.threads, 10),
      excludeTests: options.excludeTests,
    });
  });

program
  .command('init')
  .description('Initialize a configuration file in your project')
  .action(async () => {
    const configPath = 'cognium.config.json';
    if (existsSync(configPath)) {
      console.log(chalk.yellow('Configuration file already exists'));
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
    console.log(chalk.green(`Created ${configPath}`));
  });

program
  .command('version')
  .description('Display version information')
  .action(() => {
    console.log(`cognium v${version}`);
    console.log(`Powered by circle-ir`);
  });

// Parse and run
program.parse();
