#!/usr/bin/env node
/**
 * cognium CLI - AI-powered static analysis for security vulnerabilities
 */

import { readFileSync, existsSync, writeFileSync } from 'fs';
import { stat, readdir } from 'fs/promises';
import { join, extname, resolve, relative, dirname } from 'path';
import {
  initAnalyzer, analyze, analyzeProject,
  type SinkType, type SastFinding, type SupportedLanguage,
  type TaintPath, type CrossFileCall,
  type MetricValue, type FileMetrics,
  type PassOptions,
} from 'circle-ir';
import { formatResults, formatJSON, formatSARIF } from './formatters.js';
import { version } from './version.js';
import { parseArgs, showHelp, showVersion } from './utils/args.js';
import { spinner } from './utils/spinner.js';
import { colors } from './utils/colors.js';

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * Suppression entry to exclude specific findings.
 */
interface Suppression {
  /** Pass name to suppress (e.g., 'naming-convention', 'unbounded-collection') */
  pass: string;
  /** File path (relative or absolute) — if omitted, applies to all files */
  file?: string;
  /** Specific line number — if omitted, applies to all lines in the file */
  line?: number;
  /** Reason for suppression (for documentation) */
  reason?: string;
}

/**
 * cognium.config.json schema
 */
interface CogniumConfig {
  /** Config version for future compatibility */
  version?: string;
  /** Glob patterns to include */
  include?: string[];
  /** Glob patterns to exclude */
  exclude?: string[];
  /** Pass-specific options (passed to circle-ir) */
  passes?: {
    [passName: string]: boolean | {
      enabled?: boolean;
      threshold?: number;
      skipPatterns?: string[];
      [key: string]: unknown;
    };
  };
  /** Findings to suppress */
  suppressions?: Suppression[];
  /** Minimum severity filter */
  severity?: string;
  /** Category filter */
  categories?: string[];
}

/**
 * Load configuration from cognium.config.json or a custom profile path.
 */
function loadConfig(profilePath?: string): CogniumConfig | null {
  const configPath = profilePath || 'cognium.config.json';

  if (!existsSync(configPath)) {
    return null;
  }

  try {
    const content = readFileSync(configPath, 'utf-8');
    return JSON.parse(content) as CogniumConfig;
  } catch (err) {
    console.error(colors.yellow(`Warning: Failed to parse ${configPath}: ${err}`));
    return null;
  }
}

/**
 * Convert config passes to circle-ir PassOptions and disabledPasses.
 */
function convertConfigToPassOptions(config: CogniumConfig): {
  passOptions: PassOptions;
  disabledPasses: string[];
} {
  const passOptions: PassOptions = {};
  const disabledPasses: string[] = [];

  if (!config.passes) {
    return { passOptions, disabledPasses };
  }

  for (const [passName, passConfig] of Object.entries(config.passes)) {
    // Boolean false = disabled
    if (passConfig === false) {
      disabledPasses.push(passName);
      continue;
    }

    // Boolean true = enabled with defaults
    if (passConfig === true) {
      continue;
    }

    // Object config
    if (typeof passConfig === 'object') {
      if (passConfig.enabled === false) {
        disabledPasses.push(passName);
        continue;
      }

      // Map pass-specific options
      switch (passName) {
        case 'dependency-fan-out':
          if (passConfig.threshold !== undefined) {
            passOptions.dependencyFanOut = { threshold: passConfig.threshold };
          }
          break;
        case 'unbounded-collection':
          if (passConfig.skipPatterns !== undefined) {
            passOptions.unboundedCollection = { skipPatterns: passConfig.skipPatterns as string[] };
          }
          break;
        case 'naming-convention':
          if (passConfig.enforceIPrefix !== undefined) {
            passOptions.namingConvention = { enforceIPrefix: passConfig.enforceIPrefix as boolean };
          }
          break;
      }
    }
  }

  return { passOptions, disabledPasses };
}

/**
 * Apply suppressions to filter out findings.
 */
function applySuppressionsToResults(
  results: ScanResult[],
  suppressions: Suppression[],
  basePath: string,
): ScanResult[] {
  if (suppressions.length === 0) return results;

  return results.map(result => {
    const relativeFile = relative(basePath, result.file) || result.file;

    const filteredVulns = result.vulnerabilities.filter(vuln => {
      // Check each suppression
      for (const supp of suppressions) {
        // Pass must match
        if (supp.pass !== vuln.type) continue;

        // If file specified, it must match
        if (supp.file) {
          const suppFile = supp.file.replace(/^\.\//, ''); // normalize
          if (suppFile !== relativeFile && suppFile !== result.file) continue;
        }

        // If line specified, it must match
        if (supp.line !== undefined && supp.line !== vuln.line) continue;

        // All conditions matched — suppress this finding
        return false;
      }
      return true;
    });

    return { ...result, vulnerabilities: filteredVulns };
  });
}

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
  category?: string;
  output?: string;
  quiet?: boolean;
  verbose?: boolean;
  excludeTests?: boolean;
  excludeCwe?: string;
  /** Path to config file (default: cognium.config.json) */
  profile?: string;
}

interface MetricsOptions {
  format: 'text' | 'json';
  category?: string;   // comma-separated: complexity,size,coupling,inheritance,cohesion,documentation,duplication
  output?: string;
  quiet?: boolean;
  language?: string;
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
    /** Instance-specific fix suggestion forwarded from SastFinding.fix */
    fix?: string;
    /** ISO 25010 category: security | reliability | performance | maintainability | architecture */
    category: string;
  }>;
  error?: string;
}

interface CrossFileData {
  taintPaths: TaintPath[];
  crossFileCalls: CrossFileCall[];
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

function normalizeLanguage(language: string): string {
  return language.trim().toLowerCase();
}

function fileMatchesLanguage(filePath: string, language?: string): boolean {
  const detected = detectLanguage(filePath);
  if (!detected) return false;
  if (!language) return true;
  return detected === normalizeLanguage(language);
}

async function collectFiles(targetPath: string, language?: string, excludeTests = false): Promise<string[]> {
  const files: string[] = [];
  const pathStat = await stat(targetPath);

  if (pathStat.isFile()) {
    // Skip test files if excludeTests is enabled
    if (excludeTests && isTestFile(targetPath)) {
      return files;
    }
    if (fileMatchesLanguage(targetPath, language)) {
      files.push(targetPath);
    }
  } else if (pathStat.isDirectory()) {
    const entries = await readdir(targetPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
      // Skip test directories if excludeTests is enabled
      if (excludeTests && /^(test|tests|__tests__|spec|__mocks__)$/i.test(entry.name)) continue;
      const fullPath = join(targetPath, entry.name);
      files.push(...await collectFiles(fullPath, language, excludeTests));
    }
  }

  return files;
}

interface AnalyzeOptions {
  passOptions?: PassOptions;
  disabledPasses?: string[];
}

async function scanFile(filePath: string, language: string, analyzeOpts?: AnalyzeOptions): Promise<ScanResult> {
  try {
    const code = readFileSync(filePath, 'utf-8');
    const result = await analyze(code, filePath, language as any, {
      passOptions: analyzeOpts?.passOptions,
      disabledPasses: analyzeOpts?.disabledPasses,
    });

    // Security findings from taint flows
    const vulnerabilities: ScanResult['vulnerabilities'] = (result.taint.flows || []).map(flow => ({
      type: flow.sink_type,
      severity: SINK_SEVERITY[flow.sink_type] ?? 'high',
      message: `${flow.sink_type} vulnerability: tainted data flows from line ${flow.source_line} to line ${flow.sink_line}`,
      line: flow.sink_line,
      cwe: SINK_CWE[flow.sink_type],
      category: 'security',
    }));

    // Quality findings from analysis passes (dead-code, missing-await, n-plus-one, etc.)
    for (const finding of (result.findings ?? []) as SastFinding[]) {
      vulnerabilities.push({
        type: finding.rule_id,
        severity: finding.severity,
        message: finding.message,
        line: finding.line,
        cwe: finding.cwe,
        fix: finding.fix,
        category: finding.category ?? 'reliability',
      });
    }

    return { file: filePath, vulnerabilities };
  } catch (error) {
    return {
      file: filePath,
      vulnerabilities: [],
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

async function scanProject(
  files: string[],
  language: string | undefined,
  analyzeOpts?: AnalyzeOptions,
): Promise<{ results: ScanResult[]; crossFileData: CrossFileData }> {
  const filesWithCode = files.map(f => ({
    code: readFileSync(f, 'utf-8'),
    filePath: f,
    language: (language || detectLanguage(f)) as SupportedLanguage,
  }));

  const projectResult = await analyzeProject(filesWithCode, {
    passOptions: analyzeOpts?.passOptions,
    disabledPasses: analyzeOpts?.disabledPasses,
  });

  const results: ScanResult[] = projectResult.files.map(({ file, analysis }) => {
    const vulnerabilities: ScanResult['vulnerabilities'] = (analysis.taint.flows || []).map(flow => ({
      type: flow.sink_type,
      severity: SINK_SEVERITY[flow.sink_type] ?? 'high',
      message: `${flow.sink_type} vulnerability: tainted data flows from line ${flow.source_line} to line ${flow.sink_line}`,
      line: flow.sink_line,
      cwe: SINK_CWE[flow.sink_type],
      category: 'security',
    }));
    for (const finding of (analysis.findings ?? []) as SastFinding[]) {
      vulnerabilities.push({
        type: finding.rule_id,
        severity: finding.severity,
        message: finding.message,
        line: finding.line,
        cwe: finding.cwe,
        fix: finding.fix,
        category: finding.category ?? 'reliability',
      });
    }
    return { file, vulnerabilities };
  });

  return {
    results,
    crossFileData: {
      taintPaths: projectResult.taint_paths,
      crossFileCalls: projectResult.cross_file_calls,
    },
  };
}

async function runScan(targetPath: string, options: ScanOptions): Promise<void> {
  const spin = options.quiet ? null : spinner('Initializing analyzer...').start();

  // Load configuration from profile or default cognium.config.json
  const config = loadConfig(options.profile);
  let passOptions: PassOptions = {};
  let disabledPasses: string[] = [];
  let suppressions: Suppression[] = [];

  if (config) {
    const converted = convertConfigToPassOptions(config);
    passOptions = converted.passOptions;
    disabledPasses = converted.disabledPasses;
    suppressions = config.suppressions ?? [];

    if (!options.quiet) {
      console.log(colors.dim(`Loaded config: ${options.profile || 'cognium.config.json'}`));
    }
  }

  try {
    // Initialize circle-ir with appropriate WASM paths
    // Detect if we're running as a standalone binary (compiled with bun --compile)
    const isStandalone = import.meta.url.includes('/$bunfs/');

    if (isStandalone) {
      // Standalone binary or script bundle: look for wasm/ directory in multiple locations
      const { dirname, join } = await import('path');
      const binaryDir = dirname(process.execPath);
      const cwd = process.cwd();

      // For script bundles (dist/cli.js), import.meta.url is an absolute file:// URL
      // so we can resolve WASM relative to the script — this works from any working directory.
      let scriptDir: string | null = null;
      if (!import.meta.url.includes('/$bunfs/')) {
        try {
          const { fileURLToPath } = await import('url');
          scriptDir = dirname(fileURLToPath(import.meta.url));
        } catch { /* not a file:// URL */ }
      }

      // Try multiple locations for wasm directory
      const wasmLocations = [
        join(binaryDir, 'wasm'),           // Next to compiled binary
        join(cwd, 'wasm'),                 // Current working directory
        join(binaryDir, '..', 'wasm'),     // Parent of binary directory
        // Script-relative paths (work from any directory when running dist/cli.js)
        ...(scriptDir ? [
          join(scriptDir, 'wasm'),                                         // dist/wasm/
          join(scriptDir, '..', 'wasm'),                                   // project root wasm/
          join(scriptDir, '..', 'node_modules', 'circle-ir', 'dist', 'wasm'), // node_modules
        ] : []),
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
          typescript: wasmBasePath + 'tree-sitter-javascript.wasm',
          python: wasmBasePath + 'tree-sitter-python.wasm',
          rust: wasmBasePath + 'tree-sitter-rust.wasm',
        }
      });
    }

    if (spin) spin.text = 'Collecting files...';

    const absPath = resolve(targetPath);
    if (!existsSync(absPath)) {
      if (spin) spin.fail(`Path not found: ${absPath}`);
      process.exit(2);
    }

    const files = await collectFiles(absPath, options.language, options.excludeTests);

    if (files.length === 0) {
      if (spin) spin.warn('No supported files found');
      return;
    }

    let results: ScanResult[];
    let crossFileData: CrossFileData | undefined;

    // Prepare analyze options from config
    const analyzeOpts: AnalyzeOptions = { passOptions, disabledPasses };

    if ((await stat(absPath)).isDirectory()) {
      if (spin) spin.text = `Running project analysis on ${files.length} file(s)...`;
      const projectScan = await scanProject(files, options.language, analyzeOpts);
      results = projectScan.results;
      crossFileData = projectScan.crossFileData;
    } else {
      if (spin) spin.text = `Scanning ${files.length} file(s)...`;

      results = [];
      let processed = 0;

      const formatCurrentFile = (file: string): string => {
        const rel = relative(absPath, file) || file;
        // Keep spinner line readable for deeply nested paths.
        return rel.length > 80 ? `...${rel.slice(-77)}` : rel;
      };

      // Process files with concurrency
      const concurrency = options.threads;
      for (let i = 0; i < files.length; i += concurrency) {
        const batch = files.slice(i, i + concurrency);
        const batchResults = await Promise.all(
          batch.map(async (file) => {
            const lang = options.language || detectLanguage(file);
            if (!lang) return null;
            if (spin) spin.text = `Scanning ${formatCurrentFile(file)}... (${processed}/${files.length})`;
            return scanFile(file, lang, analyzeOpts);
          })
        );

        for (const result of batchResults) {
          if (result) results.push(result);
        }

        processed += batch.length;
        if (spin) spin.text = `Scanning... (${processed}/${files.length})`;
      }
    }

    if (spin) spin.succeed(`Scanned ${files.length} file(s)`);

    // Apply suppressions from config
    // Use cwd as base path since suppression files are relative to project root
    if (suppressions.length > 0) {
      const beforeCount = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
      results = applySuppressionsToResults(results, suppressions, process.cwd());
      const afterCount = results.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
      if (!options.quiet && beforeCount !== afterCount) {
        console.log(colors.dim(`Suppressed ${beforeCount - afterCount} finding(s) via config`));
      }
    }

    // Filter by severity if specified
    const severityOrder = ['low', 'medium', 'high', 'critical'];

    if (options.severity) {
      if (typeof options.severity !== 'string') {
        throw new Error('--severity requires a value. Valid levels: low, medium, high, critical');
      }
      // Check if multiple severities are specified (comma-separated)
      if (options.severity.includes(',')) {
        const allowedSeverities = options.severity.split(',').map(s => s.trim().toLowerCase());
        for (const result of results) {
          result.vulnerabilities = result.vulnerabilities.filter(v =>
            allowedSeverities.includes(v.severity.toLowerCase())
          );
        }
        if (crossFileData) {
          crossFileData.taintPaths = crossFileData.taintPaths.filter(p =>
            allowedSeverities.includes((SINK_SEVERITY[p.sink.type as SinkType] ?? 'high').toLowerCase())
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
        if (crossFileData) {
          crossFileData.taintPaths = crossFileData.taintPaths.filter(p => {
            const sev = SINK_SEVERITY[p.sink.type as SinkType] ?? 'high';
            return severityOrder.indexOf(sev) >= minSeverityIndex;
          });
        }
      }
    }

    // Filter by excluded CWEs if specified
    if (options.excludeCwe) {
      if (typeof options.excludeCwe !== 'string') {
        throw new Error('--exclude-cwe requires a value. Example: --exclude-cwe CWE-330,CWE-327');
      }
      const excludedCwes = options.excludeCwe.split(',').map(c => c.trim().toUpperCase());
      for (const result of results) {
        result.vulnerabilities = result.vulnerabilities.filter(v => {
          if (!v.cwe) return true; // Keep vulnerabilities without CWE
          const cweNumber = v.cwe.toUpperCase();
          return !excludedCwes.includes(cweNumber);
        });
      }
      if (crossFileData) {
        crossFileData.taintPaths = crossFileData.taintPaths.filter(p =>
          !excludedCwes.includes(p.sink.cwe.toUpperCase())
        );
      }
    }

    // Filter by category if specified
    if (options.category) {
      if (typeof options.category !== 'string') {
        throw new Error('--category requires a value. Valid categories: security, reliability, performance, maintainability, architecture');
      }
      const allowedCategories = options.category.split(',').map(c => c.trim().toLowerCase());
      for (const result of results) {
        result.vulnerabilities = result.vulnerabilities.filter(v =>
          allowedCategories.includes(v.category.toLowerCase())
        );
      }
      // Cross-file taint paths are always security findings; exclude them when security isn't requested
      if (crossFileData && !allowedCategories.includes('security')) {
        crossFileData.taintPaths = [];
      }
    }

    // Count findings by category
    const allVulns = results.reduce((acc: ScanResult['vulnerabilities'], r) => acc.concat(r.vulnerabilities), []);
    const totalVulns = allVulns.length;
    const securityCount = allVulns.filter(v => v.category === 'security').length + (crossFileData?.taintPaths.length ?? 0);
    const qualityCount = allVulns.filter(v => v.category !== 'security').length;
    const errors = results.filter(r => r.error).length;

    const crossFilePaths = crossFileData?.taintPaths.length ?? 0;

    // Only output if there are findings, errors, or verbose/output file requested
    // Always output for JSON/SARIF formats (structured output expected)
    const shouldOutput = totalVulns > 0 || crossFilePaths > 0 || errors > 0 || options.verbose || options.output || options.format !== 'text';

    if (shouldOutput) {
      // Output results
      let output: string;
      switch (options.format) {
        case 'json':
          output = formatJSON(results, crossFileData);
          break;
        case 'sarif':
          output = formatSARIF(results, crossFileData);
          break;
        default:
          output = formatResults(results, options.verbose, crossFileData);
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
        if (securityCount > 0) {
          console.log(colors.red(`Found ${securityCount} security finding(s) in ${files.length} file(s)`));
        }
        if (qualityCount > 0) {
          const label = securityCount > 0 ? 'Also found' : 'Found';
          console.log(colors.yellow(`${label} ${qualityCount} code quality finding(s) in ${files.length} file(s)`));
        }
        if (securityCount === 0 && qualityCount === 0 && options.verbose) {
          console.log(colors.green(`No findings in ${files.length} file(s)`));
        }
        if (errors > 0) {
          console.log(colors.yellow(`${errors} file(s) had errors during analysis`));
        }
      }
    }

    // Exit code: 1 for security findings, 0 for quality-only or clean
    process.exit(securityCount > 0 ? 1 : 0);

  } catch (error) {
    if (spin) spin.fail('Analysis failed');
    console.error(colors.red(error instanceof Error ? error.message : 'Unknown error'));
    process.exit(2);
  }
}

// ─── Metrics command ─────────────────────────────────────────────────────────

/**
 * Format a metric name for display: replace underscores with spaces, pad to 28 chars.
 */
function fmtMetricName(name: string): string {
  return name.replace(/_/g, ' ').padEnd(28);
}

/**
 * Format a metric value for display: right-align the numeric value and append unit.
 */
function fmtMetricValue(value: number, unit?: string): string {
  const num = Number.isInteger(value)
    ? value.toString()
    : value.toFixed(2);
  return unit ? `${num} ${unit}` : num;
}

async function runMetrics(targetPath: string, options: MetricsOptions): Promise<void> {
  const spin = options.quiet ? null : spinner('Initializing analyzer...').start();

  try {
    // Initialize WASM (same as runScan)
    const isStandalone = import.meta.url.includes('/$bunfs/');

    if (isStandalone) {
      const { dirname, join } = await import('path');
      const binaryDir = dirname(process.execPath);
      const cwd = process.cwd();

      let scriptDir: string | null = null;
      if (!import.meta.url.includes('/$bunfs/')) {
        try {
          const { fileURLToPath } = await import('url');
          scriptDir = dirname(fileURLToPath(import.meta.url));
        } catch { /* not a file:// URL */ }
      }

      const wasmLocations = [
        join(binaryDir, 'wasm'),
        join(cwd, 'wasm'),
        join(binaryDir, '..', 'wasm'),
        ...(scriptDir ? [
          join(scriptDir, 'wasm'),
          join(scriptDir, '..', 'wasm'),
          join(scriptDir, '..', 'node_modules', 'circle-ir', 'dist', 'wasm'),
        ] : []),
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
            typescript: join(wasmDir, 'tree-sitter-javascript.wasm'),
            python: join(wasmDir, 'tree-sitter-python.wasm'),
            rust: join(wasmDir, 'tree-sitter-rust.wasm'),
          }
        });
      } else {
        if (spin) spin.fail('WASM files not found');
        console.error(colors.red('\nError: WASM files not found'));
        process.exit(2);
      }
    } else {
      const wasmBasePath = new URL('../node_modules/circle-ir/dist/wasm/', import.meta.url).pathname;
      await initAnalyzer({
        wasmPath: wasmBasePath + 'web-tree-sitter.wasm',
        languagePaths: {
          bash: wasmBasePath + 'tree-sitter-bash.wasm',
          java: wasmBasePath + 'tree-sitter-java.wasm',
          javascript: wasmBasePath + 'tree-sitter-javascript.wasm',
          typescript: wasmBasePath + 'tree-sitter-javascript.wasm',
          python: wasmBasePath + 'tree-sitter-python.wasm',
          rust: wasmBasePath + 'tree-sitter-rust.wasm',
        }
      });
    }

    if (spin) spin.text = 'Collecting files...';

    const absPath = resolve(targetPath);
    if (!existsSync(absPath)) {
      if (spin) spin.fail(`Path not found: ${absPath}`);
      process.exit(2);
    }

    const files = await collectFiles(absPath, options.language, options.excludeTests);

    if (files.length === 0) {
      if (spin) spin.warn('No supported files found');
      return;
    }

    // Collect metrics per file
    const fileMetricsList: FileMetrics[] = [];
    let processed = 0;
    const totalFiles = files.length;

    for (const file of files) {
      const lang = options.language || detectLanguage(file);
      if (!lang) { processed++; continue; }

      if (spin) {
        const rel = relative(absPath, file) || file;
        const maxLen = 80;
        const label = rel.length > maxLen ? `...${rel.slice(-(maxLen - 3))}` : rel;
        spin.text = `Analyzing ${label}... (${processed}/${totalFiles})`;
      }

      try {
        const code = readFileSync(file, 'utf-8');
        const result = await analyze(code, file, lang as any);
        if (result.metrics) {
          fileMetricsList.push(result.metrics);
        }
      } catch {
        // Skip files that fail to parse
      }
      processed++;
    }

    if (spin) spin.succeed(`Analyzed ${files.length} file(s)`);

    // Filter by category if specified
    let allowedCategories: string[] | null = null;
    if (options.category) {
      allowedCategories = options.category.split(',').map(c => c.trim().toLowerCase());
    }

    const filtered = fileMetricsList.map(fm => ({
      file: fm.file,
      metrics: allowedCategories
        ? fm.metrics.filter(m => allowedCategories!.includes(m.category))
        : fm.metrics,
    })).filter(fm => fm.metrics.length > 0);

    const totalMetrics = filtered.reduce((sum, fm) => sum + fm.metrics.length, 0);

    // Format output
    let output: string;
    if (options.format === 'json') {
      output = JSON.stringify({
        version,
        timestamp: new Date().toISOString(),
        files: filtered.map(fm => ({
          file: fm.file,
          metrics: fm.metrics,
        })),
        summary: {
          files: filtered.length,
          total_metrics: totalMetrics,
        },
      }, null, 2);
    } else {
      // Text format: grouped by category
      const lines: string[] = [];
      for (const fm of filtered) {
        const rel = relative(absPath, fm.file) || fm.file;
        lines.push(rel);

        // Group metrics by category
        const byCategory = new Map<string, MetricValue[]>();
        for (const m of fm.metrics) {
          const cat = m.category;
          const list = byCategory.get(cat) ?? [];
          list.push(m);
          byCategory.set(cat, list);
        }

        for (const [cat, metrics] of byCategory.entries()) {
          lines.push(`  ${cat}`);
          for (const m of metrics) {
            lines.push(`    ${fmtMetricName(m.name)}${fmtMetricValue(m.value, m.unit)}`);
          }
        }
        lines.push('');
      }

      if (filtered.length === 0) {
        lines.push('No metrics available for the scanned files.');
      } else {
        lines.push(`Summary: ${totalMetrics} metric(s) across ${filtered.length} file(s)`);
      }

      output = lines.join('\n');
    }

    if (options.output) {
      const { writeFileSync } = await import('fs');
      writeFileSync(options.output, output);
      console.log(colors.green(`Results written to ${options.output}`));
    } else {
      console.log(output);
    }

    process.exit(0);

  } catch (error) {
    if (spin) spin.fail('Metrics analysis failed');
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

  // Handle metrics command
  if (command === 'metrics') {
    if (args.length === 0) {
      console.error(colors.red('Error: metrics command requires a path argument'));
      console.log('\nUsage: cognium metrics <path> [options]');
      process.exit(1);
    }

    const targetPath = args[0];
    const metricsOptions: MetricsOptions = {
      format: (options.format || options.f || 'text') as 'text' | 'json',
      category: (options.category) as string | undefined,
      output: (options.output || options.o) as string | undefined,
      quiet: options.quiet === true || options.q === true,
      language: (options.language || options.l) ? normalizeLanguage((options.language || options.l) as string) : undefined,
      excludeTests: options['exclude-tests'] === true,
    };

    await runMetrics(targetPath, metricsOptions);
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
      language: (options.language || options.l) ? normalizeLanguage((options.language || options.l) as string) : undefined,
      format: (options.format || options.f || 'text') as 'text' | 'json' | 'sarif',
      threads: parseInt((options.threads as string) || '4', 10),
      severity: (options.severity) as string | undefined,
      category: (options.category) as string | undefined,
      output: (options.output || options.o) as string | undefined,
      quiet: options.quiet === true || options.q === true,
      verbose: options.verbose === true || options.v === true,
      excludeTests: options['exclude-tests'] === true,
      excludeCwe: (options['exclude-cwe']) as string | undefined,
      profile: (options.profile || options.p) as string | undefined,
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
