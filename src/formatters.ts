/**
 * Output formatters for CLI results
 */

import { colors } from './utils/colors.js';
import type { TaintPath, CrossFileCall, SinkType } from 'circle-ir';

interface Vulnerability {
  type: string;
  severity: string;
  message: string;
  line: number;
  cwe?: string;
  /** Instance-specific fix forwarded from SastFinding.fix; takes precedence over VULNERABILITY_HELP */
  fix?: string;
}

interface ScanResult {
  file: string;
  vulnerabilities: Vulnerability[];
  error?: string;
}

// Help text for each vulnerability type
const VULNERABILITY_HELP: Record<string, { description: string; fix: string }> = {
  sql_injection: {
    description: 'User input is used in SQL query without sanitization',
    fix: 'Use PreparedStatement with parameterized queries instead of string concatenation'
  },
  nosql_injection: {
    description: 'User input is used in NoSQL query without sanitization',
    fix: 'Use parameterized queries or properly escape user input before using in queries'
  },
  command_injection: {
    description: 'User input is used in system command without sanitization',
    fix: 'Avoid Runtime.exec() with user input. Use ProcessBuilder with argument arrays instead'
  },
  path_traversal: {
    description: 'User input is used in file path without validation',
    fix: 'Validate file paths against allowlist, use canonical paths, and check for ".." sequences'
  },
  xss: {
    description: 'User input is rendered in HTML without proper encoding',
    fix: 'Use HTML encoding/escaping functions before rendering user input in web pages'
  },
  xxe: {
    description: 'XML parser may process external entities from untrusted input',
    fix: 'Disable external entity processing in XML parsers (setFeature("external-general-entities", false))'
  },
  deserialization: {
    description: 'Untrusted data is deserialized which can lead to remote code execution',
    fix: 'Avoid deserializing untrusted data. Use safe formats like JSON instead of Java serialization'
  },
  ldap_injection: {
    description: 'User input is used in LDAP query without sanitization',
    fix: 'Escape LDAP special characters or use parameterized LDAP queries'
  },
  xpath_injection: {
    description: 'User input is used in XPath query without sanitization',
    fix: 'Use parameterized XPath queries or properly escape user input'
  },
  ssrf: {
    description: 'Server-Side Request Forgery: user controls URL in server-side request',
    fix: 'Validate URLs against allowlist of domains, block internal IPs, use URL parsing libraries'
  },
  open_redirect: {
    description: 'User input controls redirect destination which can be abused for phishing',
    fix: 'Validate redirect URLs against allowlist or use relative paths only'
  },
  code_injection: {
    description: 'User input is evaluated as code (eval, script execution, etc.)',
    fix: 'Never execute user input as code. Use safe alternatives like JSON parsing'
  },
  log_injection: {
    description: 'User input in logs can inject fake log entries or exploit log viewers',
    fix: 'Sanitize newlines and special characters from user input before logging'
  },
  weak_random: {
    description: 'Cryptographically weak random number generator used for security purposes',
    fix: 'Use SecureRandom instead of Random for security-sensitive operations'
  },
  weak_hash: {
    description: 'Weak hashing algorithm (MD5, SHA1) used for security purposes',
    fix: 'Use SHA-256 or stronger hashing algorithms for security-sensitive operations'
  },
  weak_crypto: {
    description: 'Weak cryptographic algorithm or configuration',
    fix: 'Use strong encryption algorithms (AES-256) and secure configurations'
  },
  insecure_cookie: {
    description: 'Cookie without Secure or HttpOnly flags exposes it to attacks',
    fix: 'Set Secure and HttpOnly flags on sensitive cookies'
  },
  trust_boundary: {
    description: 'Data crosses trust boundary without validation',
    fix: 'Validate and sanitize data when crossing trust boundaries'
  },
  external_taint_escape: {
    description: 'External input reaches a sensitive sink without proper validation',
    fix: 'Validate, sanitize, or escape external input before use in sensitive operations'
  },

  // Reliability & performance findings from analysis passes
  'dead-code': {
    description: 'Unreachable code block has no execution path from any entry point',
    fix: 'Remove the unreachable block or fix the control flow that precedes it'
  },
  'missing-await': {
    description: 'Promise-returning async function called without await — errors are silently discarded and execution continues without the result',
    fix: 'Add await before the call, or assign the Promise and handle rejection with .catch()'
  },
  'n-plus-one': {
    description: 'Database or HTTP call executes inside a loop — produces N round-trips instead of one batched operation',
    fix: 'Move the call outside the loop and batch using findMany(), executeIn(), or a bulk API'
  },

  // Maintainability findings
  'missing-public-doc': {
    description: 'Public API member has no JSDoc/Javadoc comment — hinders IDE tooling, code review, and onboarding',
    fix: 'Add a /** ... */ doc comment above the declaration describing purpose, params, and return value'
  },
  'todo-in-prod': {
    description: 'Deferred-work marker left in production code signals unresolved technical debt',
    fix: 'Resolve the issue and remove the marker, or open a tracked ticket and delete the comment'
  },

  // Reliability — Group 2 passes (v3.9.2)
  'null-deref': {
    description: 'Variable explicitly assigned null/None/undefined is dereferenced without a prior null check',
    fix: 'Add a null check before dereferencing: `if (x != null) { ... }` or use Optional/optional chaining'
  },
  'resource-leak': {
    description: 'Resource (file, socket, stream) is opened but not guaranteed to be closed on all exit paths',
    fix: 'Use try-with-resources (Java 7+): `try (FileInputStream fis = ...) { ... }`, or Python `with open(...) as f:`'
  },
  'unchecked-return': {
    description: 'Return value of a critical operation (delete, mkdir, tryLock) is silently discarded — failures go undetected',
    fix: 'Check the return value: `if (!file.delete()) { throw new IOException("failed to delete " + file); }`'
  },

  // Performance — Group 2 passes (v3.9.2)
  'sync-io-async': {
    description: 'Blocking I/O call inside an async function blocks the event loop and degrades throughput under load',
    fix: 'Replace *Sync calls with their async equivalents and await the result: `await fs.promises.readFile(...)`'
  },
  'string-concat-loop': {
    description: 'String concatenation with += inside a loop produces O(n²) allocations as strings are immutable',
    fix: 'Accumulate parts in an array and join() after the loop, or use StringBuilder (Java)'
  }
};

const SEVERITY_COLORS: Record<string, (text: string) => string> = {
  critical: colors.red,
  high: colors.red,
  medium: colors.yellow,
  low: colors.cyan,
};

const SEVERITY_ICONS: Record<string, string> = {
  critical: '!!!',
  high: '!!',
  medium: '!',
  low: 'i',
};

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

interface CrossFileData {
  taintPaths: TaintPath[];
  crossFileCalls: CrossFileCall[];
}

function formatCrossFilePaths(taintPaths: TaintPath[]): string {
  if (taintPaths.length === 0) return '';
  const lines: string[] = [];
  lines.push(colors.bold(`Cross-file taint paths (${taintPaths.length} found)`));
  lines.push('');

  for (const p of taintPaths) {
    const severity = SINK_SEVERITY[p.sink.type] ?? 'high';
    const colorFn = SEVERITY_COLORS[severity] || ((t: string) => t);
    const icon = SEVERITY_ICONS[severity] || '?';
    const cweTag = p.sink.cwe ? ` [${p.sink.cwe}]` : '';
    const severityUpper = severity.charAt(0).toUpperCase() + severity.slice(1);

    lines.push(`  ${colorFn(`[${icon}]`)} ${colorFn(p.sink.type)} (${severityUpper})${cweTag}`);

    // Hop chain: source → ... → sink
    const hopChain = p.hops.length > 0
      ? p.hops.map(h => `${h.file}:${h.line}`).join(' → ')
      : `${p.source.file}:${p.source.line} → ${p.sink.file}:${p.sink.line}`;
    lines.push(`      ${hopChain}`);
    lines.push(`      Source: ${p.source.type} at ${p.source.file}:${p.source.line}`);
    lines.push(`      Sink:   ${p.sink.type} at ${p.sink.file}:${p.sink.line}`);
    lines.push(`      Confidence: ${p.confidence.toFixed(2)}`);

    const help = VULNERABILITY_HELP[p.sink.type];
    if (help?.fix) {
      lines.push(colors.cyan(`      → Fix: ${help.fix}`));
    }
    lines.push('');
  }
  return lines.join('\n');
}

export function formatResults(results: ScanResult[], verbose?: boolean, crossFileData?: CrossFileData): string {
  const lines: string[] = [];

  for (const result of results) {
    if (result.error) {
      lines.push(colors.red(`[ERROR] ${result.file}: ${result.error}`));
      continue;
    }

    if (result.vulnerabilities.length === 0) {
      if (verbose) {
        lines.push(colors.green(`[OK] ${result.file}`));
      }
      continue;
    }

    lines.push(colors.bold(result.file));

    for (const vuln of result.vulnerabilities) {
      const colorFn = SEVERITY_COLORS[vuln.severity] || ((text: string) => text);
      const icon = SEVERITY_ICONS[vuln.severity] || '?';
      const cweTag = vuln.cwe ? ` [${vuln.cwe}]` : '';
      const severityUpper = vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1);

      // Main vulnerability line with severity, type, and CWE
      lines.push(
        `  ${colorFn(`[${icon}]`)} ${colorFn(vuln.type)} (${severityUpper})${cweTag}`
      );

      // Line number and taint flow message
      lines.push(`      Line ${vuln.line}: ${vuln.message}`);

      // Add help text for the vulnerability
      const help = VULNERABILITY_HELP[vuln.type];
      const fixText = vuln.fix ?? help?.fix;
      if (help) {
        lines.push(`      ${help.description}`);
      }
      if (fixText) {
        lines.push(colors.cyan(`      → Fix: ${fixText}`));
      }
    }

    lines.push('');
  }

  if (crossFileData?.taintPaths.length) {
    lines.push('');
    lines.push(formatCrossFilePaths(crossFileData.taintPaths));
  }

  return lines.join('\n');
}

export function formatJSON(results: ScanResult[], crossFileData?: CrossFileData): string {
  const output = {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    results: results.map(r => ({
      file: r.file,
      vulnerabilities: r.vulnerabilities,
      error: r.error,
    })),
    cross_file_taint_paths: crossFileData?.taintPaths ?? [],
    cross_file_calls: crossFileData?.crossFileCalls ?? [],
    summary: {
      filesScanned: results.length,
      filesWithVulnerabilities: results.filter(r => r.vulnerabilities.length > 0).length,
      totalVulnerabilities: results.reduce((sum, r) => sum + r.vulnerabilities.length, 0),
      crossFileTaintPaths: crossFileData?.taintPaths.length ?? 0,
      errors: results.filter(r => r.error).length,
    },
  };

  return JSON.stringify(output, null, 2);
}

export function formatSARIF(results: ScanResult[], crossFileData?: CrossFileData): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'cognium',
            version: '1.0.0',
            informationUri: 'https://cognium.dev',
            rules: generateRules(results, crossFileData),
          },
        },
        results: generateSarifResults(results, crossFileData),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function generateRules(results: ScanResult[], crossFileData?: CrossFileData): any[] {
  const ruleSet = new Map<string, any>();

  for (const result of results) {
    for (const vuln of result.vulnerabilities) {
      if (!ruleSet.has(vuln.type)) {
        ruleSet.set(vuln.type, {
          id: vuln.type.replace(/\s+/g, '-').toLowerCase(),
          name: vuln.type,
          shortDescription: { text: vuln.type },
          defaultConfiguration: {
            level: vuln.severity === 'critical' || vuln.severity === 'high' ? 'error' : 'warning',
          },
          properties: {
            'security-severity': vuln.severity === 'critical' ? '9.0' :
                                 vuln.severity === 'high' ? '7.0' :
                                 vuln.severity === 'medium' ? '5.0' : '3.0',
          },
        });
      }
    }
  }

  for (const p of (crossFileData?.taintPaths ?? [])) {
    const ruleId = `cross-file-${p.sink.type}`;
    if (!ruleSet.has(ruleId)) {
      const severity = SINK_SEVERITY[p.sink.type] ?? 'high';
      ruleSet.set(ruleId, {
        id: ruleId,
        name: `cross-file-${p.sink.type}`,
        shortDescription: { text: `Cross-file ${p.sink.type}` },
        defaultConfiguration: {
          level: severity === 'critical' || severity === 'high' ? 'error' : 'warning',
        },
        properties: {
          'security-severity': severity === 'critical' ? '9.0' :
                               severity === 'high' ? '7.0' :
                               severity === 'medium' ? '5.0' : '3.0',
        },
      });
    }
  }

  return Array.from(ruleSet.values());
}

function generateSarifResults(results: ScanResult[], crossFileData?: CrossFileData): any[] {
  const sarifResults: any[] = [];

  for (const result of results) {
    for (const vuln of result.vulnerabilities) {
      sarifResults.push({
        ruleId: vuln.type.replace(/\s+/g, '-').toLowerCase(),
        level: vuln.severity === 'critical' || vuln.severity === 'high' ? 'error' : 'warning',
        message: { text: vuln.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: result.file },
              region: { startLine: vuln.line },
            },
          },
        ],
        properties: {
          cwe: vuln.cwe,
          severity: vuln.severity,
          ...(vuln.fix ? { fix: vuln.fix } : {}),
        },
      });
    }
  }

  for (const p of (crossFileData?.taintPaths ?? [])) {
    const severity = SINK_SEVERITY[p.sink.type] ?? 'high';
    sarifResults.push({
      ruleId: `cross-file-${p.sink.type}`,
      level: severity === 'critical' || severity === 'high' ? 'error' : 'warning',
      message: {
        text: `Cross-file taint flow from ${p.source.file}:${p.source.line} to ${p.sink.file}:${p.sink.line}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: p.sink.file },
            region: { startLine: p.sink.line },
          },
        },
      ],
      relatedLocations: [
        {
          id: 0,
          message: { text: 'taint source' },
          physicalLocation: {
            artifactLocation: { uri: p.source.file },
            region: { startLine: p.source.line },
          },
        },
      ],
      properties: {
        cwe: p.sink.cwe,
        severity,
        confidence: p.confidence,
      },
    });
  }

  return sarifResults;
}
