/**
 * Output formatters for CLI results
 */

import { colors } from './utils/colors.js';
import { version } from './version.js';
import type { TaintPath, CrossFileCall, SinkType } from 'circle-ir';

// ─── Shared types (canonical definitions, imported by cli.ts) ────────────────

export interface Vulnerability {
  type: string;
  severity: string;
  message: string;
  line: number;
  cwe?: string;
  /** Instance-specific fix forwarded from SastFinding.fix; takes precedence over VULNERABILITY_HELP */
  fix?: string;
  /** ISO 25010 category: security | reliability | performance | maintainability | architecture */
  category: string;
}

export interface ScanResult {
  file: string;
  vulnerabilities: Vulnerability[];
  error?: string;
}

export interface CrossFileData {
  taintPaths: TaintPath[];
  crossFileCalls: CrossFileCall[];
}

export const SINK_SEVERITY: Record<SinkType, string> = {
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

export const SINK_CWE: Record<SinkType, string> = {
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
  weak_hash: 'CWE-328',    // Use of Weak Hash (MD5, SHA-1, etc.)
  weak_crypto: 'CWE-327',  // Use of Broken/Risky Cryptographic Algorithm
  insecure_cookie: 'CWE-614',
  trust_boundary: 'CWE-501',
  external_taint_escape: 'CWE-20',
};

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
  },

  // Reliability — Group 3 passes (v3.9.3)
  'variable-shadowing': {
    description: 'Inner scope declares a variable with the same name as an outer-scope variable or parameter, hiding the outer binding',
    fix: 'Rename the inner variable to avoid hiding the outer binding and make the intent explicit'
  },
  'leaked-global': {
    description: 'Assignment without let/const/var inside a function creates an accidental global property in non-strict mode JS',
    fix: 'Add let, const, or var before the first assignment to explicitly declare the variable'
  },
  'unused-variable': {
    description: 'A local variable is declared and assigned but its value is never read — the computation is dead',
    fix: 'Remove the assignment, use the value, or prefix the variable with _ if intentionally unused'
  },
  'dependency-fan-out': {
    description: 'This module imports 20 or more other modules, indicating high efferent coupling that makes it harder to test and modify independently',
    fix: 'Extract related logic into smaller focused modules, apply the Interface Segregation Principle, or introduce a facade layer to hide dependencies'
  },
  'stale-doc-ref': {
    description: 'A doc comment references a class or symbol (via {@link} or @see) that cannot be found in the file\'s type declarations or imports',
    fix: 'Update the reference to point to the correct current symbol, add a missing import, or remove the stale reference entirely'
  },
  'circular-dependency': {
    description: 'A cycle exists in the module import graph — module A imports B which (directly or transitively) imports A — creating tight coupling and potential initialization-order bugs',
    fix: 'Extract the shared code into a third module that both A and B can import without creating a cycle, or invert a dependency using dependency injection'
  },
  'orphan-module': {
    description: 'This module has no incoming import edges and is not a recognized entry point (index, main, app, server, or mod) — it may be dead code or accidentally disconnected',
    fix: 'Either import the module where its functionality is needed, mark it as an entry point, or delete it if it is truly unused'
  },

  // Reliability — dominator + exception flow passes (v3.9.8 / v3.9.9)
  'infinite-loop': {
    description: 'A CFG cycle has no reachable exit edge — the loop can never terminate and will hang the process',
    fix: 'Add a guaranteed exit condition (break, return, or a counter-based bound) on every back-edge path'
  },
  'double-close': {
    description: 'A resource is closed twice — both close() calls are reachable on at least one execution path, which typically throws an exception',
    fix: 'Track whether the resource is already closed with a boolean flag, or use try-with-resources / context managers that prevent double-close'
  },
  'use-after-close': {
    description: 'A method is called on a resource after close() has been invoked — the resource is in an undefined state and calls will throw',
    fix: 'Move all resource usage before the close() call, or null-check and re-open the resource if reuse is intended'
  },
  'unhandled-exception': {
    description: 'A throw/raise statement has no enclosing try/catch in the same function — the exception will propagate unchecked to callers',
    fix: 'Wrap the throw in a try/catch block, declare the exception in the method signature (Java checked), or document that callers must handle it'
  },
  'broad-catch': {
    description: 'catch(Exception) or a bare except catches more exception types than intended, masking unexpected errors and making debugging harder',
    fix: 'Catch only the specific exception types you can handle; let unexpected exceptions propagate or log-and-rethrow'
  },
  'swallowed-exception': {
    description: 'A catch block neither re-throws, logs, nor returns an error value — the exception is silently discarded and the failure goes undetected',
    fix: 'At minimum log the exception; preferably re-throw, wrap in a runtime exception, or propagate as an error return value'
  },

  // Performance — v3.9.8 passes
  'redundant-loop-computation': {
    description: 'A loop-invariant expression (.length, .size(), Math.*) is recomputed on every iteration, performing unnecessary work',
    fix: 'Hoist the invariant computation into a variable before the loop: `const len = arr.length; for (let i = 0; i < len; i++)`'
  },
  'unbounded-collection': {
    description: 'A collection grows inside a loop with no size check or clear() call — can cause unbounded memory growth under high load',
    fix: 'Add a size cap (if (list.size() >= MAX) break), batch-flush the collection inside the loop, or switch to a bounded data structure'
  },
  'serial-await': {
    description: 'Sequential await calls with no data dependency between them run operations serially when they could run concurrently',
    fix: 'Replace sequential awaits with Promise.all([...]) to run independent async operations in parallel'
  },
  'react-inline-jsx': {
    description: 'An inline object literal or arrow function in JSX props creates a new reference on every render, defeating React.memo and causing unnecessary re-renders',
    fix: 'Move the object/function outside the component or wrap it with useMemo/useCallback to stabilize the reference'
  },

  // Architecture — v3.9.8 passes
  'deep-inheritance': {
    description: 'The inheritance chain exceeds 5 levels — deep hierarchies increase coupling, make behaviour hard to reason about, and complicate testing',
    fix: 'Prefer composition over inheritance; flatten the hierarchy by extracting shared behaviour into collaborating objects or mixins'
  },

  // Reliability — v3.11.0 passes
  'missing-guard-dom': {
    description: 'A sensitive operation (delete, drop, executeUpdate, grantRole, etc.) is not dominated by an authentication or authorization check on all CFG paths — unauthenticated callers may reach it',
    fix: 'Add an authentication/authorization check that dominates all paths to the sensitive operation; throw or redirect immediately on failure'
  },
  'cleanup-verify': {
    description: 'Resource cleanup (close(), disconnect(), release()) does not post-dominate the acquisition — on at least one execution path the resource is left open',
    fix: 'Use try-with-resources (Java) or a finally block to guarantee cleanup on all paths, including exception paths'
  },

  // Architecture — v3.11.0 passes
  'missing-override': {
    description: 'A method matches a parent class method signature but lacks the @Override annotation — the intent to override is unclear and typos in the method name go undetected',
    fix: 'Add @Override to make the intent explicit; the compiler will then catch signature mismatches'
  },
  'unused-interface-method': {
    description: 'An interface method is never called anywhere in this file — it may be dead API surface that inflates the public contract',
    fix: 'Remove the method if it is truly unused, or verify that it is called from other files; reduce interface surface to the minimum needed'
  },

  // Performance — v3.14.0 passes
  'blocking-main-thread': {
    description: 'A blocking call (crypto.pbkdf2Sync, readFileSync, etc.) runs inside a request handler — it stalls the event loop and degrades throughput for all concurrent requests',
    fix: 'Replace with the async variant (crypto.pbkdf2, fs.promises.readFile) and await the result'
  },
  'excessive-allocation': {
    description: 'A new object or collection is allocated on every iteration of a loop — causes GC pressure and O(n) heap growth',
    fix: 'Hoist the allocation before the loop and reuse/clear it on each iteration, or use an object pool'
  },
  'missing-stream': {
    description: 'An entire file or response body is read into memory at once (readFile, Buffer.concat) instead of being streamed — risks OOM on large inputs',
    fix: 'Use createReadStream/pipeline or process data in chunks instead of buffering the whole content'
  },

  // Architecture — v3.14.0 passes
  'god-class': {
    description: 'A class has excessively high WMC, low cohesion (LCOM), and/or high coupling (CBO) — it does too much and is hard to test, understand, and maintain',
    fix: 'Extract cohesive subsets of methods and fields into smaller focused classes using the Single Responsibility Principle'
  },

  // Maintainability — v3.14.0 passes
  'naming-convention': {
    description: 'A class, method, or variable name violates the language\'s standard naming convention (e.g., camelCase for JS methods, PascalCase for Java classes)',
    fix: 'Rename to follow the language\'s established convention — consistency aids readability and tool integration'
  },
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

      // Main finding line with severity, type, CWE, and category for non-security findings
      const categoryTag = vuln.category && vuln.category !== 'security' ? ` [${vuln.category}]` : '';
      lines.push(
        `  ${colorFn(`[${icon}]`)} ${colorFn(vuln.type)} (${severityUpper})${cweTag}${categoryTag}`
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
    version,
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
            version,
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
