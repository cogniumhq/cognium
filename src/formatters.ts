/**
 * Output formatters for CLI results
 */

import { colors } from './utils/colors.js';

interface Vulnerability {
  type: string;
  severity: string;
  message: string;
  line: number;
  cwe?: string;
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

export function formatResults(results: ScanResult[], verbose?: boolean): string {
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
      if (help) {
        lines.push(`      ${help.description}`);
        lines.push(colors.cyan(`      → Fix: ${help.fix}`));
      }
    }

    lines.push('');
  }

  return lines.join('\n');
}

export function formatJSON(results: ScanResult[]): string {
  const output = {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    results: results.map(r => ({
      file: r.file,
      vulnerabilities: r.vulnerabilities,
      error: r.error,
    })),
    summary: {
      filesScanned: results.length,
      filesWithVulnerabilities: results.filter(r => r.vulnerabilities.length > 0).length,
      totalVulnerabilities: results.reduce((sum, r) => sum + r.vulnerabilities.length, 0),
      errors: results.filter(r => r.error).length,
    },
  };

  return JSON.stringify(output, null, 2);
}

export function formatSARIF(results: ScanResult[]): string {
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
            rules: generateRules(results),
          },
        },
        results: generateSarifResults(results),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function generateRules(results: ScanResult[]): any[] {
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

  return Array.from(ruleSet.values());
}

function generateSarifResults(results: ScanResult[]): any[] {
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
        },
      });
    }
  }

  return sarifResults;
}
