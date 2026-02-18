/**
 * Output formatters for CLI results
 */

import chalk from 'chalk';

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

const SEVERITY_COLORS: Record<string, (text: string) => string> = {
  critical: chalk.bgRed.white,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
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
      lines.push(chalk.red(`[ERROR] ${result.file}: ${result.error}`));
      continue;
    }

    if (result.vulnerabilities.length === 0) {
      if (verbose) {
        lines.push(chalk.green(`[OK] ${result.file}`));
      }
      continue;
    }

    lines.push(chalk.white.bold(result.file));

    for (const vuln of result.vulnerabilities) {
      const colorFn = SEVERITY_COLORS[vuln.severity] || chalk.white;
      const icon = SEVERITY_ICONS[vuln.severity] || '?';
      const cweTag = vuln.cwe ? chalk.gray(` [${vuln.cwe}]`) : '';

      lines.push(
        `  ${colorFn(`[${icon}]`)} Line ${vuln.line}: ${colorFn(vuln.type)}${cweTag}`
      );

      if (verbose) {
        lines.push(chalk.gray(`      ${vuln.message}`));
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
