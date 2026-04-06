import { describe, test, expect } from 'bun:test';
import { formatResults, formatJSON, formatSARIF, type ScanResult, type CrossFileData } from '../src/formatters.js';
import { version } from '../src/version.js';

function makeResult(file: string, vulns: ScanResult['vulnerabilities'], error?: string): ScanResult {
  return { file, vulnerabilities: vulns, error };
}

const sqlVuln = {
  type: 'sql_injection',
  severity: 'critical',
  message: 'sql_injection vulnerability: tainted data flows from line 5 to line 20',
  line: 20,
  cwe: 'CWE-89',
  category: 'security',
};

const deadCodeVuln = {
  type: 'dead-code',
  severity: 'low',
  message: 'Unreachable block',
  line: 42,
  cwe: 'CWE-561',
  category: 'reliability',
};

// ─── formatResults (text) ────────────────────────────────────────────────────

describe('formatResults', () => {
  test('shows file name and vulnerability', () => {
    const results = [makeResult('src/Foo.java', [sqlVuln])];
    const output = formatResults(results);
    expect(output).toContain('src/Foo.java');
    expect(output).toContain('sql_injection');
    expect(output).toContain('Line 20');
  });

  test('shows category tag for non-security findings', () => {
    const results = [makeResult('src/App.ts', [deadCodeVuln])];
    const output = formatResults(results);
    expect(output).toContain('[reliability]');
  });

  test('does not show category tag for security findings', () => {
    const results = [makeResult('src/Foo.java', [sqlVuln])];
    const output = formatResults(results);
    expect(output).not.toContain('[security]');
  });

  test('shows fix suggestion from VULNERABILITY_HELP', () => {
    const results = [makeResult('src/Foo.java', [sqlVuln])];
    const output = formatResults(results);
    expect(output).toContain('Fix:');
    expect(output).toContain('PreparedStatement');
  });

  test('prefers instance-specific fix over VULNERABILITY_HELP', () => {
    const withFix = { ...deadCodeVuln, fix: 'Remove the unreachable if-block' };
    const results = [makeResult('src/App.ts', [withFix])];
    const output = formatResults(results);
    expect(output).toContain('Remove the unreachable if-block');
  });

  test('shows [OK] for clean files in verbose mode', () => {
    const results = [makeResult('src/Clean.java', [])];
    const output = formatResults(results, true);
    expect(output).toContain('[OK]');
    expect(output).toContain('Clean.java');
  });

  test('hides clean files in non-verbose mode', () => {
    const results = [makeResult('src/Clean.java', [])];
    const output = formatResults(results, false);
    expect(output).not.toContain('Clean.java');
  });

  test('shows errors', () => {
    const results = [makeResult('src/Bad.java', [], 'Parse error')];
    const output = formatResults(results);
    expect(output).toContain('[ERROR]');
    expect(output).toContain('Parse error');
  });
});

// ─── formatJSON ──────────────────────────────────────────────────────────────

describe('formatJSON', () => {
  test('produces valid JSON', () => {
    const results = [makeResult('src/Foo.java', [sqlVuln])];
    const output = formatJSON(results);
    const parsed = JSON.parse(output);
    expect(parsed).toBeDefined();
  });

  test('includes version from package', () => {
    const results = [makeResult('src/Foo.java', [])];
    const parsed = JSON.parse(formatJSON(results));
    expect(parsed.version).toBe(version);
  });

  test('includes summary counts', () => {
    const results = [
      makeResult('src/A.java', [sqlVuln]),
      makeResult('src/B.java', []),
    ];
    const parsed = JSON.parse(formatJSON(results));
    expect(parsed.summary.filesScanned).toBe(2);
    expect(parsed.summary.filesWithVulnerabilities).toBe(1);
    expect(parsed.summary.totalVulnerabilities).toBe(1);
  });

  test('includes cross-file taint paths when provided', () => {
    const crossFileData: CrossFileData = {
      taintPaths: [{
        id: 'tp-1',
        source: { file: 'A.java', line: 5, type: 'http_param', cwe: '', code: '' },
        sink: { file: 'B.java', line: 20, type: 'sql_injection', cwe: 'CWE-89', code: '' },
        hops: [],
        sanitizers_in_path: [],
        path_exists: true,
        confidence: 0.95,
      }],
      crossFileCalls: [],
    };
    const results = [makeResult('A.java', [])];
    const parsed = JSON.parse(formatJSON(results, crossFileData));
    expect(parsed.cross_file_taint_paths).toHaveLength(1);
    expect(parsed.summary.crossFileTaintPaths).toBe(1);
  });
});

// ─── formatSARIF ─────────────────────────────────────────────────────────────

describe('formatSARIF', () => {
  test('produces valid SARIF 2.1.0', () => {
    const results = [makeResult('src/Foo.java', [sqlVuln])];
    const parsed = JSON.parse(formatSARIF(results));
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toContain('sarif-schema-2.1.0');
    expect(parsed.runs).toHaveLength(1);
  });

  test('uses actual cognium version', () => {
    const results = [makeResult('src/Foo.java', [])];
    const parsed = JSON.parse(formatSARIF(results));
    expect(parsed.runs[0].tool.driver.version).toBe(version);
  });

  test('maps severity to SARIF level', () => {
    const results = [makeResult('src/Foo.java', [sqlVuln, deadCodeVuln])];
    const parsed = JSON.parse(formatSARIF(results));
    const sarifResults = parsed.runs[0].results;
    const sqlResult = sarifResults.find((r: any) => r.ruleId === 'sql_injection');
    const deadResult = sarifResults.find((r: any) => r.ruleId === 'dead-code');
    expect(sqlResult.level).toBe('error');
    expect(deadResult.level).toBe('warning');
  });

  test('includes CWE in properties', () => {
    const results = [makeResult('src/Foo.java', [sqlVuln])];
    const parsed = JSON.parse(formatSARIF(results));
    expect(parsed.runs[0].results[0].properties.cwe).toBe('CWE-89');
  });

  test('generates unique rules', () => {
    const results = [
      makeResult('A.java', [sqlVuln]),
      makeResult('B.java', [sqlVuln]),
    ];
    const parsed = JSON.parse(formatSARIF(results));
    const rules = parsed.runs[0].tool.driver.rules;
    // Should have 1 unique rule, not 2
    expect(rules).toHaveLength(1);
  });

  test('includes fix in properties when present', () => {
    const withFix = { ...deadCodeVuln, fix: 'Remove unreachable block' };
    const results = [makeResult('src/Foo.java', [withFix])];
    const parsed = JSON.parse(formatSARIF(results));
    expect(parsed.runs[0].results[0].properties.fix).toBe('Remove unreachable block');
  });
});
