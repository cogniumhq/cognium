import { describe, test, expect } from 'bun:test';
import { applySuppressionsToResults, type Suppression } from '../src/cli.js';
import type { ScanResult } from '../src/formatters.js';

function makeResult(file: string, vulns: Array<{ type: string; line: number }>): ScanResult {
  return {
    file,
    vulnerabilities: vulns.map(v => ({
      type: v.type,
      severity: 'high',
      message: `${v.type} at line ${v.line}`,
      line: v.line,
      category: 'security',
    })),
  };
}

describe('applySuppressionsToResults', () => {
  test('returns results unchanged when no suppressions', () => {
    const results = [makeResult('/app/src/Foo.java', [{ type: 'sql_injection', line: 10 }])];
    const out = applySuppressionsToResults(results, [], '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('suppresses by pass name (all files)', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'naming-convention', line: 5 }]),
      makeResult('/app/src/B.java', [{ type: 'naming-convention', line: 12 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'naming-convention' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(0);
    expect(out[1].vulnerabilities).toHaveLength(0);
  });

  test('suppresses by pass + file', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'dead-code', line: 5 }]),
      makeResult('/app/src/B.java', [{ type: 'dead-code', line: 10 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'dead-code', file: 'src/A.java' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(0); // suppressed
    expect(out[1].vulnerabilities).toHaveLength(1); // not suppressed
  });

  test('suppresses by pass + file + line', () => {
    const results = [
      makeResult('/app/src/A.java', [
        { type: 'dead-code', line: 5 },
        { type: 'dead-code', line: 20 },
      ]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code', file: 'src/A.java', line: 5 },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
    expect(out[0].vulnerabilities[0].line).toBe(20);
  });

  test('does not suppress when pass name does not match', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'sql_injection', line: 10 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'xss' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('does not suppress when file does not match', () => {
    const results = [
      makeResult('/app/src/B.java', [{ type: 'dead-code', line: 5 }]),
    ];
    const suppressions: Suppression[] = [{ pass: 'dead-code', file: 'src/A.java' }];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('does not suppress when line does not match', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'dead-code', line: 20 }]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code', file: 'src/A.java', line: 5 },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
  });

  test('multiple suppressions can stack', () => {
    const results = [
      makeResult('/app/src/A.java', [
        { type: 'dead-code', line: 5 },
        { type: 'naming-convention', line: 10 },
        { type: 'sql_injection', line: 15 },
      ]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code' },
      { pass: 'naming-convention' },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(1);
    expect(out[0].vulnerabilities[0].type).toBe('sql_injection');
  });

  test('handles file with ./prefix in suppression', () => {
    const results = [
      makeResult('/app/src/A.java', [{ type: 'dead-code', line: 5 }]),
    ];
    const suppressions: Suppression[] = [
      { pass: 'dead-code', file: './src/A.java' },
    ];
    const out = applySuppressionsToResults(results, suppressions, '/app');
    expect(out[0].vulnerabilities).toHaveLength(0);
  });
});
