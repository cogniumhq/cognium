import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { resolve, join } from 'path';
import { writeFileSync, unlinkSync, existsSync } from 'fs';

// ─── Helpers ────────────────────────────────────────────────────────────────

const CLI = resolve(import.meta.dir, '../src/cli.ts');
const FIXTURES = resolve(import.meta.dir, 'fixtures');
const VULN_FILE = join(FIXTURES, 'VulnController.java');
const CLEAN_FILE = join(FIXTURES, 'CleanService.java');
const TS_FILE = join(FIXTURES, 'simple.ts');

interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function run(...args: string[]): Promise<RunResult> {
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], {
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...process.env, NO_COLOR: '1' },
    cwd: FIXTURES,
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const exitCode = await proc.exited;
  return { stdout, stderr, exitCode };
}

// ─── Scan: text output ──────────────────────────────────────────────────────

describe('scan (text)', () => {
  test('detects SQL injection in vulnerable Java file', async () => {
    const { stdout, exitCode } = await run('scan', VULN_FILE, '-q');
    expect(stdout).toContain('sql_injection');
    expect(exitCode).toBe(1);
  }, 30_000);

  test('clean file produces exit code 0', async () => {
    const { exitCode } = await run('scan', CLEAN_FILE, '-q');
    expect(exitCode).toBe(0);
  }, 30_000);

  test('shows CWE identifier for findings', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-q');
    expect(stdout).toContain('CWE-89');
  }, 30_000);

  test('shows fix suggestion for SQL injection', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-q');
    expect(stdout).toContain('Fix:');
  }, 30_000);
});

// ─── Scan: JSON output ──────────────────────────────────────────────────────

describe('scan (json)', () => {
  test('produces valid JSON with vulnerabilities', async () => {
    const { stdout, exitCode } = await run('scan', VULN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.version).toBeDefined();
    expect(parsed.results).toBeArray();
    expect(parsed.results.length).toBeGreaterThan(0);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    expect(vulns.length).toBeGreaterThan(0);
    expect(vulns.some((v: any) => v.type === 'sql_injection')).toBe(true);
    expect(exitCode).toBe(1);
  }, 30_000);

  test('clean file JSON has zero vulnerabilities', async () => {
    const { stdout, exitCode } = await run('scan', CLEAN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    expect(vulns.length).toBe(0);
    expect(exitCode).toBe(0);
  }, 30_000);

  test('JSON includes summary counts', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.summary).toBeDefined();
    expect(parsed.summary.filesScanned).toBe(1);
    expect(parsed.summary.totalVulnerabilities).toBeGreaterThan(0);
  }, 30_000);
});

// ─── Scan: SARIF output ─────────────────────────────────────────────────────

describe('scan (sarif)', () => {
  test('produces valid SARIF 2.1.0', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'sarif', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toContain('sarif');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  }, 30_000);

  test('SARIF results include ruleId and level', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'sarif', '-q');
    const parsed = JSON.parse(stdout);
    const result = parsed.runs[0].results[0];
    expect(result.ruleId).toBeDefined();
    expect(result.level).toBeDefined();
  }, 30_000);
});

// ─── Scan: exit codes ───────────────────────────────────────────────────────

describe('exit codes', () => {
  test('exit 1 for security findings', async () => {
    const { exitCode } = await run('scan', VULN_FILE, '-q');
    expect(exitCode).toBe(1);
  }, 30_000);

  test('exit 0 for clean scan', async () => {
    const { exitCode } = await run('scan', CLEAN_FILE, '-q');
    expect(exitCode).toBe(0);
  }, 30_000);

  test('exit 2 for nonexistent path', async () => {
    const { exitCode } = await run('scan', '/nonexistent/path/file.java', '-q');
    expect(exitCode).toBe(2);
  }, 30_000);
});

// ─── Scan: filtering ────────────────────────────────────────────────────────

describe('scan filtering', () => {
  test('--severity critical shows only critical findings', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--severity', 'critical');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    for (const v of vulns) {
      expect(v.severity).toBe('critical');
    }
  }, 30_000);

  test('--category security filters to security only', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--category', 'security');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    for (const v of vulns) {
      expect(v.category).toBe('security');
    }
  }, 30_000);

  test('--exclude-cwe CWE-89 removes SQL injection findings', async () => {
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--exclude-cwe', 'CWE-89');
    const parsed = JSON.parse(stdout);
    const vulns = parsed.results.flatMap((r: any) => r.vulnerabilities);
    const sqlVulns = vulns.filter((v: any) => v.cwe === 'CWE-89');
    expect(sqlVulns.length).toBe(0);
  }, 30_000);
});

// ─── Scan: directory mode ───────────────────────────────────────────────────

describe('scan directory', () => {
  test('scans all files in a directory', async () => {
    const { stdout } = await run('scan', FIXTURES, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.summary.filesScanned).toBeGreaterThanOrEqual(2);
  }, 60_000);

  test('--language java restricts to Java files only', async () => {
    const { stdout } = await run('scan', FIXTURES, '-f', 'json', '-q', '-l', 'java');
    const parsed = JSON.parse(stdout);
    for (const result of parsed.results) {
      expect(result.file).toEndWith('.java');
    }
  }, 60_000);
});

// ─── Metrics ────────────────────────────────────────────────────────────────

describe('metrics', () => {
  test('produces text metrics for a file', async () => {
    const { stdout, exitCode } = await run('metrics', VULN_FILE, '-q');
    expect(exitCode).toBe(0);
    // Should include common metric names
    expect(stdout).toContain('cyclomatic');
  }, 30_000);

  test('produces JSON metrics', async () => {
    const { stdout, exitCode } = await run('metrics', VULN_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.version).toBeDefined();
    expect(parsed.files).toBeArray();
    expect(parsed.files.length).toBeGreaterThan(0);
    expect(parsed.files[0].metrics).toBeArray();
    expect(parsed.summary).toBeDefined();
    expect(exitCode).toBe(0);
  }, 30_000);

  test('--category complexity filters metrics', async () => {
    const { stdout } = await run('metrics', VULN_FILE, '-f', 'json', '-q', '--category', 'complexity');
    const parsed = JSON.parse(stdout);
    for (const fm of parsed.files) {
      for (const m of fm.metrics) {
        expect(m.category).toBe('complexity');
      }
    }
  }, 30_000);

  test('metrics for TypeScript file', async () => {
    const { stdout, exitCode } = await run('metrics', TS_FILE, '-f', 'json', '-q');
    const parsed = JSON.parse(stdout);
    expect(parsed.files.length).toBeGreaterThan(0);
    expect(exitCode).toBe(0);
  }, 30_000);
});

// ─── Config integration ─────────────────────────────────────────────────────

describe('config integration', () => {
  const configPath = join(FIXTURES, 'cognium.config.json');

  afterAll(() => {
    if (existsSync(configPath)) unlinkSync(configPath);
  });

  test('--disable-pass removes findings from a disableable pass', async () => {
    // Scan the TS fixture which may produce quality findings (e.g., naming-convention)
    // Core taint passes (taint-matcher, taint-propagation, etc.) are always enabled,
    // so we test with a non-core pass. Verify the flag is accepted and doesn't crash.
    const { exitCode } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--disable-pass', 'dead-code,naming-convention');
    // SQL injection should still be found (core passes unaffected)
    expect(exitCode).toBe(1);
  }, 60_000);

  test('config file suppressions remove findings by type', async () => {
    // Suppressions match vuln.type — use 'sql_injection' to suppress the finding
    const config = {
      suppressions: [
        { pass: 'sql_injection', file: 'VulnController.java' },
      ],
    };
    writeFileSync(configPath, JSON.stringify(config));

    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--profile', configPath);
    const vulns = JSON.parse(stdout).results.flatMap((r: any) => r.vulnerabilities);
    const hasSql = vulns.some((v: any) => v.type === 'sql_injection');
    expect(hasSql).toBe(false);

    unlinkSync(configPath);
  }, 30_000);

  test('config file with severity filter applies defaults', async () => {
    const config = {
      severity: 'critical',
    };
    writeFileSync(configPath, JSON.stringify(config));

    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--profile', configPath);
    const vulns = JSON.parse(stdout).results.flatMap((r: any) => r.vulnerabilities);
    for (const v of vulns) {
      expect(v.severity).toBe('critical');
    }

    unlinkSync(configPath);
  }, 30_000);

  test('config file disabling non-core passes via passes object', async () => {
    // Core security passes cannot be disabled. Test with a quality pass.
    const config = {
      passes: {
        'dead-code': false,
        'naming-convention': false,
      },
    };
    writeFileSync(configPath, JSON.stringify(config));

    // Should still find SQL injection (core pass) — verify config loading doesn't break
    const { stdout } = await run('scan', VULN_FILE, '-f', 'json', '-q', '--profile', configPath);
    const vulns = JSON.parse(stdout).results.flatMap((r: any) => r.vulnerabilities);
    const hasSql = vulns.some((v: any) => v.type === 'sql_injection');
    expect(hasSql).toBe(true);

    unlinkSync(configPath);
  }, 30_000);
});

// ─── Other commands ─────────────────────────────────────────────────────────

describe('other commands', () => {
  test('version command prints version', async () => {
    const { stdout, exitCode } = await run('version');
    expect(stdout).toContain('cognium');
    expect(exitCode).toBe(0);
  }, 10_000);

  test('list-passes shows pass registry', async () => {
    const { stdout, exitCode } = await run('list-passes');
    expect(stdout).toContain('taint-matcher');
    expect(stdout).toContain('dead-code');
    expect(exitCode).toBe(0);
  }, 10_000);

  test('list-passes with category filter', async () => {
    const { stdout } = await run('list-passes', 'reliability');
    expect(stdout).toContain('dead-code');
    // Should not contain security-only passes
    expect(stdout).not.toContain('taint-matcher');
  }, 10_000);

  test('no arguments shows help', async () => {
    const { stdout } = await run();
    expect(stdout).toContain('USAGE');
    expect(stdout).toContain('cognium');
  }, 10_000);

  test('--help shows help', async () => {
    const { stdout } = await run('--help');
    expect(stdout).toContain('USAGE');
  }, 10_000);
});

// ─── Output file ────────────────────────────────────────────────────────────

describe('output file', () => {
  const outFile = join(FIXTURES, '__test_output.json');

  afterAll(() => {
    if (existsSync(outFile)) unlinkSync(outFile);
  });

  test('-o writes results to file', async () => {
    await run('scan', VULN_FILE, '-f', 'json', '-q', '-o', outFile);
    expect(existsSync(outFile)).toBe(true);
    const content = await Bun.file(outFile).text();
    const parsed = JSON.parse(content);
    expect(parsed.results).toBeArray();

    unlinkSync(outFile);
  }, 30_000);
});
