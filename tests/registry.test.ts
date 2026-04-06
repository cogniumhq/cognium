import { describe, test, expect } from 'bun:test';
import { PASS_REGISTRY } from '../src/cli.js';
import { SINK_SEVERITY, SINK_CWE } from '../src/formatters.js';

// ─── PASS_REGISTRY ──────────────────────────────────────────────────────────

describe('PASS_REGISTRY', () => {
  test('contains at least 40 passes', () => {
    expect(PASS_REGISTRY.length).toBeGreaterThanOrEqual(40);
  });

  test('every pass has required fields', () => {
    for (const pass of PASS_REGISTRY) {
      expect(pass.rule_id).toBeTruthy();
      expect(pass.category).toBeTruthy();
      expect(pass.severity).toBeTruthy();
      expect(pass.description).toBeTruthy();
    }
  });

  test('all categories are valid', () => {
    const validCategories = ['security', 'reliability', 'performance', 'maintainability', 'architecture'];
    for (const pass of PASS_REGISTRY) {
      expect(validCategories).toContain(pass.category);
    }
  });

  test('all severities are valid', () => {
    const validSeverities = ['-', 'low', 'medium', 'high', 'critical'];
    for (const pass of PASS_REGISTRY) {
      expect(validSeverities).toContain(pass.severity);
    }
  });

  test('rule_ids are unique', () => {
    const ids = PASS_REGISTRY.map(p => p.rule_id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test('CWE format is valid when present', () => {
    for (const pass of PASS_REGISTRY) {
      if (pass.cwe) {
        expect(pass.cwe).toMatch(/^CWE-\d+$/);
      }
    }
  });

  test('contains known core passes', () => {
    const ids = PASS_REGISTRY.map(p => p.rule_id);
    expect(ids).toContain('taint-matcher');
    expect(ids).toContain('dead-code');
    expect(ids).toContain('n-plus-one');
    expect(ids).toContain('god-class');
    expect(ids).toContain('naming-convention');
    expect(ids).toContain('circular-dependency');
  });

  test('security passes have severity "-" (internal)', () => {
    const securityPasses = PASS_REGISTRY.filter(p => p.category === 'security');
    for (const pass of securityPasses) {
      expect(pass.severity).toBe('-');
    }
  });

  test('non-security passes have real severity', () => {
    const nonSecurity = PASS_REGISTRY.filter(p => p.category !== 'security');
    for (const pass of nonSecurity) {
      expect(pass.severity).not.toBe('-');
    }
  });
});

// ─── SINK_SEVERITY ──────────────────────────────────────────────────────────

describe('SINK_SEVERITY', () => {
  test('all 19 sink types have severity', () => {
    const sinkTypes = [
      'sql_injection', 'nosql_injection', 'command_injection', 'path_traversal',
      'xss', 'xxe', 'deserialization', 'ldap_injection', 'xpath_injection',
      'ssrf', 'open_redirect', 'code_injection', 'log_injection',
      'weak_random', 'weak_hash', 'weak_crypto', 'insecure_cookie',
      'trust_boundary', 'external_taint_escape',
    ];
    for (const type of sinkTypes) {
      expect(SINK_SEVERITY[type as keyof typeof SINK_SEVERITY]).toBeTruthy();
    }
  });

  test('critical sinks include sql_injection and command_injection', () => {
    expect(SINK_SEVERITY.sql_injection).toBe('critical');
    expect(SINK_SEVERITY.command_injection).toBe('critical');
    expect(SINK_SEVERITY.xxe).toBe('critical');
    expect(SINK_SEVERITY.deserialization).toBe('critical');
    expect(SINK_SEVERITY.code_injection).toBe('critical');
  });

  test('severity values are valid', () => {
    const valid = ['critical', 'high', 'medium', 'low'];
    for (const sev of Object.values(SINK_SEVERITY)) {
      expect(valid).toContain(sev);
    }
  });
});

// ─── SINK_CWE ───────────────────────────────────────────────────────────────

describe('SINK_CWE', () => {
  test('matches SINK_SEVERITY keys', () => {
    const sevKeys = Object.keys(SINK_SEVERITY).sort();
    const cweKeys = Object.keys(SINK_CWE).sort();
    expect(cweKeys).toEqual(sevKeys);
  });

  test('all CWEs are valid format', () => {
    for (const cwe of Object.values(SINK_CWE)) {
      expect(cwe).toMatch(/^CWE-\d+$/);
    }
  });

  test('known CWE mappings are correct', () => {
    expect(SINK_CWE.sql_injection).toBe('CWE-89');
    expect(SINK_CWE.command_injection).toBe('CWE-78');
    expect(SINK_CWE.xss).toBe('CWE-79');
    expect(SINK_CWE.path_traversal).toBe('CWE-22');
    expect(SINK_CWE.ssrf).toBe('CWE-918');
  });
});
