import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { writeFileSync, unlinkSync, existsSync } from 'fs';
import {
  loadConfig,
  convertConfigToPassOptions,
  type CogniumConfig,
} from '../src/cli.js';

const TMP_CONFIG = '__test_cognium_config.json';

afterEach(() => {
  if (existsSync(TMP_CONFIG)) unlinkSync(TMP_CONFIG);
});

// ─── loadConfig ──────────────────────────────────────────────────────────────

describe('loadConfig', () => {
  test('returns null when file does not exist', () => {
    expect(loadConfig('nonexistent.json')).toBeNull();
  });

  test('returns null for default path when no config exists', () => {
    // Only passes if there is no cognium.config.json in the cwd while testing
    // (there IS one in the cognium project root, so use explicit path)
    expect(loadConfig('__no_such_file__.json')).toBeNull();
  });

  test('loads valid config from custom path', () => {
    const cfg: CogniumConfig = {
      version: '1.0',
      include: ['src/**/*.ts'],
      exclude: ['**/dist/**'],
      passes: { 'naming-convention': false },
    };
    writeFileSync(TMP_CONFIG, JSON.stringify(cfg));
    const loaded = loadConfig(TMP_CONFIG);
    expect(loaded).not.toBeNull();
    expect(loaded!.version).toBe('1.0');
    expect(loaded!.include).toEqual(['src/**/*.ts']);
    expect(loaded!.passes?.['naming-convention']).toBe(false);
  });

  test('returns null and warns on invalid JSON', () => {
    writeFileSync(TMP_CONFIG, '{ invalid json');
    const loaded = loadConfig(TMP_CONFIG);
    expect(loaded).toBeNull();
  });
});

// ─── convertConfigToPassOptions ──────────────────────────────────────────────

describe('convertConfigToPassOptions', () => {
  test('returns empty defaults when no passes defined', () => {
    const result = convertConfigToPassOptions({});
    expect(result.passOptions).toEqual({});
    expect(result.disabledPasses).toEqual([]);
  });

  test('disables passes set to false', () => {
    const result = convertConfigToPassOptions({
      passes: {
        'naming-convention': false,
        'todo-in-prod': false,
        'missing-public-doc': false,
      },
    });
    expect(result.disabledPasses).toContain('naming-convention');
    expect(result.disabledPasses).toContain('todo-in-prod');
    expect(result.disabledPasses).toContain('missing-public-doc');
    expect(result.disabledPasses).toHaveLength(3);
  });

  test('passes set to true are enabled with defaults (no-op)', () => {
    const result = convertConfigToPassOptions({
      passes: { 'dead-code': true },
    });
    expect(result.disabledPasses).toEqual([]);
    expect(result.passOptions).toEqual({});
  });

  test('disables passes with enabled: false in object form', () => {
    const result = convertConfigToPassOptions({
      passes: {
        'unbounded-collection': { enabled: false },
      },
    });
    expect(result.disabledPasses).toContain('unbounded-collection');
  });

  test('maps dependency-fan-out threshold', () => {
    const result = convertConfigToPassOptions({
      passes: {
        'dependency-fan-out': { threshold: 50 },
      },
    });
    expect(result.passOptions.dependencyFanOut).toEqual({ threshold: 50 });
    expect(result.disabledPasses).toEqual([]);
  });

  test('maps unbounded-collection skipPatterns', () => {
    const result = convertConfigToPassOptions({
      passes: {
        'unbounded-collection': { skipPatterns: ['cache', 'results'] },
      },
    });
    expect(result.passOptions.unboundedCollection).toEqual({
      skipPatterns: ['cache', 'results'],
    });
  });

  test('maps naming-convention enforceIPrefix', () => {
    const result = convertConfigToPassOptions({
      passes: {
        'naming-convention': { enforceIPrefix: true },
      },
    });
    expect(result.passOptions.namingConvention).toEqual({ enforceIPrefix: true });
  });

  test('handles mixed disabled and configured passes', () => {
    const result = convertConfigToPassOptions({
      passes: {
        'naming-convention': false,
        'dependency-fan-out': { threshold: 30 },
        'todo-in-prod': false,
        'dead-code': true,
      },
    });
    expect(result.disabledPasses).toEqual(['naming-convention', 'todo-in-prod']);
    expect(result.passOptions.dependencyFanOut).toEqual({ threshold: 30 });
  });
});
