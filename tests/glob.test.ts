import { describe, test, expect } from 'bun:test';
import { matchesGlob, isTestFile, detectLanguage } from '../src/cli.js';

// ─── matchesGlob ─────────────────────────────────────────────────────────────

describe('matchesGlob', () => {
  test('** matches any path depth', () => {
    expect(matchesGlob('src/foo/bar/baz.ts', '**/*.ts')).toBe(true);
    expect(matchesGlob('src/foo.java', '**/*.ts')).toBe(false);
  });

  test('** matches files at root level too', () => {
    expect(matchesGlob('baz.ts', '**/*.ts')).toBe(true);
  });

  test('* matches within a single segment', () => {
    expect(matchesGlob('src/foo.ts', 'src/*.ts')).toBe(true);
    expect(matchesGlob('src/bar.ts', 'src/*.ts')).toBe(true);
    expect(matchesGlob('src/sub/foo.ts', 'src/*.ts')).toBe(false);
  });

  test('? matches a single character', () => {
    expect(matchesGlob('src/a.ts', 'src/?.ts')).toBe(true);
    expect(matchesGlob('src/ab.ts', 'src/?.ts')).toBe(false);
  });

  test('exact match', () => {
    expect(matchesGlob('src/main.ts', 'src/main.ts')).toBe(true);
    expect(matchesGlob('src/other.ts', 'src/main.ts')).toBe(false);
  });

  test('leading ** matches deep paths', () => {
    expect(matchesGlob('a/b/c/node_modules/foo.js', '**/node_modules/**')).toBe(true);
    expect(matchesGlob('node_modules/foo.js', '**/node_modules/**')).toBe(true);
  });

  test('pattern with directory wildcard', () => {
    expect(matchesGlob('src/components/Button.tsx', 'src/**/*.tsx')).toBe(true);
    expect(matchesGlob('src/Button.tsx', 'src/**/*.tsx')).toBe(true);
  });

  test('normalizes backslashes', () => {
    expect(matchesGlob('src\\foo\\bar.ts', '**/*.ts')).toBe(true);
  });

  test('does not match wrong extension', () => {
    expect(matchesGlob('src/foo.js', '**/*.ts')).toBe(false);
  });

  test('**/test/** matches nested test dirs', () => {
    expect(matchesGlob('src/test/foo.ts', '**/test/**')).toBe(true);
    expect(matchesGlob('test/foo.ts', '**/test/**')).toBe(true);
    expect(matchesGlob('src/testing/foo.ts', '**/test/**')).toBe(false);
  });

  test('**/dist/** matches dist directory', () => {
    expect(matchesGlob('dist/index.js', '**/dist/**')).toBe(true);
    expect(matchesGlob('src/dist/file.js', '**/dist/**')).toBe(true);
  });
});

// ─── isTestFile ──────────────────────────────────────────────────────────────

describe('isTestFile', () => {
  // Java
  test('detects Java test files', () => {
    expect(isTestFile('src/com/example/FooTest.java')).toBe(true);
    expect(isTestFile('src/com/example/FooTests.java')).toBe(true);
    expect(isTestFile('src/com/example/FooIT.java')).toBe(true);
    expect(isTestFile('src/com/example/Foo.java')).toBe(false);
  });

  // JavaScript/TypeScript
  test('detects JS/TS test files', () => {
    expect(isTestFile('src/foo.test.ts')).toBe(true);
    expect(isTestFile('src/foo.spec.ts')).toBe(true);
    expect(isTestFile('src/foo.test.js')).toBe(true);
    expect(isTestFile('src/foo.spec.jsx')).toBe(true);
    expect(isTestFile('src/foo.test.tsx')).toBe(true);
    expect(isTestFile('src/foo.ts')).toBe(false);
  });

  // Python
  test('detects Python test files', () => {
    expect(isTestFile('tests/test_foo.py')).toBe(true);
    expect(isTestFile('src/foo_test.py')).toBe(true);
    expect(isTestFile('src/foo_tests.py')).toBe(true);
    expect(isTestFile('src/foo.py')).toBe(false);
  });

  // Rust
  test('detects Rust test files', () => {
    expect(isTestFile('src/foo_test.rs')).toBe(true);
    expect(isTestFile('src/foo.rs')).toBe(false);
  });

  // Test directories
  test('detects test directory paths', () => {
    expect(isTestFile('src/test/Foo.java')).toBe(true);
    expect(isTestFile('src/tests/Foo.java')).toBe(true);
    expect(isTestFile('src/__tests__/foo.ts')).toBe(true);
    expect(isTestFile('src/spec/foo.ts')).toBe(true);
    expect(isTestFile('src/__mocks__/foo.ts')).toBe(true);
  });

  // Non-test files
  test('does not flag non-test files', () => {
    expect(isTestFile('src/main.ts')).toBe(false);
    expect(isTestFile('src/utils/helper.py')).toBe(false);
    expect(isTestFile('src/Controller.java')).toBe(false);
  });
});

// ─── detectLanguage ──────────────────────────────────────────────────────────

describe('detectLanguage', () => {
  test('detects Java', () => {
    expect(detectLanguage('Foo.java')).toBe('java');
  });

  test('detects JavaScript', () => {
    expect(detectLanguage('app.js')).toBe('javascript');
    expect(detectLanguage('module.mjs')).toBe('javascript');
  });

  test('detects TypeScript', () => {
    expect(detectLanguage('app.ts')).toBe('typescript');
    expect(detectLanguage('component.tsx')).toBe('typescript');
  });

  test('detects Python', () => {
    expect(detectLanguage('script.py')).toBe('python');
  });

  test('detects Rust', () => {
    expect(detectLanguage('main.rs')).toBe('rust');
  });

  test('detects Bash', () => {
    expect(detectLanguage('deploy.sh')).toBe('bash');
    expect(detectLanguage('init.bash')).toBe('bash');
  });

  test('returns null for unknown extension', () => {
    expect(detectLanguage('README.md')).toBeNull();
    expect(detectLanguage('data.csv')).toBeNull();
    expect(detectLanguage('Makefile')).toBeNull();
  });

  test('is case-insensitive on extension', () => {
    expect(detectLanguage('Foo.JAVA')).toBe('java');
    expect(detectLanguage('app.TS')).toBe('typescript');
  });
});
