import { describe, test, expect } from 'bun:test';
import { parseArgs } from '../src/utils/args.js';

describe('parseArgs', () => {
  test('parses command with no options', () => {
    const result = parseArgs(['scan', 'src/']);
    expect(result.command).toBe('scan');
    expect(result.args).toEqual(['src/']);
    expect(result.options).toEqual({});
  });

  test('parses long options with values', () => {
    const result = parseArgs(['scan', 'src/', '--format', 'json', '--severity', 'high']);
    expect(result.command).toBe('scan');
    expect(result.args).toEqual(['src/']);
    expect(result.options.format).toBe('json');
    expect(result.options.severity).toBe('high');
  });

  test('parses long options with = syntax', () => {
    const result = parseArgs(['scan', 'src/', '--format=sarif', '--threads=8']);
    expect(result.options.format).toBe('sarif');
    expect(result.options.threads).toBe('8');
  });

  test('parses boolean flags', () => {
    const result = parseArgs(['scan', '.', '--exclude-tests', '--quiet', '--verbose']);
    expect(result.options['exclude-tests']).toBe(true);
    expect(result.options.quiet).toBe(true);
    expect(result.options.verbose).toBe(true);
  });

  test('parses short options with values', () => {
    const result = parseArgs(['scan', '.', '-f', 'json', '-o', 'out.json']);
    expect(result.options.f).toBe('json');
    expect(result.options.o).toBe('out.json');
  });

  test('parses short boolean flags', () => {
    const result = parseArgs(['scan', '.', '-q', '-v']);
    expect(result.options.q).toBe(true);
    expect(result.options.v).toBe(true);
  });

  test('handles no arguments', () => {
    const result = parseArgs([]);
    expect(result.command).toBeUndefined();
    expect(result.args).toEqual([]);
    expect(result.options).toEqual({});
  });

  test('handles help flag without command', () => {
    const result = parseArgs(['--help']);
    expect(result.command).toBeUndefined();
    expect(result.options.help).toBe(true);
  });

  test('handles --version flag', () => {
    const result = parseArgs(['--version']);
    expect(result.options.version).toBe(true);
  });

  test('parses command with multiple positional args', () => {
    const result = parseArgs(['list-passes', 'security']);
    expect(result.command).toBe('list-passes');
    expect(result.args).toEqual(['security']);
  });

  test('parses --disable-pass with comma-separated value', () => {
    const result = parseArgs(['scan', '.', '--disable-pass', 'naming-convention,todo-in-prod']);
    expect(result.options['disable-pass']).toBe('naming-convention,todo-in-prod');
  });

  test('parses --profile option', () => {
    const result = parseArgs(['scan', '.', '--profile', 'custom.json']);
    expect(result.options.profile).toBe('custom.json');
  });

  test('parses --exclude-cwe option', () => {
    const result = parseArgs(['scan', '.', '--exclude-cwe', 'CWE-330,CWE-327']);
    expect(result.options['exclude-cwe']).toBe('CWE-330,CWE-327');
  });

  test('treats next arg starting with - as boolean (no value)', () => {
    const result = parseArgs(['scan', '.', '--quiet', '--format', 'json']);
    expect(result.options.quiet).toBe(true);
    expect(result.options.format).toBe('json');
  });

  test('mixed short and long options', () => {
    const result = parseArgs(['scan', 'src/', '-l', 'java', '--severity', 'high', '-f', 'sarif', '-q']);
    expect(result.command).toBe('scan');
    expect(result.args).toEqual(['src/']);
    expect(result.options.l).toBe('java');
    expect(result.options.severity).toBe('high');
    expect(result.options.f).toBe('sarif');
    expect(result.options.q).toBe(true);
  });
});
