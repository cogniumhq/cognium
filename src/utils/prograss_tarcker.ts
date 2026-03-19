import type { Spinner } from './spinner.js';

export type ProgressReporter = (text: string, final?: boolean) => void;

export const formatProgressBar = (done: number, total: number, width = 18): string => {
  if (total <= 0) return '[]';
  const clampedDone = Math.max(0, Math.min(done, total));
  const ratio = clampedDone / total;
  const filled = Math.round(ratio * width);
  const empty = Math.max(0, width - filled);
  return `[${'='.repeat(filled)}${' '.repeat(empty)}]`;
}

export function createProgressReporter(options: { quiet?: boolean; spinner?: Spinner | null }): ProgressReporter {
  if (options.quiet) return (_text: string, _final?: boolean) => {};

  // If spinner is active, just update its text.
  if (options.spinner) {
    return (text: string) => {
      options.spinner!.text = text;
    };
  }

  // Otherwise, write a single-line progress indicator to stderr.
  // If stderr isn't a TTY, emit newline logs so output is still visible in CI.
  let lastLine = '';
  return (text: string, final = false) => {
    if (!process.stderr.isTTY) {
      if (final || text !== lastLine) {
        console.error(text);
        lastLine = text;
      }
      return;
    }
    lastLine = text;
    process.stderr.write(`\r\x1b[K${text}`);
    if (final) process.stderr.write('\n');
  };
}
