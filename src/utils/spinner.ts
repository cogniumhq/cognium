/**
 * Lightweight spinner utility
 * Replaces ora dependency with zero-dependency alternative
 */

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const CHECKMARK = '✔';
const CROSS = '✖';
const WARNING = '⚠';

export class Spinner {
  private _text: string;
  private frameIndex = 0;
  private intervalId?: NodeJS.Timeout;
  private isSpinning = false;

  constructor(text: string) {
    this._text = text;
  }

  start(): this {
    if (this.isSpinning) return this;

    this.isSpinning = true;
    this.frameIndex = 0;

    // Hide cursor
    process.stdout.write('\x1b[?25l');

    this.intervalId = setInterval(() => {
      const frame = SPINNER_FRAMES[this.frameIndex];
      this.frameIndex = (this.frameIndex + 1) % SPINNER_FRAMES.length;

      // Clear line and write spinner
      process.stdout.write(`\r\x1b[K${frame} ${this._text}`);
    }, 80);

    return this;
  }

  stop(): this {
    if (!this.isSpinning) return this;

    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }

    this.isSpinning = false;

    // Clear line and show cursor
    process.stdout.write('\r\x1b[K');
    process.stdout.write('\x1b[?25h');

    return this;
  }

  succeed(text?: string): this {
    this.stop();
    const message = text || this._text;
    console.log(`\x1b[32m${CHECKMARK}\x1b[0m ${message}`);
    return this;
  }

  fail(text?: string): this {
    this.stop();
    const message = text || this._text;
    console.log(`\x1b[31m${CROSS}\x1b[0m ${message}`);
    return this;
  }

  warn(text?: string): this {
    this.stop();
    const message = text || this._text;
    console.log(`\x1b[33m${WARNING}\x1b[0m ${message}`);
    return this;
  }

  set text(value: string) {
    this._text = value;
  }

  get text(): string {
    return this._text;
  }
}

export function spinner(text: string): Spinner {
  return new Spinner(text);
}
