/**
 * Lightweight ANSI color utilities
 * Replaces chalk dependency with zero-dependency alternative
 */

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

// Foreground colors (using bright variants for better visibility)
const RED = '\x1b[91m';      // Bright red
const GREEN = '\x1b[92m';    // Bright green
const YELLOW = '\x1b[93m';   // Bright yellow
const BLUE = '\x1b[94m';     // Bright blue
const CYAN = '\x1b[96m';     // Bright cyan
const MAGENTA = '\x1b[95m';  // Bright magenta

export const colors = {
  red: (text: string) => `${RED}${text}${RESET}`,
  green: (text: string) => `${GREEN}${text}${RESET}`,
  yellow: (text: string) => `${YELLOW}${text}${RESET}`,
  blue: (text: string) => `${BLUE}${text}${RESET}`,
  cyan: (text: string) => `${CYAN}${text}${RESET}`,
  magenta: (text: string) => `${MAGENTA}${text}${RESET}`,
  bold: (text: string) => `${BOLD}${text}${RESET}`,
  dim: (text: string) => text, // No dimming - keep text readable
};
