/**
 * cognium - AI-powered static analysis
 *
 * This module exports the programmatic API for cognium.
 * For CLI usage, run `cognium` directly.
 */

export { version } from './version.js';

// Re-export circle-ir types for convenience
export {
  initAnalyzer,
  analyze,
  analyzeForAPI,
  type CircleIR,
  type TaintFlow,
  type AnalyzerOptions,
} from 'circle-ir';
