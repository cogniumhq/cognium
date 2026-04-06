/**
 * cognium - Semantic static analysis engine
 *
 * This module exports the programmatic API for cognium.
 * For CLI usage, run `cognium` directly.
 */

export { version } from './version.js';

// Re-export circle-ir core API
export {
  initAnalyzer,
  analyze,
  analyzeForAPI,
  analyzeProject,
  isAnalyzerInitialized,
  resetAnalyzer,
  type AnalyzerOptions,
  type PassOptions,
} from 'circle-ir';

// Re-export circle-ir types for consumers
export type {
  // Core IR
  CircleIR,
  Meta,
  TypeInfo,
  MethodInfo,
  FieldInfo,
  CallInfo,
  CFG,
  CFGBlock,
  CFGEdge,
  DFG,
  DFGDef,
  DFGUse,
  DFGChain,
  Taint,
  TaintSource,
  TaintSink,
  TaintSanitizer,
  ImportInfo,
  ExportInfo,

  // Utility types
  SinkType,
  SourceType,
  Severity,
  SupportedLanguage,

  // SAST taxonomy
  PassCategory,
  SarifLevel,
  SastFinding,
  MetricCategory,
  MetricValue,
  FileMetrics,

  // Project-level
  ProjectAnalysis,
  ProjectMeta,
  FileAnalysis,
  TypeHierarchy,
  CrossFileCall,
  TaintPath,
  TaintFlow,

  // Config
  TaintConfig,
  SourcePattern,
  SinkPattern,
  SanitizerPattern,

  // Analysis response
  AnalysisResponse,
  Vulnerability,
} from 'circle-ir';
