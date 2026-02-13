//! ModSecurity integration module
//!
//! This module provides WAF (Web Application Firewall) scanning capabilities
//! using libmodsecurity (ModSecurity v3) for request and response body scanning.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        modsec module                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ffi.rs          - Raw FFI bindings to libmodsecurity           │
//! │  engine.rs       - Safe ModSecurityEngine wrapper               │
//! │  rules.rs        - RulesSet management                          │
//! │  transaction.rs  - Per-request transaction handling             │
//! │  pool.rs         - Thread pool for async scanning               │
//! │  scanner.rs      - DualRulesetScanner (OLD/NEW support)         │
//! │  config.rs       - ModSecurityConfig types                      │
//! │  string_extractor.rs - JSON string extraction optimization      │
//! │  base64_detector.rs  - Base64 detection to skip false positives │
//! │  observability.rs    - Metrics and dynamic metadata             │
//! │  error.rs        - Error types                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! - `ModSecurityEngine` is `Send` but NOT `Sync` - one per thread or use `Mutex`
//! - `RulesSet` is `Send + Sync` after compilation - shareable across threads
//! - `Transaction` is `Send` but NOT `Sync` - one per HTTP request
//! - `ScannerPool` manages thread-safe scanning via message passing

mod base64_detector;
pub mod bundled_crs;
mod config;
mod engine;
mod error;
#[allow(dead_code)]
mod ffi;
pub mod global;
mod intervention;
mod observability;
mod pool;
mod rules;
mod scanner;
mod string_extractor;
mod transaction;

#[cfg(test)]
mod crs_tests;

// Public API
pub use base64_detector::is_likely_base64;
pub use config::{
    ModSecurityConfig, RemoteRulesConfig, RulesetConfig, ScanAction, ScannerPoolConfig,
    StringExtractorConfig, TimeoutAction,
};
pub use engine::ModSecurityEngine;
pub use error::{ModSecError, ModSecResult};
pub use intervention::{Intervention, MatchedRule};
pub use observability::{
    set_modsec_request_metadata, set_modsec_response_metadata, MetadataSetter, ModSecMetrics,
};
pub use pool::{ScanJob, ScanPayload, ScanResult, ScanType, ScannerPool};
pub use rules::RulesSet;
pub use scanner::{DualRulesetScanner, DualScanResult};
pub use string_extractor::{extract_strings, ExtractionResult};
pub use transaction::Transaction;
