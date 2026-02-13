//! ModSecurity error types
//!
//! This module defines error types for all ModSecurity operations.

use thiserror::Error;

/// Result type for ModSecurity operations
pub type ModSecResult<T> = Result<T, ModSecError>;

/// Errors that can occur during ModSecurity operations
#[derive(Debug, Error)]
pub enum ModSecError {
    /// Failed to initialize the ModSecurity engine
    #[error("failed to initialize ModSecurity engine")]
    InitializationFailed,

    /// Failed to create rules set
    #[error("failed to create rules set")]
    RulesSetCreationFailed,

    /// Failed to load rules from file
    #[error("failed to load rules from '{path}': {message}")]
    RulesLoadError {
        /// Path to the rules file
        path: String,
        /// Error message from ModSecurity
        message: String,
    },

    /// Failed to load rules from remote URL
    #[error("failed to load rules from remote '{uri}': {message}")]
    RemoteRulesLoadError {
        /// URI of the remote rules
        uri: String,
        /// Error message from ModSecurity
        message: String,
    },

    /// Failed to parse inline rules
    #[error("failed to parse inline rules: {message}")]
    InlineRulesParseError {
        /// Error message from ModSecurity
        message: String,
    },

    /// Failed to create transaction
    #[error("failed to create transaction")]
    TransactionCreationFailed,

    /// Failed to process connection info
    #[error("failed to process connection info")]
    ConnectionProcessingFailed,

    /// Failed to process URI
    #[error("failed to process URI '{uri}'")]
    UriProcessingFailed {
        /// The URI that failed processing
        uri: String,
    },

    /// Failed to process request headers
    #[error("failed to process request headers")]
    RequestHeadersProcessingFailed,

    /// Failed to process request body
    #[error("failed to process request body")]
    RequestBodyProcessingFailed,

    /// Failed to process response headers
    #[error("failed to process response headers")]
    ResponseHeadersProcessingFailed,

    /// Failed to process response body
    #[error("failed to process response body")]
    ResponseBodyProcessingFailed,

    /// Scan timeout exceeded
    #[error("scan timeout exceeded ({timeout_ms}ms)")]
    ScanTimeout {
        /// Configured timeout in milliseconds
        timeout_ms: u64,
    },

    /// Thread pool error
    #[error("scanner pool error: {message}")]
    PoolError {
        /// Error description
        message: String,
    },

    /// Invalid configuration
    #[error("invalid ModSecurity configuration: {message}")]
    ConfigurationError {
        /// Error description
        message: String,
    },

    /// Glob pattern error when loading multiple rule files
    #[error("invalid glob pattern '{pattern}': {message}")]
    GlobPatternError {
        /// The glob pattern that failed
        pattern: String,
        /// Error message
        message: String,
    },

    /// No rules loaded
    #[error("no rules loaded - at least one ruleset must be configured")]
    NoRulesLoaded,
}
