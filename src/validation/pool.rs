// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Thread pool for JSON Schema validation
//!
//! This module provides a thread pool for executing JSON Schema compilation
//! and validation operations without blocking Envoy worker threads.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      ValidationPool                          │
//! │  ┌───────────┐    ┌──────────────────────────────────────┐  │
//! │  │ Job Queue │───>│ Worker Threads                        │  │
//! │  │ (mpsc)    │    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ │  │
//! │  └───────────┘    │  │Worker 1 │ │Worker 2 │ │Worker N │ │  │
//! │                   │  │(Cache)  │ │(Cache)  │ │(Cache)  │ │  │
//! │                   │  └─────────┘ └─────────┘ └─────────┘ │  │
//! │                   └──────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! - `ValidationPool` is `Send + Sync` and can be shared via `Arc`
//! - Jobs are submitted via channel and processed by worker threads
//! - The schema cache (moka) is already thread-safe and shared across workers
//! - Results are returned via mpsc sync channels

use crate::config::CacheConfig;
use crate::schema::{SchemaCache, SchemaCompiler};
use crate::security::SecurityLimits;
use openapiv3::Schema;
use schemars::JsonSchema;
use serde::Deserialize;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Configuration for the validation thread pool
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[schemars(title = "Validation Pool Configuration")]
pub struct ValidationPoolConfig {
    /// Whether the pool is enabled (default: false)
    ///
    /// When disabled, validation runs synchronously on the Envoy worker thread.
    #[serde(default)]
    pub enabled: bool,

    /// Number of worker threads (default: 2)
    #[serde(default = "default_thread_count")]
    pub thread_count: usize,

    /// Maximum time to wait for validation in milliseconds (default: 50)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum job queue capacity (default: 1000)
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,

    /// Action to take when validation times out
    #[serde(default)]
    pub timeout_action: ValidationTimeoutAction,
}

fn default_thread_count() -> usize {
    2
}

fn default_timeout_ms() -> u64 {
    50
}

fn default_queue_capacity() -> usize {
    1000
}

impl Default for ValidationPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            thread_count: default_thread_count(),
            timeout_ms: default_timeout_ms(),
            queue_capacity: default_queue_capacity(),
            timeout_action: ValidationTimeoutAction::default(),
        }
    }
}

impl ValidationPoolConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.thread_count == 0 {
            return Err("thread_count must be at least 1 when pool is enabled".to_string());
        }
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// Action to take when validation times out
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ValidationTimeoutAction {
    /// Allow the request/response through (log warning)
    #[default]
    Allow,
    /// Block the request/response with an error
    Block,
}

/// Type of validation job
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationJobType {
    /// Validate a request body
    RequestBody,
    /// Validate a response body
    ResponseBody,
    /// Validate a parameter (query, path, header)
    Parameter,
}

/// A validation job to be processed by a worker
pub struct ValidationJob {
    /// Type of validation
    pub job_type: ValidationJobType,

    /// The JSON value to validate
    pub value: serde_json::Value,

    /// The schema to validate against (serialized for thread safety)
    pub schema: Schema,

    /// Optional security limits for schema complexity checking
    pub security_limits: Option<SecurityLimits>,

    /// Channel to send the result back
    pub result_sender: SyncSender<ValidationResult>,
}

/// Result of a validation operation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether validation passed
    pub valid: bool,

    /// Validation errors (if any)
    pub errors: Vec<String>,

    /// Time taken to validate in milliseconds
    pub validation_time_ms: u64,

    /// Whether the validation timed out
    pub timed_out: bool,

    /// Whether this was a cache hit for schema compilation
    pub cache_hit: bool,

    /// Schema compile time in milliseconds (0 if cache hit or timeout)
    pub compile_time_ms: u64,
}

impl ValidationResult {
    /// Create a timeout result
    fn timeout(timeout_ms: u64) -> Self {
        Self {
            valid: false,
            errors: vec!["Validation timed out".to_string()],
            validation_time_ms: timeout_ms,
            timed_out: true,
            cache_hit: false,
            compile_time_ms: 0,
        }
    }

    /// Create an error result
    fn error(message: String) -> Self {
        Self {
            valid: false,
            errors: vec![message],
            validation_time_ms: 0,
            timed_out: false,
            cache_hit: false,
            compile_time_ms: 0,
        }
    }

    /// Create a success result
    fn success(validation_time_ms: u64, cache_hit: bool, compile_time_ms: u64) -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            validation_time_ms,
            timed_out: false,
            cache_hit,
            compile_time_ms,
        }
    }

    /// Create a validation failed result
    fn failed(
        errors: Vec<String>,
        validation_time_ms: u64,
        cache_hit: bool,
        compile_time_ms: u64,
    ) -> Self {
        Self {
            valid: false,
            errors,
            validation_time_ms,
            timed_out: false,
            cache_hit,
            compile_time_ms,
        }
    }
}

/// Message sent to worker threads
enum WorkerMessage {
    /// A job to process
    Job(Box<ValidationJob>),
    /// Shutdown signal
    Shutdown,
}

/// Thread pool for JSON Schema validation
///
/// The pool manages worker threads that share a thread-safe schema cache.
/// Jobs are distributed to workers via a shared queue.
pub struct ValidationPool {
    /// Sender for submitting jobs
    job_sender: Sender<WorkerMessage>,

    /// Worker thread handles
    workers: Vec<JoinHandle<()>>,

    /// Configuration
    config: ValidationPoolConfig,

    /// Shared schema compiler (for sync fallback and cache access)
    schema_compiler: SchemaCompiler,
}

// Safety: ValidationPool can be sent between threads
unsafe impl Send for ValidationPool {}
// Safety: ValidationPool can be shared between threads (uses channels and thread-safe cache)
unsafe impl Sync for ValidationPool {}

impl ValidationPool {
    /// Create a new validation pool
    ///
    /// # Arguments
    ///
    /// * `thread_count` - Number of worker threads to spawn
    /// * `pool_config` - Thread pool configuration (timeout, queue settings)
    /// * `cache_config` - Cache configuration for schema caching
    ///
    /// # Errors
    ///
    /// Returns an error if workers cannot be started.
    pub fn new(
        thread_count: usize,
        pool_config: &ValidationPoolConfig,
        cache_config: &CacheConfig,
    ) -> Result<Self, String> {
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));

        // Create shared schema cache (moka is thread-safe)
        let schema_cache = SchemaCache::new(cache_config);
        let schema_compiler = SchemaCompiler::new(schema_cache.clone());

        // Start worker threads
        let mut workers = Vec::with_capacity(thread_count);

        for worker_id in 0..thread_count {
            let receiver = Arc::clone(&receiver);
            let compiler = schema_compiler.clone();

            let handle = thread::Builder::new()
                .name(format!("validation-worker-{}", worker_id))
                .spawn(move || {
                    worker_loop(receiver, compiler);
                })
                .map_err(|e| format!("failed to spawn validation worker thread: {}", e))?;

            workers.push(handle);
        }

        Ok(Self {
            job_sender: sender,
            workers,
            config: pool_config.clone(),
            schema_compiler,
        })
    }

    /// Submit a validation job to the pool
    ///
    /// This is non-blocking - the job is queued and a receiver
    /// is returned for getting the result.
    ///
    /// # Arguments
    ///
    /// * `job_type` - Type of validation job
    /// * `value` - JSON value to validate
    /// * `schema` - Schema to validate against
    /// * `security_limits` - Optional security limits
    ///
    /// # Returns
    ///
    /// A receiver for the validation result.
    ///
    /// # Errors
    ///
    /// Returns an error if the pool has been shut down.
    pub fn submit(
        &self,
        job_type: ValidationJobType,
        value: serde_json::Value,
        schema: Schema,
        security_limits: Option<SecurityLimits>,
    ) -> Result<mpsc::Receiver<ValidationResult>, String> {
        let (result_sender, result_receiver) = mpsc::sync_channel(1);

        let job = ValidationJob {
            job_type,
            value,
            schema,
            security_limits,
            result_sender,
        };

        self.job_sender
            .send(WorkerMessage::Job(Box::new(job)))
            .map_err(|_| "validation pool has been shut down".to_string())?;

        Ok(result_receiver)
    }

    /// Submit a validation job and block until completion or timeout
    ///
    /// # Arguments
    ///
    /// * `job_type` - Type of validation job
    /// * `value` - JSON value to validate
    /// * `schema` - Schema to validate against
    /// * `security_limits` - Optional security limits
    ///
    /// # Returns
    ///
    /// The validation result.
    pub fn validate_blocking(
        &self,
        job_type: ValidationJobType,
        value: serde_json::Value,
        schema: Schema,
        security_limits: Option<SecurityLimits>,
    ) -> ValidationResult {
        match self.submit(job_type, value, schema, security_limits) {
            Ok(receiver) => {
                let timeout = Duration::from_millis(self.config.timeout_ms);
                match receiver.recv_timeout(timeout) {
                    Ok(result) => result,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        ValidationResult::timeout(self.config.timeout_ms)
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        ValidationResult::error("Worker disconnected".to_string())
                    }
                }
            }
            Err(e) => ValidationResult::error(e),
        }
    }

    /// Validate synchronously using the shared schema compiler
    ///
    /// This bypasses the thread pool and validates directly.
    /// Useful when the pool is disabled or for fallback scenarios.
    pub fn validate_sync(
        &self,
        value: &serde_json::Value,
        schema: &Schema,
        security_limits: Option<&SecurityLimits>,
    ) -> ValidationResult {
        let start = Instant::now();

        let compile_result = match self
            .schema_compiler
            .get_or_compile_with_limits(schema, security_limits)
        {
            Ok(r) => r,
            Err(e) => {
                return ValidationResult::error(format!("Schema compilation failed: {}", e));
            }
        };

        let validation_result = compile_result.schema.validate(value);
        let duration_ms = start.elapsed().as_millis() as u64;

        match validation_result {
            Ok(()) => ValidationResult::success(
                duration_ms,
                compile_result.cache_hit,
                compile_result.compile_time_ms,
            ),
            Err(errors) => {
                let error_msgs: Vec<String> = errors
                    .map(|e| format!("{} at {}", e, e.instance_path))
                    .collect();
                ValidationResult::failed(
                    error_msgs,
                    duration_ms,
                    compile_result.cache_hit,
                    compile_result.compile_time_ms,
                )
            }
        }
    }

    /// Get a reference to the underlying schema compiler
    pub fn schema_compiler(&self) -> &SchemaCompiler {
        &self.schema_compiler
    }

    /// Get the configuration
    pub fn config(&self) -> &ValidationPoolConfig {
        &self.config
    }

    /// Check if the pool is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Shut down the pool and wait for workers to finish
    pub fn shutdown(self) {
        // Send shutdown signal to all workers
        for _ in 0..self.workers.len() {
            let _ = self.job_sender.send(WorkerMessage::Shutdown);
        }

        // Wait for workers to finish
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

/// Worker loop - processes jobs until shutdown
fn worker_loop(receiver: Arc<Mutex<Receiver<WorkerMessage>>>, compiler: SchemaCompiler) {
    loop {
        // Get next job from the queue
        let message = {
            let rx = match receiver.lock() {
                Ok(rx) => rx,
                Err(_) => return, // Mutex poisoned, exit
            };
            rx.recv()
        };

        match message {
            Ok(WorkerMessage::Job(job)) => {
                let result = process_validation_job(&job, &compiler);

                // Send result back (ignore send errors - receiver may have dropped)
                let _ = job.result_sender.send(result);
            }
            Ok(WorkerMessage::Shutdown) | Err(_) => {
                // Shutdown or channel closed
                return;
            }
        }
    }
}

/// Process a single validation job
fn process_validation_job(job: &ValidationJob, compiler: &SchemaCompiler) -> ValidationResult {
    let start = Instant::now();

    // Compile schema (may be cached)
    let compile_result =
        match compiler.get_or_compile_with_limits(&job.schema, job.security_limits.as_ref()) {
            Ok(r) => r,
            Err(e) => {
                return ValidationResult::error(format!("Schema compilation failed: {}", e));
            }
        };

    // Validate the value
    let validation_result = compile_result.schema.validate(&job.value);
    let duration_ms = start.elapsed().as_millis() as u64;

    match validation_result {
        Ok(()) => ValidationResult::success(
            duration_ms,
            compile_result.cache_hit,
            compile_result.compile_time_ms,
        ),
        Err(errors) => {
            let error_msgs: Vec<String> = errors
                .map(|e| format!("{} at {}", e, e.instance_path))
                .collect();
            ValidationResult::failed(
                error_msgs,
                duration_ms,
                compile_result.cache_hit,
                compile_result.compile_time_ms,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapiv3::{SchemaKind, Type};

    fn make_string_schema() -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(Default::default())),
        }
    }

    fn make_integer_schema() -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::Integer(Default::default())),
        }
    }

    #[test]
    fn test_validation_pool_config_default() {
        let config = ValidationPoolConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.thread_count, 2);
        assert_eq!(config.timeout_ms, 50);
        assert_eq!(config.queue_capacity, 1000);
        assert_eq!(config.timeout_action, ValidationTimeoutAction::Allow);
    }

    #[test]
    fn test_validation_pool_config_validate() {
        let mut config = ValidationPoolConfig::default();

        // Valid config (disabled)
        assert!(config.validate().is_ok());

        // Invalid: enabled with 0 threads
        config.enabled = true;
        config.thread_count = 0;
        assert!(config.validate().is_err());

        // Valid: enabled with threads
        config.thread_count = 2;
        assert!(config.validate().is_ok());

        // Invalid: 0 timeout
        config.timeout_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_result_success() {
        let result = ValidationResult::success(10, true, 0);
        assert!(result.valid);
        assert!(result.errors.is_empty());
        assert!(!result.timed_out);
        assert!(result.cache_hit);
    }

    #[test]
    fn test_validation_result_failed() {
        let result = ValidationResult::failed(vec!["error1".to_string()], 10, false, 5);
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(!result.timed_out);
    }

    #[test]
    fn test_validation_result_timeout() {
        let result = ValidationResult::timeout(50);
        assert!(!result.valid);
        assert!(result.timed_out);
        assert_eq!(result.validation_time_ms, 50);
    }

    #[test]
    fn test_validation_pool_sync_valid() {
        let pool_config = ValidationPoolConfig {
            enabled: true,
            thread_count: 1,
            timeout_ms: 100,
            ..Default::default()
        };
        let cache_config = CacheConfig::default();

        let pool = ValidationPool::new(1, &pool_config, &cache_config).unwrap();
        let schema = make_string_schema();
        let value = serde_json::json!("hello");

        let result = pool.validate_sync(&value, &schema, None);
        assert!(result.valid);
        assert!(result.errors.is_empty());

        pool.shutdown();
    }

    #[test]
    fn test_validation_pool_sync_invalid() {
        let pool_config = ValidationPoolConfig {
            enabled: true,
            thread_count: 1,
            timeout_ms: 100,
            ..Default::default()
        };
        let cache_config = CacheConfig::default();

        let pool = ValidationPool::new(1, &pool_config, &cache_config).unwrap();
        let schema = make_integer_schema();
        let value = serde_json::json!("not an integer");

        let result = pool.validate_sync(&value, &schema, None);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());

        pool.shutdown();
    }

    #[test]
    fn test_validation_pool_blocking_valid() {
        let pool_config = ValidationPoolConfig {
            enabled: true,
            thread_count: 2,
            timeout_ms: 1000,
            ..Default::default()
        };
        let cache_config = CacheConfig::default();

        let pool = ValidationPool::new(2, &pool_config, &cache_config).unwrap();
        let schema = make_string_schema();
        let value = serde_json::json!("hello");

        let result =
            pool.validate_blocking(ValidationJobType::RequestBody, value, schema.clone(), None);
        assert!(result.valid);

        // Second call should hit cache
        let result2 = pool.validate_blocking(
            ValidationJobType::RequestBody,
            serde_json::json!("world"),
            schema,
            None,
        );
        assert!(result2.valid);
        assert!(result2.cache_hit);

        pool.shutdown();
    }

    #[test]
    fn test_validation_pool_blocking_invalid() {
        let pool_config = ValidationPoolConfig {
            enabled: true,
            thread_count: 2,
            timeout_ms: 1000,
            ..Default::default()
        };
        let cache_config = CacheConfig::default();

        let pool = ValidationPool::new(2, &pool_config, &cache_config).unwrap();
        let schema = make_integer_schema();
        let value = serde_json::json!("not an integer");

        let result = pool.validate_blocking(ValidationJobType::RequestBody, value, schema, None);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());

        pool.shutdown();
    }

    #[test]
    fn test_validation_job_type() {
        assert_eq!(
            ValidationJobType::RequestBody,
            ValidationJobType::RequestBody
        );
        assert_ne!(
            ValidationJobType::RequestBody,
            ValidationJobType::ResponseBody
        );
        assert_ne!(
            ValidationJobType::ResponseBody,
            ValidationJobType::Parameter
        );
    }

    #[test]
    fn test_validation_pool_multiple_jobs() {
        let pool_config = ValidationPoolConfig {
            enabled: true,
            thread_count: 4,
            timeout_ms: 1000,
            ..Default::default()
        };
        let cache_config = CacheConfig::default();

        let pool = ValidationPool::new(4, &pool_config, &cache_config).unwrap();
        let schema = make_string_schema();

        // Submit multiple jobs
        let mut results = Vec::new();
        for i in 0..10 {
            let value = serde_json::json!(format!("value{}", i));
            let result =
                pool.validate_blocking(ValidationJobType::RequestBody, value, schema.clone(), None);
            results.push(result);
        }

        // All should be valid
        for result in results {
            assert!(result.valid);
        }

        pool.shutdown();
    }
}
