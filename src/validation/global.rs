//! Global validation thread pool singleton
//!
//! Provides a single shared validation pool for all API filter instances,
//! eliminating per-API thread pool creation and reducing total thread count.
//!
//! Thread count is controlled by the `API_FENCE_VALIDATION_THREADS` environment
//! variable, defaulting to the number of available CPUs.

use crate::config::CacheConfig;
use crate::validation::pool::{ValidationPool, ValidationPoolConfig};
use std::sync::OnceLock;

/// Global validation thread pool, initialized once on first access.
static GLOBAL_VALIDATION_POOL: OnceLock<ValidationPool> = OnceLock::new();

/// Get or initialize the global validation thread pool.
///
/// The pool is created on first call and reused for all subsequent calls.
/// Thread count is determined by:
/// 1. `API_FENCE_VALIDATION_THREADS` environment variable (if set)
/// 2. Number of available CPUs (fallback)
///
/// # Returns
///
/// A static reference to the shared validation pool.
pub fn global_validation_pool() -> &'static ValidationPool {
    GLOBAL_VALIDATION_POOL.get_or_init(|| {
        let thread_count = resolve_validation_thread_count();

        let pool_config = ValidationPoolConfig {
            enabled: true,
            timeout_ms: 50,
            queue_capacity: 1000,
            ..Default::default()
        };

        let cache_config = CacheConfig::default();

        // The pool is created with the resolved thread count passed directly
        ValidationPool::new(thread_count, &pool_config, &cache_config)
            .unwrap_or_else(|e| panic!("failed to initialize global validation pool: {}", e))
    })
}

/// Resolve the validation thread count from environment or CPU count.
fn resolve_validation_thread_count() -> usize {
    if let Ok(val) = std::env::var("API_FENCE_VALIDATION_THREADS") {
        if let Ok(count) = val.parse::<usize>() {
            if count > 0 {
                return count;
            }
        }
    }

    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}
