// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Global ModSecurity singletons
//!
//! Provides shared global resources for all API filter instances:
//! - Single ModSecurity engine
//! - Rules registry (deduplicates identical rulesets across APIs)
//! - Single scanner thread pool
//!
//! Thread count is controlled by the `API_FENCE_MODSEC_THREADS` environment
//! variable, defaulting to the number of available CPUs.

use crate::modsec::config::RulesetConfig;
use crate::modsec::engine::ModSecurityEngine;
use crate::modsec::error::{ModSecError, ModSecResult};
use crate::modsec::pool::ScannerPool;
use crate::modsec::rules::RulesSet;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

/// Global ModSecurity engine, initialized once on first access.
static GLOBAL_ENGINE: OnceLock<Arc<ModSecurityEngine>> = OnceLock::new();

/// Global rules registry: maps config hash -> compiled ruleset.
/// Deduplicates identical rulesets across multiple API filter instances.
static RULES_REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<RulesSet>>>> = OnceLock::new();

/// Global ModSecurity scanner thread pool, shared by all APIs.
static GLOBAL_SCANNER_POOL: OnceLock<ScannerPool> = OnceLock::new();

/// Get or initialize the global ModSecurity engine.
pub fn global_modsec_engine() -> &'static Arc<ModSecurityEngine> {
    GLOBAL_ENGINE.get_or_init(|| {
        Arc::new(
            ModSecurityEngine::new("api_fence/1.0").unwrap_or_else(|e| {
                panic!("failed to initialize global ModSecurity engine: {}", e)
            }),
        )
    })
}

/// Get or initialize the global scanner thread pool.
///
/// Thread count is determined by:
/// 1. `API_FENCE_MODSEC_THREADS` environment variable (if set)
/// 2. Number of available CPUs (fallback)
pub fn global_scanner_pool() -> &'static ScannerPool {
    GLOBAL_SCANNER_POOL.get_or_init(|| {
        let thread_count = resolve_modsec_thread_count();
        ScannerPool::new(thread_count)
            .unwrap_or_else(|e| panic!("failed to initialize global scanner pool: {}", e))
    })
}

/// Get or compile a ruleset, returning a shared reference.
///
/// If a ruleset with the same configuration has already been compiled,
/// the cached `Arc<RulesSet>` is returned. Otherwise, the ruleset is
/// compiled and stored in the registry.
///
/// # Arguments
///
/// * `config` - Ruleset configuration to compile
///
/// # Errors
///
/// Returns an error if rule compilation fails.
pub fn get_or_compile_ruleset(config: &RulesetConfig) -> ModSecResult<Arc<RulesSet>> {
    let config_hash = hash_ruleset_config(config);

    let registry = RULES_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));

    // Check cache first
    {
        let guard = registry.lock().map_err(|_| ModSecError::PoolError {
            message: "rules registry mutex poisoned".to_string(),
        })?;
        if let Some(rules) = guard.get(&config_hash) {
            return Ok(Arc::clone(rules));
        }
    }

    // Cache miss: compile ruleset
    let engine = global_modsec_engine();
    let mut rules = RulesSet::new(Arc::clone(engine))?;

    // Load bundled CRS rules first (if enabled)
    if let Some(bundled_rules) = config.get_bundled_rules() {
        rules.add_inline(bundled_rules)?;
    }

    // Load rules from configured sources
    for path in &config.rules_path {
        rules.add_file(path)?;
    }

    if let Some(ref remote) = config.rules_remote {
        rules.add_remote(&remote.url, remote.key.as_deref())?;
    }

    if let Some(ref inline) = config.rules_inline {
        rules.add_inline(inline)?;
    }

    if rules.rules_count() == 0 {
        return Err(ModSecError::NoRulesLoaded);
    }

    let rules = Arc::new(rules);

    // Store in registry
    {
        let mut guard = registry.lock().map_err(|_| ModSecError::PoolError {
            message: "rules registry mutex poisoned".to_string(),
        })?;
        guard.insert(config_hash, Arc::clone(&rules));
    }

    Ok(rules)
}

/// Compute a hash for a `RulesetConfig` to use as registry key.
fn hash_ruleset_config(config: &RulesetConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    config.name.hash(&mut hasher);
    config.use_bundled_crs.hash(&mut hasher);
    config.bundled_crs_profile.hash(&mut hasher);
    config.rules_path.hash(&mut hasher);
    config.rules_inline.hash(&mut hasher);
    if let Some(ref remote) = config.rules_remote {
        remote.url.hash(&mut hasher);
    }
    hasher.finish()
}

/// Resolve the ModSecurity thread count from environment or CPU count.
fn resolve_modsec_thread_count() -> usize {
    if let Ok(val) = std::env::var("API_FENCE_MODSEC_THREADS") {
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
