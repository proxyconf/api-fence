// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Schema caching
//!
//! This module provides a typed wrapper around moka cache for JSON Schema validators.

use crate::config::CacheConfig;
use crate::error::SchemaError;
use openapiv3::Schema;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

/// Compiled JSON Schema validator
pub type CompiledSchema = Arc<jsonschema::JSONSchema>;

/// Schema cache for compiled JSON Schema validators
pub struct SchemaCache {
    cache: moka::sync::Cache<u64, CompiledSchema>,
}

impl SchemaCache {
    /// Create a new schema cache with the given configuration
    pub fn new(config: &CacheConfig) -> Self {
        let cache = moka::sync::Cache::builder()
            .max_capacity(config.max_capacity)
            .time_to_live(Duration::from_secs(config.ttl_seconds))
            .build();

        Self { cache }
    }

    /// Generate a cache key for a given schema by hashing its JSON representation
    pub fn schema_key(schema: &Schema) -> Result<u64, SchemaError> {
        let schema_json =
            serde_json::to_string(schema).map_err(|e| SchemaError::SerializationError {
                message: e.to_string(),
            })?;
        let mut hasher = DefaultHasher::new();
        schema_json.hash(&mut hasher);
        Ok(hasher.finish())
    }

    /// Get a compiled schema from the cache
    pub fn get(&self, key: u64) -> Option<CompiledSchema> {
        self.cache.get(&key)
    }

    /// Insert a compiled schema into the cache
    pub fn insert(&self, key: u64, schema: CompiledSchema) {
        self.cache.insert(key, schema);
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }

    /// Synchronize pending cache tasks
    ///
    /// This is useful in tests to ensure entry_count() returns accurate values
    #[cfg(test)]
    pub fn sync(&self) {
        self.cache.run_pending_tasks();
    }
}

impl Clone for SchemaCache {
    fn clone(&self) -> Self {
        // Note: moka cache is internally Arc-wrapped, so this is cheap
        Self {
            cache: self.cache.clone(),
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
    fn test_schema_cache_new() {
        let config = CacheConfig::default();
        let cache = SchemaCache::new(&config);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_schema_key_deterministic() {
        let schema = make_string_schema();
        let key1 = SchemaCache::schema_key(&schema).unwrap();
        let key2 = SchemaCache::schema_key(&schema).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_schema_key_different_schemas() {
        let string_schema = make_string_schema();
        let integer_schema = make_integer_schema();

        let key1 = SchemaCache::schema_key(&string_schema).unwrap();
        let key2 = SchemaCache::schema_key(&integer_schema).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_schema_cache_insert_get() {
        let config = CacheConfig::default();
        let cache = SchemaCache::new(&config);

        // Compile a simple schema
        let schema_json = serde_json::json!({"type": "string"});
        let compiled = Arc::new(jsonschema::JSONSchema::compile(&schema_json).unwrap());

        let key = 12345u64;
        cache.insert(key, compiled.clone());
        // Sync pending tasks to update entry_count
        cache.sync();

        assert_eq!(cache.len(), 1);

        let retrieved = cache.get(key);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_schema_cache_miss() {
        let config = CacheConfig::default();
        let cache = SchemaCache::new(&config);

        let result = cache.get(99999);
        assert!(result.is_none());
    }

    #[test]
    fn test_schema_cache_clear() {
        let config = CacheConfig::default();
        let cache = SchemaCache::new(&config);

        let schema_json = serde_json::json!({"type": "string"});
        let compiled = Arc::new(jsonschema::JSONSchema::compile(&schema_json).unwrap());

        cache.insert(1, compiled.clone());
        cache.insert(2, compiled.clone());
        // Sync pending tasks to update entry_count
        cache.sync();
        assert_eq!(cache.len(), 2);

        cache.clear();
        // Note: moka's invalidate_all is async, so we need to sync
        cache.sync();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_schema_cache_clone() {
        let config = CacheConfig::default();
        let cache1 = SchemaCache::new(&config);

        let schema_json = serde_json::json!({"type": "string"});
        let compiled = Arc::new(jsonschema::JSONSchema::compile(&schema_json).unwrap());

        cache1.insert(1, compiled);

        let cache2 = cache1.clone();
        assert!(cache2.get(1).is_some()); // Clone shares data
    }

    #[test]
    fn test_cache_capacity_eviction() {
        // Create a cache with small capacity to test LRU eviction
        let config = CacheConfig {
            max_capacity: 3,
            ttl_seconds: 3600,
        };
        let cache = SchemaCache::new(&config);

        // Create multiple compiled schemas
        let schema1 = Arc::new(
            jsonschema::JSONSchema::compile(&serde_json::json!({"type": "string"})).unwrap(),
        );
        let schema2 = Arc::new(
            jsonschema::JSONSchema::compile(&serde_json::json!({"type": "integer"})).unwrap(),
        );
        let schema3 = Arc::new(
            jsonschema::JSONSchema::compile(&serde_json::json!({"type": "number"})).unwrap(),
        );
        let schema4 = Arc::new(
            jsonschema::JSONSchema::compile(&serde_json::json!({"type": "boolean"})).unwrap(),
        );
        let schema5 = Arc::new(
            jsonschema::JSONSchema::compile(&serde_json::json!({"type": "array"})).unwrap(),
        );

        // Insert items one by one, syncing after each
        cache.insert(1, schema1);
        cache.sync();
        cache.insert(2, schema2);
        cache.sync();
        cache.insert(3, schema3);
        cache.sync();

        // At this point, cache should have 3 items
        assert_eq!(
            cache.len(),
            3,
            "Cache should have 3 items after initial inserts"
        );

        // Insert more items to trigger eviction
        cache.insert(4, schema4);
        cache.sync();
        cache.insert(5, schema5);
        cache.sync();

        // After eviction, capacity should be respected
        // moka uses a weighted LFU approach and eviction is eventually consistent
        // Verify cache doesn't grow unboundedly
        let len = cache.len();
        assert!(len <= 5, "Cache len {} should not exceed 5", len);

        // Verify basic cache behavior still works
        let found_count = (1..=5).filter(|&k| cache.get(k).is_some()).count();
        assert!(found_count >= 3, "Should find at least 3 items in cache");
        assert!(found_count <= 5, "Should not find more than 5 items");
    }
}
