//! Schema compilation
//!
//! This module handles JSON Schema compilation and validation.

use crate::error::SchemaError;
use crate::schema::cache::{CompiledSchema, SchemaCache};
use crate::security::{self, SecurityLimits};
use openapiv3::Schema;
use std::sync::Arc;
use std::time::Instant;

/// Default maximum schema complexity (number of nodes)
const DEFAULT_MAX_SCHEMA_COMPLEXITY: usize = 1000;

/// Schema compiler with caching support
pub struct SchemaCompiler {
    cache: SchemaCache,
}

/// Result of a schema lookup/compilation
pub struct CompileResult {
    /// The compiled schema
    pub schema: CompiledSchema,
    /// Whether this was a cache hit
    pub cache_hit: bool,
    /// Compilation time in milliseconds (0 if cache hit)
    pub compile_time_ms: u64,
}

impl SchemaCompiler {
    /// Create a new schema compiler with the given cache
    pub fn new(cache: SchemaCache) -> Self {
        Self { cache }
    }

    /// Get a compiled schema from cache, or compile and cache it
    ///
    /// Returns the compiled schema along with cache hit information.
    pub fn get_or_compile(&self, schema: &Schema) -> Result<CompileResult, SchemaError> {
        self.get_or_compile_with_limits(schema, None)
    }

    /// Get a compiled schema with security limits applied
    ///
    /// This version checks schema complexity before compilation.
    pub fn get_or_compile_with_limits(
        &self,
        schema: &Schema,
        security_limits: Option<&SecurityLimits>,
    ) -> Result<CompileResult, SchemaError> {
        let cache_key = SchemaCache::schema_key(schema)?;

        // Try cache first
        if let Some(validator) = self.cache.get(cache_key) {
            return Ok(CompileResult {
                schema: validator,
                cache_hit: true,
                compile_time_ms: 0,
            });
        }

        // Security check: Estimate schema complexity before compilation
        let max_depth = security_limits.map(|l| l.max_schema_depth).unwrap_or(32);
        let max_complexity = DEFAULT_MAX_SCHEMA_COMPLEXITY;

        let complexity = security::estimate_schema_complexity(schema, max_depth);
        if complexity > max_complexity {
            return Err(SchemaError::CompilationError {
                message: format!(
                    "Schema too complex: {} nodes exceeds limit of {} nodes",
                    complexity, max_complexity
                ),
            });
        }

        // Cache miss - compile the schema
        let compile_start = Instant::now();

        let schema_json =
            serde_json::to_value(schema).map_err(|e| SchemaError::SerializationError {
                message: e.to_string(),
            })?;

        let validator = jsonschema::JSONSchema::compile(&schema_json).map_err(|e| {
            SchemaError::CompilationError {
                message: e.to_string(),
            }
        })?;

        let compile_time_ms = compile_start.elapsed().as_millis() as u64;
        let validator_arc = Arc::new(validator);

        // Store in cache
        self.cache.insert(cache_key, validator_arc.clone());

        Ok(CompileResult {
            schema: validator_arc,
            cache_hit: false,
            compile_time_ms,
        })
    }

    /// Validate a JSON value against a schema
    ///
    /// Returns Ok(()) if valid, or a list of error messages if invalid.
    pub fn validate(&self, value: &serde_json::Value, schema: &Schema) -> Result<(), Vec<String>> {
        let compile_result = self
            .get_or_compile(schema)
            .map_err(|e| vec![e.to_string()])?;

        let validation_result = compile_result.schema.validate(value);
        let result = match validation_result {
            Ok(()) => Ok(()),
            Err(errors) => {
                let error_msgs: Vec<String> = errors
                    .map(|e| format!("{} at {}", e, e.instance_path))
                    .collect();
                Err(error_msgs)
            }
        };
        result
    }

    /// Get a reference to the underlying cache
    pub fn cache(&self) -> &SchemaCache {
        &self.cache
    }
}

impl Clone for SchemaCompiler {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CacheConfig;
    use openapiv3::{SchemaKind, StringType, Type};

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

    fn make_enum_schema(values: Vec<&str>) -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                enumeration: values.into_iter().map(|v| Some(v.to_string())).collect(),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn test_compiler_compile_and_cache() {
        let cache = SchemaCache::new(&CacheConfig::default());
        let compiler = SchemaCompiler::new(cache);

        let schema = make_string_schema();

        // First call - cache miss
        let result1 = compiler.get_or_compile(&schema).unwrap();
        assert!(!result1.cache_hit);

        // Second call - cache hit
        let result2 = compiler.get_or_compile(&schema).unwrap();
        assert!(result2.cache_hit);
        assert_eq!(result2.compile_time_ms, 0);
    }

    #[test]
    fn test_compiler_validate_valid() {
        let cache = SchemaCache::new(&CacheConfig::default());
        let compiler = SchemaCompiler::new(cache);

        let schema = make_string_schema();
        let value = serde_json::json!("hello");

        let result = compiler.validate(&value, &schema);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compiler_validate_invalid() {
        let cache = SchemaCache::new(&CacheConfig::default());
        let compiler = SchemaCompiler::new(cache);

        let schema = make_integer_schema();
        let value = serde_json::json!("not an integer");

        let result = compiler.validate(&value, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_compiler_validate_enum() {
        let cache = SchemaCache::new(&CacheConfig::default());
        let compiler = SchemaCompiler::new(cache);

        let schema = make_enum_schema(vec!["active", "inactive"]);

        // Valid enum value
        let result = compiler.validate(&serde_json::json!("active"), &schema);
        assert!(result.is_ok());

        // Invalid enum value
        let result = compiler.validate(&serde_json::json!("unknown"), &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_compiler_different_schemas() {
        let cache = SchemaCache::new(&CacheConfig::default());
        let compiler = SchemaCompiler::new(cache);

        let string_schema = make_string_schema();
        let integer_schema = make_integer_schema();

        compiler.get_or_compile(&string_schema).unwrap();
        compiler.get_or_compile(&integer_schema).unwrap();

        // Sync pending tasks to update entry_count
        compiler.cache().sync();

        // Both should be cached
        assert_eq!(compiler.cache().len(), 2);
    }

    #[test]
    fn test_compiler_clone() {
        let cache = SchemaCache::new(&CacheConfig::default());
        let compiler1 = SchemaCompiler::new(cache);

        let schema = make_string_schema();
        compiler1.get_or_compile(&schema).unwrap();

        let compiler2 = compiler1.clone();

        // Cloned compiler shares the cache
        let result = compiler2.get_or_compile(&schema).unwrap();
        assert!(result.cache_hit);
    }
}
