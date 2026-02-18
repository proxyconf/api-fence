// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Binary to export JSON Schema for API Fence configuration
//!
//! This binary generates a JSON Schema document from the Config struct,
//! which is used for documentation generation on the ProxyConf website.
//!
//! Usage:
//!   cargo run --bin export-schema > config-schema.json
//!   cargo run --bin export-schema -- --pretty > config-schema.json

use api_fence::config::Config;
use schemars::schema_for;
use std::env;

fn main() {
    let schema = schema_for!(Config);

    // Check for --pretty flag
    let pretty = env::args().any(|arg| arg == "--pretty" || arg == "-p");

    let output = if pretty {
        serde_json::to_string_pretty(&schema).expect("Failed to serialize schema")
    } else {
        serde_json::to_string(&schema).expect("Failed to serialize schema")
    };

    println!("{}", output);
}
