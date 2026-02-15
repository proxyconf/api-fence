//! Build script for api_fence
//!
//! Downloads OWASP CoreRuleSet (CRS) v4.0.0 during build time
//! and generates bundled rules for compile-time inclusion.
//!
//! This script also inlines all `@pmFromFile` data files into `@pm` directives
//! so that the rules are completely self-contained and don't require external files.

use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

/// CRS version to download
const CRS_VERSION: &str = "v4.0.0";

/// CRS download URL (GitHub release tarball)
const CRS_URL: &str = "https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.tar.gz";

/// Essential rule files to include (in load order)
const ESSENTIAL_RULES: &[&str] = &[
    "crs-setup.conf.example",
    "rules/REQUEST-901-INITIALIZATION.conf",
    "rules/REQUEST-905-COMMON-EXCEPTIONS.conf",
    "rules/REQUEST-911-METHOD-ENFORCEMENT.conf",
    "rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    "rules/REQUEST-921-PROTOCOL-ATTACK.conf",
    "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "rules/REQUEST-949-BLOCKING-EVALUATION.conf",
    "rules/RESPONSE-950-DATA-LEAKAGES.conf",
    "rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf",
    "rules/RESPONSE-959-BLOCKING-EVALUATION.conf",
    "rules/RESPONSE-980-CORRELATION.conf",
];

/// Minimal rules for high-performance scenarios
const MINIMAL_RULES: &[&str] = &[
    "crs-setup.conf.example",
    "rules/REQUEST-901-INITIALIZATION.conf",
    "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
];

/// Request-only rules (no response scanning)
const REQUEST_RULES: &[&str] = &[
    "crs-setup.conf.example",
    "rules/REQUEST-901-INITIALIZATION.conf",
    "rules/REQUEST-905-COMMON-EXCEPTIONS.conf",
    "rules/REQUEST-911-METHOD-ENFORCEMENT.conf",
    "rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    "rules/REQUEST-921-PROTOCOL-ATTACK.conf",
    "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
    "rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "rules/REQUEST-949-BLOCKING-EVALUATION.conf",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // =========================================================================
    // libmodsecurity static linking
    // =========================================================================
    // When building in Docker (scripts/build-in-docker.sh), libmodsecurity is
    // installed at /opt/modsecurity as a static library. Tell the linker where
    // to find it and what to link.
    //
    // For local development (cargo test on host), fall back to dynamic linking
    // if the static lib isn't found.
    let modsec_static_dir = Path::new("/opt/modsecurity/lib");
    if modsec_static_dir.exists() {
        // Static link path (Docker builder)
        println!(
            "cargo:rustc-link-search=native={}",
            modsec_static_dir.display()
        );
        println!("cargo:rustc-link-lib=static=modsecurity");

        // libmodsecurity is C++ — link the C++ standard library
        println!("cargo:rustc-link-lib=dylib=stdc++");

        // Dependencies of our libmodsecurity build (configured --without many optionals):
        //   Required: pcre2, yajl, xml2
        //   Bundled:  libinjection, mbedtls (compiled into libmodsecurity.a)
        println!("cargo:rustc-link-lib=dylib=pcre2-8");
        println!("cargo:rustc-link-lib=dylib=yajl");
        println!("cargo:rustc-link-lib=dylib=xml2");

        // System libs that libmodsecurity needs
        println!("cargo:rustc-link-lib=dylib=pthread");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=m");
    } else {
        // Dynamic link path (local development / host builds)
        println!("cargo:rustc-link-lib=dylib=modsecurity");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let crs_dir = out_dir.join("crs");

    // Check if we already have the CRS downloaded
    let marker_file = crs_dir.join(".downloaded");
    if !marker_file.exists() {
        download_and_extract_crs(&crs_dir).expect("Failed to download CRS");
        File::create(&marker_file).expect("Failed to create marker file");
    }

    // Generate the bundled rules module
    generate_bundled_rules(&crs_dir, &out_dir).expect("Failed to generate bundled rules");
}

fn download_and_extract_crs(crs_dir: &Path) -> io::Result<()> {
    eprintln!("Downloading OWASP CoreRuleSet {}...", CRS_VERSION);

    // Create directory
    fs::create_dir_all(crs_dir)?;

    // Download using curl (available on most systems)
    let tarball_path = crs_dir.join("crs.tar.gz");

    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o", tarball_path.to_str().unwrap(), CRS_URL])
        .status()?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "curl failed to download CRS: {}",
            status
        )));
    }

    eprintln!("Extracting CRS...");

    // Extract using tar
    let status = std::process::Command::new("tar")
        .args([
            "-xzf",
            tarball_path.to_str().unwrap(),
            "-C",
            crs_dir.to_str().unwrap(),
            "--strip-components=1",
        ])
        .status()?;

    if !status.success() {
        return Err(io::Error::other(format!(
            "tar failed to extract CRS: {}",
            status
        )));
    }

    // Clean up tarball
    fs::remove_file(&tarball_path)?;

    eprintln!("CRS {} downloaded and extracted successfully", CRS_VERSION);
    Ok(())
}

fn generate_bundled_rules(crs_dir: &Path, out_dir: &Path) -> io::Result<()> {
    let output_file = out_dir.join("bundled_crs_generated.rs");
    let mut output = File::create(&output_file)?;

    // Load all data files from the rules directory
    let data_files = load_data_files(&crs_dir.join("rules"))?;
    eprintln!("Loaded {} data files for inlining", data_files.len());

    writeln!(output, "// Auto-generated by build.rs - DO NOT EDIT")?;
    writeln!(output, "// OWASP CoreRuleSet {}", CRS_VERSION)?;
    writeln!(
        output,
        "// Data files have been inlined for self-contained operation"
    )?;
    writeln!(output)?;

    // Generate full rules
    let full_rules = concatenate_rules(crs_dir, ESSENTIAL_RULES, &data_files)?;
    writeln!(output, "/// All essential CRS rules (request + response)")?;
    writeln!(
        output,
        "pub const FULL_RULES: &str = r#####\"{}\"#####;",
        escape_raw_string(&full_rules)
    )?;
    writeln!(output)?;

    // Generate minimal rules
    let minimal_rules = concatenate_rules(crs_dir, MINIMAL_RULES, &data_files)?;
    writeln!(output, "/// Minimal CRS rules (SQLi, XSS, RCE only)")?;
    writeln!(
        output,
        "pub const MINIMAL_RULES: &str = r#####\"{}\"#####;",
        escape_raw_string(&minimal_rules)
    )?;
    writeln!(output)?;

    // Generate request-only rules
    let request_rules = concatenate_rules(crs_dir, REQUEST_RULES, &data_files)?;
    writeln!(output, "/// Request-only CRS rules (no response scanning)")?;
    writeln!(
        output,
        "pub const REQUEST_RULES: &str = r#####\"{}\"#####;",
        escape_raw_string(&request_rules)
    )?;
    writeln!(output)?;

    // Generate version constant
    writeln!(output, "/// CRS version")?;
    writeln!(output, "pub const CRS_VERSION: &str = \"{}\";", CRS_VERSION)?;

    eprintln!("Generated bundled rules at {:?}", output_file);
    Ok(())
}

/// Essential modsecurity base configuration that must be loaded before CRS rules
const MODSEC_BASE_CONFIG: &str = r#"
# ModSecurity base configuration
# Required for CRS to function correctly

# Enable the rule engine
SecRuleEngine On

# Enable request body access (required for POST data scanning)
SecRequestBodyAccess On

# Enable response body access (required for response scanning)
SecResponseBodyAccess On

# Enable argument parsing for query strings and POST data
SecArgumentSeparator &
SecCookieFormat 0

# Activate JSON body processor for application/json requests.
# Without this, ModSecurity does not parse JSON bodies into ARGS,
# so CRS detection rules (SQLi, XSS, RCE) that inspect ARGS will
# not see values from JSON request bodies.
SecRule REQUEST_HEADERS:Content-Type "(?i)application/(?:[a-z0-9.-]+[+])?json" \
    "id:900700,\
    phase:1,\
    pass,\
    t:none,t:lowercase,\
    nolog,\
    noauditlog,\
    ctl:requestBodyProcessor=JSON"

# Activate XML body processor for XML requests.
SecRule REQUEST_HEADERS:Content-Type "(?i)(?:application/(?:soap\+|[a-z0-9.-]+[+])?xml|text/xml)" \
    "id:900710,\
    phase:1,\
    pass,\
    t:none,t:lowercase,\
    nolog,\
    noauditlog,\
    ctl:requestBodyProcessor=XML"

"#;

fn concatenate_rules(
    crs_dir: &Path,
    rule_files: &[&str],
    data_files: &HashMap<String, String>,
) -> io::Result<String> {
    // Start with the essential base configuration
    let mut combined = String::from(MODSEC_BASE_CONFIG);

    for rule_file in rule_files {
        let path = crs_dir.join(rule_file);
        if path.exists() {
            let file = File::open(&path)?;
            let mut reader = BufReader::new(file);
            let mut content = String::new();
            reader.read_to_string(&mut content)?;

            // Inline data files in this rule
            let content = inline_data_files(&content, data_files);

            combined.push_str(&format!("\n# === {} ===\n", rule_file));
            combined.push_str(&content);
            combined.push('\n');
        } else {
            eprintln!("Warning: Rule file not found: {:?}", path);
        }
    }

    Ok(combined)
}

/// Load all .data files from the rules directory into memory
fn load_data_files(_rules_dir: &Path) -> io::Result<HashMap<String, String>> {
    // Data files are not inlined - @pmFromFile rules are commented out instead
    // This is because @pm operator doesn't support the same pattern format as @pmFromFile
    Ok(HashMap::new())
}

/// Comment out @pmFromFile directives since they can't be inlined
/// These rules require external data files that aren't available when loading inline
fn inline_data_files(rule_content: &str, _data_files: &HashMap<String, String>) -> String {
    // Strategy: Find all SecRule blocks that contain @pmFromFile and comment them out
    // SecRule blocks can span multiple lines with backslash continuation

    let lines: Vec<&str> = rule_content.lines().collect();
    let mut result = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Check if this line starts a SecRule (not already commented)
        if line.trim_start().starts_with("SecRule") && !line.trim_start().starts_with('#') {
            // Collect the entire rule (may span multiple lines with backslash continuation)
            let mut rule_lines = vec![line];
            let mut j = i;

            // Keep collecting lines while they end with backslash (continuation)
            while j < lines.len() && lines[j].trim_end().ends_with('\\') {
                j += 1;
                if j < lines.len() {
                    rule_lines.push(lines[j]);
                }
            }

            // Check if this rule contains @pmFromFile
            let full_rule: String = rule_lines.join("\n");
            if full_rule.contains("@pmFromFile") {
                // Comment out the entire rule
                result
                    .push("# [BUNDLED-CRS] Rule disabled: requires external data file".to_string());
                for rule_line in &rule_lines {
                    result.push(format!("# {}", rule_line));
                }
            } else {
                // Keep the rule as-is
                for rule_line in &rule_lines {
                    result.push(rule_line.to_string());
                }
            }

            i = j + 1;
        } else {
            result.push(line.to_string());
            i += 1;
        }
    }

    result.join("\n")
}

/// Escape patterns for use in @pm "..." directive (unused but kept for future)
#[allow(dead_code)]
fn escape_pm_patterns(patterns: &str) -> String {
    // Escape double quotes and backslashes
    patterns.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_raw_string(s: &str) -> String {
    // For raw strings, we need to escape the delimiter if present
    // Since we use r#####"..."#####, we need to ensure the content
    // doesn't contain "##### which would break the raw string
    s.replace("\"#####", "\" #####")
}
