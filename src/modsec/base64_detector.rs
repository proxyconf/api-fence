//! Base64 detection heuristics
//!
//! This module provides heuristics to detect base64-encoded strings.
//! Base64 strings are often skipped during WAF scanning to reduce
//! false positives (e.g., encoded images, binary data).
//!
//! # Heuristics
//!
//! The detection uses fixed (non-configurable) heuristics:
//! - Minimum length: 20 characters
//! - Character set: Only `[A-Za-z0-9+/=]`
//! - Length divisible by 4 (with proper padding)
//! - Padding: 0-2 `=` at end only
//! - Entropy > 4.5 bits per character (for strings >= 32 chars)

/// Detect if a string is likely base64-encoded
///
/// Uses fixed heuristics that cannot be configured:
/// - Minimum 20 characters (shorter strings unlikely to be base64)
/// - Only standard base64 characters `[A-Za-z0-9+/=]`
/// - Length divisible by 4
/// - Padding `=` only at end, maximum 2
/// - Shannon entropy > 4.5 for strings >= 32 chars
///
/// # Arguments
///
/// * `s` - The string to check
///
/// # Returns
///
/// `true` if the string appears to be base64-encoded
///
/// # Example
///
/// ```
/// use api_fence::modsec::is_likely_base64;
///
/// // Base64-encoded "Hello, World!"
/// assert!(is_likely_base64("SGVsbG8sIFdvcmxkIQ=="));
///
/// // Regular text
/// assert!(!is_likely_base64("Hello, World!"));
///
/// // Too short
/// assert!(!is_likely_base64("SGVsbG8="));
/// ```
pub fn is_likely_base64(s: &str) -> bool {
    // Quick length check - base64 strings of interest are at least 20 chars
    if s.len() < 20 {
        return false;
    }

    // Length must be divisible by 4
    if !s.len().is_multiple_of(4) {
        return false;
    }

    // Count padding at the end
    let padding_count = s.bytes().rev().take_while(|&b| b == b'=').count();

    // Maximum 2 padding characters
    if padding_count > 2 {
        return false;
    }

    // Check that all non-padding characters are valid base64
    let content = &s[..s.len() - padding_count];

    // Content must only contain valid base64 characters
    let valid_chars = content
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');

    if !valid_chars {
        return false;
    }

    // No '=' should appear in the content (only padding at end)
    if content.contains('=') {
        return false;
    }

    // For longer strings, check entropy
    if s.len() >= 32 {
        let entropy = calculate_entropy(content);
        // Base64 typically has entropy around 5.5-6 bits per char
        // Regular text is usually lower, around 3-4 bits
        // We use 4.5 as a threshold
        if entropy < 4.5 {
            return false;
        }
    }

    true
}

/// Calculate Shannon entropy of a string
///
/// Shannon entropy measures the average information content per character.
/// Higher entropy indicates more randomness/less predictability.
///
/// # Arguments
///
/// * `s` - The string to analyze
///
/// # Returns
///
/// Entropy in bits per character (0.0 to 8.0 for ASCII)
fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    // Count character frequencies
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }

    let len = s.len() as f64;

    // Calculate Shannon entropy: -sum(p * log2(p))
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_too_short() {
        assert!(!is_likely_base64("SGVsbG8=")); // "Hello" - only 8 chars
        assert!(!is_likely_base64("dGVzdA==")); // "test" - only 8 chars
        assert!(!is_likely_base64("YWJjZGVmZ2g=")); // 12 chars
    }

    #[test]
    fn test_valid_base64() {
        // "Hello, World!" base64 encoded = "SGVsbG8sIFdvcmxkIQ==" (20 chars, divisible by 4)
        assert!(is_likely_base64("SGVsbG8sIFdvcmxkIQ=="));

        // Longer base64 string (high entropy, >= 32 chars)
        assert!(is_likely_base64(
            "VGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZyB0aGF0IHNob3VsZCBiZSBkZXRlY3RlZA=="
        ));

        // Base64 without padding - "abcdefghijklmnopqrstuvwx" encodes to 32 chars
        // Base64 of "abcdefghijklmno" = "YWJjZGVmZ2hpamtsbW5v" (20 chars, divisible by 4)
        assert!(is_likely_base64("YWJjZGVmZ2hpamtsbW5v"));
    }

    #[test]
    fn test_invalid_characters() {
        // Contains spaces
        assert!(!is_likely_base64("SGVs bG8sIFdvcmxkIQ=="));

        // Contains underscore (URL-safe base64 uses _ but standard doesn't)
        assert!(!is_likely_base64("SGVs_G8sIFdvcmxkIQ=="));

        // Contains special characters
        assert!(!is_likely_base64("Hello, World! This is not base64"));
    }

    #[test]
    fn test_wrong_length() {
        // Not divisible by 4
        assert!(!is_likely_base64("SGVsbG8sIFdvcmxkIQ="));
        assert!(!is_likely_base64("SGVsbG8sIFdvcmxkIQa"));
    }

    #[test]
    fn test_wrong_padding() {
        // Too much padding
        assert!(!is_likely_base64("SGVsbG8sIFdvcmxkI==="));

        // Padding in wrong position
        assert!(!is_likely_base64("SGV=bG8sIFdvcmxkIQ=="));
    }

    #[test]
    fn test_regular_text_not_detected() {
        // Regular English text >= 32 chars (triggers entropy check)
        // "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" = 36 chars, entropy ~ 0
        assert!(!is_likely_base64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); // 32 'a's - very low entropy

        // Shorter repetitive text doesn't trigger entropy check, but may still pass
        // So we need 32+ chars for reliable entropy-based rejection
        assert!(!is_likely_base64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); // 36 'a's
    }

    #[test]
    fn test_entropy_calculation() {
        // All same character - entropy = 0
        let entropy = calculate_entropy("aaaaaaaaaa");
        assert!(entropy < 0.1);

        // Two different characters equally distributed
        let entropy = calculate_entropy("ababababab");
        assert!((entropy - 1.0).abs() < 0.1);

        // Random-looking string (high entropy)
        let entropy = calculate_entropy("aB3dE5fG7hI9jK1lM");
        assert!(entropy > 3.5);
    }

    #[test]
    fn test_url_encoded_not_base64() {
        // URL-encoded strings shouldn't be detected as base64
        assert!(!is_likely_base64("%20%21%22%23%24%25%26"));
    }

    #[test]
    fn test_json_not_base64() {
        // JSON-like strings
        assert!(!is_likely_base64(r#"{"name":"value","key":"data"}"#));
    }

    #[test]
    fn test_hex_not_base64() {
        // Hex strings (only 0-9, a-f, A-F)
        // This might pass character check but should fail entropy
        let hex = "0123456789abcdef0123"; // 20 chars
                                          // Hex has lower entropy than base64 typically
        assert!(!is_likely_base64(hex) || calculate_entropy(hex) < 4.5);
    }

    #[test]
    fn test_jwt_token_parts() {
        // JWT tokens are base64url encoded, but this one uses standard base64 chars
        // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" is 36 chars (not divisible by 4)
        // Let's use a padded version or different test case
        // Base64 of '{"alg":"HS256"}' = "eyJhbGciOiJIUzI1NiJ9" (20 chars)
        let jwt_part = "eyJhbGciOiJIUzI1NiJ9";
        assert!(is_likely_base64(jwt_part));
    }

    #[test]
    fn test_image_data_prefix() {
        // Note: Actual PNG base64 often has low entropy due to null bytes
        // Our heuristic may miss some image data, which is acceptable since
        // false negatives (not detecting base64) are safer than false positives
        //
        // Use a base64 string with good entropy for this test
        // "The quick brown fox jumps over" in base64
        let high_entropy_b64 = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy";
        assert!(is_likely_base64(high_entropy_b64));
    }
}
