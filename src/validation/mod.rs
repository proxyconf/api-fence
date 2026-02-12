//! Validation module
//!
//! This module contains all validation logic for the OpenAPI filter,
//! organized into submodules by validation target:
//!
//! - `path`: Path parameter validation
//! - `query`: Query string parameter validation
//! - `header`: HTTP header validation
//! - `body`: Request/response body validation
//! - `response`: Response-specific validation

pub mod body;
pub mod header;
pub mod path;
pub mod query;
pub mod response;

// Re-export commonly used types
pub use body::{body_to_json, body_to_json_secure, coerce_form_data_to_schema, find_matching_content_type, parse_form_urlencoded_to_json, parse_multipart_to_json, parse_xml_to_json};
pub use header::{validate_request_headers, validate_response_headers};
pub use path::{validate_path_param_types, ParamSchema};
pub use query::{convert_param_to_json, validate_query_params};
pub use response::{get_response_for_status, validate_response_body};
