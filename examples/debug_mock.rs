use openapiv3::OpenAPI;
use std::fs;
use std::sync::Arc;

// Minimal test to debug mock generation
fn main() {
    // Load the spec
    let spec_content = fs::read_to_string("tests/fixtures/openapi/comprehensive.yaml")
        .expect("Failed to read spec");
    let spec: OpenAPI = serde_yaml::from_str(&spec_content).expect("Failed to parse spec");
    let spec = Arc::new(spec);

    // Create resolver
    let resolver = api_fence::resolver::RefResolver::new(spec.clone());

    // Get the POST /users operation
    let path = spec
        .paths
        .paths
        .get("/users")
        .expect("Path /users not found");
    let path_item = match path {
        openapiv3::ReferenceOr::Item(item) => item,
        _ => panic!("Path is a reference"),
    };
    let operation = path_item.post.as_ref().expect("POST method not found");

    println!("Found POST /users operation: {:?}", operation.operation_id);
    println!(
        "Responses: {:?}",
        operation.responses.responses.keys().collect::<Vec<_>>()
    );

    // Try to generate mock
    let config = api_fence::mock::MockConfig {
        enabled: true,
        prefer_examples: true,
        default_status_code: None,
        delay_ms: None,
        add_mock_header: true,
    };

    match api_fence::mock::generate_mock_response(operation, &config, &resolver) {
        Ok(response) => {
            println!("Mock generation SUCCESS:");
            println!("  Status: {}", response.status_code);
            println!("  Content-Type: {}", response.content_type);
            println!("  Body: {}", String::from_utf8_lossy(&response.body));
        }
        Err(e) => {
            println!("Mock generation FAILED: {:?}", e);
        }
    }
}
