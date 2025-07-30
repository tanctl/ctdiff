//! integration examples
//! 
//! demonstrates how to integrate ctdiff into larger applications

use ctdiff::{DiffBuilder, SecurityLevel, OutputFormat};
use serde_json::Value;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Integration Examples ===\n");
    
    // example 1: web service integration
    web_service_example()?;
    
    // example 2: automated testing integration
    automated_testing_example()?;
    
    // example 3: version control integration
    version_control_example()?;
    
    // example 4: monitoring and logging
    monitoring_example()?;
    
    Ok(())
}

/// example of integrating ctdiff into a web service
fn web_service_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Web Service Integration:\n");
    
    // simulate web service request
    let request = WebDiffRequest {
        left_content: "Lorem ipsum dolor sit amet,\nconsectetur adipiscing elit,\nsed do eiusmod tempor.".to_string(),
        right_content: "Lorem ipsum dolor sit amet,\nconsectetur adipiscing elit,\nsed do eiusmod tempor incididunt.".to_string(),
        format: "json".to_string(),
        security_level: "balanced".to_string(),
    };
    
    let response = handle_diff_request(request)?;
    
    println!("   Request processed successfully:");
    println!("   Response: {}", serde_json::to_string_pretty(&response)?);
    println!();
    
    Ok(())
}

/// simulated web service request structure
#[derive(Debug)]
struct WebDiffRequest {
    left_content: String,
    right_content: String,
    format: String,
    security_level: String,
}

/// simulated web service response
#[derive(Debug, serde::Serialize)]
struct WebDiffResponse {
    success: bool,
    edit_distance: usize,
    similarity: f64,
    output: String,
    metadata: HashMap<String, Value>,
}

/// handles a diff request (simulated web service handler)
fn handle_diff_request(request: WebDiffRequest) -> Result<WebDiffResponse, Box<dyn std::error::Error>> {
    // parse security level
    let security_level = match request.security_level.as_str() {
        "maximum" => SecurityLevel::Maximum,
        "balanced" => SecurityLevel::Balanced,
        "fast" => SecurityLevel::Fast,
        _ => SecurityLevel::Balanced, // default
    };
    
    // parse output format
    let output_format = match request.format.as_str() {
        "json" => OutputFormat::Json,
        "html" => OutputFormat::Html,
        "summary" => OutputFormat::Summary,
        _ => OutputFormat::Unified, // default
    };
    
    // create diff builder with security restrictions for web service
    let diff = DiffBuilder::new()
        .security_level(security_level)
        .output_format(output_format)
        .max_file_size(64 * 1024) // 64KB limit for web requests
        .build()?;
    
    // perform diff
    let result = diff.compare_text(&request.left_content, &request.right_content)?;
    
    // create metadata
    let mut metadata = HashMap::new();
    metadata.insert("processing_time".to_string(), Value::String("< 1ms".to_string()));
    metadata.insert("security_level".to_string(), Value::String(request.security_level));
    metadata.insert("output_format".to_string(), Value::String(request.format));
    
    Ok(WebDiffResponse {
        success: true,
        edit_distance: result.edit_distance(),
        similarity: result.similarity(),
        output: result.format()?,
        metadata,
    })
}

/// example of using ctdiff in automated testing
fn automated_testing_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("2. Automated Testing Integration:\n");
    
    // simulate test case with expected vs actual output
    let test_cases = vec![
        TestCase {
            name: "string_processing_test",
            expected: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            actual: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            threshold: 0.95, // 95% similarity required
        },
        TestCase {
            name: "formatting_test", 
            expected: "Lorem ipsum:\n  dolor sit amet\n  consectetur adipiscing",
            actual: "Lorem ipsum:\n  dolor sit amet\n  consectetur modificat",
            threshold: 0.80,
        },
    ];
    
    for test_case in test_cases {
        let result = run_similarity_test(test_case)?;
        println!("   Test Result: {:?}", result);
    }
    println!();
    
    Ok(())
}

#[derive(Debug)]
struct TestCase {
    name: &'static str,
    expected: &'static str,
    actual: &'static str,
    threshold: f64,
}

#[derive(Debug)]
struct TestResult {
    name: &'static str,
    passed: bool,
    similarity: f64,
    edit_distance: usize,
}

fn run_similarity_test(test_case: TestCase) -> Result<TestResult, Box<dyn std::error::Error>> {
    let diff = DiffBuilder::new()
        .security_level(SecurityLevel::Fast) // fast mode for testing
        .output_format(OutputFormat::Summary)
        .build()?;
    
    let result = diff.compare_text(test_case.expected, test_case.actual)?;
    let similarity = result.similarity();
    
    Ok(TestResult {
        name: test_case.name,
        passed: similarity >= test_case.threshold,
        similarity,
        edit_distance: result.edit_distance(),
    })
}

/// example of version control integration
fn version_control_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("3. Version Control Integration:\n");
    
    // simulate git-like diff operation
    let old_version = r#"
function processData(input) {
    let result = input.trim();
    return result.toUpperCase();
}
"#.trim();
    
    let new_version = r#"
function processData(input) {
    if (!input) return '';
    let result = input.trim();
    return result.toUpperCase();
}
"#.trim();
    
    // create git-compatible patch
    let diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .output_format(OutputFormat::Git)
        .context_lines(3)
        .build()?;
    
    let result = diff.compare_text(old_version, new_version)?;
    let patch = result.format()?;
    
    println!("   Git-compatible patch:");
    println!("{}", patch);
    
    // also generate summary for commit message
    let summary_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .output_format(OutputFormat::Summary)
        .build()?;
    
    let summary_result = summary_diff.compare_text(old_version, new_version)?;
    let summary = summary_result.format()?;
    
    println!("   Commit summary:");
    println!("{}", summary);
    
    Ok(())
}

/// example of monitoring and logging integration
fn monitoring_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("4. Monitoring and Logging:\n");
    
    // simulate monitoring configuration changes
    let old_config = r#"
{
    "database": {
        "host": "localhost",
        "port": 5432,
        "ssl": false
    },
    "cache": {
        "enabled": true,
        "ttl": 3600
    }
}
"#.trim();
    
    let new_config = r#"
{
    "database": {
        "host": "prod-db.example.com",
        "port": 5432,
        "ssl": true
    },
    "cache": {
        "enabled": true,
        "ttl": 7200
    }
}
"#.trim();
    
    // generate structured diff for logging
    let diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .output_format(OutputFormat::Json)
        .build()?;
    
    let result = diff.compare_text(old_config, new_config)?;
    let json_output = result.format()?;
    
    // parse and extract key information for monitoring
    let diff_data: Value = serde_json::from_str(&json_output)?;
    
    println!("   Configuration Change Detected:");
    if let Some(stats) = diff_data.get("statistics") {
        println!("   - Edit Distance: {}", stats.get("edit_distance").unwrap_or(&Value::Null));
        println!("   - Similarity: {:.1}%", 
                 stats.get("similarity").and_then(|v| v.as_f64()).unwrap_or(0.0) * 100.0);
    }
    
    // log security-relevant changes
    if result.edit_distance() > 0 {
        println!("   🔍 Security Review Required: Configuration has changed");
        
        // example: check for specific security-relevant changes
        if new_config.contains("ssl\": true") && old_config.contains("ssl\": false") {
            println!("   ✅ Security Improvement: SSL enabled");
        }
        
        if new_config.contains("prod-db") {
            println!("   ⚠️  Environment Change: Switched to production database");
        }
    }
    
    println!();
    println!("Integration Best Practices:");
    println!("  1. Use structured formats (JSON) for automated processing");
    println!("  2. Set appropriate security levels based on data sensitivity");
    println!("  3. Implement proper error handling and logging");
    println!("  4. Monitor performance in production environments");
    println!("  5. Use summary format for high-level change detection");
    
    Ok(())
}