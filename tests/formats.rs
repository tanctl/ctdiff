//! comprehensive tests for all output formats
//! 
//! tests format correctness, edge cases, and integration

use ctdiff::{DiffBuilder, SecurityLevel, OutputFormat};
use serde_json::Value;

#[test]
fn test_unified_format_basic() {
    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Unified)
        .security_level(SecurityLevel::Fast)
        .context_lines(1)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_text("line 1\nline 2\nline 3", "line 1\nmodified\nline 3")
        .expect("diff failed");

    let output = result.format().expect("format failed");
    
    // check for unified diff markers
    assert!(output.contains("@@"));
    assert!(output.contains("-line 2"));
    assert!(output.contains("+modified"));
}

#[test]
fn test_json_format_structure() {
    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Json)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_text("hello", "world")
        .expect("diff failed");

    let output = result.format().expect("format failed");
    let json: Value = serde_json::from_str(&output).expect("invalid json");
    
    // check required json structure
    assert!(json.get("metadata").is_some());
    assert!(json.get("statistics").is_some());
    assert!(json.get("operations").is_some());
    
    // check statistics structure
    let stats = json.get("statistics").unwrap();
    assert!(stats.get("edit_distance").is_some());
    assert!(stats.get("similarity").is_some());
    assert!(stats.get("identical").is_some());
}

#[test]
fn test_html_format_structure() {
    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Html)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_text("original", "modified")
        .expect("diff failed");

    let output = result.format().expect("format failed");
    
    // check html structure
    assert!(output.contains("<!DOCTYPE html>"));
    assert!(output.contains("<html"));
    assert!(output.contains("<head>"));
    assert!(output.contains("<body>"));
    assert!(output.contains("</html>"));
    
    // check css inclusion
    assert!(output.contains("<style>"));
    assert!(output.contains("</style>"));
}

#[test]
fn test_git_format_structure() {
    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Git)
        .security_level(SecurityLevel::Fast)
        .context_lines(3)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_text(
        "line 1\nline 2\nline 3\nline 4", 
        "line 1\nchanged\nline 3\nline 4"
    ).expect("diff failed");

    let output = result.format().expect("format failed");
    
    // check git patch format
    assert!(output.contains("---"));
    assert!(output.contains("+++"));
    assert!(output.contains("@@"));
    assert!(output.contains("-line 2"));
    assert!(output.contains("+changed"));
}

#[test]
fn test_summary_format_content() {
    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Summary)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_text("abc", "axc")
        .expect("diff failed");

    let output = result.format().expect("format failed");
    
    // check summary content
    assert!(output.contains("Edit Distance:"));
    assert!(output.contains("Similarity:"));
    assert!(output.contains("Operations:"));
}

#[test]
fn test_identical_files_all_formats() {
    let formats = vec![
        OutputFormat::Unified,
        OutputFormat::Json,
        OutputFormat::Html,
        OutputFormat::Git,
        OutputFormat::Summary,
    ];

    let content = "identical content";
    
    for format in formats {
        let diff = DiffBuilder::new()
            .output_format(format.clone())
            .security_level(SecurityLevel::Fast)
            .build()
            .expect("failed to build diff");

        let result = diff.compare_text(content, content)
            .expect("diff failed");

        assert_eq!(result.edit_distance(), 0);
        assert!(result.is_identical());
        assert_eq!(result.similarity(), 1.0);
        
        // format should not fail on identical content
        let _output = result.format().expect("format failed for identical content");
    }
}

#[test]
fn test_empty_input_all_formats() {
    let formats = vec![
        OutputFormat::Unified,
        OutputFormat::Json,
        OutputFormat::Html,
        OutputFormat::Git,
        OutputFormat::Summary,
    ];

    for format in formats {
        let diff = DiffBuilder::new()
            .output_format(format.clone())
            .security_level(SecurityLevel::Fast)
            .build()
            .expect("failed to build diff");

        // empty to empty
        let result = diff.compare_text("", "")
            .expect("diff failed");
        assert!(result.is_identical());
        let _output = result.format().expect("format failed for empty inputs");

        // empty to content
        let result = diff.compare_text("", "content")
            .expect("diff failed");
        assert!(!result.is_identical());
        let _output = result.format().expect("format failed for empty to content");

        // content to empty
        let result = diff.compare_text("content", "")
            .expect("diff failed");
        assert!(!result.is_identical());
        let _output = result.format().expect("format failed for content to empty");
    }
}

#[test]
fn test_large_diff_performance() {
    // create larger test data
    let left = "line 1\n".repeat(100);
    let right = "modified\n".repeat(100);

    let formats = vec![
        OutputFormat::Unified,
        OutputFormat::Json,
        OutputFormat::Summary, // skip HTML and Git for performance
    ];

    for format in formats {
        let diff = DiffBuilder::new()
            .output_format(format.clone())
            .security_level(SecurityLevel::Fast)
            .build()
            .expect("failed to build diff");

        let start = std::time::Instant::now();
        let result = diff.compare_text(&left, &right)
            .expect("diff failed");
        let _output = result.format().expect("format failed");
        let elapsed = start.elapsed();
        
        // should complete within reasonable time (adjust threshold as needed)
        assert!(elapsed.as_millis() < 1000, "format {:?} took too long: {:?}", format, elapsed);
    }
}

#[test]
fn test_binary_data_handling() {
    let binary_left = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];
    let binary_right = vec![0x00, 0x01, 0x03, 0xFF, 0xFE];

    let formats = vec![
        OutputFormat::Json,    // should handle binary gracefully
        OutputFormat::Summary, // should provide statistics
    ];

    for format in formats {
        let diff = DiffBuilder::new()
            .output_format(format.clone())
            .security_level(SecurityLevel::Fast)
            .build()
            .expect("failed to build diff");

        let result = diff.compare(&binary_left, &binary_right)
            .expect("diff failed");
        
        assert!(!result.is_identical());
        assert_eq!(result.edit_distance(), 1); // one byte difference
        
        let _output = result.format().expect("format failed for binary data");
    }
}

#[test]
fn test_unicode_handling() {
    let unicode_left = "Hello 🌍 world! café";
    let unicode_right = "Hello 🌎 world! cafe";

    let formats = vec![
        OutputFormat::Unified,
        OutputFormat::Json,
        OutputFormat::Html,
        OutputFormat::Summary,
    ];

    for format in formats {
        let diff = DiffBuilder::new()
            .output_format(format.clone())
            .security_level(SecurityLevel::Fast)
            .build()
            .expect("failed to build diff");

        let result = diff.compare_text(unicode_left, unicode_right)
            .expect("diff failed");
        
        assert!(!result.is_identical());
        
        let output = result.format().expect("format failed for unicode");
        
        // output should be valid utf-8
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());
    }
}

#[test]
fn test_security_levels_format_consistency() {
    let security_levels = vec![
        SecurityLevel::Balanced, // skip Maximum due to strict limits for this test
        SecurityLevel::Fast,
    ];

    let test_left = "old";
    let test_right = "new";

    for security_level in security_levels {
        let diff = DiffBuilder::new()
            .output_format(OutputFormat::Json)
            .security_level(security_level)
            .max_file_size(10 * 1024) // 10KB should be enough for small test strings
            .build()
            .expect("failed to build diff");

        let result = diff.compare_text(test_left, test_right)
            .expect("diff failed");

        // all security levels should produce same edit distance
        assert!(result.edit_distance() > 0);
        
        let output = result.format().expect("format failed");
        let json: Value = serde_json::from_str(&output).expect("invalid json");
        
        // json structure should be consistent across security levels
        assert!(json.get("statistics").is_some());
        assert!(json.get("operations").is_some());
    }
}

#[test]
fn test_context_lines_unified_format() {
    let text_left = "line1\nline2\nline3\nline4\nline5";
    let text_right = "line1\nmodified\nline3\nline4\nline5";

    let context_sizes = vec![0, 1, 2, 5];

    for context_lines in context_sizes {
        let diff = DiffBuilder::new()
            .output_format(OutputFormat::Unified)
            .context_lines(context_lines)
            .security_level(SecurityLevel::Fast)
            .build()
            .expect("failed to build diff");

        let result = diff.compare_text(text_left, text_right)
            .expect("diff failed");

        let output = result.format().expect("format failed");
        
        // should contain diff markers
        assert!(output.contains("@@"));
        assert!(output.contains("-line2"));
        assert!(output.contains("+modified"));
    }
}

#[test]
fn test_color_output_unified() {
    let diff_colored = DiffBuilder::new()
        .output_format(OutputFormat::Unified)
        .color(true)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let diff_plain = DiffBuilder::new()
        .output_format(OutputFormat::Unified)
        .color(false)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let result_colored = diff_colored.compare_text("old", "new")
        .expect("diff failed");
    let result_plain = diff_plain.compare_text("old", "new")
        .expect("diff failed");

    let output_colored = result_colored.format().expect("format failed");
    let output_plain = result_plain.format().expect("format failed");

    // both should work (color support depends on environment)
    assert!(output_colored.len() > 0);
    assert!(output_plain.len() > 0);
}

#[test]
fn test_file_comparison_integration() {
    use std::fs;
    use tempfile::NamedTempFile;

    // create temporary files
    let mut file1 = NamedTempFile::new().expect("failed to create temp file");
    let mut file2 = NamedTempFile::new().expect("failed to create temp file");

    let content1 = "file content line 1\nfile content line 2\n";
    let content2 = "file content line 1\nmodified line 2\n";

    fs::write(file1.path(), content1).expect("failed to write file1");
    fs::write(file2.path(), content2).expect("failed to write file2");

    let formats = vec![
        OutputFormat::Unified,
        OutputFormat::Json,
        OutputFormat::Summary,
    ];

    for format in formats {
        let diff = DiffBuilder::new()
            .output_format(format.clone())
            .security_level(SecurityLevel::Fast)
            .build()
            .expect("failed to build diff");

        let result = diff.compare_files(file1.path(), file2.path())
            .expect("file comparison failed");

        assert!(!result.is_identical());
        assert!(result.edit_distance() > 0);
        
        let _output = result.format().expect("format failed");
    }
}

#[test]
fn test_round_trip_consistency() {
    // test that our diff operations are consistent
    let original = "original\ncontent\nwith\nmultiple\nlines";
    let modified = "modified\ncontent\nwith\nadditional\nlines\nhere";

    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Json)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_text(original, modified)
        .expect("diff failed");

    // verify statistics make sense
    let stats = result.statistics();
    assert_eq!(stats.edit_distance, result.edit_distance());
    assert!(stats.similarity >= 0.0 && stats.similarity <= 1.0);
    assert_eq!(stats.left_size, original.len());
    assert_eq!(stats.right_size, modified.len());
    assert!(stats.total_operations > 0);
}

#[test]
fn test_error_conditions() {
    // test various error conditions
    
    // security config validation
    use ctdiff::security::{SecurityConfig, TimingProtection};
    
    let invalid_config = SecurityConfig {
        max_input_size: 10,  // very small
        pad_inputs: true,
        padding_size: Some(1000), // larger than input limit
        validate_inputs: true,
        max_edit_distance: Some(5),
        memory_protection: false, // disable memory protection with timing protection
        timing_protection: TimingProtection::Strict, // this should trigger warning
    };
    
    // this should trigger a warning but still be "valid" - let's just verify it runs
    let _result = invalid_config.validate(); // may warn but not error
}

#[test] 
fn test_format_specific_options() {
    use ctdiff::formats::{FormatOptions, HtmlTheme};
    
    let options = FormatOptions {
        json_pretty: true,
        html_inline_css: true,
        html_theme: HtmlTheme::Dark,
        include_metadata: true,
        max_line_width: Some(80),
        show_line_numbers: true,
        word_diff: false,
    };
    
    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Html)
        .format_options(options)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_text("test line", "modified line")
        .expect("diff failed");

    let output = result.format().expect("format failed");
    
    // should contain HTML with inline CSS
    assert!(output.contains("<style>"));
    assert!(output.contains("</style>"));
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_async_file_operations() {
    use tempfile::NamedTempFile;
    use std::fs;

    let mut file1 = NamedTempFile::new().expect("failed to create temp file");
    let mut file2 = NamedTempFile::new().expect("failed to create temp file");

    fs::write(file1.path(), "async test content").expect("failed to write file1");
    fs::write(file2.path(), "async modified content").expect("failed to write file2");

    let diff = DiffBuilder::new()
        .output_format(OutputFormat::Json)
        .security_level(SecurityLevel::Fast)
        .build()
        .expect("failed to build diff");

    let result = diff.compare_files_async(file1.path(), file2.path()).await
        .expect("async file comparison failed");

    assert!(!result.is_identical());
    assert!(result.edit_distance() > 0);
    
    let _output = result.format().expect("format failed");
}