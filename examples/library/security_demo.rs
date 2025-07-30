//! security configuration examples
//! 
//! demonstrates security features and best practices

use ctdiff::{DiffBuilder, SecurityLevel, OutputFormat};
use ctdiff::security::{SecurityConfig, TimingProtection};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Security Configuration Examples ===\n");
    
    // demonstrate built-in security levels
    security_levels_overview()?;
    
    // demonstrate custom security configurations
    custom_security_config()?;
    
    // demonstrate security validation
    security_validation_demo()?;
    
    // demonstrate secure file handling
    secure_file_handling()?;
    
    Ok(())
}

/// overview of built-in security levels
fn security_levels_overview() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Built-in Security Levels:\n");
    
    let test_data = (b"sensitive data".to_vec(), b"modified data".to_vec());
    
    // maximum security configuration
    println!("   Maximum Security:");
    println!("     - Strongest timing attack resistance");
    println!("     - Memory padding enabled");
    println!("     - Strict input validation");
    println!("     - Recommended for: classified/highly sensitive data");
    
    let max_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Maximum)
        .max_file_size(4 * 1024) // 4KB limit for max security
        .build()?;
    
    let result = max_diff.compare(&test_data.0, &test_data.1)?;
    println!("     - Edit Distance: {}", result.edit_distance());
    println!();
    
    // balanced configuration
    println!("   Balanced Security:");
    println!("     - Good timing protection with reasonable performance");
    println!("     - Moderate input validation");
    println!("     - Recommended for: general secure applications");
    
    let balanced_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .max_file_size(256 * 1024) // 256KB limit
        .build()?;
    
    let result = balanced_diff.compare(&test_data.0, &test_data.1)?;
    println!("     - Edit Distance: {}", result.edit_distance());
    println!();
    
    // fast configuration
    println!("   Fast Mode:");
    println!("     - Minimal security overhead");
    println!("     - Basic input validation only");
    println!("     - Recommended for: non-sensitive data, development");
    
    let fast_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Fast)
        .build()?;
    
    let result = fast_diff.compare(&test_data.0, &test_data.1)?;
    println!("     - Edit Distance: {}", result.edit_distance());
    println!();
    
    Ok(())
}

/// demonstrates custom security configurations
fn custom_security_config() -> Result<(), Box<dyn std::error::Error>> {
    println!("2. Custom Security Configuration:\n");
    
    // create a custom high-security config
    let custom_config = SecurityConfig {
        max_input_size: 2048, // very small limit
        pad_inputs: true,
        padding_size: Some(4096), // fixed padding size
        validate_inputs: true,
        max_edit_distance: Some(512), // limit computation
        memory_protection: true,
        timing_protection: TimingProtection::Strict,
    };
    
    println!("   Custom Configuration:");
    println!("     - Max input: 2KB");
    println!("     - Fixed padding: 4KB");
    println!("     - Strict timing protection");
    println!("     - Limited edit distance computation");
    
    // validate the configuration
    match custom_config.validate() {
        Ok(()) => println!("     - Configuration is valid"),
        Err(e) => println!("     - Configuration error: {}", e),
    }
    
    let diff = DiffBuilder::new()
        .security_config(custom_config)
        .build()?;
    
    let small_data = (b"small".to_vec(), b"test".to_vec());
    let result = diff.compare(&small_data.0, &small_data.1)?;
    println!("     - Test result: {} edit distance", result.edit_distance());
    println!();
    
    Ok(())
}

/// demonstrates security validation
fn security_validation_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("3. Security Validation:\n");
    
    // create configurations with different security issues
    let configs = vec![
        ("Insecure Config", SecurityConfig::insecure()),
        ("Maximum Security", SecurityConfig::maximum_security(Some(1024))),
        ("Balanced", SecurityConfig::balanced(Some(4096))),
    ];
    
    for (name, config) in configs {
        print!("   {}: ", name);
        match config.validate() {
            Ok(()) => println!("✅ Valid"),
            Err(e) => println!("⚠️  {}", e),
        }
    }
    println!();
    
    Ok(())
}

/// demonstrates secure file handling practices
fn secure_file_handling() -> Result<(), Box<dyn std::error::Error>> {
    println!("4. Secure File Handling:\n");
    
    // create test files with different characteristics
    let small_file = "/tmp/small_secure.txt";
    let large_file = "/tmp/large_secure.txt";
    
    std::fs::write(small_file, b"small secure content")?;
    std::fs::write(large_file, &vec![b'x'; 10000])?; // 10KB file
    
    println!("   Testing file size limits:");
    
    // test with restrictive size limits
    let restrictive_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Maximum)
        .max_file_size(1024) // 1KB limit
        .build()?;
    
    // small file should work
    match restrictive_diff.compare_files(small_file, small_file) {
        Ok(result) => println!("     - Small file: ✅ ({} bytes, {} distance)", 
                               std::fs::metadata(small_file)?.len(), 
                               result.edit_distance()),
        Err(e) => println!("     - Small file: ❌ {}", e),
    }
    
    // large file should be rejected
    match restrictive_diff.compare_files(large_file, large_file) {
        Ok(result) => println!("     - Large file: ✅ ({} bytes, {} distance)", 
                               std::fs::metadata(large_file)?.len(), 
                               result.edit_distance()),
        Err(e) => println!("     - Large file: ❌ {}", e),
    }
    
    // cleanup
    std::fs::remove_file(small_file).ok();
    std::fs::remove_file(large_file).ok();
    
    println!();
    println!("Security Best Practices:");
    println!("  1. Always set appropriate file size limits");
    println!("  2. Use Maximum security for sensitive data");
    println!("  3. Validate security configs before use");
    println!("  4. Monitor for timing-based information leaks");
    println!("  5. Use structured output (JSON) for automated systems");
    
    Ok(())
}