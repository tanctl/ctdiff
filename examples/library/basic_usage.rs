//! basic library usage examples
//! 
//! demonstrates how to use ctdiff as a library for simple diff operations

use ctdiff::{DiffBuilder, SecurityLevel, OutputFormat};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic ctdiff Library Usage ===\n");
    
    // example 1: simple text comparison
    basic_text_diff()?;
    
    // example 2: file comparison
    file_comparison()?;
    
    // example 3: different security levels
    security_levels_demo()?;
    
    // example 4: different output formats
    output_formats_demo()?;
    
    Ok(())
}

/// demonstrates basic text diffing
fn basic_text_diff() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Basic Text Comparison:");
    
    let left = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
    let right = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod.";
    
    let diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .build()?;
    
    let result = diff.compare_text(left, right)?;
    
    println!("   Edit Distance: {}", result.edit_distance());
    println!("   Similar: {:.1}%", result.similarity() * 100.0);
    println!("   Identical: {}", result.is_identical());
    println!();
    
    Ok(())
}

/// demonstrates file comparison
fn file_comparison() -> Result<(), Box<dyn std::error::Error>> {
    println!("2. File Comparison:");
    
    // create temporary test files
    let left_content = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\nUt enim ad minim veniam, quis nostrud exercitation.\nDuis aute irure dolor in reprehenderit in voluptate.\n";
    let right_content = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.\nUt enim ad minim veniam, quis nostrud exercitation ullamco.\nDuis aute irure dolor in reprehenderit in voluptate.\nExcepteur sint occaecat cupidatat non proident.\n";
    
    std::fs::write("/tmp/left.txt", left_content)?;
    std::fs::write("/tmp/right.txt", right_content)?;
    
    let diff = DiffBuilder::new()
        .security_level(SecurityLevel::Fast)
        .color(true) // enable colors if supported
        .build()?;
    
    let result = diff.compare_files("/tmp/left.txt", "/tmp/right.txt")?;
    
    println!("   Files: /tmp/left.txt vs /tmp/right.txt");
    println!("   Edit Distance: {}", result.edit_distance());
    println!("   Statistics: {:?}", result.statistics());
    println!();
    
    // cleanup
    std::fs::remove_file("/tmp/left.txt").ok();
    std::fs::remove_file("/tmp/right.txt").ok();
    
    Ok(())
}

/// demonstrates different security levels
fn security_levels_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("3. Security Levels:");
    
    let data1 = b"Lorem ipsum dolor sit amet, consectetur adipiscing.";
    let data2 = b"Lorem ipsum dolor sit amet, consectetuer adipiscing.";
    
    // maximum security - strongest timing attack resistance
    let max_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Maximum)
        .build()?;
    
    let result = max_diff.compare(data1, data2)?;
    println!("   Maximum Security - Edit Distance: {}", result.edit_distance());
    
    // balanced security and performance
    let balanced_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .build()?;
    
    let result = balanced_diff.compare(data1, data2)?;
    println!("   Balanced Security - Edit Distance: {}", result.edit_distance());
    
    // fast but less secure
    let fast_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Fast)
        .build()?;
    
    let result = fast_diff.compare(data1, data2)?;
    println!("   Fast Mode - Edit Distance: {}", result.edit_distance());
    println!();
    
    Ok(())
}

/// demonstrates different output formats
fn output_formats_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("4. Output Formats:");
    
    let left = "Lorem ipsum dolor sit amet,\nconsectetur adipiscing elit,\nsed do eiusmod tempor.";
    let right = "Lorem ipsum dolor sit amet,\nconsectetur adipiscing elit,\nsed do eiusmod tempor incididunt,\nut labore et dolore magna.";
    
    // unified diff format (default)
    let unified = DiffBuilder::new()
        .output_format(OutputFormat::Unified)
        .context_lines(2)
        .build()?;
    
    let result = unified.compare_text(left, right)?;
    println!("   Unified Format:");
    println!("{}", result.format()?);
    
    // json format
    let json = DiffBuilder::new()
        .output_format(OutputFormat::Json)
        .build()?;
    
    let result = json.compare_text(left, right)?;
    println!("   JSON Format (first 200 chars):");
    let json_str = result.format()?;
    println!("{}...", &json_str[..json_str.len().min(200)]);
    println!();
    
    // summary format
    let summary = DiffBuilder::new()
        .output_format(OutputFormat::Summary)
        .build()?;
    
    let result = summary.compare_text(left, right)?;
    println!("   Summary Format:");
    println!("{}", result.format()?);
    
    Ok(())
}