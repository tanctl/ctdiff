//! performance comparison examples
//! 
//! demonstrates performance characteristics of different security levels

use ctdiff::{DiffBuilder, SecurityLevel, OutputFormat};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Performance Comparison ===\n");
    
    // create test data of different sizes
    let small_data = generate_test_data(100);
    let medium_data = generate_test_data(1000);
    let large_data = generate_test_data(5000);
    
    println!("Testing with data sizes: 100, 1000, 5000 bytes\n");
    
    // test different security levels
    test_security_level_performance(&small_data, "Small")?;
    test_security_level_performance(&medium_data, "Medium")?;
    test_security_level_performance(&large_data, "Large")?;
    
    // test different output formats
    println!("\n=== Output Format Performance ===");
    test_output_format_performance(&medium_data)?;
    
    Ok(())
}

/// generates test data with some patterns
fn generate_test_data(size: usize) -> (Vec<u8>, Vec<u8>) {
    let mut left = Vec::with_capacity(size);
    let mut right = Vec::with_capacity(size);
    
    for i in 0..size {
        left.push((i % 256) as u8);
        // modify every 10th byte to create differences
        if i % 10 == 0 {
            right.push(((i + 1) % 256) as u8);
        } else {
            right.push((i % 256) as u8);
        }
    }
    
    (left, right)
}

/// tests performance across different security levels
fn test_security_level_performance(
    test_data: &(Vec<u8>, Vec<u8>), 
    size_label: &str
) -> Result<(), Box<dyn std::error::Error>> {
    println!("--- {} Data Performance ---", size_label);
    
    let (left, right) = test_data;
    let iterations = 10;
    
    // test maximum security
    let start = Instant::now();
    let max_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Maximum)
        .build()?;
    
    for _ in 0..iterations {
        let _result = max_diff.compare(left, right)?;
    }
    let max_time = start.elapsed();
    
    // test balanced security
    let start = Instant::now();
    let balanced_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .build()?;
    
    for _ in 0..iterations {
        let _result = balanced_diff.compare(left, right)?;
    }
    let balanced_time = start.elapsed();
    
    // test fast mode
    let start = Instant::now();
    let fast_diff = DiffBuilder::new()
        .security_level(SecurityLevel::Fast)
        .build()?;
    
    for _ in 0..iterations {
        let _result = fast_diff.compare(left, right)?;
    }
    let fast_time = start.elapsed();
    
    println!("  Maximum Security: {:?} ({} iterations)", max_time, iterations);
    println!("  Balanced:         {:?} ({} iterations)", balanced_time, iterations);
    println!("  Fast Mode:        {:?} ({} iterations)", fast_time, iterations);
    
    // calculate relative performance
    let baseline = fast_time.as_nanos() as f64;
    let max_overhead = (max_time.as_nanos() as f64 / baseline) - 1.0;
    let balanced_overhead = (balanced_time.as_nanos() as f64 / baseline) - 1.0;
    
    println!("  Relative Overhead:");
    println!("    Maximum: {:.1}% slower than Fast", max_overhead * 100.0);
    println!("    Balanced: {:.1}% slower than Fast", balanced_overhead * 100.0);
    println!();
    
    Ok(())
}

/// tests performance of different output formats
fn test_output_format_performance(
    test_data: &(Vec<u8>, Vec<u8>)
) -> Result<(), Box<dyn std::error::Error>> {
    let (left, right) = test_data;
    let iterations = 5;
    
    let formats = vec![
        ("Unified", OutputFormat::Unified),
        ("JSON", OutputFormat::Json),
        ("HTML", OutputFormat::Html),
        ("Git", OutputFormat::Git),
        ("Summary", OutputFormat::Summary),
    ];
    
    for (name, format) in formats {
        let start = Instant::now();
        
        let diff = DiffBuilder::new()
            .security_level(SecurityLevel::Balanced)
            .output_format(format)
            .build()?;
        
        for _ in 0..iterations {
            let result = diff.compare(left, right)?;
            let _formatted = result.format()?;
        }
        
        let elapsed = start.elapsed();
        println!("  {} Format: {:?} ({} iterations)", name, elapsed, iterations);
    }
    
    Ok(())
}