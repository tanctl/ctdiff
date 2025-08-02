//! summary statistics format implementation
//! 
//! high-level diff statistics and summary information

use crate::{error::Result, types::{DiffResult, DiffOperation}};
use crate::formats::FormatOptions;

/// formats diff result as summary statistics
pub fn format(
    left_name: &str,
    right_name: &str,
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
    options: &FormatOptions,
) -> Result<String> {
    let mut output = String::new();
    
    // header
    if options.include_metadata {
        output.push_str(&format_header(left_name, right_name));
    }
    
    // main statistics
    output.push_str(&format_statistics(left_data, right_data, result, options));
    
    // detailed breakdown if requested
    if options.include_metadata {
        output.push_str(&format_detailed_breakdown(result, options));
    }
    
    Ok(output)
}

/// formats the summary header
fn format_header(left_name: &str, right_name: &str) -> String {
    format!("Diff Summary: {} → {}\n{}\n", 
        left_name, 
        right_name,
        "=".repeat(40)
    )
}

/// formats main statistics
fn format_statistics(
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
    options: &FormatOptions,
) -> String {
    let mut stats = String::new();
    
    // basic metrics
    let max_len = left_data.len().max(right_data.len());
    let similarity = if max_len == 0 {
        1.0
    } else {
        1.0 - (result.edit_distance as f64 / max_len as f64)
    };
    
    let similarity_percent = (similarity * 100.0).round();
    
    // status line
    if result.edit_distance == 0 {
        stats.push_str("Status: IDENTICAL\n");
    } else {
        stats.push_str(&format!("Status: {} changes ({:.1}% similar)\n", 
            result.edit_distance, similarity_percent));
    }
    
    stats.push_str(&format!("Edit Distance: {}\n", result.edit_distance));
    stats.push_str(&format!("Similarity: {:.2}%\n", similarity_percent));
    
    // file sizes
    stats.push_str(&format!("Left Size: {} bytes\n", left_data.len()));
    stats.push_str(&format!("Right Size: {} bytes\n", right_data.len()));
    
    let size_change = right_data.len() as i64 - left_data.len() as i64;
    if size_change != 0 {
        let sign = if size_change > 0 { "+" } else { "" };
        stats.push_str(&format!("Size Change: {}{} bytes\n", sign, size_change));
    }
    
    // operation counts
    let op_stats = compute_operation_stats(&result.operations);
    stats.push_str("\nOperations:\n");
    stats.push_str(&format!("  Total: {}\n", op_stats.total));
    
    if op_stats.insertions > 0 {
        stats.push_str(&format!("  Insertions: {} ({:.1}%)\n", 
            op_stats.insertions, 
            (op_stats.insertions as f64 / op_stats.total as f64) * 100.0
        ));
    }
    
    if op_stats.deletions > 0 {
        stats.push_str(&format!("  Deletions: {} ({:.1}%)\n", 
            op_stats.deletions,
            (op_stats.deletions as f64 / op_stats.total as f64) * 100.0
        ));
    }
    
    if op_stats.substitutions > 0 {
        stats.push_str(&format!("  Substitutions: {} ({:.1}%)\n", 
            op_stats.substitutions,
            (op_stats.substitutions as f64 / op_stats.total as f64) * 100.0
        ));
    }
    
    if op_stats.keeps > 0 {
        stats.push_str(&format!("  Unchanged: {} ({:.1}%)\n", 
            op_stats.keeps,
            (op_stats.keeps as f64 / op_stats.total as f64) * 100.0
        ));
    }
    
    // line-based statistics if text
    if is_likely_text(left_data) && is_likely_text(right_data) {
        match format_line_statistics(left_data, right_data, result, options) {
            Ok(line_stats) => stats.push_str(&line_stats),
            Err(_) => {}, // ignore errors in statistics
        }
    }
    
    stats
}

/// formats detailed breakdown section
fn format_detailed_breakdown(result: &DiffResult, options: &FormatOptions) -> String {
    let mut breakdown = String::new();
    
    breakdown.push_str("\nDetailed Breakdown:\n");
    breakdown.push_str(&"-".repeat(20));
    breakdown.push_str("\n");
    
    // operation type analysis
    let op_stats = compute_operation_stats(&result.operations);
    
    if op_stats.insertions > 0 || op_stats.deletions > 0 {
        breakdown.push_str(&format!("Content Changes: {} operations\n", 
            op_stats.insertions + op_stats.deletions + op_stats.substitutions));
    }
    
    if op_stats.keeps > 0 {
        breakdown.push_str(&format!("Preserved Content: {} bytes\n", op_stats.keeps));
    }
    
    // complexity assessment
    let complexity = assess_complexity(&op_stats);
    breakdown.push_str(&format!("Change Complexity: {}\n", complexity));
    
    // recommendations
    if options.include_metadata {
        breakdown.push_str(&format_recommendations(result, &op_stats));
    }
    
    breakdown
}

/// formats line-based statistics for text files
fn format_line_statistics(
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
    _options: &FormatOptions,
) -> Result<String> {
    let mut stats = String::new();
    
    // reconstruct right side for line counting
    let right_reconstructed = result.apply_to(left_data)
        .map_err(|e| crate::Error::format(format!("failed to reconstruct: {}", e)))?;
    
    let left_text = String::from_utf8_lossy(left_data);
    let right_text = String::from_utf8_lossy(&right_reconstructed);
    
    let left_lines = left_text.lines().count();
    let right_lines = right_text.lines().count();
    
    stats.push_str("\nLine Statistics:\n");
    stats.push_str(&format!("  Left Lines: {}\n", left_lines));
    stats.push_str(&format!("  Right Lines: {}\n", right_lines));
    
    let line_change = right_lines as i64 - left_lines as i64;
    if line_change != 0 {
        let sign = if line_change > 0 { "+" } else { "" };
        stats.push_str(&format!("  Line Change: {}{}\n", sign, line_change));
    }
    
    Ok(stats)
}

/// computes operation statistics
fn compute_operation_stats(operations: &[DiffOperation]) -> OperationStats {
    let total = operations.len();
    let insertions = operations.iter().filter(|op| matches!(op, DiffOperation::Insert(_))).count();
    let deletions = operations.iter().filter(|op| matches!(op, DiffOperation::Delete)).count();
    let substitutions = operations.iter().filter(|op| matches!(op, DiffOperation::Substitute(_))).count();
    let keeps = total - insertions - deletions - substitutions;
    
    OperationStats {
        total,
        insertions,
        deletions,
        substitutions,
        keeps,
    }
}

/// assesses change complexity
fn assess_complexity(stats: &OperationStats) -> &'static str {
    let change_ratio = (stats.insertions + stats.deletions + stats.substitutions) as f64 / stats.total as f64;
    
    if change_ratio < 0.1 {
        "Low (minor changes)"
    } else if change_ratio < 0.3 {
        "Medium (moderate changes)"
    } else if change_ratio < 0.7 {
        "High (significant changes)"
    } else {
        "Very High (major rewrite)"
    }
}

/// provides recommendations based on diff analysis
fn format_recommendations(result: &DiffResult, stats: &OperationStats) -> String {
    let mut recs = String::new();
    
    recs.push_str("\nRecommendations:\n");
    
    if result.edit_distance == 0 {
        recs.push_str("• Files are identical - no action needed\n");
    } else if stats.keeps as f64 / stats.total as f64 > 0.9 {
        recs.push_str("• Minimal changes detected - review changes carefully\n");
    } else if stats.substitutions > stats.insertions + stats.deletions {
        recs.push_str("• Many character substitutions - may indicate encoding issues\n");
    } else if stats.insertions > stats.deletions * 2 {
        recs.push_str("• Significant content additions detected\n");
    } else if stats.deletions > stats.insertions * 2 {
        recs.push_str("• Significant content removals detected\n");
    }
    
    if stats.total > 10000 {
        recs.push_str("• Large diff detected - consider breaking into smaller changes\n");
    }
    
    recs
}

/// checks if data is likely text
fn is_likely_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    
    // check for null bytes (strong indicator of binary)
    if data.contains(&0) {
        return false;
    }
    
    // check for reasonable ascii/utf8 content
    let text = String::from_utf8_lossy(data);
    let printable_ratio = text.chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count() as f64 / text.chars().count() as f64;
    
    printable_ratio > 0.7
}

/// operation statistics structure
#[derive(Debug)]
struct OperationStats {
    total: usize,
    insertions: usize,
    deletions: usize,
    substitutions: usize,
    keeps: usize,
}