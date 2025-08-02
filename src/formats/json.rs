//! json output format implementation
//! 
//! structured json output for programmatic consumption

use crate::{error::Result, types::{DiffResult, DiffOperation}};
use crate::formats::FormatOptions;
use serde::{Serialize, Deserialize};

/// represents the complete diff result in json format
#[derive(Debug, Serialize, Deserialize)]
struct JsonDiffResult {
    /// metadata about the comparison
    metadata: JsonMetadata,
    /// detailed statistics
    statistics: JsonStatistics,
    /// list of diff operations
    operations: Vec<JsonOperation>,
    /// line-based changes (if requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    lines: Option<Vec<JsonLineChange>>,
}

/// metadata about the diff
#[derive(Debug, Serialize, Deserialize)]
struct JsonMetadata {
    /// name/path of left file
    left_name: String,
    /// name/path of right file  
    right_name: String,
    /// size of left input in bytes
    left_size: usize,
    /// size of right input in bytes
    right_size: usize,
    /// format version for compatibility
    format_version: String,
    /// timestamp of comparison
    timestamp: String,
}

/// statistical information about the diff
#[derive(Debug, Serialize, Deserialize)]
struct JsonStatistics {
    /// total edit distance
    edit_distance: usize,
    /// similarity ratio (0.0 to 1.0)
    similarity: f64,
    /// whether files are identical
    identical: bool,
    /// operation counts
    operations: JsonOperationCounts,
}

/// counts of different operation types
#[derive(Debug, Serialize, Deserialize)]
struct JsonOperationCounts {
    /// total number of operations
    total: usize,
    /// number of insertions
    insertions: usize,
    /// number of deletions
    deletions: usize,
    /// number of substitutions
    substitutions: usize,
    /// number of unchanged bytes
    keeps: usize,
}

/// individual diff operation in json format
#[derive(Debug, Serialize, Deserialize)]
struct JsonOperation {
    /// type of operation
    #[serde(rename = "type")]
    op_type: String,
    /// position in original sequence
    position: usize,
    /// byte value for insert/substitute operations
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<u8>,
    /// character representation (if printable)
    #[serde(skip_serializing_if = "Option::is_none")]
    char: Option<String>,
}

/// line-based change representation
#[derive(Debug, Serialize, Deserialize)]
struct JsonLineChange {
    /// type of change (equal, delete, insert)
    #[serde(rename = "type")]
    change_type: String,
    /// line number in original file
    #[serde(skip_serializing_if = "Option::is_none")]
    old_line: Option<usize>,
    /// line number in new file
    #[serde(skip_serializing_if = "Option::is_none")]
    new_line: Option<usize>,
    /// content of the line
    content: String,
}

/// formats diff result as json
pub fn format(
    left_name: &str,
    right_name: &str,
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
    options: &FormatOptions,
) -> Result<String> {
    let statistics = compute_statistics(left_data, right_data, result);
    
    let json_result = JsonDiffResult {
        metadata: JsonMetadata {
            left_name: left_name.to_string(),
            right_name: right_name.to_string(),
            left_size: left_data.len(),
            right_size: right_data.len(),
            format_version: "1.0".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
        statistics,
        operations: convert_operations(&result.operations),
        lines: if should_include_lines(options) {
            Some(compute_line_changes(left_data, right_data, result)?)
        } else {
            None
        },
    };
    
    let json_str = if options.json_pretty {
        serde_json::to_string_pretty(&json_result)?
    } else {
        serde_json::to_string(&json_result)?
    };
    
    Ok(json_str)
}

/// computes statistics for json output
fn compute_statistics(left_data: &[u8], right_data: &[u8], result: &DiffResult) -> JsonStatistics {
    let total_ops = result.operations.len();
    let insertions = result.operations.iter()
        .filter(|op| matches!(op, DiffOperation::Insert(_)))
        .count();
    let deletions = result.operations.iter()
        .filter(|op| matches!(op, DiffOperation::Delete))
        .count();
    let substitutions = result.operations.iter()
        .filter(|op| matches!(op, DiffOperation::Substitute(_)))
        .count();
    let keeps = total_ops - insertions - deletions - substitutions;
    
    let max_len = left_data.len().max(right_data.len());
    let similarity = if max_len == 0 {
        1.0
    } else {
        1.0 - (result.edit_distance as f64 / max_len as f64)
    };
    
    JsonStatistics {
        edit_distance: result.edit_distance,
        similarity,
        identical: result.edit_distance == 0,
        operations: JsonOperationCounts {
            total: total_ops,
            insertions,
            deletions,
            substitutions,
            keeps,
        },
    }
}

/// converts diff operations to json format
fn convert_operations(operations: &[DiffOperation]) -> Vec<JsonOperation> {
    operations.iter().enumerate().map(|(pos, op)| {
        match op {
            DiffOperation::Keep => JsonOperation {
                op_type: "keep".to_string(),
                position: pos,
                value: None,
                char: None,
            },
            DiffOperation::Insert(byte) => JsonOperation {
                op_type: "insert".to_string(),
                position: pos,
                value: Some(*byte),
                char: char_representation(*byte),
            },
            DiffOperation::Delete => JsonOperation {
                op_type: "delete".to_string(),
                position: pos,
                value: None,
                char: None,
            },
            DiffOperation::Substitute(byte) => JsonOperation {
                op_type: "substitute".to_string(),
                position: pos,
                value: Some(*byte),
                char: char_representation(*byte),
            },
        }
    }).collect()
}

/// creates character representation for byte value
fn char_representation(byte: u8) -> Option<String> {
    let ch = char::from(byte);
    if ch.is_ascii_graphic() || ch == ' ' {
        Some(ch.to_string())
    } else {
        Some(format!("\\x{:02x}", byte))
    }
}

/// determines if line changes should be included
fn should_include_lines(options: &FormatOptions) -> bool {
    // include lines for verbose output or if specifically requested
    options.include_metadata || options.word_diff
}

/// computes line changes for json output
fn compute_line_changes(
    left_data: &[u8],
    _right_data: &[u8],
    result: &DiffResult,
) -> Result<Vec<JsonLineChange>> {
    // reconstruct right side
    let right_reconstructed = result.apply_to(left_data)
        .map_err(|e| crate::Error::format(format!("failed to reconstruct: {}", e)))?;
    
    let left_text = String::from_utf8_lossy(left_data);
    let right_text = String::from_utf8_lossy(&right_reconstructed);
    
    let left_lines: Vec<&str> = left_text.lines().collect();
    let right_lines: Vec<&str> = right_text.lines().collect();
    
    let mut changes = Vec::new();
    let mut old_line = 1;
    let mut new_line = 1;
    let mut i = 0;
    let mut j = 0;
    
    while i < left_lines.len() || j < right_lines.len() {
        if i < left_lines.len() && j < right_lines.len() && left_lines[i] == right_lines[j] {
            changes.push(JsonLineChange {
                change_type: "equal".to_string(),
                old_line: Some(old_line),
                new_line: Some(new_line),
                content: left_lines[i].to_string(),
            });
            i += 1;
            j += 1;
            old_line += 1;
            new_line += 1;
        } else if i < left_lines.len() && (j >= right_lines.len() || left_lines[i] != *right_lines.get(j).unwrap_or(&"")) {
            changes.push(JsonLineChange {
                change_type: "delete".to_string(),
                old_line: Some(old_line),
                new_line: None,
                content: left_lines[i].to_string(),
            });
            i += 1;
            old_line += 1;
        } else if j < right_lines.len() {
            changes.push(JsonLineChange {
                change_type: "insert".to_string(),
                old_line: None,
                new_line: Some(new_line),
                content: right_lines[j].to_string(),
            });
            j += 1;
            new_line += 1;
        }
    }
    
    Ok(changes)
}

// add chrono dependency placeholder - would need to add to Cargo.toml
mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> DateTime {
            DateTime
        }
    }
    
    pub struct DateTime;
    impl DateTime {
        pub fn to_rfc3339(&self) -> String {
            // placeholder - would use actual chrono in real implementation
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string()
        }
    }
}