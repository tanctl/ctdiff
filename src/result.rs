//! diff result types and formatting
//! 
//! provides rich result objects with multiple output format support

use crate::{
    error::Result,
    formats::{OutputFormat, FormatOptions, unified, json, html, git, summary},
    types::DiffResult as LegacyDiffResult,
};

/// rich diff result with formatting capabilities
#[derive(Debug, Clone)]
pub struct DiffResult {
    inner: LegacyDiffResult,
    left_data: Vec<u8>,
    right_data: Vec<u8>,
    left_name: String,
    right_name: String,
    output_format: OutputFormat,
    format_options: FormatOptions,
    context_lines: usize,
    enable_color: bool,
}

impl DiffResult {
    /// creates a new diff result
    pub fn new(
        inner: LegacyDiffResult,
        left_data: Vec<u8>,
        right_data: Vec<u8>,
        output_format: OutputFormat,
        format_options: FormatOptions,
        context_lines: usize,
        enable_color: bool,
    ) -> Self {
        Self {
            inner,
            left_data,
            right_data,
            left_name: "left".to_string(),
            right_name: "right".to_string(),
            output_format,
            format_options,
            context_lines,
            enable_color,
        }
    }
    
    /// creates a new diff result with file names
    pub fn new_with_names(
        inner: LegacyDiffResult,
        left_data: Vec<u8>,
        right_data: Vec<u8>,
        left_name: String,
        right_name: String,
        output_format: OutputFormat,
        format_options: FormatOptions,
        context_lines: usize,
        enable_color: bool,
    ) -> Self {
        Self {
            inner,
            left_data,
            right_data,
            left_name,
            right_name,
            output_format,
            format_options,
            context_lines,
            enable_color,
        }
    }
    
    /// gets the edit distance between inputs
    pub fn edit_distance(&self) -> usize {
        self.inner.edit_distance
    }
    
    /// checks if inputs are identical
    pub fn is_identical(&self) -> bool {
        self.inner.edit_distance == 0
    }
    
    /// gets the raw diff operations
    pub fn operations(&self) -> &[crate::types::DiffOperation] {
        &self.inner.operations
    }
    
    /// gets similarity ratio (0.0 = completely different, 1.0 = identical)
    pub fn similarity(&self) -> f64 {
        let max_len = self.left_data.len().max(self.right_data.len());
        if max_len == 0 {
            return 1.0;
        }
        1.0 - (self.edit_distance() as f64 / max_len as f64)
    }
    
    /// formats result using configured output format
    pub fn format(&self) -> Result<String> {
        match self.output_format {
            OutputFormat::Unified => {
                unified::format(
                    &self.left_name,
                    &self.right_name,
                    &self.left_data,
                    &self.right_data,
                    &self.inner,
                    self.context_lines,
                    self.enable_color,
                    &self.format_options,
                )
            }
            OutputFormat::Json => {
                json::format(
                    &self.left_name,
                    &self.right_name,
                    &self.left_data,
                    &self.right_data,
                    &self.inner,
                    &self.format_options,
                )
            }
            OutputFormat::Html => {
                html::format(
                    &self.left_name,
                    &self.right_name,
                    &self.left_data,
                    &self.right_data,
                    &self.inner,
                    self.context_lines,
                    &self.format_options,
                )
            }
            OutputFormat::Git => {
                git::format(
                    &self.left_name,
                    &self.right_name,
                    &self.left_data,
                    &self.right_data,
                    &self.inner,
                    self.context_lines,
                    &self.format_options,
                )
            }
            OutputFormat::Summary => {
                summary::format(
                    &self.left_name,
                    &self.right_name,
                    &self.left_data,
                    &self.right_data,
                    &self.inner,
                    &self.format_options,
                )
            }
        }
    }
    
    /// formats result with specific format (overrides configured format)
    pub fn format_as(&self, format: OutputFormat) -> Result<String> {
        let mut result = self.clone();
        result.output_format = format;
        result.format()
    }
    
    /// writes formatted result to file
    pub fn write_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let formatted = self.format()?;
        std::fs::write(path, formatted)?;
        Ok(())
    }
    
    /// writes formatted result to writer
    pub fn write_to<W: std::io::Write>(&self, mut writer: W) -> Result<()> {
        let formatted = self.format()?;
        writer.write_all(formatted.as_bytes())?;
        Ok(())
    }
    
    /// converts to json value for programmatic access
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let json_str = self.format_as(OutputFormat::Json)?;
        let value: serde_json::Value = serde_json::from_str(&json_str)?;
        Ok(value)
    }
    
    /// gets detailed statistics about the diff
    pub fn statistics(&self) -> DiffStatistics {
        let total_ops = self.inner.operations.len();
        let insertions = self.inner.operations.iter()
            .filter(|op| matches!(op, crate::types::DiffOperation::Insert(_)))
            .count();
        let deletions = self.inner.operations.iter()
            .filter(|op| matches!(op, crate::types::DiffOperation::Delete))
            .count();
        let substitutions = self.inner.operations.iter()
            .filter(|op| matches!(op, crate::types::DiffOperation::Substitute(_)))
            .count();
        let keeps = total_ops - insertions - deletions - substitutions;
        
        DiffStatistics {
            edit_distance: self.edit_distance(),
            similarity: self.similarity(),
            total_operations: total_ops,
            insertions,
            deletions,
            substitutions,
            keeps,
            left_size: self.left_data.len(),
            right_size: self.right_data.len(),
        }
    }
}

/// detailed statistics about a diff operation
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffStatistics {
    /// total edit distance
    pub edit_distance: usize,
    /// similarity ratio (0.0 to 1.0)
    pub similarity: f64,
    /// total number of operations
    pub total_operations: usize,
    /// number of insertions
    pub insertions: usize,
    /// number of deletions
    pub deletions: usize,
    /// number of substitutions
    pub substitutions: usize,
    /// number of keeps (unchanged)
    pub keeps: usize,
    /// size of left input
    pub left_size: usize,
    /// size of right input
    pub right_size: usize,
}