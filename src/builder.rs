//! builder pattern for configuring diff operations
//! 
//! provides ergonomic api for creating and configuring diff instances

use crate::{
    error::{Error, Result}, 
    security::{SecurityLevel, SecurityConfig}, 
    formats::{OutputFormat, FormatOptions},
    result::DiffResult,
    algorithm::ConstantTimeDiff,
};
use std::path::Path;

/// builder for configuring diff operations with fluent api
#[derive(Debug, Clone)]
pub struct DiffBuilder {
    security_config: SecurityConfig,
    output_format: OutputFormat,
    format_options: FormatOptions,
    context_lines: usize,
    enable_color: bool,
    max_file_size: Option<usize>,
}

impl DiffBuilder {
    /// creates a new diff builder with default settings
    pub fn new() -> Self {
        Self {
            security_config: SecurityConfig::default(),
            output_format: OutputFormat::Unified,
            format_options: FormatOptions::default(),
            context_lines: 3,
            enable_color: false,
            max_file_size: None,
        }
    }
    
    /// sets the security level (convenience method)
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.security_config = level.to_config(self.max_file_size);
        self
    }
    
    /// sets detailed security configuration
    pub fn security_config(mut self, config: SecurityConfig) -> Self {
        self.security_config = config;
        self
    }
    
    /// sets the output format
    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }
    
    /// sets format-specific options
    pub fn format_options(mut self, options: FormatOptions) -> Self {
        self.format_options = options;
        self
    }
    
    /// sets context lines for unified diff format
    pub fn context_lines(mut self, lines: usize) -> Self {
        self.context_lines = lines;
        self
    }
    
    /// enables or disables colored output
    pub fn color(mut self, enable: bool) -> Self {
        self.enable_color = enable;
        self
    }
    
    /// sets maximum file size limit
    pub fn max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = Some(size);
        self.security_config.max_input_size = size;
        self
    }
    
    /// builds the configured diff instance
    pub fn build(self) -> Result<Diff> {
        // validate configuration
        self.security_config.validate()?;
        
        let differ = ConstantTimeDiff::new(self.security_config.to_legacy());
        
        Ok(Diff {
            differ,
            output_format: self.output_format,
            format_options: self.format_options,
            context_lines: self.context_lines,
            enable_color: self.enable_color,
        })
    }
}

impl Default for DiffBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// configured diff instance for performing comparisons
#[derive(Debug)]
pub struct Diff {
    differ: ConstantTimeDiff,
    output_format: OutputFormat,
    format_options: FormatOptions,
    context_lines: usize,
    enable_color: bool,
}

impl Diff {
    /// compares two byte sequences
    pub fn compare(&self, left: &[u8], right: &[u8]) -> Result<DiffResult> {
        let result = self.differ.diff(left, right)?;
        
        Ok(DiffResult::new(
            result,
            left.to_vec(),
            right.to_vec(),
            self.output_format.clone(),
            self.format_options.clone(),
            self.context_lines,
            self.enable_color,
        ))
    }
    
    /// compares two text strings
    pub fn compare_text(&self, left: &str, right: &str) -> Result<DiffResult> {
        self.compare(left.as_bytes(), right.as_bytes())
    }
    
    /// compares two files by path
    pub fn compare_files<P: AsRef<Path>>(&self, left_path: P, right_path: P) -> Result<DiffResult> {
        let left_data = std::fs::read(left_path.as_ref())
            .map_err(|e| Error::Io(e))?;
        let right_data = std::fs::read(right_path.as_ref())
            .map_err(|e| Error::Io(e))?;
        
        // check file size limits
        let max_size = self.differ.config().max_input_size;
        if max_size > 0 {
            if left_data.len() > max_size || right_data.len() > max_size {
                return Err(Error::resource_limit(format!(
                    "file size {} exceeds limit {}",
                    left_data.len().max(right_data.len()),
                    max_size
                )));
            }
        }
        
        self.compare(&left_data, &right_data)
    }
    
    /// compares two files with string names (for display)
    pub fn compare_files_named(&self, left_path: &str, right_path: &str, left_data: &[u8], right_data: &[u8]) -> Result<DiffResult> {
        let result = self.differ.diff(left_data, right_data)?;
        
        Ok(DiffResult::new_with_names(
            result,
            left_data.to_vec(),
            right_data.to_vec(),
            left_path.to_string(),
            right_path.to_string(),
            self.output_format.clone(),
            self.format_options.clone(),
            self.context_lines,
            self.enable_color,
        ))
    }
    
    /// async file comparison (requires async feature)
    #[cfg(feature = "async")]
    pub async fn compare_files_async<P: AsRef<Path>>(&self, left_path: P, right_path: P) -> Result<DiffResult> {
        let left_data = tokio::fs::read(left_path.as_ref()).await?;
        let right_data = tokio::fs::read(right_path.as_ref()).await?;
        
        // perform diff in blocking task to avoid blocking async runtime
        let differ = self.differ.clone();
        let output_format = self.output_format.clone();
        let format_options = self.format_options.clone();
        let context_lines = self.context_lines;
        let enable_color = self.enable_color;
        
        let result = tokio::task::spawn_blocking(move || {
            let result = differ.diff(&left_data, &right_data)?;
            Ok(DiffResult::new(
                result,
                left_data,
                right_data,
                output_format,
                format_options,
                context_lines,
                enable_color,
            ))
        }).await??;
        
        Ok(result)
    }
}