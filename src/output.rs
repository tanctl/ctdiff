//! output formatting for diff results
//! 
//! implements various output formats including unified diff compatible
//! with standard unix diff tools and security-focused formatting.

use ctdiff::types::{DiffOperation, DiffResult};
use clap::ValueEnum;
use colored::Colorize;

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// unified diff format (default)
    Unified,
    /// side-by-side comparison
    SideBySide,
    /// simple operation list
    Operations,
    /// security-focused minimal output
    Minimal,
}

pub struct DiffFormatter {
    format: OutputFormat,
    use_color: bool,
    _context_lines: usize,
}

impl DiffFormatter {
    pub fn new(format: OutputFormat, use_color: bool, context_lines: usize) -> Self {
        Self {
            format,
            use_color,
            _context_lines: context_lines,
        }
    }
    
    pub fn format_diff(
        &self,
        file1_name: &str,
        file2_name: &str,
        file1_data: &[u8],
        file2_data: &[u8],
        result: &DiffResult,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match self.format {
            OutputFormat::Unified => self.format_unified(file1_name, file2_name, file1_data, result),
            OutputFormat::SideBySide => self.format_side_by_side(file1_name, file2_name, file1_data, file2_data, result),
            OutputFormat::Operations => self.format_operations(result),
            OutputFormat::Minimal => self.format_minimal(result),
        }
    }
    
    fn format_unified(
        &self,
        file1_name: &str,
        file2_name: &str,
        file1_data: &[u8],
        result: &DiffResult,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();
        
        // header
        output.push_str(&format!("--- {}\n", file1_name));
        output.push_str(&format!("+++ {}\n", file2_name));
        
        if result.edit_distance == 0 {
            return Ok(output);
        }
        
        // convert operations to unified format
        let hunks = self.build_hunks(file1_data, result)?;
        
        for hunk in hunks {
            output.push_str(&hunk.format_header());
            output.push('\n');
            
            for line in hunk.lines {
                let formatted_line = if self.use_color {
                    match line.operation {
                        LineOperation::Context => format!(" {}", line.content),
                        LineOperation::Delete => format!("-{}", line.content).red().to_string(),
                        LineOperation::Insert => format!("+{}", line.content).green().to_string(),
                    }
                } else {
                    match line.operation {
                        LineOperation::Context => format!(" {}", line.content),
                        LineOperation::Delete => format!("-{}", line.content),
                        LineOperation::Insert => format!("+{}", line.content),
                    }
                };
                output.push_str(&formatted_line);
                output.push('\n');
            }
        }
        
        Ok(output)
    }
    
    fn format_side_by_side(
        &self,
        file1_name: &str,
        file2_name: &str,
        file1_data: &[u8],
        _file2_data: &[u8],
        result: &DiffResult,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();
        
        // header
        let header = format!("{:40} | {}", file1_name, file2_name);
        output.push_str(&header);
        output.push('\n');
        output.push_str(&"-".repeat(header.len()));
        output.push('\n');
        
        // reconstruct both sequences line by line
        let file1_lines = self.bytes_to_display_lines(file1_data);
        let file2_lines = self.bytes_to_display_lines(&result.apply_to(file1_data)?);
        
        let max_lines = file1_lines.len().max(file2_lines.len());
        
        for i in 0..max_lines {
            let empty_string = String::new();
            let left = file1_lines.get(i).unwrap_or(&empty_string);
            let right = file2_lines.get(i).unwrap_or(&empty_string);
            
            let line_same = left == right;
            let left_display = format!("{:40}", left.chars().take(40).collect::<String>());
            
            let formatted_line = if self.use_color && !line_same {
                format!("{} | {}", left_display.red(), right.green())
            } else if line_same {
                format!("{} | {}", left_display, right)
            } else {
                format!("{} | {}", left_display, right)
            };
            
            output.push_str(&formatted_line);
            output.push('\n');
        }
        
        Ok(output)
    }
    
    fn format_operations(&self, result: &DiffResult) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();
        
        output.push_str(&format!("edit distance: {}\n", result.edit_distance));
        output.push_str(&format!("operations: {}\n", result.operations.len()));
        output.push_str("---\n");
        
        for (i, op) in result.operations.iter().enumerate() {
            let op_str = match op {
                DiffOperation::Keep => "keep".to_string(),
                DiffOperation::Insert(b) => format!("insert '{}'", char::from(*b).escape_debug()),
                DiffOperation::Delete => "delete".to_string(),
                DiffOperation::Substitute(b) => format!("substitute '{}'", char::from(*b).escape_debug()),
            };
            
            let formatted = if self.use_color {
                match op {
                    DiffOperation::Keep => format!("{:4}: {}", i, op_str),
                    DiffOperation::Insert(_) => format!("{:4}: {}", i, op_str).green().to_string(),
                    DiffOperation::Delete => format!("{:4}: {}", i, op_str).red().to_string(),
                    DiffOperation::Substitute(_) => format!("{:4}: {}", i, op_str).yellow().to_string(),
                }
            } else {
                format!("{:4}: {}", i, op_str)
            };
            
            output.push_str(&formatted);
            output.push('\n');
        }
        
        Ok(output)
    }
    
    fn format_minimal(&self, result: &DiffResult) -> Result<String, Box<dyn std::error::Error>> {
        if result.edit_distance == 0 {
            Ok("files identical\n".to_string())
        } else {
            Ok(format!("files differ: {} changes\n", result.edit_distance))
        }
    }
    
    fn bytes_to_display_lines(&self, data: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(data)
            .lines()
            .map(|line| line.to_string())
            .collect()
    }
    
    fn build_hunks(&self, file1_data: &[u8], result: &DiffResult) -> Result<Vec<Hunk>, Box<dyn std::error::Error>> {
        // convert byte-level operations to line-level for unified diff
        let file1_str = String::from_utf8_lossy(file1_data);
        let file2_data = result.apply_to(file1_data)?;
        let file2_str = String::from_utf8_lossy(&file2_data);
        
        let file1_lines: Vec<&str> = file1_str.lines().collect();
        let file2_lines: Vec<&str> = file2_str.lines().collect();
        
        // simple implementation: treat entire diff as one hunk
        // could be optimized to create multiple hunks for large files
        let mut hunk = Hunk {
            old_start: 1,
            old_count: file1_lines.len(),
            new_start: 1,
            new_count: file2_lines.len(),
            lines: Vec::new(),
        };
        
        // use a simple line-based diff for display purposes
        // this is not constant-time but only used for output formatting
        let changes = self.compute_line_diff(&file1_lines, &file2_lines);
        
        for change in changes {
            match change {
                LineChange::Equal(line) => {
                    hunk.lines.push(HunkLine {
                        operation: LineOperation::Context,
                        content: line,
                    });
                }
                LineChange::Delete(line) => {
                    hunk.lines.push(HunkLine {
                        operation: LineOperation::Delete,
                        content: line,
                    });
                }
                LineChange::Insert(line) => {
                    hunk.lines.push(HunkLine {
                        operation: LineOperation::Insert,
                        content: line,
                    });
                }
            }
        }
        
        Ok(vec![hunk])
    }
    
    fn compute_line_diff(&self, old_lines: &[&str], new_lines: &[&str]) -> Vec<LineChange> {
        // simple line-based diff implementation for display
        // not constant-time, but only used for output formatting
        let mut changes = Vec::new();
        let mut i = 0;
        let mut j = 0;
        
        while i < old_lines.len() || j < new_lines.len() {
            if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
                changes.push(LineChange::Equal(old_lines[i].to_string()));
                i += 1;
                j += 1;
            } else if i < old_lines.len() && (j >= new_lines.len() || old_lines[i] != new_lines[j]) {
                changes.push(LineChange::Delete(old_lines[i].to_string()));
                i += 1;
            } else if j < new_lines.len() {
                changes.push(LineChange::Insert(new_lines[j].to_string()));
                j += 1;
            }
        }
        
        changes
    }
}

struct Hunk {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    lines: Vec<HunkLine>,
}

impl Hunk {
    fn format_header(&self) -> String {
        format!("@@ -{},{} +{},{} @@", 
                self.old_start, self.old_count,
                self.new_start, self.new_count)
    }
}

struct HunkLine {
    operation: LineOperation,
    content: String,
}

#[derive(Debug)]
enum LineOperation {
    Context,
    Delete,
    Insert,
}

enum LineChange {
    Equal(String),
    Delete(String),
    Insert(String),
}