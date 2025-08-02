//! unified diff format implementation
//! 
//! standard unified diff format compatible with unix diff tools

use crate::{error::{Error, Result}, types::{DiffResult, DiffOperation}};
use crate::formats::FormatOptions;
use colored::Colorize;

/// formats diff result as unified diff
pub fn format(
    left_name: &str,
    right_name: &str,
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
    context_lines: usize,
    enable_color: bool,
    options: &FormatOptions,
) -> Result<String> {
    let mut output = String::new();
    
    // add metadata if requested
    if options.include_metadata {
        output.push_str(&format!("--- {}\n", left_name));
        output.push_str(&format!("+++ {}\n", right_name));
    }
    
    // if files are identical, return early
    if result.edit_distance == 0 {
        return Ok(output);
    }
    
    // convert to text for line-based processing
    let left_text = String::from_utf8_lossy(left_data);
    let right_text = reconstruct_right_text(left_data, result)?;
    let right_text_str = String::from_utf8_lossy(&right_text);
    
    let left_lines: Vec<&str> = left_text.lines().collect();
    let right_lines: Vec<&str> = right_text_str.lines().collect();
    
    // build hunks with context
    let hunks = build_hunks(&left_lines, &right_lines, context_lines, options)?;
    
    for hunk in hunks {
        output.push_str(&hunk.format_header());
        output.push('\n');
        
        for line in hunk.lines {
            let formatted_line = format_line(&line, enable_color, options);
            output.push_str(&formatted_line);
            output.push('\n');
        }
    }
    
    Ok(output)
}

/// reconstructs the right-side text from operations
fn reconstruct_right_text(left_data: &[u8], result: &DiffResult) -> Result<Vec<u8>> {
    result.apply_to(left_data).map_err(|e| Error::format(format!("failed to reconstruct text: {}", e)))
}

/// builds hunks with proper context lines
fn build_hunks(
    left_lines: &[&str],
    right_lines: &[&str], 
    context_lines: usize,
    options: &FormatOptions,
) -> Result<Vec<Hunk>> {
    // simple line-based diff for display
    let changes = compute_line_changes(left_lines, right_lines);
    
    if changes.is_empty() {
        return Ok(vec![]);
    }
    
    // group changes into hunks with context
    let mut hunks = Vec::new();
    let mut current_hunk: Option<HunkBuilder> = None;
    
    for (i, change) in changes.iter().enumerate() {
        match change {
            LineChange::Equal(_) => {
                if let Some(ref mut hunk) = current_hunk {
                    // add context line to existing hunk or finish it
                    if hunk.should_continue(i, context_lines) {
                        hunk.add_line(change.clone(), i);
                    } else {
                        // finish current hunk and start new one if more changes follow
                        let built_hunk = std::mem::replace(hunk, HunkBuilder::new()).build(options);
                        hunks.push(built_hunk);
                        current_hunk = None;
                        
                        // check if we need to start a new hunk soon
                        if has_changes_ahead(&changes[i..], context_lines) {
                            let mut new_hunk = HunkBuilder::new();
                            new_hunk.add_line(change.clone(), i);
                            current_hunk = Some(new_hunk);
                        }
                    }
                }
            }
            LineChange::Delete(_) | LineChange::Insert(_) => {
                if current_hunk.is_none() {
                    let mut new_hunk = HunkBuilder::new();
                    // add leading context
                    let context_start = i.saturating_sub(context_lines);
                    for j in context_start..i {
                        if let LineChange::Equal(_) = &changes[j] {
                            new_hunk.add_line(changes[j].clone(), j);
                        }
                    }
                    current_hunk = Some(new_hunk);
                }
                
                if let Some(ref mut hunk) = current_hunk {
                    hunk.add_line(change.clone(), i);
                }
            }
        }
    }
    
    // finish last hunk
    if let Some(hunk) = current_hunk {
        hunks.push(hunk.build(options));
    }
    
    Ok(hunks)
}

/// checks if there are changes ahead within context distance
fn has_changes_ahead(changes: &[LineChange], context_lines: usize) -> bool {
    changes.iter().take(context_lines * 2).any(|c| !matches!(c, LineChange::Equal(_)))
}

/// computes line-level changes between texts
fn compute_line_changes(left_lines: &[&str], right_lines: &[&str]) -> Vec<LineChange> {
    // simple line-based diff using myers algorithm approximation
    let mut changes = Vec::new();
    let mut i = 0;
    let mut j = 0;
    
    while i < left_lines.len() || j < right_lines.len() {
        if i < left_lines.len() && j < right_lines.len() && left_lines[i] == right_lines[j] {
            changes.push(LineChange::Equal(left_lines[i].to_string()));
            i += 1;
            j += 1;
        } else if i < left_lines.len() && (j >= right_lines.len() || left_lines[i] != *right_lines.get(j).unwrap_or(&"")) {
            changes.push(LineChange::Delete(left_lines[i].to_string()));
            i += 1;
        } else if j < right_lines.len() {
            changes.push(LineChange::Insert(right_lines[j].to_string()));
            j += 1;
        }
    }
    
    changes
}

/// formats a single line with colors and options
fn format_line(line: &HunkLine, enable_color: bool, options: &FormatOptions) -> String {
    let prefix = match line.operation {
        LineOperation::Context => " ",
        LineOperation::Delete => "-",
        LineOperation::Insert => "+",
    };
    
    let line_number = if options.show_line_numbers {
        format!("{:4} ", line.line_number)
    } else {
        String::new()
    };
    
    let content = if let Some(max_width) = options.max_line_width {
        if line.content.len() > max_width {
            format!("{}...", &line.content[..max_width.saturating_sub(3)])
        } else {
            line.content.clone()
        }
    } else {
        line.content.clone()
    };
    
    let full_line = format!("{}{}{}", line_number, prefix, content);
    
    if enable_color {
        match line.operation {
            LineOperation::Context => full_line,
            LineOperation::Delete => full_line.red().to_string(),
            LineOperation::Insert => full_line.green().to_string(),
        }
    } else {
        full_line
    }
}

/// hunk builder for collecting lines
#[derive(Debug)]
struct HunkBuilder {
    lines: Vec<HunkLine>,
    old_start: usize,
    new_start: usize,
    last_line: usize,
}

impl HunkBuilder {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            old_start: 0,
            new_start: 0,
            last_line: 0,
        }
    }
    
    fn add_line(&mut self, change: LineChange, line_number: usize) {
        if self.lines.is_empty() {
            self.old_start = line_number + 1;
            self.new_start = line_number + 1;
        }
        
        let hunk_line = match change {
            LineChange::Equal(content) => HunkLine {
                operation: LineOperation::Context,
                content,
                line_number: line_number + 1,
            },
            LineChange::Delete(content) => HunkLine {
                operation: LineOperation::Delete,
                content,
                line_number: line_number + 1,
            },
            LineChange::Insert(content) => HunkLine {
                operation: LineOperation::Insert,
                content,
                line_number: line_number + 1,
            },
        };
        
        self.lines.push(hunk_line);
        self.last_line = line_number;
    }
    
    fn should_continue(&self, current_line: usize, context_lines: usize) -> bool {
        current_line - self.last_line <= context_lines * 2
    }
    
    fn build(self, _options: &FormatOptions) -> Hunk {
        let old_count = self.lines.iter().filter(|l| matches!(l.operation, LineOperation::Context | LineOperation::Delete)).count();
        let new_count = self.lines.iter().filter(|l| matches!(l.operation, LineOperation::Context | LineOperation::Insert)).count();
        
        Hunk {
            old_start: self.old_start,
            old_count,
            new_start: self.new_start,
            new_count,
            lines: self.lines,
        }
    }
}

/// represents a hunk in unified diff format
#[derive(Debug)]
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

/// represents a line within a hunk
#[derive(Debug, Clone)]
struct HunkLine {
    operation: LineOperation,
    content: String,
    line_number: usize,
}

/// line operation types
#[derive(Debug, Clone, PartialEq, Eq)]
enum LineOperation {
    Context,
    Delete,
    Insert,
}

/// line change types for diff computation
#[derive(Debug, Clone)]
enum LineChange {
    Equal(String),
    Delete(String),
    Insert(String),
}