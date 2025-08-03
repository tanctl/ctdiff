//! git patch format implementation
//! 
//! git-compatible patch format for version control integration

use crate::{error::Result, types::DiffResult};
use crate::formats::FormatOptions;

/// formats diff result as git patch
pub fn format(
    left_name: &str,
    right_name: &str,
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
    context_lines: usize,
    options: &FormatOptions,
) -> Result<String> {
    let mut output = String::new();
    
    // git patch header
    if options.include_metadata {
        output.push_str(&format_git_header(left_name, right_name, left_data, right_data, result));
    }
    
    // if files are identical, return early
    if result.edit_distance == 0 {
        return Ok(output);
    }
    
    // reconstruct right side
    let right_reconstructed = result.apply_to(left_data)
        .map_err(|e| crate::Error::format(format!("failed to reconstruct: {}", e)))?;
    
    let left_text = String::from_utf8_lossy(left_data);
    let right_text = String::from_utf8_lossy(&right_reconstructed);
    
    let left_lines: Vec<&str> = left_text.lines().collect();
    let right_lines: Vec<&str> = right_text.lines().collect();
    
    // add standard diff header
    output.push_str(&format!("--- {}\n", left_name));
    output.push_str(&format!("+++ {}\n", right_name));
    
    // generate hunks
    let hunks = build_git_hunks(&left_lines, &right_lines, context_lines, options)?;
    
    for hunk in hunks {
        output.push_str(&hunk.format_git_hunk());
    }
    
    Ok(output)
}

/// formats git-style patch header with metadata
fn format_git_header(
    left_name: &str,
    right_name: &str,
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
) -> String {
    let mut header = String::new();
    
    // simplified git header (would normally include commit hashes, etc.)
    header.push_str(&format!("diff --git a/{} b/{}\n", left_name, right_name));
    
    // file mode (assume text files)
    header.push_str("index 0000000..1111111 100644\n");
    
    // detect new/deleted files
    if left_data.is_empty() {
        header.push_str(&format!("new file mode 100644\n"));
    } else if right_data.is_empty() || result.edit_distance == left_data.len() {
        header.push_str(&format!("deleted file mode 100644\n"));
    }
    
    header
}

/// builds git-style hunks with proper context
fn build_git_hunks(
    left_lines: &[&str],
    right_lines: &[&str],
    context_lines: usize,
    _options: &FormatOptions,
) -> Result<Vec<GitHunk>> {
    let changes = compute_line_changes(left_lines, right_lines);
    
    if changes.is_empty() {
        return Ok(vec![]);
    }
    
    let mut hunks = Vec::new();
    let mut current_hunk: Option<GitHunkBuilder> = None;
    
    for (i, change) in changes.iter().enumerate() {
        match change {
            LineChange::Equal(_) => {
                if let Some(ref mut hunk) = current_hunk {
                    if hunk.should_continue(i, context_lines, &changes) {
                        hunk.add_line(change.clone(), i);
                    } else {
                        let built_hunk = std::mem::replace(hunk, GitHunkBuilder::new(i)).build();
                        hunks.push(built_hunk);
                        current_hunk = None;
                        
                        // start new hunk if more changes ahead
                        if has_changes_ahead(&changes[i..], context_lines) {
                            let mut new_hunk = GitHunkBuilder::new(i);
                            new_hunk.add_context_before(&changes, i, context_lines);
                            new_hunk.add_line(change.clone(), i);
                            current_hunk = Some(new_hunk);
                        }
                    }
                }
            }
            LineChange::Delete(_) | LineChange::Insert(_) => {
                if current_hunk.is_none() {
                    let mut new_hunk = GitHunkBuilder::new(i);
                    new_hunk.add_context_before(&changes, i, context_lines);
                    current_hunk = Some(new_hunk);
                }
                
                if let Some(ref mut hunk) = current_hunk {
                    hunk.add_line(change.clone(), i);
                }
            }
        }
    }
    
    // finish last hunk with trailing context
    if let Some(mut hunk) = current_hunk {
        hunk.add_context_after(&changes, context_lines);
        hunks.push(hunk.build());
    }
    
    Ok(hunks)
}

/// git hunk builder
#[derive(Debug)]
struct GitHunkBuilder {
    lines: Vec<GitHunkLine>,
    old_start: usize,
    new_start: usize,
    _start_index: usize,
    last_change_index: usize,
}

impl GitHunkBuilder {
    fn new(start_index: usize) -> Self {
        Self {
            lines: Vec::new(),
            old_start: start_index + 1,
            new_start: start_index + 1,
            _start_index: start_index,
            last_change_index: start_index,
        }
    }
    
    fn add_context_before(&mut self, changes: &[LineChange], current_index: usize, context_lines: usize) {
        let start = current_index.saturating_sub(context_lines);
        for i in start..current_index {
            if let LineChange::Equal(content) = &changes[i] {
                self.lines.push(GitHunkLine {
                    operation: GitLineOperation::Context,
                    content: content.clone(),
                });
                if self.lines.len() == 1 {
                    self.old_start = i + 1;
                    self.new_start = i + 1;
                }
            }
        }
    }
    
    fn add_context_after(&mut self, changes: &[LineChange], context_lines: usize) {
        let start = self.last_change_index + 1;
        let end = (start + context_lines).min(changes.len());
        
        for i in start..end {
            if let LineChange::Equal(content) = &changes[i] {
                self.lines.push(GitHunkLine {
                    operation: GitLineOperation::Context,
                    content: content.clone(),
                });
            }
        }
    }
    
    fn add_line(&mut self, change: LineChange, index: usize) {
        let git_line = match change {
            LineChange::Equal(content) => GitHunkLine {
                operation: GitLineOperation::Context,
                content,
            },
            LineChange::Delete(content) => {
                self.last_change_index = index;
                GitHunkLine {
                    operation: GitLineOperation::Delete,
                    content,
                }
            }
            LineChange::Insert(content) => {
                self.last_change_index = index;
                GitHunkLine {
                    operation: GitLineOperation::Insert,
                    content,
                }
            }
        };
        
        self.lines.push(git_line);
    }
    
    fn should_continue(&self, current_index: usize, context_lines: usize, _changes: &[LineChange]) -> bool {
        current_index - self.last_change_index <= context_lines * 2
    }
    
    fn build(self) -> GitHunk {
        let old_count = self.lines.iter()
            .filter(|l| matches!(l.operation, GitLineOperation::Context | GitLineOperation::Delete))
            .count();
        let new_count = self.lines.iter()
            .filter(|l| matches!(l.operation, GitLineOperation::Context | GitLineOperation::Insert))
            .count();
        
        GitHunk {
            old_start: self.old_start,
            old_count,
            new_start: self.new_start,
            new_count,
            lines: self.lines,
        }
    }
}

/// git hunk representation
#[derive(Debug)]
struct GitHunk {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    lines: Vec<GitHunkLine>,
}

impl GitHunk {
    fn format_git_hunk(&self) -> String {
        let mut output = String::new();
        
        // hunk header
        output.push_str(&format!("@@ -{},{} +{},{} @@\n",
            self.old_start, self.old_count,
            self.new_start, self.new_count));
        
        // hunk lines
        for line in &self.lines {
            let prefix = match line.operation {
                GitLineOperation::Context => " ",
                GitLineOperation::Delete => "-",
                GitLineOperation::Insert => "+",
            };
            output.push_str(&format!("{}{}\n", prefix, line.content));
        }
        
        output
    }
}

/// git hunk line
#[derive(Debug)]
struct GitHunkLine {
    operation: GitLineOperation,
    content: String,
}

/// git line operations
#[derive(Debug, PartialEq)]
enum GitLineOperation {
    Context,
    Delete,
    Insert,
}

/// checks if there are changes ahead within context distance
fn has_changes_ahead(changes: &[LineChange], context_lines: usize) -> bool {
    changes.iter()
        .take(context_lines * 2)
        .any(|c| !matches!(c, LineChange::Equal(_)))
}

/// computes line changes
fn compute_line_changes(left_lines: &[&str], right_lines: &[&str]) -> Vec<LineChange> {
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

/// line change types
#[derive(Debug, Clone)]
enum LineChange {
    Equal(String),
    Delete(String),
    Insert(String),
}