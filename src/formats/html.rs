//! html output format implementation
//! 
//! web-friendly html output with css styling for browser viewing

use crate::{error::Result, types::DiffResult};
use crate::formats::{FormatOptions, HtmlTheme};

/// formats diff result as html
pub fn format(
    left_name: &str,
    right_name: &str,
    left_data: &[u8],
    right_data: &[u8],
    result: &DiffResult,
    context_lines: usize,
    options: &FormatOptions,
) -> Result<String> {
    let mut html = String::new();
    
    // html document structure
    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html lang=\"en\">\n");
    html.push_str("<head>\n");
    html.push_str("    <meta charset=\"UTF-8\">\n");
    html.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("    <title>Diff Results</title>\n");
    
    // include css
    if options.html_inline_css {
        html.push_str("    <style>\n");
        html.push_str(&generate_css(&options.html_theme));
        html.push_str("    </style>\n");
    } else {
        html.push_str("    <link rel=\"stylesheet\" href=\"diff.css\">\n");
    }
    
    html.push_str("</head>\n");
    html.push_str("<body>\n");
    
    // header section
    html.push_str(&format_header(left_name, right_name, result, options));
    
    // diff content
    if result.edit_distance == 0 {
        html.push_str("    <div class=\"identical\">\n");
        html.push_str("        <p>Files are identical</p>\n");
        html.push_str("    </div>\n");
    } else {
        html.push_str(&format_diff_content(left_data, right_data, result, context_lines, options)?);
    }
    
    html.push_str("</body>\n");
    html.push_str("</html>\n");
    
    Ok(html)
}

/// formats the html header section
fn format_header(left_name: &str, right_name: &str, result: &DiffResult, options: &FormatOptions) -> String {
    let mut header = String::new();
    
    header.push_str("    <header class=\"diff-header\">\n");
    header.push_str("        <h1>Diff Results</h1>\n");
    header.push_str("        <div class=\"file-info\">\n");
    header.push_str(&format!("            <div class=\"file left-file\">{}</div>\n", escape_html(left_name)));
    header.push_str("            <div class=\"vs\">vs</div>\n");
    header.push_str(&format!("            <div class=\"file right-file\">{}</div>\n", escape_html(right_name)));
    header.push_str("        </div>\n");
    
    if options.include_metadata {
        header.push_str(&format_statistics(result));
    }
    
    header.push_str("    </header>\n");
    header
}

/// formats statistics section
fn format_statistics(result: &DiffResult) -> String {
    let mut stats = String::new();
    
    let total_ops = result.operations.len();
    let insertions = result.operations.iter()
        .filter(|op| matches!(op, crate::types::DiffOperation::Insert(_)))
        .count();
    let deletions = result.operations.iter()
        .filter(|op| matches!(op, crate::types::DiffOperation::Delete))
        .count();
    let substitutions = result.operations.iter()
        .filter(|op| matches!(op, crate::types::DiffOperation::Substitute(_)))
        .count();
    
    stats.push_str("        <div class=\"statistics\">\n");
    stats.push_str(&format!("            <div class=\"stat\"><label>Edit Distance:</label> {}</div>\n", result.edit_distance));
    stats.push_str(&format!("            <div class=\"stat\"><label>Operations:</label> {}</div>\n", total_ops));
    stats.push_str(&format!("            <div class=\"stat insertions\"><label>Insertions:</label> {}</div>\n", insertions));
    stats.push_str(&format!("            <div class=\"stat deletions\"><label>Deletions:</label> {}</div>\n", deletions));
    stats.push_str(&format!("            <div class=\"stat substitutions\"><label>Substitutions:</label> {}</div>\n", substitutions));
    stats.push_str("        </div>\n");
    
    stats
}

/// formats the main diff content
fn format_diff_content(
    left_data: &[u8],
    _right_data: &[u8],
    result: &DiffResult,
    _context_lines: usize,
    options: &FormatOptions,
) -> Result<String> {
    let mut content = String::new();
    
    // reconstruct right side text
    let right_reconstructed = result.apply_to(left_data)
        .map_err(|e| crate::Error::format(format!("failed to reconstruct: {}", e)))?;
    
    let left_text = String::from_utf8_lossy(left_data);
    let right_text = String::from_utf8_lossy(&right_reconstructed);
    
    let left_lines: Vec<&str> = left_text.lines().collect();
    let right_lines: Vec<&str> = right_text.lines().collect();
    
    content.push_str("    <main class=\"diff-content\">\n");
    
    if options.word_diff {
        content.push_str(&format_side_by_side(&left_lines, &right_lines, options));
    } else {
        content.push_str(&format_unified_html(&left_lines, &right_lines, options));
    }
    
    content.push_str("    </main>\n");
    
    Ok(content)
}

/// formats diff as side-by-side view
fn format_side_by_side(left_lines: &[&str], right_lines: &[&str], options: &FormatOptions) -> String {
    let mut content = String::new();
    
    content.push_str("        <div class=\"side-by-side\">\n");
    content.push_str("            <div class=\"left-pane\">\n");
    content.push_str("                <h3>Before</h3>\n");
    content.push_str("                <pre class=\"code-block\">\n");
    
    for (i, line) in left_lines.iter().enumerate() {
        let line_num = if options.show_line_numbers {
            format!("{:4} ", i + 1)
        } else {
            String::new()
        };
        content.push_str(&format!("{}{}\\n", line_num, escape_html(line)));
    }
    
    content.push_str("                </pre>\n");
    content.push_str("            </div>\n");
    content.push_str("            <div class=\"right-pane\">\n");
    content.push_str("                <h3>After</h3>\n");
    content.push_str("                <pre class=\"code-block\">\n");
    
    for (i, line) in right_lines.iter().enumerate() {
        let line_num = if options.show_line_numbers {
            format!("{:4} ", i + 1)
        } else {
            String::new()
        };
        content.push_str(&format!("{}{}\\n", line_num, escape_html(line)));
    }
    
    content.push_str("                </pre>\n");
    content.push_str("            </div>\n");
    content.push_str("        </div>\n");
    
    content
}

/// formats diff as unified view with highlighting
fn format_unified_html(left_lines: &[&str], right_lines: &[&str], options: &FormatOptions) -> String {
    let mut content = String::new();
    
    content.push_str("        <div class=\"unified\">\n");
    content.push_str("            <pre class=\"diff-block\">\n");
    
    // simple line diff for display
    let changes = compute_line_changes(left_lines, right_lines);
    
    for (i, change) in changes.iter().enumerate() {
        let line_num = if options.show_line_numbers {
            format!("{:4} ", i + 1)
        } else {
            String::new()
        };
        
        match change {
            LineChange::Equal(line) => {
                content.push_str(&format!("{}  {}\\n", line_num, escape_html(line)));
            }
            LineChange::Delete(line) => {
                content.push_str(&format!("<span class=\"delete-line\">{}- {}\\n</span>", line_num, escape_html(line)));
            }
            LineChange::Insert(line) => {
                content.push_str(&format!("<span class=\"insert-line\">{}+ {}\\n</span>", line_num, escape_html(line)));
            }
        }
    }
    
    content.push_str("            </pre>\n");
    content.push_str("        </div>\n");
    
    content
}

/// computes simple line changes
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

/// generates css styles for html output
fn generate_css(theme: &HtmlTheme) -> String {
    let (bg_color, text_color, border_color, insert_bg, delete_bg, header_bg) = match theme {
        HtmlTheme::Light => ("#ffffff", "#333333", "#e1e4e8", "#d4edda", "#f8d7da", "#f6f8fa"),
        HtmlTheme::Dark => ("#0d1117", "#c9d1d9", "#30363d", "#1f3c27", "#4d1e1e", "#161b22"),
        HtmlTheme::Auto => ("#ffffff", "#333333", "#e1e4e8", "#d4edda", "#f8d7da", "#f6f8fa"), // default to light
    };
    
    format!(r#"
        body {{
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background-color: {bg_color};
            color: {text_color};
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }}
        
        .diff-header {{
            background-color: {header_bg};
            padding: 20px;
            border: 1px solid {border_color};
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        .diff-header h1 {{
            margin: 0 0 15px 0;
            font-size: 24px;
        }}
        
        .file-info {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }}
        
        .file {{
            font-weight: bold;
            padding: 5px 10px;
            border-radius: 4px;
            background-color: {bg_color};
            border: 1px solid {border_color};
        }}
        
        .vs {{
            color: #666;
            font-style: italic;
        }}
        
        .statistics {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .stat {{
            padding: 5px 10px;
            border-radius: 4px;
            background-color: {bg_color};
        }}
        
        .stat label {{
            font-weight: bold;
            margin-right: 5px;
        }}
        
        .insertions {{
            border-left: 3px solid #28a745;
        }}
        
        .deletions {{
            border-left: 3px solid #dc3545;
        }}
        
        .substitutions {{
            border-left: 3px solid #fd7e14;
        }}
        
        .diff-content {{
            border: 1px solid {border_color};
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .side-by-side {{
            display: flex;
        }}
        
        .left-pane, .right-pane {{
            flex: 1;
            padding: 15px;
        }}
        
        .left-pane {{
            border-right: 1px solid {border_color};
        }}
        
        .code-block, .diff-block {{
            margin: 0;
            padding: 15px;
            overflow-x: auto;
            background-color: {bg_color};
            font-size: 14px;
        }}
        
        .delete-line {{
            background-color: {delete_bg};
            display: block;
            padding: 2px 5px;
            margin: 1px 0;
        }}
        
        .insert-line {{
            background-color: {insert_bg};
            display: block;
            padding: 2px 5px;
            margin: 1px 0;
        }}
        
        .identical {{
            text-align: center;
            padding: 40px;
            background-color: {insert_bg};
            border-radius: 8px;
            margin: 20px 0;
            font-size: 18px;
        }}
        
        @media (max-width: 768px) {{
            .side-by-side {{
                flex-direction: column;
            }}
            
            .left-pane {{
                border-right: none;
                border-bottom: 1px solid {border_color};
            }}
            
            .statistics {{
                flex-direction: column;
                gap: 10px;
            }}
        }}
    "#, 
    bg_color = bg_color,
    text_color = text_color,
    border_color = border_color,
    insert_bg = insert_bg,
    delete_bg = delete_bg,
    header_bg = header_bg
    )
}

/// escapes html special characters
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// line change types for html processing
#[derive(Debug, Clone)]
enum LineChange {
    Equal(String),
    Delete(String),
    Insert(String),
}