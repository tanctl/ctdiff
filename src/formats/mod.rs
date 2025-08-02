//! output format implementations for diff results
//! 
//! provides multiple output formats including unified, json, html, git, and summary

use serde::{Deserialize, Serialize};

pub mod unified;
pub mod json;
pub mod html;
pub mod git;
pub mod summary;

/// supported output formats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// unified diff format (default, compatible with unix diff)
    Unified,
    /// structured json output for tools
    Json,
    /// web-friendly html with css styling
    Html,
    /// git-compatible patch format
    Git,
    /// high-level diff statistics summary
    Summary,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Unified => write!(f, "unified"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Html => write!(f, "html"),
            OutputFormat::Git => write!(f, "git"),
            OutputFormat::Summary => write!(f, "summary"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = crate::Error;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unified" | "u" => Ok(OutputFormat::Unified),
            "json" | "j" => Ok(OutputFormat::Json),
            "html" | "h" => Ok(OutputFormat::Html),
            "git" | "g" => Ok(OutputFormat::Git),
            "summary" | "s" => Ok(OutputFormat::Summary),
            _ => Err(crate::Error::invalid_input(format!("unknown format: {}", s))),
        }
    }
}

/// format-specific configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatOptions {
    /// pretty-print json output
    pub json_pretty: bool,
    /// include inline css in html output
    pub html_inline_css: bool,
    /// html theme (light, dark, auto)
    pub html_theme: HtmlTheme,
    /// include file metadata in output
    pub include_metadata: bool,
    /// maximum line width for output
    pub max_line_width: Option<usize>,
    /// show line numbers
    pub show_line_numbers: bool,
    /// word-level diffing for text
    pub word_diff: bool,
}

/// html theme options
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtmlTheme {
    Light,
    Dark,
    Auto,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            json_pretty: true,
            html_inline_css: true,
            html_theme: HtmlTheme::Auto,
            include_metadata: true,
            max_line_width: Some(120),
            show_line_numbers: true,
            word_diff: false,
        }
    }
}

impl FormatOptions {
    /// creates minimal options for compact output
    pub fn minimal() -> Self {
        Self {
            json_pretty: false,
            html_inline_css: false,
            html_theme: HtmlTheme::Light,
            include_metadata: false,
            max_line_width: None,
            show_line_numbers: false,
            word_diff: false,
        }
    }
    
    /// creates verbose options with all features
    pub fn verbose() -> Self {
        Self {
            json_pretty: true,
            html_inline_css: true,
            html_theme: HtmlTheme::Auto,
            include_metadata: true,
            max_line_width: Some(120),
            show_line_numbers: true,
            word_diff: true,
        }
    }
}