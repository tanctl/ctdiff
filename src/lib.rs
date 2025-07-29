//! constant-time diff operations to prevent timing attacks
//! 
//! this library provides primitives and algorithms for comparing data without
//! leaking information through execution time variations. critical for security
//! applications where timing side-channels could reveal sensitive info.
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```rust
//! use ctdiff::DiffBuilder;
//!
//! let diff = DiffBuilder::new()
//!     .security_level(ctdiff::SecurityLevel::Balanced)
//!     .build();
//!
//! let result = diff.compare(b"hello", b"world")?;
//! println!("Edit distance: {}", result.edit_distance());
//! # Ok::<(), ctdiff::Error>(())
//! ```
//!
//! ## Multiple Output Formats
//!
//! ```rust
//! use ctdiff::{DiffBuilder, OutputFormat};
//!
//! let diff = DiffBuilder::new()
//!     .output_format(OutputFormat::Json)
//!     .build();
//!
//! let result = diff.compare_files("file1.txt", "file2.txt")?;
//! let json_output = result.format()?;
//! println!("{}", json_output);
//! # Ok::<(), ctdiff::Error>(())
//! ```

// main public api exports
pub use crate::builder::DiffBuilder;
pub use crate::result::DiffResult;
pub use crate::error::{Error, Result};
pub use crate::security::{SecurityLevel, SecurityConfig};
pub use crate::formats::OutputFormat;

// re-export core algorithm types for compatibility
pub use crate::algorithm::{constant_time_diff, secure_diff, balanced_diff, ConstantTimeDiff};
pub use crate::types::{DiffOperation, DiffError};

// internal modules
pub mod primitives;
pub mod types;
pub mod algorithm;
pub mod builder;
pub mod result;
pub mod error;
pub mod security;
pub mod formats;

// attack demonstration modules (for research/demo purposes only)
pub mod vulnerable;
pub mod timing;
pub mod attack;

// convenience re-exports of common primitives
pub use primitives::{ct_bytes_eq, ct_min, ct_max, ct_copy_if, ct_lookup, ct_memcmp};