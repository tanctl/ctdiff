//! constant-time diff operations to prevent timing attacks
//! 
//! this library provides primitives and algorithms for comparing data without
//! leaking information through execution time variations. critical for security
//! applications where timing side-channels could reveal sensitive info.

// re-export main types and functions for public api
pub use crate::algorithm::{constant_time_diff, secure_diff, balanced_diff, ConstantTimeDiff};
pub use crate::types::{DiffOperation, DiffResult, DiffError, SecurityConfig};

// internal modules
pub mod primitives;
pub mod types;
pub mod algorithm;

// convenience re-exports of common primitives
pub use primitives::{ct_bytes_eq, ct_min, ct_max, ct_copy_if, ct_lookup, ct_memcmp};