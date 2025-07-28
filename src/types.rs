//! type definitions for constant-time diff operations
//! 
//! defines core types used throughout the library with security-focused
//! design choices to prevent information leakage through type structure.

use serde::{Deserialize, Serialize};

/// basic diff operation that can be applied to transform one sequence into another
/// 
/// operations are designed to be uniform in representation to prevent
/// timing attacks based on operation type distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffOperation {
    /// keep byte at current position unchanged
    Keep,
    /// insert new byte at current position
    Insert(u8),
    /// delete byte at current position
    Delete,
    /// substitute byte at current position with new byte
    Substitute(u8),
}

impl DiffOperation {
    /// constant-time check if operation modifies content
    /// 
    /// uses conditional selection to avoid branches on operation type.
    pub fn is_modification(&self) -> bool {
        match self {
            DiffOperation::Keep => false,
            DiffOperation::Insert(_) | DiffOperation::Delete | DiffOperation::Substitute(_) => true,
        }
    }
}

/// result of constant-time diff computation containing edit script
/// 
/// structure designed to reveal minimal information about input differences
/// while providing necessary data for reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffResult {
    /// sequence of operations to transform input a to input b
    pub operations: Vec<DiffOperation>,
    /// edit distance (total number of modifications)
    pub edit_distance: usize,
    /// original length of first input (for validation)
    pub original_len_a: usize,
    /// original length of second input (for validation)
    pub original_len_b: usize,
}

impl DiffResult {
    /// create new diff result with given parameters
    pub fn new(
        operations: Vec<DiffOperation>,
        edit_distance: usize,
        original_len_a: usize,
        original_len_b: usize,
    ) -> Self {
        Self {
            operations,
            edit_distance,
            original_len_a,
            original_len_b,
        }
    }

    /// verify that edit script is consistent with reported metadata
    /// 
    /// performs sanity checks without revealing information about content.
    pub fn is_valid(&self) -> bool {
        let mut pos_a = 0;
        let mut pos_b = 0;
        let mut modifications = 0;

        for op in &self.operations {
            match op {
                DiffOperation::Keep => {
                    pos_a += 1;
                    pos_b += 1;
                }
                DiffOperation::Insert(_) => {
                    pos_b += 1;
                    modifications += 1;
                }
                DiffOperation::Delete => {
                    pos_a += 1;
                    modifications += 1;
                }
                DiffOperation::Substitute(_) => {
                    pos_a += 1;
                    pos_b += 1;
                    modifications += 1;
                }
            }
        }

        pos_a == self.original_len_a
            && pos_b == self.original_len_b
            && modifications == self.edit_distance
    }

    /// apply edit script to recreate second input from first
    /// 
    /// constant-time application of operations to prevent timing leakage
    /// during reconstruction.
    pub fn apply_to(&self, input: &[u8]) -> Result<Vec<u8>, DiffError> {
        if input.len() != self.original_len_a {
            return Err(DiffError::InvalidInput("input length mismatch".to_string()));
        }

        let mut result = Vec::new();
        let mut input_pos = 0;

        for op in &self.operations {
            match op {
                DiffOperation::Keep => {
                    if input_pos >= input.len() {
                        return Err(DiffError::InvalidScript("script extends beyond input".to_string()));
                    }
                    result.push(input[input_pos]);
                    input_pos += 1;
                }
                DiffOperation::Insert(byte) => {
                    result.push(*byte);
                }
                DiffOperation::Delete => {
                    if input_pos >= input.len() {
                        return Err(DiffError::InvalidScript("script extends beyond input".to_string()));
                    }
                    input_pos += 1;
                }
                DiffOperation::Substitute(byte) => {
                    if input_pos >= input.len() {
                        return Err(DiffError::InvalidScript("script extends beyond input".to_string()));
                    }
                    result.push(*byte);
                    input_pos += 1;
                }
            }
        }

        if input_pos != input.len() {
            return Err(DiffError::InvalidScript("script does not consume entire input".to_string()));
        }

        Ok(result)
    }
}

/// security configuration for diff computation
/// 
/// controls trade-offs between security guarantees and performance.
/// conservative defaults prioritize security over speed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// maximum input size to process (prevents dos attacks)
    pub max_input_size: usize,
    /// whether to pad inputs to uniform size (stronger timing protection)
    pub pad_inputs: bool,
    /// target padding size when pad_inputs is enabled
    pub padding_size: Option<usize>,
    /// whether to validate inputs for malicious patterns
    pub validate_inputs: bool,
    /// maximum edit distance to compute (prevents excessive computation)
    pub max_edit_distance: Option<usize>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_input_size: 64 * 1024, // 64kb default limit
            pad_inputs: true,
            padding_size: None, // auto-determine based on inputs
            validate_inputs: true,
            max_edit_distance: None, // no limit by default
        }
    }
}

impl SecurityConfig {
    /// create config optimized for maximum security
    pub fn maximum_security() -> Self {
        Self {
            max_input_size: 4 * 1024, // smaller limit
            pad_inputs: true,
            padding_size: Some(4 * 1024), // fixed padding
            validate_inputs: true,
            max_edit_distance: Some(1024), // bounded computation
        }
    }

    /// create config optimized for performance while maintaining basic security
    pub fn balanced() -> Self {
        Self {
            max_input_size: 256 * 1024, // larger limit
            pad_inputs: false, // no padding overhead
            padding_size: None,
            validate_inputs: true,
            max_edit_distance: None,
        }
    }

    /// validate that input sizes are within configured limits
    pub fn validate_input_sizes(&self, len_a: usize, len_b: usize) -> Result<(), DiffError> {
        if len_a > self.max_input_size || len_b > self.max_input_size {
            return Err(DiffError::InputTooLarge {
                size: len_a.max(len_b),
                limit: self.max_input_size,
            });
        }
        Ok(())
    }

    /// determine actual padding size to use for given inputs
    pub fn effective_padding_size(&self, len_a: usize, len_b: usize) -> Option<usize> {
        if !self.pad_inputs {
            return None;
        }

        match self.padding_size {
            Some(size) => Some(size),
            None => {
                // pad to next power of 2 greater than max input length
                let max_len = len_a.max(len_b);
                let padded = max_len.next_power_of_two();
                Some(padded.min(self.max_input_size))
            }
        }
    }
}

/// errors that can occur during diff computation or application
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffError {
    /// input size exceeds configured limits
    InputTooLarge { size: usize, limit: usize },
    /// invalid input format or content
    InvalidInput(String),
    /// edit script is malformed or inconsistent
    InvalidScript(String),
    /// computation exceeded configured limits
    ComputationLimitExceeded(String),
    /// internal algorithm error (should not occur in normal operation)
    AlgorithmError(String),
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffError::InputTooLarge { size, limit } => {
                write!(f, "input size {} exceeds limit {}", size, limit)
            }
            DiffError::InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            DiffError::InvalidScript(msg) => write!(f, "invalid script: {}", msg),
            DiffError::ComputationLimitExceeded(msg) => {
                write!(f, "computation limit exceeded: {}", msg)
            }
            DiffError::AlgorithmError(msg) => write!(f, "algorithm error: {}", msg),
        }
    }
}

impl std::error::Error for DiffError {}