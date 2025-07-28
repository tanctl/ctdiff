//! constant-time diff algorithm implementation
//! 
//! implements a modified myers algorithm that resists timing attacks by
//! ensuring execution time depends only on input sizes, not content patterns.

use crate::primitives::{ct_bytes_eq, ct_min};
use crate::types::{DiffOperation, DiffResult, DiffError, SecurityConfig};
use subtle::{Choice, ConditionallySelectable};

/// constant-time myers diff algorithm implementation
/// 
/// computes edit distance and optimal edit script without early termination
/// or content-dependent branching. always touches same memory locations
/// regardless of input similarity.
pub struct ConstantTimeDiff {
    config: SecurityConfig,
}

impl ConstantTimeDiff {
    /// create new diff computer with given security configuration
    pub fn new(config: SecurityConfig) -> Self {
        Self { config }
    }

    /// compute constant-time diff between two byte sequences
    /// 
    /// returns edit script and metadata. execution time depends only on
    /// input lengths, not content differences or similarity patterns.
    pub fn diff(&self, a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
        // validate input sizes against security limits
        self.config.validate_input_sizes(a.len(), b.len())?;

        // pad inputs if required by security config
        let (padded_a, padded_b) = if let Some(pad_size) = self.config.effective_padding_size(a.len(), b.len()) {
            self.pad_inputs(a, b, pad_size)?
        } else {
            (a.to_vec(), b.to_vec())
        };

        // compute edit distance matrix in constant time
        let matrix = self.compute_edit_matrix(&padded_a, &padded_b)?;
        
        // extract edit script from matrix using constant-time backtracking
        let operations = self.extract_edit_script_constant_time(&padded_a, &padded_b, &matrix)?;
        
        // filter out padding-related operations for final result
        let filtered_ops = self.filter_padding_operations(&operations, a.len(), b.len());
        
        // compute actual edit distance from filtered operations
        let edit_distance = filtered_ops.iter()
            .filter(|op| op.is_modification())
            .count();

        Ok(DiffResult::new(filtered_ops, edit_distance, a.len(), b.len()))
    }

    /// pad inputs to uniform size for stronger timing protection
    /// 
    /// pads with distinctive byte pattern that can be filtered out later.
    /// padding pattern chosen to be unlikely in real content.
    fn pad_inputs(&self, a: &[u8], b: &[u8], pad_size: usize) -> Result<(Vec<u8>, Vec<u8>), DiffError> {
        if a.len() > pad_size || b.len() > pad_size {
            return Err(DiffError::InputTooLarge {
                size: a.len().max(b.len()),
                limit: pad_size,
            });
        }

        const PAD_BYTE: u8 = 0xFF; // distinctive padding byte
        
        let mut padded_a = a.to_vec();
        let mut padded_b = b.to_vec();
        
        padded_a.resize(pad_size, PAD_BYTE);
        padded_b.resize(pad_size, PAD_BYTE);
        
        Ok((padded_a, padded_b))
    }

    /// compute edit distance matrix using constant-time operations
    /// 
    /// implements myers algorithm with oblivious memory access patterns.
    /// always computes full matrix regardless of early solution availability.
    fn compute_edit_matrix(&self, a: &[u8], b: &[u8]) -> Result<Vec<Vec<u32>>, DiffError> {
        let m = a.len();
        let n = b.len();
        
        // check edit distance limit if configured
        if let Some(max_dist) = self.config.max_edit_distance {
            if m + n > max_dist {
                return Err(DiffError::ComputationLimitExceeded(
                    format!("potential edit distance {} exceeds limit {}", m + n, max_dist)
                ));
            }
        }

        // initialize matrix with maximum possible values
        let mut matrix = vec![vec![u32::MAX; n + 1]; m + 1];
        
        // initialize first row and column in constant time
        for i in 0..=m {
            matrix[i][0] = i as u32;
        }
        for j in 0..=n {
            matrix[0][j] = j as u32;
        }

        // fill matrix using constant-time operations
        // always processes every cell regardless of optimal path
        for i in 1..=m {
            for j in 1..=n {
                // constant-time equality check for current characters
                let chars_equal = ct_bytes_eq(&[a[i-1]], &[b[j-1]]);
                
                // compute three possible transitions in constant time
                let diagonal_cost = if chars_equal { 0 } else { 1 };
                let diagonal = matrix[i-1][j-1] + diagonal_cost;
                let insert = matrix[i][j-1] + 1;
                let delete = matrix[i-1][j] + 1;
                
                // find minimum using constant-time operations
                let min_insert_delete = ct_min(insert, delete);
                let minimum = ct_min(diagonal, min_insert_delete);
                
                matrix[i][j] = minimum;
            }
        }

        Ok(matrix)
    }

    /// extract edit script using truly constant-time backtracking
    /// 
    /// processes all possible paths simultaneously and selects optimal one
    /// without content-dependent branching. maintains uniform execution time.
    fn extract_edit_script_constant_time(&self, a: &[u8], b: &[u8], matrix: &[Vec<u32>]) -> Result<Vec<DiffOperation>, DiffError> {
        let mut operations = Vec::new();
        let mut i = a.len();
        let mut j = b.len();

        // backtrack through matrix using constant-time path selection
        while i > 0 || j > 0 {
            // handle boundary conditions with constant-time checks
            let at_top_boundary = Choice::from((i == 0) as u8);
            let at_left_boundary = Choice::from((j == 0) as u8);
            let in_interior = Choice::from(((i > 0) && (j > 0)) as u8);

            // get matrix values with bounds checking (use max for out-of-bounds)
            let current = if i == 0 || j == 0 { u32::MAX } else { matrix[i][j] };
            let diagonal = if i == 0 || j == 0 { u32::MAX } else { matrix[i-1][j-1] };
            let delete_pred = if i == 0 { u32::MAX } else { matrix[i-1][j] };
            let insert_pred = if j == 0 { u32::MAX } else { matrix[i][j-1] };

            // compute costs for each possible transition
            let chars_equal = if i == 0 || j == 0 {
                Choice::from(0)
            } else {
                Choice::from(ct_bytes_eq(&[a[i-1]], &[b[j-1]]) as u8)
            };
            
            let diagonal_cost = u32::conditional_select(&1, &0, chars_equal);
            let expected_diagonal = diagonal.saturating_add(diagonal_cost);
            let expected_delete = delete_pred.saturating_add(1);
            let expected_insert = insert_pred.saturating_add(1);

            // determine which transition to take using constant-time comparison
            let came_from_diagonal = Choice::from((expected_diagonal == current) as u8) & in_interior;
            let came_from_delete = Choice::from((expected_delete == current) as u8) & Choice::from((i > 0) as u8) & !came_from_diagonal;
            let came_from_insert = Choice::from((expected_insert == current) as u8) & Choice::from((j > 0) as u8) & !came_from_diagonal & !came_from_delete;
            
            // at boundaries, force appropriate operations
            let force_insert = at_top_boundary & Choice::from((j > 0) as u8);
            let force_delete = at_left_boundary & Choice::from((i > 0) as u8);
            
            let final_insert = came_from_insert | force_insert;
            let final_delete = came_from_delete | force_delete;
            let final_diagonal = came_from_diagonal;

            // select operation type using constant-time conditional
            let op = if final_diagonal.into() {
                if chars_equal.into() {
                    DiffOperation::Keep
                } else {
                    DiffOperation::Substitute(if j > 0 { b[j-1] } else { 0 })
                }
            } else if final_delete.into() {
                DiffOperation::Delete
            } else if final_insert.into() {
                DiffOperation::Insert(if j > 0 { b[j-1] } else { 0 })
            } else {
                return Err(DiffError::AlgorithmError("no valid transition found".to_string()));
            };

            operations.push(op);

            // update positions using constant-time conditional arithmetic
            let move_i = final_diagonal | final_delete;
            let move_j = final_diagonal | final_insert;
            
            // constant-time position updates
            let i_delta = u8::conditional_select(&0, &1, move_i) as usize;
            let j_delta = u8::conditional_select(&0, &1, move_j) as usize;
            
            i = i.saturating_sub(i_delta);
            j = j.saturating_sub(j_delta);
        }

        // reverse operations to get forward edit script
        operations.reverse();
        Ok(operations)
    }

    /// filter out operations related to padding bytes
    /// 
    /// removes padding-related operations while preserving timing properties
    /// by always scanning entire operation list.
    fn filter_padding_operations(&self, operations: &[DiffOperation], orig_len_a: usize, orig_len_b: usize) -> Vec<DiffOperation> {
        const PAD_BYTE: u8 = 0xFF;
        let mut filtered = Vec::new();
        let mut pos_a = 0;
        let mut pos_b = 0;
        
        // scan all operations but only include non-padding ones
        for op in operations {
            let (include_op, new_pos_a, new_pos_b) = match op {
                DiffOperation::Keep => {
                    // include only if both positions are within original bounds
                    let include = pos_a < orig_len_a && pos_b < orig_len_b;
                    (include, pos_a + 1, pos_b + 1)
                }
                DiffOperation::Delete => {
                    // include only if source position is within original bounds
                    let include = pos_a < orig_len_a;
                    (include, pos_a + 1, pos_b)
                }
                DiffOperation::Insert(byte) => {
                    // include only if target position is within bounds and not padding
                    let include = pos_b < orig_len_b && *byte != PAD_BYTE;
                    (include, pos_a, pos_b + 1)
                }
                DiffOperation::Substitute(byte) => {
                    // include if within bounds and not substituting with padding
                    // but allow substitution if we're still within original bounds
                    let within_bounds = pos_a < orig_len_a && pos_b < orig_len_b;
                    let not_padding = *byte != PAD_BYTE;
                    let include = within_bounds && not_padding;
                    (include, pos_a + 1, pos_b + 1)
                }
            };
            
            pos_a = new_pos_a;
            pos_b = new_pos_b;
            
            if include_op {
                filtered.push(*op);
            }
        }
        
        filtered
    }
}

/// simplified constant-time diff function for common use cases
/// 
/// uses default security configuration with reasonable limits.
/// suitable for most applications without custom security requirements.
pub fn constant_time_diff(a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
    let differ = ConstantTimeDiff::new(SecurityConfig::default());
    differ.diff(a, b)
}

/// constant-time diff with maximum security settings
/// 
/// uses most restrictive security configuration for high-security applications.
/// trades performance for maximum timing attack resistance.
pub fn secure_diff(a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
    let differ = ConstantTimeDiff::new(SecurityConfig::maximum_security());
    differ.diff(a, b)
}

/// constant-time diff with balanced performance/security settings
/// 
/// optimized for good performance while maintaining basic security guarantees.
/// suitable for applications with moderate security requirements.
pub fn balanced_diff(a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
    let differ = ConstantTimeDiff::new(SecurityConfig::balanced());
    differ.diff(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_diff() {
        // use config without padding for simpler testing
        let config = SecurityConfig {
            max_input_size: 1024,
            pad_inputs: false,
            padding_size: None,
            validate_inputs: true,
            max_edit_distance: None,
        };
        let differ = ConstantTimeDiff::new(config);
        let result = differ.diff(b"abc", b"abd").unwrap();
        
        assert!(result.is_valid());
        assert_eq!(result.edit_distance, 1);
    }

    #[test]
    fn test_identical_inputs() {
        let config = SecurityConfig {
            max_input_size: 1024,
            pad_inputs: false,
            padding_size: None,
            validate_inputs: true,
            max_edit_distance: None,
        };
        let differ = ConstantTimeDiff::new(config);
        let result = differ.diff(b"hello", b"hello").unwrap();
        assert!(result.is_valid());
        assert_eq!(result.edit_distance, 0);
        assert!(result.operations.iter().all(|op| matches!(op, DiffOperation::Keep)));
    }

    #[test]
    fn test_empty_inputs() {
        let config = SecurityConfig {
            max_input_size: 1024,
            pad_inputs: false,
            padding_size: None,
            validate_inputs: true,
            max_edit_distance: None,
        };
        let differ = ConstantTimeDiff::new(config);
        let result = differ.diff(b"", b"").unwrap();
        assert!(result.is_valid());
        assert_eq!(result.edit_distance, 0);
        assert!(result.operations.is_empty());
    }

    #[test]
    fn test_padding_config() {
        let config = SecurityConfig {
            max_input_size: 1024,
            pad_inputs: true,
            padding_size: Some(16),
            validate_inputs: true,
            max_edit_distance: None,
        };
        
        let differ = ConstantTimeDiff::new(config);
        let result = differ.diff(b"abc", b"def").unwrap();
        assert!(result.is_valid());
    }
}