//! vulnerable diff implementation for timing attack demonstrations
//! 
//! this module implements a traditional, fast diff algorithm that is vulnerable
//! to timing attacks. it serves as a baseline to demonstrate why constant-time
//! algorithms are necessary for security-sensitive applications.
//! 
//! SECURITY WARNING: never use this implementation in production!
//! this code intentionally contains timing side-channel vulnerabilities.

use crate::types::{DiffOperation, DiffResult, DiffError};

/// vulnerable diff implementation with timing side-channels
/// 
/// this implementation uses several optimization techniques that create
/// timing vulnerabilities:
/// 
/// 1. **early termination**: stops as soon as differences are found
/// 2. **short-circuit evaluation**: string comparisons exit on first byte difference  
/// 3. **content-dependent branching**: different code paths based on input patterns
/// 4. **optimized identical detection**: fast path for identical inputs
/// 
/// these optimizations make the algorithm faster in many cases but leak
/// information about input content through execution time variations.
pub struct VulnerableDiff;

impl VulnerableDiff {
    /// create new vulnerable diff instance
    pub fn new() -> Self {
        Self
    }
    
    /// perform vulnerable diff with timing side-channels
    /// 
    /// execution time varies significantly based on:
    /// - how early differences are found
    /// - degree of input similarity  
    /// - specific content patterns
    /// - input length differences
    pub fn diff(&self, a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
        // VULNERABILITY 1: fast identical check with early return
        // identical inputs return much faster than different ones
        if self.fast_identical_check(a, b) {
            return Ok(DiffResult::new(
                vec![DiffOperation::Keep; a.len()],
                0,
                a.len(),
                b.len(),
            ));
        }
        
        // VULNERABILITY 2: content-dependent algorithm selection
        // different algorithms used based on input characteristics
        if self.should_use_fast_path(a, b) {
            self.fast_diff_algorithm(a, b)
        } else {
            self.slow_diff_algorithm(a, b)
        }
    }
    
    /// fast identical check with short-circuit evaluation
    /// 
    /// VULNERABILITY: exits immediately on first difference
    /// - identical files: O(n) time 
    /// - files differing at position k: O(k) time
    /// - attacker can determine difference location by measuring time
    fn fast_identical_check(&self, a: &[u8], b: &[u8]) -> bool {
        // early length check reveals length information
        if a.len() != b.len() {
            return false;
        }
        
        // short-circuit byte comparison - exits on first difference
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            if byte_a != byte_b {
                return false; // VULNERABILITY: early exit reveals difference position
            }
        }
        
        true
    }
    
    /// decide algorithm based on input characteristics
    /// 
    /// VULNERABILITY: algorithm choice reveals input properties
    /// - small files use different algorithm than large files
    /// - similar files use different algorithm than dissimilar files
    /// - timing patterns reveal which algorithm was chosen
    fn should_use_fast_path(&self, a: &[u8], b: &[u8]) -> bool {
        let total_size = a.len() + b.len();
        let size_ratio = (a.len() as f64) / (b.len().max(1) as f64);
        
        // VULNERABILITY: branching based on input properties
        // different code paths leak information about input characteristics
        total_size < 1000 && (0.5..=2.0).contains(&size_ratio)
    }
    
    /// fast algorithm for small, similar inputs
    /// 
    /// VULNERABILITY: optimized for early difference detection
    /// - stops processing as soon as sufficient differences found
    /// - timing reveals how similar inputs are
    fn fast_diff_algorithm(&self, a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
        let mut operations = Vec::new();
        let mut edit_distance = 0;
        let mut i = 0;
        let mut j = 0;
        
        // VULNERABILITY: early termination on "enough" differences
        let max_differences = (a.len() + b.len()) / 4; // arbitrary threshold
        
        while i < a.len() && j < b.len() && edit_distance < max_differences {
            // VULNERABILITY: short-circuit byte comparison
            if a[i] == b[j] {
                operations.push(DiffOperation::Keep);
                i += 1;
                j += 1;
            } else {
                // VULNERABILITY: complex heuristics that leak information
                let should_substitute = self.heuristic_should_substitute(a, b, i, j);
                
                if should_substitute {
                    operations.push(DiffOperation::Substitute(b[j]));
                    i += 1;
                    j += 1;
                } else if i + 1 < a.len() && a[i + 1] == b[j] {
                    // lookahead optimization - reveals content patterns
                    operations.push(DiffOperation::Delete);
                    i += 1;
                } else {
                    operations.push(DiffOperation::Insert(b[j]));
                    j += 1;
                }
                edit_distance += 1;
            }
        }
        
        // VULNERABILITY: early termination leaves incomplete result
        // but timing still reveals how much was processed
        if edit_distance >= max_differences {
            // truncate processing - timing reveals degree of similarity
            while i < a.len() {
                operations.push(DiffOperation::Delete);
                i += 1;
                edit_distance += 1;
            }
            while j < b.len() {
                operations.push(DiffOperation::Insert(b[j]));
                j += 1;
                edit_distance += 1;
            }
        } else {
            // complete processing for similar files
            while i < a.len() {
                operations.push(DiffOperation::Delete);
                i += 1;
                edit_distance += 1;
            }
            while j < b.len() {
                operations.push(DiffOperation::Insert(b[j]));
                j += 1;
                edit_distance += 1;
            }
        }
        
        Ok(DiffResult::new(operations, edit_distance, a.len(), b.len()))
    }
    
    /// slow algorithm for large or dissimilar inputs
    /// 
    /// VULNERABILITY: different performance characteristics 
    /// - timing reveals which algorithm was chosen
    /// - still has early termination opportunities
    fn slow_diff_algorithm(&self, a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
        // VULNERABILITY: simulated "slow" algorithm with different timing profile
        // in reality this is just a slightly different version with its own leaks
        
        let mut operations = Vec::new();
        let mut edit_distance = 0;
        
        // VULNERABILITY: nested loops with content-dependent execution time
        let mut i = 0;
        while i < a.len() {
            let mut j = 0;
            let mut found_match = false;
            
            // VULNERABILITY: search time depends on where matches are found
            while j < b.len() && !found_match {
                if a[i] == b[j] {
                    // VULNERABILITY: match position affects total execution time
                    operations.push(DiffOperation::Keep);
                    found_match = true;
                } else {
                    // VULNERABILITY: comparison time depends on byte values
                    // some byte comparisons might be optimized differently by cpu
                    let diff = (a[i] as i16) - (b[j] as i16);
                    if diff.abs() < 32 {
                        // "similar" bytes get different treatment
                        // artificial timing variation based on content
                        for _ in 0..((diff.abs() as usize) % 3) {
                            // busywork that depends on byte values
                            std::hint::black_box(diff * diff);
                        }
                    }
                }
                j += 1;
            }
            
            if !found_match {
                operations.push(DiffOperation::Delete);
                edit_distance += 1;
            }
            
            i += 1;
        }
        
        // add remaining insertions
        let remaining_b = b.len().saturating_sub(operations.len());
        for i in 0..remaining_b {
            operations.push(DiffOperation::Insert(b[b.len() - remaining_b + i]));
            edit_distance += 1;
        }
        
        Ok(DiffResult::new(operations, edit_distance, a.len(), b.len()))
    }
    
    /// heuristic decision making with timing side-channels
    /// 
    /// VULNERABILITY: decision time depends on input content
    /// - different byte patterns take different amounts of time to analyze
    /// - reveals information about content characteristics
    fn heuristic_should_substitute(&self, a: &[u8], b: &[u8], i: usize, j: usize) -> bool {
        let byte_a = a[i];
        let byte_b = b[j];
        
        // VULNERABILITY: complex content-dependent logic
        // execution time varies based on specific byte values
        match (byte_a, byte_b) {
            // ascii letters get special treatment
            (b'a'..=b'z', b'a'..=b'z') | (b'A'..=b'Z', b'A'..=b'Z') => {
                // VULNERABILITY: case analysis takes variable time
                let case_diff = (byte_a.to_ascii_lowercase() as i16) - (byte_b.to_ascii_lowercase() as i16);
                case_diff.abs() < 5 // "similar" letters
            }
            // digits get different treatment  
            (b'0'..=b'9', b'0'..=b'9') => {
                // VULNERABILITY: arithmetic on content values
                let numeric_diff = (byte_a - b'0') as i16 - (byte_b - b'0') as i16;
                numeric_diff.abs() < 3
            }
            // whitespace analysis
            (b' ' | b'\t' | b'\n', b' ' | b'\t' | b'\n') => true,
            // punctuation requires complex analysis
            _ => {
                // VULNERABILITY: variable-time content analysis
                let mut similarity_score = 0;
                
                // analyze surrounding context - timing depends on content
                for offset in 1..=3 {
                    if i >= offset && j >= offset {
                        if a[i - offset] == b[j - offset] {
                            similarity_score += 1;
                        }
                    }
                    if i + offset < a.len() && j + offset < b.len() {
                        if a[i + offset] == b[j + offset] {
                            similarity_score += 1;
                        }
                    }
                }
                
                similarity_score >= 2
            }
        }
    }
}

impl Default for VulnerableDiff {
    fn default() -> Self {
        Self::new()
    }
}

/// convenience function using vulnerable implementation
/// 
/// WARNING: this function is intentionally vulnerable to timing attacks!
/// never use in production - for demonstration purposes only.
pub fn vulnerable_diff(a: &[u8], b: &[u8]) -> Result<DiffResult, DiffError> {
    let differ = VulnerableDiff::new();
    differ.diff(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vulnerable_identical_files() {
        let differ = VulnerableDiff::new();
        let result = differ.diff(b"hello", b"hello").unwrap();
        assert_eq!(result.edit_distance, 0);
    }
    
    #[test]
    fn test_vulnerable_different_files() {
        let differ = VulnerableDiff::new();
        let result = differ.diff(b"hello", b"world").unwrap();
        assert!(result.edit_distance > 0);
    }
    
    #[test] 
    fn test_vulnerable_algorithm_selection() {
        let differ = VulnerableDiff::new();
        
        // small files should use fast path
        assert!(differ.should_use_fast_path(b"small", b"tiny"));
        
        // large files should use slow path
        let large_a = vec![b'a'; 2000];
        let large_b = vec![b'b'; 2000]; 
        assert!(!differ.should_use_fast_path(&large_a, &large_b));
    }
}