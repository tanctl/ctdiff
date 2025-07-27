//! Constant-time primitive operations
//! Provides basic building blocks for constant-time algorithms that resist timing attacks through uniform execution patterns

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};

/// constant-time byte slice equality comparison
/// execution time depends only on slice length
pub fn ct_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    a.ct_eq(b).into()
}

/// constant-time minimum of two values
pub fn ct_min(a: u32, b: u32) -> u32 {
    let a_is_smaller = a.ct_lt(&b);
    u32::conditional_select(&b, &a, a_is_smaller)
}

/// constant-time maximum of two values
pub fn ct_max(a: u32, b: u32) -> u32 {
    let a_is_larger = a.ct_gt(&b);
    u32::conditional_select(&b, &a, a_is_larger)
}

/// constant-time conditional copy
/// copies src to dst if condition is true while keeping memory access uniform
pub fn ct_copy_if(dst: &mut [u8], src: &[u8], condition: Choice) {
    assert_eq!(dst.len(), src.len(), "slice lengths must match");
    
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = u8::conditional_select(d, s, condition);
    }
}

/// constant-time array lookup w oblivious indexing
/// scans all elements and assumes index is valid
pub fn ct_lookup(array: &[u8], index: usize) -> u8 {
    assert!(index < array.len(), "index out of bounds");
    
    let mut result = 0u8;
    for (i, &value) in array.iter().enumerate() {
        let is_target = Choice::from((i == index) as u8);
        result = u8::conditional_select(&result, &value, is_target);
    }
    result
}

/// constant-time memory comparison with early termination resistance
/// matches rust slice ordering semantics without early exits
pub fn ct_memcmp(a: &[u8], b: &[u8]) -> i32 {
    let min_len = ct_min(a.len() as u32, b.len() as u32) as usize;
    
    let mut result = 0i32;
    for i in 0..min_len {
        let diff = (a[i] as i32) - (b[i] as i32);
        let is_zero = Choice::from((result == 0) as u8);
        result = i32::conditional_select(&result, &diff, is_zero);
    }
    
    if result == 0 {
        use std::cmp::Ordering;
        match a.len().cmp(&b.len()) {
            Ordering::Less => -1,
            Ordering::Greater => 1,
            Ordering::Equal => 0,
        }
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_bytes_eq_basic() {
        assert!(ct_bytes_eq(b"hello", b"hello"));
        assert!(!ct_bytes_eq(b"hello", b"world"));
        assert!(!ct_bytes_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_ct_min_max() {
        assert_eq!(ct_min(5, 10), 5);
        assert_eq!(ct_min(10, 5), 5);
        assert_eq!(ct_max(5, 10), 10);
        assert_eq!(ct_max(10, 5), 10);
    }

    #[test]
    fn test_ct_lookup() {
        let data = [1, 2, 3, 4, 5];
        assert_eq!(ct_lookup(&data, 0), 1);
        assert_eq!(ct_lookup(&data, 2), 3);
        assert_eq!(ct_lookup(&data, 4), 5);
    }
}
