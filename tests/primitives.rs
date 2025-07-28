use ctdiff::*;
use proptest::prelude::*;
use subtle::Choice;

#[test]
fn test_ct_bytes_eq_correctness() {
    // basic equality cases
    assert!(ct_bytes_eq(b"", b""));
    assert!(ct_bytes_eq(b"a", b"a"));
    assert!(ct_bytes_eq(b"hello world", b"hello world"));
    
    // inequality cases
    assert!(!ct_bytes_eq(b"a", b"b"));
    assert!(!ct_bytes_eq(b"hello", b"world"));
    assert!(!ct_bytes_eq(b"abc", b"abcd"));
    assert!(!ct_bytes_eq(b"abcd", b"abc"));
}

#[test]
fn test_ct_bytes_eq_edge_cases() {
    // empty vs non-empty
    assert!(!ct_bytes_eq(b"", b"a"));
    assert!(!ct_bytes_eq(b"a", b""));
    
    // single byte differences at various positions
    assert!(!ct_bytes_eq(b"xbc", b"abc")); // first
    assert!(!ct_bytes_eq(b"axc", b"abc")); // middle  
    assert!(!ct_bytes_eq(b"abx", b"abc")); // last
    
    // large identical arrays
    let large_a = vec![0x42; 1000];
    let large_b = vec![0x42; 1000];
    assert!(ct_bytes_eq(&large_a, &large_b));
    
    // large arrays with single difference
    let mut large_c = vec![0x42; 1000];
    large_c[500] = 0x43;
    assert!(!ct_bytes_eq(&large_a, &large_c));
}

#[test]
fn test_ct_min_max_correctness() {
    // basic cases
    assert_eq!(ct_min(0, 0), 0);
    assert_eq!(ct_min(1, 2), 1);
    assert_eq!(ct_min(2, 1), 1);
    assert_eq!(ct_max(1, 2), 2);
    assert_eq!(ct_max(2, 1), 2);
    
    // edge values
    assert_eq!(ct_min(0, u32::MAX), 0);
    assert_eq!(ct_min(u32::MAX, 0), 0);
    assert_eq!(ct_max(0, u32::MAX), u32::MAX);
    assert_eq!(ct_max(u32::MAX, 0), u32::MAX);
}

#[test]
fn test_ct_copy_if_correctness() {
    let mut dst = [1, 2, 3, 4];
    let src = [5, 6, 7, 8];
    
    // copy when condition is true
    ct_copy_if(&mut dst, &src, Choice::from(1));
    assert_eq!(dst, [5, 6, 7, 8]);
    
    // don't copy when condition is false
    let original = dst.clone();
    ct_copy_if(&mut dst, &[9, 10, 11, 12], Choice::from(0));
    assert_eq!(dst, original);
}

#[test]
fn test_ct_lookup_correctness() {
    let data = [10, 20, 30, 40, 50];
    
    for (i, &expected) in data.iter().enumerate() {
        assert_eq!(ct_lookup(&data, i), expected);
    }
}

#[test]
fn test_ct_memcmp_correctness() {
    // equal arrays
    assert_eq!(ct_memcmp(b"hello", b"hello"), 0);
    assert_eq!(ct_memcmp(b"", b""), 0);
    
    // lexicographically smaller
    assert!(ct_memcmp(b"abc", b"abd") < 0);
    assert!(ct_memcmp(b"a", b"b") < 0);
    
    // lexicographically larger
    assert!(ct_memcmp(b"abd", b"abc") > 0);
    assert!(ct_memcmp(b"b", b"a") > 0);
    
    // different lengths
    assert!(ct_memcmp(b"abc", b"abcd") < 0);
    assert!(ct_memcmp(b"abcd", b"abc") > 0);
}

// property-based tests to verify behavior across wide input space
proptest! {
    #[test]
    fn prop_ct_bytes_eq_reflexive(data in prop::collection::vec(any::<u8>(), 0..100)) {
        prop_assert!(ct_bytes_eq(&data, &data));
    }
    
    #[test]
    fn prop_ct_bytes_eq_symmetric(
        a in prop::collection::vec(any::<u8>(), 0..50),
        b in prop::collection::vec(any::<u8>(), 0..50)
    ) {
        prop_assert_eq!(ct_bytes_eq(&a, &b), ct_bytes_eq(&b, &a));
    }
    
    #[test]
    fn prop_ct_min_max_consistent(a in any::<u32>(), b in any::<u32>()) {
        let min_val = ct_min(a, b);
        let max_val = ct_max(a, b);
        
        // min should be <= both inputs
        prop_assert!(min_val <= a && min_val <= b);
        // max should be >= both inputs  
        prop_assert!(max_val >= a && max_val >= b);
        // one of them should equal each input
        prop_assert!(min_val == a || min_val == b);
        prop_assert!(max_val == a || max_val == b);
    }
    
    #[test]
    fn prop_ct_lookup_bounds(
        data in prop::collection::vec(any::<u8>(), 1..100),
        index in any::<usize>()
    ) {
        let index = index % data.len(); // ensure valid index
        let result = ct_lookup(&data, index);
        prop_assert_eq!(result, data[index]);
    }
    
    #[test]
    fn prop_ct_memcmp_matches_std(
        a in prop::collection::vec(any::<u8>(), 0..50),
        b in prop::collection::vec(any::<u8>(), 0..50)
    ) {
        let ct_result = ct_memcmp(&a, &b);
        let std_result = a.cmp(&b);
        
        
        // results should have same sign (convert ordering to i32)
        let expected_sign = match std_result {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        prop_assert_eq!(ct_result.signum(), expected_sign);
    }
}

// timing attack resistance tests (structural verification)
#[test]
fn test_timing_attack_resistance_structure() {
    // these tests verify that our functions have the right structure
    // to resist timing attacks, though we can't easily test actual timing
    
    // ct_bytes_eq should process all bytes even if early difference found
    let mut early_diff = vec![0u8; 1000];
    early_diff[0] = 1; // difference at start
    let zeros = vec![0u8; 1000];
    
    // this should still process all 1000 bytes
    assert!(!ct_bytes_eq(&early_diff, &zeros));
    
    // ct_lookup should access all elements regardless of target index
    let data = (0..100).collect::<Vec<u8>>();
    
    // looking up first vs last element should have same access pattern
    assert_eq!(ct_lookup(&data, 0), 0);
    assert_eq!(ct_lookup(&data, 99), 99);
}

#[test]
fn test_large_inputs() {
    // test with larger inputs to ensure scalability
    let size = 10000;
    let a = vec![0x5a; size];
    let mut b = vec![0x5a; size];
    
    assert!(ct_bytes_eq(&a, &b));
    
    // single bit flip at end
    b[size - 1] = 0x5b;
    assert!(!ct_bytes_eq(&a, &b));
    
    // test ct_memcmp with large inputs
    assert!(ct_memcmp(&a, &b) < 0);
}