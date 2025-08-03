use ctdiff::{ConstantTimeDiff, constant_time_diff};
use ctdiff::types::{SecurityConfig, DiffResult, DiffOperation, DiffError};
use std::time::Instant;

// helper function to create no-padding config for cleaner tests
fn no_padding_config() -> SecurityConfig {
    SecurityConfig {
        max_input_size: 1024,
        pad_inputs: false,
        padding_size: None,
        validate_inputs: true,
        max_edit_distance: None,
    }
}

#[test]
fn test_identical_files() {
    let input = b"hello world";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(input, input).unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 0);
    assert_eq!(result.original_len_a, input.len());
    assert_eq!(result.original_len_b, input.len());
    
    // all operations should be keep
    assert!(result.operations.iter().all(|op| matches!(op, DiffOperation::Keep)));
    
    // applying script should recreate original
    let reconstructed = result.apply_to(input).unwrap();
    assert_eq!(reconstructed, input);
}

#[test]
fn test_completely_different() {
    let a = b"abc";
    let b = b"xyz";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 3); // all chars different
    assert_eq!(result.original_len_a, a.len());
    assert_eq!(result.original_len_b, b.len());
    
    // applying script should recreate b
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_empty_files() {
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(b"", b"").unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 0);
    assert_eq!(result.original_len_a, 0);
    assert_eq!(result.original_len_b, 0);
    assert!(result.operations.is_empty());
    
    let reconstructed = result.apply_to(b"").unwrap();
    assert_eq!(reconstructed, b"");
}

#[test]
fn test_empty_to_content() {
    let a = b"";
    let b = b"hello";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 5); // 5 insertions
    assert_eq!(result.original_len_a, 0);
    assert_eq!(result.original_len_b, 5);
    
    // all operations should be inserts
    assert!(result.operations.iter().all(|op| matches!(op, DiffOperation::Insert(_))));
    
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_content_to_empty() {
    let a = b"hello";
    let b = b"";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 5); // 5 deletions
    assert_eq!(result.original_len_a, 5);
    assert_eq!(result.original_len_b, 0);
    
    // all operations should be deletes
    assert!(result.operations.iter().all(|op| matches!(op, DiffOperation::Delete)));
    
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_single_character_change() {
    let a = b"hello";
    let b = b"hallo";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 1);
    
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_insertion_in_middle() {
    let a = b"ac";
    let b = b"abc";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 1);
    
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_deletion_in_middle() {
    let a = b"abc";
    let b = b"ac";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    println!("Operations: {:?}", result.operations);
    println!("Edit distance: {}", result.edit_distance);
    println!("Original lengths: {} -> {}", result.original_len_a, result.original_len_b);
    
    if !result.is_valid() {
        let mut pos_a = 0;
        let mut pos_b = 0;
        let mut modifications = 0;
        for op in &result.operations {
            println!("Op: {:?}, pos_a={}, pos_b={}", op, pos_a, pos_b);
            match op {
                DiffOperation::Keep => { pos_a += 1; pos_b += 1; }
                DiffOperation::Insert(_) => { pos_b += 1; modifications += 1; }
                DiffOperation::Delete => { pos_a += 1; modifications += 1; }
                DiffOperation::Substitute(_) => { pos_a += 1; pos_b += 1; modifications += 1; }
            }
        }
        println!("Final pos_a={}, pos_b={}, modifications={}", pos_a, pos_b, modifications);
    }
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 1);
    
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_complex_diff() {
    let a = b"the quick brown fox";
    let b = b"the slow brown wolf";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    assert!(result.is_valid());
    assert!(result.edit_distance > 0);
    
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_longer_sequences() {
    let a = b"this is a longer test sequence with multiple words and characters";
    let b = b"this was a much longer test sequence with many different words and symbols";
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(a, b).unwrap();
    
    assert!(result.is_valid());
    assert!(result.edit_distance > 0);
    
    let reconstructed = result.apply_to(a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_binary_data() {
    let a = vec![0x00, 0x01, 0x02, 0x03, 0xFF];
    let b = vec![0x00, 0x01, 0x04, 0x03, 0xFF];
    let result = constant_time_diff(&a, &b).unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 1);
    
    let reconstructed = result.apply_to(&a).unwrap();
    assert_eq!(reconstructed, b);
}

#[test]
fn test_security_configurations() {
    let a = b"test";
    let b = b"text";
    
    // test no-padding config
    let differ1 = ConstantTimeDiff::new(no_padding_config());
    let result1 = differ1.diff(a, b).unwrap();
    assert!(result1.is_valid());
    
    // test secure config with small inputs
    let secure_config = SecurityConfig {
        max_input_size: 4 * 1024,
        pad_inputs: true,
        padding_size: Some(16), // small fixed padding
        validate_inputs: true,
        max_edit_distance: Some(1024),
    };
    let differ2 = ConstantTimeDiff::new(secure_config);
    let result2 = differ2.diff(a, b).unwrap();
    assert!(result2.is_valid());
    assert_eq!(result1.edit_distance, result2.edit_distance);
    
    // test balanced config
    let differ3 = ConstantTimeDiff::new(SecurityConfig::balanced());
    let result3 = differ3.diff(a, b).unwrap();
    assert!(result3.is_valid());
    assert_eq!(result1.edit_distance, result3.edit_distance);
}

#[test]
fn test_input_size_limits() {
    let config = SecurityConfig {
        max_input_size: 10,
        pad_inputs: false,
        padding_size: None,
        validate_inputs: true,
        max_edit_distance: None,
    };
    
    let differ = ConstantTimeDiff::new(config);
    
    // should succeed with small inputs
    let result = differ.diff(b"small", b"tiny");
    assert!(result.is_ok());
    
    // should fail with large inputs
    let large_input = vec![b'x'; 20];
    let result = differ.diff(&large_input, b"small");
    assert!(matches!(result, Err(DiffError::InputTooLarge { .. })));
}

#[test]
fn test_edit_distance_limits() {
    let config = SecurityConfig {
        max_input_size: 1000,
        pad_inputs: false,
        padding_size: None,
        validate_inputs: true,
        max_edit_distance: Some(15), // allow small inputs
    };
    
    let differ = ConstantTimeDiff::new(config);
    
    // should succeed with small edit distance
    let result = differ.diff(b"abc", b"abd");
    assert!(result.is_ok());
    
    // should fail with large potential edit distance
    let config_restrictive = SecurityConfig {
        max_input_size: 1000,
        pad_inputs: false,
        padding_size: None,
        validate_inputs: true,
        max_edit_distance: Some(5), // very restrictive
    };
    let differ_restrictive = ConstantTimeDiff::new(config_restrictive);
    let a = vec![b'a'; 10];
    let b = vec![b'b'; 10];
    let result = differ_restrictive.diff(&a, &b);
    // this should fail due to potential edit distance being too large (10+10=20 > 5)
    assert!(matches!(result, Err(DiffError::ComputationLimitExceeded(_))));
}

#[test]
fn test_padding_functionality() {
    let config = SecurityConfig {
        max_input_size: 100,
        pad_inputs: true,
        padding_size: Some(16),  // smaller padding
        validate_inputs: true,
        max_edit_distance: None,
    };
    
    let differ = ConstantTimeDiff::new(config);
    // test with same-length inputs first (easier case)
    let result = differ.diff(b"abc", b"def").unwrap();
    
    assert!(result.is_valid());
    assert_eq!(result.edit_distance, 3); // all substitutions
    // result should still be correct despite padding
    let reconstructed = result.apply_to(b"abc").unwrap();
    assert_eq!(reconstructed, b"def");
}

#[test]
fn test_timing_consistency_basic() {
    // basic structural test that same inputs take similar time
    // note: this is not a rigorous timing test, just a sanity check
    let differ = ConstantTimeDiff::new(no_padding_config());
    
    let a = b"consistent timing test input";
    let b = b"consistent timing test input";
    
    // run multiple iterations to get more stable timing
    let mut durations = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        let _result = differ.diff(a, b).unwrap();
        durations.push(start.elapsed());
    }
    
    // check that timing is reasonably consistent (within 10x variation)
    // this is very loose due to system scheduling noise
    let min_duration = durations.iter().min().unwrap();
    let max_duration = durations.iter().max().unwrap();
    let ratio = max_duration.as_nanos() as f64 / min_duration.as_nanos() as f64;
    assert!(ratio < 10.0, "timing variation too large: {}", ratio);
}

#[test]
fn test_diff_result_validation() {
    let differ = ConstantTimeDiff::new(no_padding_config());
    let result = differ.diff(b"abc", b"def").unwrap();
    
    // valid result should pass validation
    assert!(result.is_valid());
    
    // create invalid result with wrong metadata
    let invalid_result = DiffResult::new(
        result.operations.clone(),
        999, // wrong edit distance
        result.original_len_a,
        result.original_len_b,
    );
    assert!(!invalid_result.is_valid());
}

#[test]
fn test_error_handling() {
    // test apply with wrong input length
    let result = constant_time_diff(b"abc", b"def").unwrap();
    let apply_result = result.apply_to(b"wrong length input");
    assert!(matches!(apply_result, Err(DiffError::InvalidInput(_))));
}

#[test]
fn test_known_diff_examples() {
    // test against known simple diffs to verify correctness
    let differ = ConstantTimeDiff::new(no_padding_config());
    
    // single substitution
    let result = differ.diff(b"cat", b"bat").unwrap();
    assert_eq!(result.edit_distance, 1);
    assert_eq!(result.apply_to(b"cat").unwrap(), b"bat");
    
    // single insertion at start
    let result = differ.diff(b"at", b"bat").unwrap();
    assert_eq!(result.edit_distance, 1);
    assert_eq!(result.apply_to(b"at").unwrap(), b"bat");
    
    // single deletion at start  
    let result = differ.diff(b"bat", b"at").unwrap();
    assert_eq!(result.edit_distance, 1);
    assert_eq!(result.apply_to(b"bat").unwrap(), b"at");
    
    // single insertion at end
    let result = differ.diff(b"ba", b"bat").unwrap();
    assert_eq!(result.edit_distance, 1);
    assert_eq!(result.apply_to(b"ba").unwrap(), b"bat");
    
    // single deletion at end
    let result = differ.diff(b"bat", b"ba").unwrap();
    assert_eq!(result.edit_distance, 1);
    assert_eq!(result.apply_to(b"bat").unwrap(), b"ba");
}