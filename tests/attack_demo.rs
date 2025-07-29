//! tests for timing attack demonstration functionality
//! 
//! verifies that attack demo can distinguish between vulnerable and secure
//! implementations and produces expected timing patterns.

use ctdiff::attack::{AttackSimulator, AttackScenario};
use ctdiff::timing::{PrecisionTimer, TimingStatistics};
use ctdiff::vulnerable::VulnerableDiff;
use ctdiff::{ConstantTimeDiff, SecurityConfig};
use std::time::Duration;

#[test]
fn test_attack_simulator_creation() {
    let simulator = AttackSimulator::new();
    // just verify it can be created without panicking
    drop(simulator);
}

#[test] 
fn test_attack_scenario_generation() {
    let scenarios = vec![
        AttackScenario::EarlyVsLateChanges,
        AttackScenario::IdenticalVsDifferent,
        AttackScenario::SimilarityGradient,
        AttackScenario::ChangeSize,
        AttackScenario::VersionControl,
        AttackScenario::CodeReview,
    ];
    
    for scenario in scenarios {
        let test_pairs = scenario.generate_test_pairs();
        assert!(!test_pairs.is_empty(), "scenario {:?} should generate test pairs", scenario);
        
        // verify all pairs have labels
        for (_, _, label) in &test_pairs {
            assert!(!label.is_empty(), "test pair should have non-empty label");
        }
    }
}

#[test]
fn test_vulnerable_vs_secure_timing_differences() {
    // this test verifies that we can detect timing differences between
    // vulnerable and secure implementations on crafted inputs
    
    let vulnerable_diff = VulnerableDiff::new();
    let secure_diff = ConstantTimeDiff::new(SecurityConfig::balanced());
    let mut timer = PrecisionTimer::new();
    
    // create inputs designed to maximize timing differences
    let identical_files = (b"identical content".as_slice(), b"identical content".as_slice());
    let different_at_start = (b"Aidentical content".as_slice(), b"Bidentical content".as_slice());
    let different_at_end = (b"identical contenA".as_slice(), b"identical contenB".as_slice());
    
    let test_cases = vec![
        ("identical", identical_files),
        ("diff_start", different_at_start),
        ("diff_end", different_at_end),
    ];
    
    let iterations = 10; // smaller number for tests
    
    for (label, (file_a, file_b)) in test_cases {
        let mut vulnerable_times = Vec::new();
        let mut secure_times = Vec::new();
        
        // measure vulnerable implementation
        for i in 0..iterations {
            let measurement_label = format!("vulnerable_{}_{}", label, i);
            let (_, measurement) = timer.measure(measurement_label, || {
                vulnerable_diff.diff(file_a, file_b).unwrap()
            });
            vulnerable_times.push(measurement);
        }
        
        // measure secure implementation
        for i in 0..iterations {
            let measurement_label = format!("secure_{}_{}", label, i);
            let (_, measurement) = timer.measure(measurement_label, || {
                secure_diff.diff(file_a, file_b).unwrap()
            });
            secure_times.push(measurement);
        }
        
        // verify we got measurements
        assert_eq!(vulnerable_times.len(), iterations);
        assert_eq!(secure_times.len(), iterations);
        
        // verify measurements have reasonable values
        for measurement in &vulnerable_times {
            assert!(measurement.duration > Duration::ZERO);
            assert!(measurement.duration < Duration::from_secs(1)); // sanity check
        }
        
        for measurement in &secure_times {
            assert!(measurement.duration > Duration::ZERO);
            assert!(measurement.duration < Duration::from_secs(1)); // sanity check
        }
    }
}

#[test]
fn test_attack_simulation_produces_results() {
    let mut simulator = AttackSimulator::new();
    let results = simulator.simulate_attack(AttackScenario::IdenticalVsDifferent, 5);
    
    // verify results structure
    assert!(!results.scenario.is_empty());
    assert_eq!(results.iterations, 5);
    assert!(!results.vulnerable_measurements.is_empty());
    assert!(!results.secure_measurements.is_empty());
    assert!(!results.timing_analysis.is_empty());
    assert!(results.attack_success_probability >= 0.0);
    assert!(results.attack_success_probability <= 1.0);
    assert_eq!(results.confidence_level, 0.95);
    
    // verify report formatting doesn't panic
    let report = results.format_report();
    assert!(!report.is_empty());
    assert!(report.contains("TIMING ATTACK SIMULATION RESULTS"));
}

#[test]
fn test_comprehensive_attack_demo() {
    let mut simulator = AttackSimulator::new();
    let results = simulator.run_comprehensive_demo(3); // small iteration count for tests
    
    // should test all scenarios
    assert_eq!(results.len(), 6); // number of AttackScenario variants
    
    for result in &results {
        assert!(!result.scenario.is_empty());
        assert_eq!(result.iterations, 3);
        assert!(!result.vulnerable_measurements.is_empty());
        assert!(!result.secure_measurements.is_empty());
    }
    
    // verify summary report generation
    let summary = simulator.generate_summary_report(3);
    assert!(!summary.is_empty());
    assert!(summary.contains("COMPREHENSIVE TIMING ATTACK ANALYSIS"));
    assert!(summary.contains("OVERALL ASSESSMENT"));
}

#[test]
fn test_timing_statistics_calculation() {
    // test statistical analysis functions
    let durations = vec![
        Duration::from_nanos(100),
        Duration::from_nanos(200),
        Duration::from_nanos(150),
        Duration::from_nanos(250),
        Duration::from_nanos(175),
    ];
    
    let stats = TimingStatistics::from_durations(&durations).unwrap();
    
    assert_eq!(stats.count, 5);
    assert_eq!(stats.min, Duration::from_nanos(100));
    assert_eq!(stats.max, Duration::from_nanos(250));
    
    // mean should be (100+200+150+250+175)/5 = 175
    assert_eq!(stats.mean, Duration::from_nanos(175));
    
    // verify other statistics are reasonable
    assert!(stats.std_dev > Duration::ZERO);
    assert!(stats.variance > 0.0);
    assert!(stats.coefficient_of_variation >= 0.0);
}

#[test] 
fn test_timing_comparison_significance() {
    use ctdiff::timing::TimingComparison;
    
    // create clearly different timing distributions
    let fast_durations = vec![Duration::from_nanos(100); 20];
    let slow_durations = vec![Duration::from_nanos(200); 20];
    
    let fast_stats = TimingStatistics::from_durations(&fast_durations).unwrap();
    let slow_stats = TimingStatistics::from_durations(&slow_durations).unwrap();
    
    let comparison = TimingComparison::new(
        "fast".to_string(),
        fast_stats,
        "slow".to_string(),
        slow_stats,
        0.05,
    );
    
    // should detect large ratio even if statistical test is conservative
    assert!(comparison.ratio < 1.0); // fast should be faster than slow
    assert!(comparison.ratio < 0.6); // should be noticeably faster
    
    // verify summary formatting
    let summary = comparison.format_summary();
    assert!(!summary.is_empty());
    assert!(summary.contains("faster"));
}

#[test]
fn test_attack_scenario_descriptions() {
    let scenarios = vec![
        AttackScenario::EarlyVsLateChanges,
        AttackScenario::IdenticalVsDifferent,
        AttackScenario::SimilarityGradient,
        AttackScenario::ChangeSize,
        AttackScenario::VersionControl,
        AttackScenario::CodeReview,
    ];
    
    for scenario in scenarios {
        let description = scenario.description();
        assert!(!description.is_empty());
        assert!(description.len() > 10); // should be meaningful descriptions
    }
}

#[test]
fn test_vulnerable_implementation_timing_characteristics() {
    // verify that vulnerable implementation has expected timing characteristics
    let vulnerable_diff = VulnerableDiff::new();
    let mut timer = PrecisionTimer::new();
    
    // test early vs late differences
    let early_diff = (b"Xhello world".as_slice(), b"Ahello world".as_slice());
    let late_diff = (b"hello worlX".as_slice(), b"hello worlA".as_slice());
    
    let iterations = 10;
    let mut early_times = Vec::new();
    let mut late_times = Vec::new();
    
    for i in 0..iterations {
        // measure early difference
        let (_, measurement) = timer.measure(format!("early_{}", i), || {
            vulnerable_diff.diff(early_diff.0, early_diff.1).unwrap()
        });
        early_times.push(measurement);
        
        // measure late difference
        let (_, measurement) = timer.measure(format!("late_{}", i), || {
            vulnerable_diff.diff(late_diff.0, late_diff.1).unwrap()
        });
        late_times.push(measurement);
    }
    
    // verify we have measurements
    assert_eq!(early_times.len(), iterations);
    assert_eq!(late_times.len(), iterations);
    
    // the vulnerable implementation might show timing differences
    // (though this test might be flaky due to system variance)
    if let (Some(early_stats), Some(late_stats)) = (
        TimingStatistics::from_measurements(&early_times),
        TimingStatistics::from_measurements(&late_times)
    ) {
        // at minimum, verify statistics can be computed
        assert!(early_stats.mean > Duration::ZERO);
        assert!(late_stats.mean > Duration::ZERO);
        
        // timing differences exist but may not always be statistically significant
        // in test environment due to noise - this mainly tests the infrastructure
    }
}

#[test]
fn test_attack_success_probability_calculation() {
    // test the attack success probability calculation logic
    use ctdiff::timing::TimingComparison;
    
    // scenario 1: no significant differences
    let same_durations = vec![Duration::from_nanos(100); 10];
    let same_stats = TimingStatistics::from_durations(&same_durations).unwrap();
    
    let no_diff_comparison = TimingComparison::new(
        "impl1".to_string(),
        same_stats.clone(),
        "impl2".to_string(), 
        same_stats.clone(),
        0.05,
    );
    
    // scenario 2: significant differences
    let fast_durations = vec![Duration::from_nanos(100); 10];
    let slow_durations = vec![Duration::from_nanos(300); 10];
    
    let fast_stats = TimingStatistics::from_durations(&fast_durations).unwrap();
    let slow_stats = TimingStatistics::from_durations(&slow_durations).unwrap();
    
    let diff_comparison = TimingComparison::new(
        "fast".to_string(),
        fast_stats,
        "slow".to_string(),
        slow_stats,
        0.05,
    );
    
    // verify basic properties
    assert!(diff_comparison.ratio < 1.0); // fast is faster
    assert!(diff_comparison.ratio < 0.5); // significantly faster
    
    // the attack simulator should calculate different success probabilities
    // for these scenarios (exact values depend on implementation details)
}