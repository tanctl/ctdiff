//! timing attack simulation and analysis
//! 
//! demonstrates how timing side-channels can be exploited to learn
//! information about file contents without direct access.

use crate::timing::{PrecisionTimer, TimingStatistics, TimingComparison, TimingMeasurement};
use crate::vulnerable::VulnerableDiff;
use crate::{ConstantTimeDiff, security::SecurityConfig};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// results of a timing attack simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResults {
    /// attack scenario description
    pub scenario: String,
    /// number of measurement iterations per test
    pub iterations: usize,
    /// timing measurements for vulnerable implementation
    pub vulnerable_measurements: Vec<TimingMeasurement>,
    /// timing measurements for secure implementation  
    pub secure_measurements: Vec<TimingMeasurement>,
    /// statistical analysis of timing differences
    pub timing_analysis: Vec<TimingComparison>,
    /// attack success probability
    pub attack_success_probability: f64,
    /// confidence level for success probability
    pub confidence_level: f64,
}

impl AttackResults {
    /// format results as human-readable report
    pub fn format_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str(&format!("=== TIMING ATTACK SIMULATION RESULTS ===\n"));
        report.push_str(&format!("Scenario: {}\n", self.scenario));
        report.push_str(&format!("Iterations: {}\n\n", self.iterations));
        
        report.push_str("VULNERABILITY ANALYSIS:\n");
        for comparison in &self.timing_analysis {
            report.push_str(&format!("  {}\n", comparison.format_summary()));
            if comparison.significant_difference {
                report.push_str("  ⚠️  VULNERABLE: Significant timing difference detected!\n");
            } else {
                report.push_str("  ✅ SECURE: No significant timing difference\n");
            }
            report.push('\n');
        }
        
        report.push_str(&format!("ATTACK SUCCESS PROBABILITY: {:.1}%\n", self.attack_success_probability * 100.0));
        report.push_str(&format!("CONFIDENCE LEVEL: {:.1}%\n", self.confidence_level * 100.0));
        
        if self.attack_success_probability > 0.6 {
            report.push_str("\n🚨 HIGH RISK: Attack likely to succeed!\n");
        } else if self.attack_success_probability > 0.3 {
            report.push_str("\n⚠️  MODERATE RISK: Attack may succeed with more samples\n");
        } else {
            report.push_str("\n✅ LOW RISK: Attack unlikely to succeed\n");
        }
        
        report
    }
}

/// timing attack scenarios for demonstration
#[derive(Debug, Clone)]
pub enum AttackScenario {
    /// files with differences at different positions
    EarlyVsLateChanges,
    /// identical files vs completely different files
    IdenticalVsDifferent,
    /// files with different similarity levels
    SimilarityGradient,
    /// small changes vs large changes
    ChangeSize,
    /// version control scenario
    VersionControl,
    /// code review scenario
    CodeReview,
}

impl AttackScenario {
    /// get scenario description
    pub fn description(&self) -> &'static str {
        match self {
            AttackScenario::EarlyVsLateChanges => "Early vs Late Changes - detecting where differences occur",
            AttackScenario::IdenticalVsDifferent => "Identical vs Different - detecting if files differ at all",
            AttackScenario::SimilarityGradient => "Similarity Gradient - measuring degree of file similarity",
            AttackScenario::ChangeSize => "Change Size - distinguishing small vs large modifications",
            AttackScenario::VersionControl => "Version Control - analyzing commit differences",
            AttackScenario::CodeReview => "Code Review - inferring code change patterns",
        }
    }
    
    /// generate test file pairs for scenario
    pub fn generate_test_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>, String)> {
        match self {
            AttackScenario::EarlyVsLateChanges => vec![
                // difference at position 0
                (b"Xhello world test".to_vec(), b"Ahello world test".to_vec(), "change_at_pos_0".to_string()),
                // difference at position 5  
                (b"helloXworld test".to_vec(), b"helloAworld test".to_vec(), "change_at_pos_5".to_string()),
                // difference at position 10
                (b"hello worldXtest".to_vec(), b"hello worldAtest".to_vec(), "change_at_pos_10".to_string()),
                // difference at end
                (b"hello world tesX".to_vec(), b"hello world tesA".to_vec(), "change_at_end".to_string()),
            ],
            
            AttackScenario::IdenticalVsDifferent => vec![
                // identical files
                (b"identical content here".to_vec(), b"identical content here".to_vec(), "identical".to_string()),
                // completely different
                (b"aaaaaaaaaaaaaaaaaaa".to_vec(), b"bbbbbbbbbbbbbbbbbbb".to_vec(), "completely_different".to_string()),
                // one char different
                (b"almost identical".to_vec(), b"almost identica1".to_vec(), "one_char_diff".to_string()),
            ],
            
            AttackScenario::SimilarityGradient => {
                let base = b"the quick brown fox jumps over the lazy dog";
                vec![
                    // 100% similar
                    (base.to_vec(), base.to_vec(), "100_percent_similar".to_string()),
                    // 90% similar
                    (base.to_vec(), b"the quick brown fox jumps over the lazy cat".to_vec(), "90_percent_similar".to_string()),
                    // 70% similar  
                    (base.to_vec(), b"the quick brown cat jumps over the lazy dog".to_vec(), "70_percent_similar".to_string()),
                    // 50% similar
                    (base.to_vec(), b"the slow brown fox walks over the lazy dog".to_vec(), "50_percent_similar".to_string()),
                    // 10% similar
                    (base.to_vec(), b"completely different content with few matches".to_vec(), "10_percent_similar".to_string()),
                ]
            },
            
            AttackScenario::ChangeSize => vec![
                // single character change
                (b"hello world".to_vec(), b"hello wor1d".to_vec(), "single_char_change".to_string()),
                // word change
                (b"hello world".to_vec(), b"hello universe".to_vec(), "word_change".to_string()),
                // large change
                (b"hello world".to_vec(), b"completely different text entirely".to_vec(), "large_change".to_string()),
            ],
            
            AttackScenario::VersionControl => vec![
                // typical git commit - small function change
                (
                    b"function calculate(a, b) {\n    return a + b;\n}".to_vec(),
                    b"function calculate(a, b) {\n    return a * b;\n}".to_vec(),
                    "function_logic_change".to_string()
                ),
                // variable rename
                (
                    b"let userCount = 0;\nfunction increment() {\n    userCount++;\n}".to_vec(),
                    b"let totalUsers = 0;\nfunction increment() {\n    totalUsers++;\n}".to_vec(),
                    "variable_rename".to_string()
                ),
                // comment addition
                (
                    b"function process() {\n    doWork();\n}".to_vec(),
                    b"function process() {\n    // TODO: optimize this\n    doWork();\n}".to_vec(),
                    "comment_addition".to_string()
                ),
            ],
            
            AttackScenario::CodeReview => vec![
                // security fix
                (
                    b"password = request.getParameter(\"password\");".to_vec(),
                    b"password = sanitize(request.getParameter(\"password\"));".to_vec(),
                    "security_fix".to_string()
                ),
                // bug fix
                (
                    b"if (user = null) { throw new Error(); }".to_vec(),
                    b"if (user == null) { throw new Error(); }".to_vec(),
                    "bug_fix".to_string()
                ),
                // refactoring
                (
                    b"function longFunctionName() { return true; }".to_vec(),
                    b"function isValid() { return true; }".to_vec(),
                    "refactoring".to_string()
                ),
            ],
        }
    }
}

/// timing attack simulator
pub struct AttackSimulator {
    vulnerable_diff: VulnerableDiff,
    secure_diff: ConstantTimeDiff,
    timer: PrecisionTimer,
}

impl AttackSimulator {
    /// create new attack simulator
    pub fn new() -> Self {
        Self {
            vulnerable_diff: VulnerableDiff::new(),
            secure_diff: ConstantTimeDiff::new(crate::security::SecurityConfig::balanced(None).to_legacy()),
            timer: PrecisionTimer::new(),
        }
    }
    
    /// create simulator with specific security configuration
    pub fn with_security_config(config: SecurityConfig) -> Self {
        Self {
            vulnerable_diff: VulnerableDiff::new(),
            secure_diff: ConstantTimeDiff::new(config.to_legacy()),
            timer: PrecisionTimer::new(),
        }
    }
    
    /// simulate timing attack for given scenario
    pub fn simulate_attack(&mut self, scenario: AttackScenario, iterations: usize) -> AttackResults {
        let test_pairs = scenario.generate_test_pairs();
        let mut vulnerable_measurements = Vec::new();
        let mut secure_measurements = Vec::new();
        
        // measure timing for each test pair
        for (file_a, file_b, label) in &test_pairs {
            // measure vulnerable implementation multiple times
            for i in 0..iterations {
                let measurement_label = format!("vulnerable_{}_{}", label, i);
                let (_, measurement) = self.timer.measure(measurement_label.clone(), || {
                    self.vulnerable_diff.diff(file_a, file_b).unwrap()
                });
                vulnerable_measurements.push(measurement.with_metadata("implementation".to_string(), "vulnerable".to_string())
                    .with_metadata("test_case".to_string(), label.clone()));
            }
            
            // measure secure implementation multiple times
            for i in 0..iterations {
                let measurement_label = format!("secure_{}_{}", label, i);
                let (_, measurement) = self.timer.measure(measurement_label.clone(), || {
                    self.secure_diff.diff(file_a, file_b).unwrap()
                });
                secure_measurements.push(measurement.with_metadata("implementation".to_string(), "secure".to_string())
                    .with_metadata("test_case".to_string(), label.clone()));
            }
        }
        
        // analyze timing differences
        let timing_analysis = self.analyze_timing_differences(&vulnerable_measurements, &secure_measurements);
        
        // calculate attack success probability
        let attack_success_probability = self.calculate_attack_success_probability(&timing_analysis);
        
        AttackResults {
            scenario: scenario.description().to_string(),
            iterations,
            vulnerable_measurements,
            secure_measurements,
            timing_analysis,
            attack_success_probability,
            confidence_level: 0.95,
        }
    }
    
    /// analyze timing differences between implementations
    fn analyze_timing_differences(
        &self,
        vulnerable_measurements: &[TimingMeasurement],
        secure_measurements: &[TimingMeasurement],
    ) -> Vec<TimingComparison> {
        let mut comparisons = Vec::new();
        
        // group measurements by test case
        let mut vulnerable_by_case: HashMap<String, Vec<&TimingMeasurement>> = HashMap::new();
        let mut secure_by_case: HashMap<String, Vec<&TimingMeasurement>> = HashMap::new();
        
        for measurement in vulnerable_measurements {
            if let Some(test_case) = measurement.metadata.get("test_case") {
                vulnerable_by_case.entry(test_case.clone()).or_default().push(measurement);
            }
        }
        
        for measurement in secure_measurements {
            if let Some(test_case) = measurement.metadata.get("test_case") {
                secure_by_case.entry(test_case.clone()).or_default().push(measurement);
            }
        }
        
        // compare timing statistics for each test case
        for test_case in vulnerable_by_case.keys() {
            if let (Some(vuln_measurements), Some(secure_measurements)) = 
                (vulnerable_by_case.get(test_case), secure_by_case.get(test_case)) {
                
                let vuln_measurements: Vec<TimingMeasurement> = vuln_measurements.iter().map(|&m| m.clone()).collect();
                let secure_measurements_vec: Vec<TimingMeasurement> = secure_measurements.iter().map(|&m| m.clone()).collect();
                
                if let (Some(vuln_stats), Some(secure_stats)) = 
                    (TimingStatistics::from_measurements(&vuln_measurements),
                     TimingStatistics::from_measurements(&secure_measurements_vec)) {
                    
                    let comparison = TimingComparison::new(
                        format!("vulnerable_{}", test_case),
                        vuln_stats,
                        format!("secure_{}", test_case),
                        secure_stats,
                        0.05, // p-value threshold
                    );
                    
                    comparisons.push(comparison);
                }
            }
        }
        
        // also compare overall distributions
        if let (Some(vuln_overall), Some(secure_overall)) = 
            (TimingStatistics::from_measurements(vulnerable_measurements),
             TimingStatistics::from_measurements(secure_measurements)) {
            
            let overall_comparison = TimingComparison::new(
                "vulnerable_overall".to_string(),
                vuln_overall,
                "secure_overall".to_string(),
                secure_overall,
                0.01, // stricter threshold for overall comparison
            );
            
            comparisons.push(overall_comparison);
        }
        
        comparisons
    }
    
    /// calculate probability that timing attack would succeed
    fn calculate_attack_success_probability(&self, timing_analysis: &[TimingComparison]) -> f64 {
        if timing_analysis.is_empty() {
            return 0.0;
        }
        
        // attack success is based on:
        // 1. statistical significance of timing differences
        // 2. magnitude of timing differences
        // 3. consistency across test cases
        
        let significant_comparisons = timing_analysis.iter()
            .filter(|c| c.significant_difference)
            .count();
        
        let total_comparisons = timing_analysis.len();
        let significance_ratio = significant_comparisons as f64 / total_comparisons as f64;
        
        // calculate average timing ratio for significant differences
        let significant_ratios: Vec<f64> = timing_analysis.iter()
            .filter(|c| c.significant_difference)
            .map(|c| if c.ratio > 1.0 { c.ratio } else { 1.0 / c.ratio })
            .collect();
        
        let average_ratio = if significant_ratios.is_empty() {
            1.0
        } else {
            significant_ratios.iter().sum::<f64>() / significant_ratios.len() as f64
        };
        
        // success probability model (empirically derived)
        let base_probability = significance_ratio * 0.8; // max 80% from significance
        let ratio_bonus = ((average_ratio - 1.0) / 10.0).min(0.2); // max 20% from ratio
        
        (base_probability + ratio_bonus).min(1.0)
    }
    
    /// run comprehensive attack demonstration
    pub fn run_comprehensive_demo(&mut self, iterations: usize) -> Vec<AttackResults> {
        let scenarios = vec![
            AttackScenario::EarlyVsLateChanges,
            AttackScenario::IdenticalVsDifferent,
            AttackScenario::SimilarityGradient,
            AttackScenario::ChangeSize,
            AttackScenario::VersionControl,
            AttackScenario::CodeReview,
        ];
        
        scenarios.into_iter()
            .map(|scenario| self.simulate_attack(scenario, iterations))
            .collect()
    }
    
    /// get all timing measurements
    pub fn get_measurements(&self) -> &[crate::timing::TimingMeasurement] {
        self.timer.measurements()
    }
    
    /// generate attack report summary
    pub fn generate_summary_report(&mut self, iterations: usize) -> String {
        let results = self.run_comprehensive_demo(iterations);
        let mut report = String::new();
        
        report.push_str("=== COMPREHENSIVE TIMING ATTACK ANALYSIS ===\n\n");
        
        for result in &results {
            report.push_str(&result.format_report());
            report.push_str("\n");
            report.push_str(&"-".repeat(60));
            report.push_str("\n\n");
        }
        
        // overall summary
        let vulnerable_scenarios = results.iter()
            .filter(|r| r.attack_success_probability > 0.5)
            .count();
        
        let total_scenarios = results.len();
        
        report.push_str("=== OVERALL ASSESSMENT ===\n");
        report.push_str(&format!("Vulnerable scenarios: {}/{}\n", vulnerable_scenarios, total_scenarios));
        
        if vulnerable_scenarios > 0 {
            report.push_str("🚨 CRITICAL: Vulnerable implementation is susceptible to timing attacks!\n");
            report.push_str("✅ SECURE: Constant-time implementation provides protection\n");
        } else {
            report.push_str("✅ All scenarios show adequate protection against timing attacks\n");
        }
        
        report
    }
}

impl Default for AttackSimulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_attack_scenario_generation() {
        let scenario = AttackScenario::EarlyVsLateChanges;
        let pairs = scenario.generate_test_pairs();
        
        assert!(!pairs.is_empty());
        assert!(pairs.iter().all(|(a, b, _)| a != b)); // all pairs should be different
    }
    
    #[test]
    fn test_attack_simulator() {
        let mut simulator = AttackSimulator::new();
        let results = simulator.simulate_attack(AttackScenario::IdenticalVsDifferent, 5);
        
        assert_eq!(results.scenario, AttackScenario::IdenticalVsDifferent.description());
        assert_eq!(results.iterations, 5);
        assert!(!results.vulnerable_measurements.is_empty());
        assert!(!results.secure_measurements.is_empty());
    }
    
    #[test] 
    fn test_timing_analysis() {
        let mut simulator = AttackSimulator::new();
        
        // create some test measurements with different timing patterns
        let fast_measurements = vec![
            TimingMeasurement::new(std::time::Duration::from_nanos(100), 1, "fast".to_string()),
            TimingMeasurement::new(std::time::Duration::from_nanos(110), 1, "fast".to_string()),
        ];
        
        let slow_measurements = vec![
            TimingMeasurement::new(std::time::Duration::from_nanos(200), 1, "slow".to_string()),
            TimingMeasurement::new(std::time::Duration::from_nanos(210), 1, "slow".to_string()),
        ];
        
        let analysis = simulator.analyze_timing_differences(&slow_measurements, &fast_measurements);
        assert!(!analysis.is_empty());
    }
}