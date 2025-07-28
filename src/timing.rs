//! high-precision timing measurement and statistical analysis utilities
//! 
//! provides tools for measuring execution time with high precision and
//! analyzing timing data to detect side-channel vulnerabilities.

use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// high-precision timing measurement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMeasurement {
    /// duration of the measured operation
    pub duration: Duration,
    /// number of iterations averaged (if applicable)
    pub iterations: usize,
    /// metadata about what was measured
    pub label: String,
    /// additional context data
    pub metadata: std::collections::HashMap<String, String>,
}

impl TimingMeasurement {
    /// create new timing measurement
    pub fn new(duration: Duration, iterations: usize, label: String) -> Self {
        Self {
            duration,
            iterations,
            label,
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// add metadata to measurement
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// get average duration per iteration
    pub fn average_duration(&self) -> Duration {
        if self.iterations == 0 {
            Duration::ZERO
        } else {
            self.duration / (self.iterations as u32)
        }
    }
    
    /// get duration in nanoseconds
    pub fn nanos(&self) -> u128 {
        self.duration.as_nanos()
    }
    
    /// get average nanoseconds per iteration
    pub fn average_nanos(&self) -> f64 {
        if self.iterations == 0 {
            0.0
        } else {
            self.duration.as_nanos() as f64 / self.iterations as f64
        }
    }
}

/// statistical analysis of timing measurements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingStatistics {
    /// number of measurements
    pub count: usize,
    /// minimum duration
    pub min: Duration,
    /// maximum duration  
    pub max: Duration,
    /// arithmetic mean
    pub mean: Duration,
    /// median value
    pub median: Duration,
    /// standard deviation
    pub std_dev: Duration,
    /// variance
    pub variance: f64,
    /// 95% confidence interval
    pub confidence_interval_95: (Duration, Duration),
    /// coefficient of variation (std_dev / mean)
    pub coefficient_of_variation: f64,
}

impl TimingStatistics {
    /// compute statistics from timing measurements
    pub fn from_measurements(measurements: &[TimingMeasurement]) -> Option<Self> {
        if measurements.is_empty() {
            return None;
        }
        
        let durations: Vec<Duration> = measurements.iter().map(|m| m.duration).collect();
        Self::from_durations(&durations)
    }
    
    /// compute statistics from raw durations
    pub fn from_durations(durations: &[Duration]) -> Option<Self> {
        if durations.is_empty() {
            return None;
        }
        
        let nanos: Vec<f64> = durations.iter().map(|d| d.as_nanos() as f64).collect();
        
        // basic statistics
        let count = nanos.len();
        let min = *durations.iter().min().unwrap();
        let max = *durations.iter().max().unwrap();
        
        // mean
        let mean_nanos = nanos.iter().sum::<f64>() / count as f64;
        let mean = Duration::from_nanos(mean_nanos as u64);
        
        // median
        let mut sorted_nanos = nanos.clone();
        sorted_nanos.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median_nanos = if count % 2 == 0 {
            (sorted_nanos[count / 2 - 1] + sorted_nanos[count / 2]) / 2.0
        } else {
            sorted_nanos[count / 2]
        };
        let median = Duration::from_nanos(median_nanos as u64);
        
        // variance and standard deviation
        let variance = nanos.iter()
            .map(|x| (x - mean_nanos).powi(2))
            .sum::<f64>() / count as f64;
        
        let std_dev_nanos = variance.sqrt();
        let std_dev = Duration::from_nanos(std_dev_nanos as u64);
        
        // coefficient of variation
        let coefficient_of_variation = if mean_nanos > 0.0 {
            std_dev_nanos / mean_nanos
        } else {
            0.0
        };
        
        // 95% confidence interval (assuming normal distribution)
        let margin_of_error = 1.96 * std_dev_nanos / (count as f64).sqrt();
        let ci_lower = Duration::from_nanos((mean_nanos - margin_of_error).max(0.0) as u64);
        let ci_upper = Duration::from_nanos((mean_nanos + margin_of_error) as u64);
        
        Some(Self {
            count,
            min,
            max,
            mean,
            median,
            std_dev,
            variance,
            confidence_interval_95: (ci_lower, ci_upper),
            coefficient_of_variation,
        })
    }
    
    /// check if timing difference is statistically significant
    pub fn is_significantly_different(&self, other: &Self, p_value: f64) -> bool {
        // simple t-test approximation
        let pooled_variance = ((self.count - 1) as f64 * self.variance + 
                              (other.count - 1) as f64 * other.variance) /
                             (self.count + other.count - 2) as f64;
        
        let standard_error = (pooled_variance * (1.0 / self.count as f64 + 1.0 / other.count as f64)).sqrt();
        
        if standard_error == 0.0 {
            return false;
        }
        
        let t_statistic = (self.mean.as_nanos() as f64 - other.mean.as_nanos() as f64).abs() / standard_error;
        
        // approximate critical values for common p-values
        let critical_value = match p_value {
            p if p <= 0.001 => 3.291, // p < 0.001
            p if p <= 0.01 => 2.576,  // p < 0.01
            p if p <= 0.05 => 1.96,   // p < 0.05
            _ => 1.645,               // p < 0.1
        };
        
        t_statistic > critical_value
    }
    
    /// get timing ratio compared to other measurement
    pub fn ratio_to(&self, other: &Self) -> f64 {
        if other.mean.as_nanos() == 0 {
            return f64::INFINITY;
        }
        self.mean.as_nanos() as f64 / other.mean.as_nanos() as f64
    }
}

/// high-precision timer for measuring operations
pub struct PrecisionTimer {
    start_time: Option<Instant>,
    measurements: Vec<TimingMeasurement>,
}

impl PrecisionTimer {
    /// create new precision timer
    pub fn new() -> Self {
        Self {
            start_time: None,
            measurements: Vec::new(),
        }
    }
    
    /// start timing measurement
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }
    
    /// stop timing and record measurement
    pub fn stop(&mut self, label: String) -> Option<TimingMeasurement> {
        if let Some(start) = self.start_time.take() {
            let duration = start.elapsed();
            let measurement = TimingMeasurement::new(duration, 1, label);
            self.measurements.push(measurement.clone());
            Some(measurement)
        } else {
            None
        }
    }
    
    /// measure a single operation
    pub fn measure<F, R>(&mut self, label: String, operation: F) -> (R, TimingMeasurement)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();
        
        let measurement = TimingMeasurement::new(duration, 1, label);
        self.measurements.push(measurement.clone());
        
        (result, measurement)
    }
    
    /// measure operation multiple times and return average
    pub fn measure_multiple<F, R>(&mut self, label: String, iterations: usize, mut operation: F) -> (Vec<R>, TimingMeasurement)
    where
        F: FnMut() -> R,
    {
        let mut results = Vec::with_capacity(iterations);
        let start = Instant::now();
        
        for _ in 0..iterations {
            results.push(operation());
        }
        
        let total_duration = start.elapsed();
        let measurement = TimingMeasurement::new(total_duration, iterations, label);
        self.measurements.push(measurement.clone());
        
        (results, measurement)
    }
    
    /// get all measurements
    pub fn measurements(&self) -> &[TimingMeasurement] {
        &self.measurements
    }
    
    /// clear all measurements
    pub fn clear(&mut self) {
        self.measurements.clear();
    }
    
    /// get statistics for measurements with specific label
    pub fn statistics_for_label(&self, label: &str) -> Option<TimingStatistics> {
        let filtered: Vec<_> = self.measurements.iter()
            .filter(|m| m.label == label)
            .cloned()
            .collect();
        
        TimingStatistics::from_measurements(&filtered)
    }
}

impl Default for PrecisionTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// timing comparison between two implementations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingComparison {
    /// label for first implementation
    pub impl_a_label: String,
    /// statistics for first implementation
    pub impl_a_stats: TimingStatistics,
    /// label for second implementation  
    pub impl_b_label: String,
    /// statistics for second implementation
    pub impl_b_stats: TimingStatistics,
    /// timing ratio (a / b)
    pub ratio: f64,
    /// whether difference is statistically significant
    pub significant_difference: bool,
    /// p-value threshold used for significance test
    pub p_value_threshold: f64,
}

impl TimingComparison {
    /// create timing comparison
    pub fn new(
        impl_a_label: String,
        impl_a_stats: TimingStatistics,
        impl_b_label: String,
        impl_b_stats: TimingStatistics,
        p_value_threshold: f64,
    ) -> Self {
        let ratio = impl_a_stats.ratio_to(&impl_b_stats);
        let significant_difference = impl_a_stats.is_significantly_different(&impl_b_stats, p_value_threshold);
        
        Self {
            impl_a_label,
            impl_a_stats,
            impl_b_label,
            impl_b_stats,
            ratio,
            significant_difference,
            p_value_threshold,
        }
    }
    
    /// format comparison as human-readable string
    pub fn format_summary(&self) -> String {
        let faster_impl = if self.ratio < 1.0 {
            &self.impl_a_label
        } else {
            &self.impl_b_label
        };
        
        let speed_diff = if self.ratio < 1.0 {
            1.0 / self.ratio
        } else {
            self.ratio
        };
        
        let significance = if self.significant_difference {
            format!("statistically significant (p < {})", self.p_value_threshold)
        } else {
            "not statistically significant".to_string()
        };
        
        format!(
            "{} is {:.2}x faster than {} ({})\n\
             {} mean: {:.2}μs (±{:.2}μs)\n\
             {} mean: {:.2}μs (±{:.2}μs)",
            faster_impl,
            speed_diff,
            if self.ratio < 1.0 { &self.impl_b_label } else { &self.impl_a_label },
            significance,
            self.impl_a_label,
            self.impl_a_stats.mean.as_nanos() as f64 / 1000.0,
            self.impl_a_stats.std_dev.as_nanos() as f64 / 1000.0,
            self.impl_b_label,
            self.impl_b_stats.mean.as_nanos() as f64 / 1000.0,
            self.impl_b_stats.std_dev.as_nanos() as f64 / 1000.0,
        )
    }
}

/// export timing data in various formats
pub mod export {
    use super::*;
    use std::io::Write;
    
    /// export measurements as csv
    pub fn to_csv<W: Write>(measurements: &[TimingMeasurement], writer: &mut W) -> std::io::Result<()> {
        writeln!(writer, "label,duration_nanos,iterations,average_nanos")?;
        for measurement in measurements {
            writeln!(
                writer,
                "{},{},{},{}",
                measurement.label,
                measurement.nanos(),
                measurement.iterations,
                measurement.average_nanos()
            )?;
        }
        Ok(())
    }
    
    /// export statistics as json
    pub fn stats_to_json(stats: &TimingStatistics) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(stats)
    }
    
    /// export comparison as json
    pub fn comparison_to_json(comparison: &TimingComparison) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(comparison)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_precision_timer() {
        let mut timer = PrecisionTimer::new();
        
        let (_, measurement) = timer.measure("test_op".to_string(), || {
            thread::sleep(Duration::from_millis(10));
        });
        
        assert!(measurement.duration >= Duration::from_millis(9));
        assert_eq!(measurement.label, "test_op");
        assert_eq!(measurement.iterations, 1);
    }
    
    #[test]
    fn test_timing_statistics() {
        let durations = vec![
            Duration::from_nanos(100),
            Duration::from_nanos(200), 
            Duration::from_nanos(300),
            Duration::from_nanos(150),
            Duration::from_nanos(250),
        ];
        
        let stats = TimingStatistics::from_durations(&durations).unwrap();
        
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min, Duration::from_nanos(100));
        assert_eq!(stats.max, Duration::from_nanos(300));
        assert_eq!(stats.mean, Duration::from_nanos(200));
    }
    
    #[test]
    fn test_timing_comparison() {
        let fast_durations = vec![Duration::from_nanos(100); 10];
        let slow_durations = vec![Duration::from_nanos(200); 10];
        
        let fast_stats = TimingStatistics::from_durations(&fast_durations).unwrap();
        let slow_stats = TimingStatistics::from_durations(&slow_durations).unwrap();
        
        let comparison = TimingComparison::new(
            "fast".to_string(),
            fast_stats,
            "slow".to_string(), 
            slow_stats,
            0.05,
        );
        
        assert!(comparison.ratio < 1.0);
        // statistical significance may not be detected with small test samples
        // but ratio should still show clear difference
    }
}