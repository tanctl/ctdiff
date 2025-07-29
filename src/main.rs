//! command-line interface for constant-time diff tool
//! 
//! provides secure file comparison with timing attack resistance
//! and familiar unix diff-style output formatting.

use clap::{Parser, Subcommand, ValueEnum};
use ctdiff::{ConstantTimeDiff, SecurityConfig};
use ctdiff::attack::{AttackSimulator, AttackScenario};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

mod output;
use output::{OutputFormat, DiffFormatter};

#[derive(Parser)]
#[command(name = "ctdiff")]
#[command(about = "constant-time diff tool - secure file comparison resistant to timing attacks")]
#[command(version = "0.1.0")]
#[command(author = "Tanya Arora")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// first file to compare (when not using subcommands)
    #[arg(value_name = "FILE1")]
    file1: Option<PathBuf>,
    
    /// second file to compare (when not using subcommands)
    #[arg(value_name = "FILE2")]
    file2: Option<PathBuf>,
    
    /// security level for timing attack resistance
    #[arg(short = 's', long = "security-level", default_value = "balanced")]
    security_level: SecurityLevel,
    
    /// maximum file size to process (in kb)
    #[arg(long = "max-size")]
    max_size: Option<usize>,
    
    /// output format
    #[arg(short = 'f', long = "format", default_value = "unified")]
    format: OutputFormat,
    
    /// enable colored output
    #[arg(short = 'c', long = "color")]
    color: bool,
    
    /// show timing information (for security analysis)
    #[arg(long = "show-timing")]
    show_timing: bool,
    
    /// context lines for unified diff format
    #[arg(short = 'u', long = "context", default_value = "3")]
    context: usize,
    
    /// suppress output, only return exit code
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
    
    /// force processing even if security warnings exist
    #[arg(long = "force")]
    force: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// run timing attack demonstration
    #[command(name = "attack-demo")]
    AttackDemo {
        /// attack scenario to demonstrate
        #[arg(long = "scenario", default_value = "comprehensive")]
        scenario: AttackScenarioArg,
        
        /// number of timing measurements per test
        #[arg(long = "iterations", default_value = "50")]
        iterations: usize,
        
        /// first test file (optional, generates files if not provided)
        #[arg(value_name = "FILE1")]
        file1: Option<PathBuf>,
        
        /// second test file (optional, generates files if not provided)
        #[arg(value_name = "FILE2")]
        file2: Option<PathBuf>,
        
        /// output detailed timing data to file
        #[arg(long = "output")]
        output_file: Option<PathBuf>,
        
        /// export timing data as CSV
        #[arg(long = "csv")]
        csv_output: bool,
        
        /// security level for secure implementation testing
        #[arg(long = "security-level", default_value = "balanced")]
        security_level: SecurityLevel,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum AttackScenarioArg {
    /// run all attack scenarios
    Comprehensive,
    /// files with differences at different positions
    EarlyVsLate,
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

impl AttackScenarioArg {
    fn to_attack_scenario(&self) -> Option<AttackScenario> {
        match self {
            AttackScenarioArg::Comprehensive => None, // special case
            AttackScenarioArg::EarlyVsLate => Some(AttackScenario::EarlyVsLateChanges),
            AttackScenarioArg::IdenticalVsDifferent => Some(AttackScenario::IdenticalVsDifferent),
            AttackScenarioArg::SimilarityGradient => Some(AttackScenario::SimilarityGradient),
            AttackScenarioArg::ChangeSize => Some(AttackScenario::ChangeSize),
            AttackScenarioArg::VersionControl => Some(AttackScenario::VersionControl),
            AttackScenarioArg::CodeReview => Some(AttackScenario::CodeReview),
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum SecurityLevel {
    /// maximum security with timing attack resistance
    Maximum,
    /// balanced performance and security
    Balanced,
    /// performance optimized with basic security
    Fast,
}

impl SecurityLevel {
    fn to_config(&self, max_size: Option<usize>) -> SecurityConfig {
        match self {
            SecurityLevel::Maximum => {
                let mut config = SecurityConfig::maximum_security();
                if let Some(size) = max_size {
                    config.max_input_size = size * 1024;
                }
                // adjust computation limit based on actual padding size
                if let Some(pad_size) = config.padding_size {
                    config.max_edit_distance = Some((pad_size * 2).max(1024));
                }
                config
            }
            SecurityLevel::Balanced => {
                let mut config = SecurityConfig::balanced();
                if let Some(size) = max_size {
                    config.max_input_size = size * 1024;
                }
                config
            }
            SecurityLevel::Fast => SecurityConfig {
                max_input_size: max_size.map(|s| s * 1024).unwrap_or(1024 * 1024), // 1mb default
                pad_inputs: false,
                padding_size: None,
                validate_inputs: false,
                max_edit_distance: None,
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    
    let result = match &cli.command {
        Some(Commands::AttackDemo { 
            scenario, 
            iterations, 
            file1, 
            file2, 
            output_file, 
            csv_output, 
            security_level 
        }) => {
            run_attack_demo(scenario, *iterations, file1.as_ref(), file2.as_ref(), 
                          output_file.as_ref(), *csv_output, security_level)
        }
        None => {
            // backwards compatibility - run diff if files provided
            if let (Some(file1), Some(file2)) = (&cli.file1, &cli.file2) {
                run_diff(&cli, file1, file2)
            } else {
                eprintln!("ctdiff: missing file arguments. Use --help for usage information.");
                std::process::exit(2);
            }
        }
    };
    
    match result {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(e) => {
            eprintln!("ctdiff: {}", e);
            std::process::exit(2);
        }
    }
}

fn run_diff(cli: &Cli, file1: &PathBuf, file2: &PathBuf) -> Result<i32, Box<dyn std::error::Error>> {
    // read input files
    let file1_data = read_file(file1)?;
    let file2_data = read_file(file2)?;
    
    // check for security warnings
    if !cli.force {
        check_security_warnings(&file1_data, &file2_data, &cli.security_level)?;
    }
    
    // configure diff algorithm  
    let mut config = cli.security_level.to_config(cli.max_size);
    
    // if force flag is used, increase limits to accommodate larger files
    if cli.force {
        config.max_input_size = file1_data.len().max(file2_data.len()).max(config.max_input_size);
        config.max_edit_distance = None; // remove computation limits when forced
    }
    
    let differ = ConstantTimeDiff::new(config);
    
    // perform diff with timing measurement
    let start_time = Instant::now();
    let result = differ.diff(&file1_data, &file2_data).map_err(|e| format!("diff failed: {}", e))?;
    let elapsed = start_time.elapsed();
    
    // check if files are identical
    let files_identical = result.edit_distance == 0;
    
    if !cli.quiet {
        // format and display output
        let formatter = DiffFormatter::new(cli.format.clone(), cli.color, cli.context);
        let output = formatter.format_diff(
            &file1.display().to_string(),
            &file2.display().to_string(),
            &file1_data,
            &file2_data,
            &result,
        )?;
        
        print!("{}", output);
        
        // show timing information if requested
        if cli.show_timing {
            eprintln!("\ntiming: {:?} (constant-time guarantee: {})", 
                elapsed, 
                match cli.security_level {
                    SecurityLevel::Maximum => "strong",
                    SecurityLevel::Balanced => "moderate", 
                    SecurityLevel::Fast => "basic",
                });
        }
    }
    
    // return appropriate exit code
    Ok(if files_identical { 0 } else { 1 })
}

fn read_file(path: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fs::read(path).map_err(|e| format!("failed to read {}: {}", path.display(), e).into())
}

fn check_security_warnings(file1: &[u8], file2: &[u8], security_level: &SecurityLevel) -> Result<(), Box<dyn std::error::Error>> {
    let max_size = match security_level {
        SecurityLevel::Maximum => 4 * 1024,
        SecurityLevel::Balanced => 256 * 1024, 
        SecurityLevel::Fast => 1024 * 1024,
    };
    
    if file1.len() > max_size || file2.len() > max_size {
        let warning = format!(
            "warning: file size {} exceeds recommended limit {} for security level {:?}\n\
             large files may be vulnerable to timing attacks. use --force to continue.",
            file1.len().max(file2.len()),
            max_size,
            security_level
        );
        return Err(warning.into());
    }
    
    Ok(())
}

fn run_attack_demo(
    scenario: &AttackScenarioArg,
    iterations: usize,
    file1: Option<&PathBuf>,
    file2: Option<&PathBuf>,
    output_file: Option<&PathBuf>,
    csv_output: bool,
    security_level: &SecurityLevel,
) -> Result<i32, Box<dyn std::error::Error>> {
    println!("🚨 TIMING ATTACK DEMONSTRATION");
    println!("This tool demonstrates timing vulnerabilities for educational purposes.");
    println!("The vulnerable implementation should NEVER be used in production!\n");
    
    // create attack simulator with specified security level
    let config = security_level.to_config(None);
    let mut simulator = AttackSimulator::with_security_config(config.clone());
    
    let report = match scenario {
        AttackScenarioArg::Comprehensive => {
            println!("Running comprehensive timing attack analysis...");
            simulator.generate_summary_report(iterations)
        }
        _ => {
            if let Some(attack_scenario) = scenario.to_attack_scenario() {
                println!("Running {} scenario...", attack_scenario.description());
                let results = simulator.simulate_attack(attack_scenario, iterations);
                results.format_report()
            } else {
                return Err("Invalid attack scenario".into());
            }
        }
    };
    
    println!("{}", report);
    
    // handle file output
    if let Some(output_path) = output_file {
        std::fs::write(output_path, &report)?;
        println!("Detailed report saved to: {}", output_path.display());
    }
    
    // handle CSV export
    if csv_output {
        let measurements = simulator.get_measurements();
        let csv_path = "timing_data.csv";
        let mut csv_file = std::fs::File::create(csv_path)?;
        ctdiff::timing::export::to_csv(measurements, &mut csv_file)?;
        println!("Timing data exported to: {}", csv_path);
    }
    
    // handle custom file inputs
    if let (Some(file1_path), Some(file2_path)) = (file1, file2) {
        println!("\n=== CUSTOM FILE ANALYSIS ===");
        
        let file1_data = read_file(file1_path)?;
        let file2_data = read_file(file2_path)?;
        
        // measure both implementations on custom files
        use ctdiff::timing::PrecisionTimer;
        use ctdiff::vulnerable::VulnerableDiff;
        
        let mut timer = PrecisionTimer::new();
        let vulnerable_diff = VulnerableDiff::new();
        let secure_diff = ctdiff::ConstantTimeDiff::new(config);
        
        // measure vulnerable implementation
        let vulnerable_times: Vec<_> = (0..iterations).map(|i| {
            let (_, measurement) = timer.measure(format!("vulnerable_{}", i), || {
                vulnerable_diff.diff(&file1_data, &file2_data).unwrap()
            });
            measurement
        }).collect();
        
        // measure secure implementation
        let secure_times: Vec<_> = (0..iterations).map(|i| {
            let (_, measurement) = timer.measure(format!("secure_{}", i), || {
                secure_diff.diff(&file1_data, &file2_data).unwrap()
            });
            measurement
        }).collect();
        
        // analyze results
        if let (Some(vuln_stats), Some(secure_stats)) = (
            ctdiff::timing::TimingStatistics::from_measurements(&vulnerable_times),
            ctdiff::timing::TimingStatistics::from_measurements(&secure_times)
        ) {
            let comparison = ctdiff::timing::TimingComparison::new(
                "vulnerable_custom".to_string(),
                vuln_stats,
                "secure_custom".to_string(),
                secure_stats,
                0.05,
            );
            
            println!("Custom file timing analysis:");
            println!("{}", comparison.format_summary());
            
            if comparison.significant_difference {
                println!("⚠️  Files show significant timing differences - vulnerable to attack!");
            } else {
                println!("✅ Files show no significant timing differences");
            }
        }
    }
    
    Ok(0)
}