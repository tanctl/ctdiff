#!/bin/bash

# timing attack demonstration script
# shows how ctdiff protects against timing attacks that could leak file information

echo "Ctdiff timing attack demo"
echo "Shows timing vulnerabilities for educational purposes"
echo "=================================================="
echo

# basic timing attack demo
echo "1. Comprehensive attack analysis"
echo "Running all scenarios"
cargo run -- attack-demo --scenario comprehensive --iterations 100
echo

# early vs late changes demonstration
echo "2. Early vs late changes"
echo "Testing position-based timing"
cargo run -- attack-demo --scenario early-vs-late examples/security/early_vs_late_1.txt examples/security/early_vs_late_2.txt --iterations 100
echo

# similar vs different files
echo "3. Similarity detection" 
echo "Testing similarity through timing"
cargo run -- attack-demo --scenario similar-vs-different examples/security/similar_files.txt examples/security/different_files.txt --iterations 100
echo

# version control scenario
echo "4. Version control simulation"
echo "Testing code change timing"
cargo run -- attack-demo --scenario version-control examples/security/version_control_old.py examples/security/version_control_new.py --iterations 75
echo

# use basic examples for code review demo
echo "5. Basic file comparison"
echo "Testing basic examples"
cargo run -- attack-demo --scenario comprehensive examples/basic/file1.txt examples/basic/file2.txt --iterations 75
echo

# export detailed timing data
echo "6. Detailed timing analysis"
echo "Exporting timing data"
cargo run -- attack-demo --scenario comprehensive --iterations 50 --output timing_report.txt --csv
echo "Results saved to timing_report.txt and timing_data.csv"
echo

echo "=================================================="
echo "Demo complete"
echo
echo "Key findings:"
echo "- Vulnerable implementation shows measurable timing differences"
echo "- ctdiff constant-time implementation provides protection"  
echo "- Attack success depends on file characteristics and measurement precision"
echo
echo "See generated reports for more info"