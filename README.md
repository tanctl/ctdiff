# ctdiff
`ctdiff` implements a constant-time diff algorithm based on a modified Myers algorithm. Unlike traditional diff tools, it maintains consistent execution time regardless of file content patterns, preventing timing-based side-channel attacks.

## Key Features
- **Timing Attack Resistance**: Execution time depends only on file sizes, not content differences
- **Multiple Security Levels**: Configurable security/performance trade-offs
- **Familiar Output**: Unix diff-compatible output formats
- **Binary File Support**: Secure comparison of non-text files
- **Cryptographic Quality**: Uses the `subtle` crate for constant-time operations

## Installation

### Install from Git [Recommended]
```
cargo install --git https://github.com/tanctl/ctdiff
```

### Building From Source
```bash
git clone https://github.com/tanctl/ctdiff
cd ctdiff
cargo build --release
```
The binary will be available at `target/release/ctdiff or you can install it with:
```shell
cargo install --path host
```

## Usage

### Basic Comparison
```bash
ctdiff file1.txt file2.txt
```

### Security Options
```bash
# Maximum security (strongest timing protection)
ctdiff --security-level maximum file1.txt file2.txt

# Balanced performance and security
ctdiff --security-level balanced file1.txt file2.txt

# Performance optimized with basic security
ctdiff --security-level fast file1.txt file2.txt
```

### Output Formats
```bash
# Unified diff (default, legacy format)
ctdiff file1.txt file2.txt

# Side-by-side comparison (legacy)
ctdiff --format side-by-side file1.txt file2.txt

# New format system with enhanced features
ctdiff --new-format json file1.txt file2.txt          # Structured JSON
ctdiff --new-format html file1.txt file2.txt          # Web-friendly HTML
ctdiff --new-format git file1.txt file2.txt           # Git-compatible patches
ctdiff --new-format summary file1.txt file2.txt       # Statistics summary

# Output to files
ctdiff --new-format html --output diff.html file1.txt file2.txt
```

### Additional Options
```bash
# Colored output
ctdiff --color file1.txt file2.txt

# Show timing information
ctdiff --show-timing file1.txt file2.txt

# Quiet mode (exit code only)
ctdiff --quiet file1.txt file2.txt

# Set maximum file size (in KB)
ctdiff --max-size 1024 file1.txt file2.txt

# Force processing despite security warnings
ctdiff --force large_file1.txt large_file2.txt
```

## Exit Codes
- `0`: Files are identical
- `1`: Files differ
- `2`: Error occurred (missing files, security limits exceeded, etc.)

## Security Levels

### Maximum Security
- Strongest timing attack resistance
- Input padding and size normalization
- Strict size limits (4KB default)
- Best for highly sensitive environments
### Balanced (Default)
- Good security with reasonable performance  
- Moderate size limits (256KB default)
- No input padding overhead
- Suitable for most applications
### Fast
- Basic security guarantees
- Larger size limits (1MB default)
- Optimized for performance
- For less sensitive use cases

## Examples
- **[`basic/`](examples/basic/README.md)** - Basic examples to understand ctdiff cli options and basic functionality.
- **[`security/`](examples/security/README.md)** - Timing attack examples and constant-time programming patterns.
- **[`library/`](examples/library/README.md)** - Rust API usage examples
- **[`tools/`](examples/tools/README.md)** - Demo scripts and utilities for automated testing.


## Security Considerations

### Why Constant-Time?
Traditional diff algorithms can leak information through execution time:
- Files with early differences may be processed faster
- Identical files might take different time than completely different ones
- Content patterns can influence algorithm performance

### When to Use ctdiff
- **Version Control**: Comparing sensitive source code
- **Document Systems**: Secure document comparison
- **Cryptographic Applications**: Any scenario where file content confidentiality matters
- **High-Security Environments**: Where side-channel resistance is required

### Limitations
- Performance trade-off for security guarantees
- Memory usage proportional to file size squared (O(m×n))
- Not suitable for very large files without careful configuration

## Algorithm Details
`ctdiff` uses a modified Myers diff algorithm with these security enhancements:
1. **Constant-Time Operations**: All comparisons use cryptographic primitives from the `subtle` crate
2. **Oblivious Memory Access**: Memory access patterns don't depend on file content
3. **No Early Termination**: Algorithm always completes full computation
4. **Uniform Branching**: No content-dependent conditional branches

## Library Usage
`ctdiff` provides a powerful library API for Rust applications:

### Quick Start
```rust
use ctdiff::{DiffBuilder, SecurityLevel, OutputFormat};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a diff builder with desired configuration
    let diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .output_format(OutputFormat::Unified)
        .context_lines(3)
        .color(true)
        .build()?;
    
    // compare two strings
    let result = diff.compare_text("hello world", "hello rust")?;
    
    // get information about the diff
    println!("Edit Distance: {}", result.edit_distance());
    println!("Similarity: {:.1}%", result.similarity() * 100.0);
    println!("Identical: {}", result.is_identical());
    
    // format output
    let formatted = result.format()?;
    println!("{}", formatted);
    
    Ok(())
}
```

### Multiple Output Formats

```rust
use ctdiff::{DiffBuilder, OutputFormat};

// JSON output for APIs
let json_diff = DiffBuilder::new()
    .output_format(OutputFormat::Json)
    .build()?;

let result = json_diff.compare_text("old", "new")?;
let json_output = result.format()?;

// HTML output for web applications
let html_diff = DiffBuilder::new()
    .output_format(OutputFormat::Html)
    .build()?;

let result = html_diff.compare_text("old", "new")?;
let html_output = result.format()?;

// summary for monitoring
let summary_diff = DiffBuilder::new()
    .output_format(OutputFormat::Summary)
    .build()?;

let result = summary_diff.compare_text("old", "new")?;
println!("{}", result.format()?);
```

### File Comparison
```rust
use ctdiff::{DiffBuilder, SecurityLevel};

let diff = DiffBuilder::new()
    .security_level(SecurityLevel::Maximum)
    .max_file_size(64 * 1024) // 64KB limit
    .build()?;

// compare files directly
let result = diff.compare_files("file1.txt", "file2.txt")?;
println!("Files differ by {} operations", result.edit_distance());

// detailed statistics
let stats = result.statistics();
println!("Insertions: {}", stats.insertions);
println!("Deletions: {}", stats.deletions);
println!("Similarity: {:.2}%", stats.similarity * 100.0);
```

### Security Configuration
```rust
use ctdiff::security::{SecurityConfig, TimingProtection};

// custom security configuration
let custom_config = SecurityConfig {
    max_input_size: 1024,
    pad_inputs: true,
    padding_size: Some(2048),
    validate_inputs: true,
    max_edit_distance: Some(512),
    memory_protection: true,
    timing_protection: TimingProtection::Strict,
};

// validaye configuration before use
custom_config.validate()?;

let diff = DiffBuilder::new()
    .security_config(custom_config)
    .build()?;
```

### Error Handling
```rust
use ctdiff::{DiffBuilder, Error};

match diff.compare_files("file1.txt", "file2.txt") {
    Ok(result) => {
        println!("Edit distance: {}", result.edit_distance());
    }
    Err(Error::Security { message }) => {
        eprintln!("Security violation: {}", message);
    }
    Err(Error::Io(io_err)) => {
        eprintln!("File I/O error: {}", io_err);
    }
    Err(Error::ResourceLimit { message }) => {
        eprintln!("Resource limit exceeded: {}", message);
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

### Integration Examples
See the `examples/library/` directory for comprehensive examples:
- **`basic_usage.rs`** - Fundamental library operations
- **`performance_comparison.rs`** - Performance benchmarks across security levels
- **`security_demo.rs`** - Security features and best practices
- **`integration_examples.rs`** - Real-world integration scenarios

## Testing
Run the test suite:
```bash
# unit tests
cargo test

# integration tests including cli
cargo test --test cli

# property-based tests
cargo test --features proptest
```

## License
GPL v3 - see LICENSE file for details.