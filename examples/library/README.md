# Library examples

Rust examples showing how to use ctdiff as a library in applications.

## Examples Overview

### 1. `basic_usage.rs`
Demonstrates fundamental library usage including:
- Simple text comparison
- File comparison
- Different security levels
- Multiple output formats

**Run with:**
```bash
cargo run --example basic_usage
```

### 2. `performance_comparison.rs`
Benchmarks and compares performance across:
- Different security levels (Maximum, Balanced, Fast)
- Various input sizes
- Different output formats

**Run with:**
```bash
cargo run --example performance_comparison
```

### 3. `security_demo.rs`
Showcases security features and best practices:
- Built-in security levels overview
- Custom security configurations
- Security validation
- Secure file handling practices

**Run with:**
```bash
cargo run --example security_demo
```

### 4. `integration_examples.rs`
Real-world integration scenarios:
- Web service integration with JSON API
- Automated testing with similarity thresholds
- Version control integration with Git patches
- Monitoring and logging for configuration changes

**Run with:**
```bash
cargo run --example integration_examples
```

## Quick Start

```rust
use ctdiff::{DiffBuilder, SecurityLevel, OutputFormat};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a diff builder with desired configuration
    let diff = DiffBuilder::new()
        .security_level(SecurityLevel::Balanced)
        .output_format(OutputFormat::Unified)
        .context_lines(3)
        .color(true)
        .build()?;
    
    // Compare two strings
    let result = diff.compare_text("hello world", "hello rust")?;
    
    // Get information about the diff
    println!("Edit Distance: {}", result.edit_distance());
    println!("Similarity: {:.1}%", result.similarity() * 100.0);
    println!("Identical: {}", result.is_identical());
    
    // Format output
    let formatted = result.format()?;
    println!("{}", formatted);
    
    Ok(())
}
```

## Security Levels

### Maximum Security
- **Use case**: Classified or highly sensitive data
- **Features**: Strongest timing attack resistance, memory padding, strict validation
- **Recommended limit**: 4KB files

### Balanced Security (Default)
- **Use case**: General secure applications
- **Features**: Good timing protection with reasonable performance
- **Recommended limit**: 256KB files

### Fast Mode
- **Use case**: Non-sensitive data, development, testing
- **Features**: Minimal security overhead, basic validation
- **Recommended limit**: 1MB+ files

## Output Formats

| Format    | Description            | Use Case                      |
| --------- | ---------------------- | ----------------------------- |
| `Unified` | Standard unified diff  | Human-readable diffs, patches |
| `Json`    | Structured JSON        | APIs, automated processing    |
| `Html`    | Web-friendly HTML      | Browser viewing, reports      |
| `Git`     | Git-compatible patches | Version control integration   |
| `Summary` | High-level statistics  | Monitoring, quick overview    |
## Common Integration Patterns

### Web Service
```rust
let diff = DiffBuilder::new()
    .security_level(SecurityLevel::Balanced)
    .output_format(OutputFormat::Json)
    .max_file_size(64 * 1024) // 64KB limit for web requests
    .build()?;
```

### Testing Framework
```rust
let diff = DiffBuilder::new()
    .security_level(SecurityLevel::Fast) // Speed for testing
    .output_format(OutputFormat::Summary)
    .build()?;
```

### Version Control
```rust
let diff = DiffBuilder::new()
    .security_level(SecurityLevel::Balanced)
    .output_format(OutputFormat::Git)
    .context_lines(3)
    .build()?;
```

### Configuration Monitoring
```rust
let diff = DiffBuilder::new()
    .security_level(SecurityLevel::Balanced)
    .output_format(OutputFormat::Json)
    .build()?;
```

## Error Handling

The library uses a comprehensive error system with specific error types:
```rust
use ctdiff::Error;

match diff.compare_files("file1.txt", "file2.txt") {
    Ok(result) => {
        // Handle successful diff
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

## Async Support
When the `async` feature is enabled:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let diff = DiffBuilder::new().build()?;
    let result = diff.compare_files_async("file1.txt", "file2.txt").await?;
    println!("Edit distance: {}", result.edit_distance());
    Ok(())
}
```

## Performance Notes
- **Maximum security**: 2-5x slower than fast mode, but provides strongest guarantees
- **Balanced**: 1.5-2x slower than fast mode, good for most applications
- **Fast mode**: Fastest, suitable for non-sensitive data
- **Output formats**: JSON and HTML generation add ~10-20% overhead
- **File I/O**: Async operations recommended for large files