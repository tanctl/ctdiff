//! integration tests for ctdiff command-line interface
//! 
//! tests cli functionality, error handling, and output formatting
//! using real file inputs and command execution.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--help");
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("constant-time diff tool"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--version");
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn test_identical_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "hello world\n").unwrap();
    fs::write(&file2, "hello world\n").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(0) // exit code 0 for identical files
        .stdout(predicate::str::contains("---"))
        .stdout(predicate::str::contains("+++"));
}

#[test]
fn test_different_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "hello world\n").unwrap();
    fs::write(&file2, "hello universe\n").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(1) // exit code 1 for different files
        .stdout(predicate::str::contains("---"))
        .stdout(predicate::str::contains("+++"));
}

#[test]
fn test_colored_output() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "line1\nline2\n").unwrap();
    fs::write(&file2, "line1\nchanged\n").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--color").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("---"))
        .stdout(predicate::str::contains("+++"));
}

#[test]
fn test_quiet_mode() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "hello\n").unwrap();
    fs::write(&file2, "world\n").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--quiet").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_operations_format() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "abc").unwrap();
    fs::write(&file2, "abd").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--format").arg("operations").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("edit distance:"))
        .stdout(predicate::str::contains("operations:"));
}

#[test]
fn test_minimal_format() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "same").unwrap();
    fs::write(&file2, "same").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--format").arg("minimal").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(0)
        .stdout(predicate::str::contains("files identical"));
}

#[test]
fn test_minimal_format_different() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "different").unwrap();
    fs::write(&file2, "content").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--format").arg("minimal").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("files differ"));
}

#[test]
fn test_security_levels() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "ab").unwrap();
    fs::write(&file2, "ac").unwrap(); // small files that fit within all security limits
    
    // test maximum security level
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--security-level").arg("maximum").arg(&file1).arg(&file2);
    cmd.assert().code(1); // files differ, so exit code 1 is expected
    
    // test balanced security level
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--security-level").arg("balanced").arg(&file1).arg(&file2);
    cmd.assert().code(1); // files differ, so exit code 1 is expected
    
    // test fast security level
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--security-level").arg("fast").arg(&file1).arg(&file2);
    cmd.assert().code(1); // files differ, so exit code 1 is expected
}

#[test]
fn test_show_timing() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "timing test").unwrap();
    fs::write(&file2, "timing test").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--show-timing").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(0)
        .stderr(predicate::str::contains("timing:"))
        .stderr(predicate::str::contains("constant-time guarantee:"));
}

#[test]
fn test_max_size_limit() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    // create files larger than 1kb
    let large_content = "x".repeat(2000);
    fs::write(&file1, &large_content).unwrap();
    fs::write(&file2, &large_content).unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--max-size").arg("1").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(2) // error exit code
        .stderr(predicate::str::contains("exceeds limit"));
}

#[test]
fn test_force_flag() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    // create files that would trigger security warning
    let large_content = "x".repeat(2000);
    fs::write(&file1, &large_content).unwrap();
    fs::write(&file2, &large_content).unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--max-size").arg("1").arg("--force").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(0); // should succeed with --force
}

#[test]
fn test_missing_file() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("exists.txt");
    let file2 = temp_dir.path().join("missing.txt");
    
    fs::write(&file1, "content").unwrap();
    // don't create file2
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(2) // error exit code
        .stderr(predicate::str::contains("failed to read"));
}

#[test]
fn test_binary_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("binary1.bin");
    let file2 = temp_dir.path().join("binary2.bin");
    
    fs::write(&file1, &[0x00, 0x01, 0x02, 0xFF]).unwrap();
    fs::write(&file2, &[0x00, 0x01, 0x03, 0xFF]).unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(1) // files are different
        .stdout(predicate::str::contains("---"))
        .stdout(predicate::str::contains("+++"));
}

#[test]
fn test_side_by_side_format() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    
    fs::write(&file1, "left side\ncontent here").unwrap();
    fs::write(&file2, "right side\ncontent here").unwrap();
    
    let mut cmd = Command::cargo_bin("ctdiff").unwrap();
    cmd.arg("--format").arg("side-by-side").arg(&file1).arg(&file2);
    
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("|")); // side-by-side separator
}