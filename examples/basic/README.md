# Basic examples 

## Text files
### Basic comparison - lorem ipsum text with line differences
```bash
ctdiff basic/file1.txt basic/file2.txt
```

### Timing consistency test - identical structure with end-only differences
```bash
ctdiff --security-level maximum --show-timing basic/timing_test_1.txt basic/timing_test_2.txt
```

### Document versions
```bash
ctdiff basic/document_draft_v1.txt basic/document_draft_v2.txt
```

## Binary files
```bash
ctdiff basic/binary1.bin basic/binary2.bin
```

## Output formats
```bash
# different ways to view diffs
ctdiff --color basic/file1.txt basic/file2.txt
ctdiff --new-format json basic/file1.txt basic/file2.txt
ctdiff --new-format html --output diff.html basic/file1.txt basic/file2.txt
```

## Next Steps
- `security/`: timing attack examples
- `library/`: Rust API usage
- `tools/`: demo scripts