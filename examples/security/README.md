# Security Examples

Comprehensive timing attack examples and constant-time programming patterns - shows vulnerable code, secure fixes, and testing methods.
## Examples Included

### 1. Password comparison
- **vulnerable**: `password_comparison_vulnerable.c`
- **secure**: `password_comparison_secure.c`
- **demonstrates**: classic strcmp() timing leak vs constant-time comparison
- **scenario**: login systems, authentication checks

```bash
gcc -o password_vuln password_comparison_vulnerable.c && ./password_vuln
gcc -o password_secure password_comparison_secure.c && ./password_secure
```

### 2. HMAC token validation  
- **vulnerable**: `hmac_token_vulnerable.c`
- **secure**: `hmac_token_secure.c`
- **demonstrates**: memcmp() early exit vs constant-time hmac verification
- **scenario**: jwt tokens, api keys, cryptographic signatures

```bash
gcc -o hmac_vuln hmac_token_vulnerable.c && ./hmac_vuln
gcc -o hmac_secure hmac_token_secure.c && ./hmac_secure
```

### 3. Private key lookup
- **vulnerable**: `key_lookup_vulnerable.c`
- **secure**: `key_lookup_secure.c`
- **demonstrates**: database/array search early returns vs oblivious access
- **scenario**: cryptocurrency wallets, ssl certificates, key management

```bash
gcc -o key_vuln key_lookup_vulnerable.c && ./key_vuln
gcc -o key_secure key_lookup_secure.c && ./key_secure
```

### 4. Random number masking
- **vulnerable**: `random_masking_vulnerable.c`
- **secure**: `random_masking_secure.c`
- **demonstrates**: conditional validation branching vs constant-time checks
- **scenario**: token generation, nonce validation, randomness testing

```bash
gcc -o random_vuln random_masking_vulnerable.c && ./random_vuln
gcc -o random_secure random_masking_secure.c && ./random_secure
```

### 5. Memory zeroization
- **file**: `memory_zeroization.c`
- **demonstrates**: compiler optimization issues vs volatile memory clearing
- **scenario**: clearing passwords, keys, sensitive buffers

```bash
gcc -o memory_zero memory_zeroization.c && ./memory_zero
```

### 6. String prefix matching
- **vulnerable**: `prefix_matching_vulnerable.c`
- **secure**: `prefix_matching_secure.c`
- **demonstrates**: strncmp() early exit vs constant-time prefix checking
- **scenario**: path authorization, api validation, route matching

```bash
gcc -o prefix_vuln prefix_matching_vulnerable.c && ./prefix_vuln
gcc -o prefix_secure prefix_matching_secure.c && ./prefix_secure
```

### 7. Constant-time index lookup
- **file**: `index_lookup_patterns.c`
- **demonstrates**: various constant-time array operations and selection
- **scenario**: table lookups, array access, conditional selection

```bash
gcc -o index_lookup index_lookup_patterns.c && ./index_lookup
```

### 8. Statistical timing analysis
- **file**: `statistical_timing_test.c`
- **demonstrates**: t-tests and histograms to validate ct properties
- **scenario**: test if ct code works

```bash
make stats_test && ./stats_test
```

### 9. Parsing vulnerabilities
- **file**: `parsing_vulnerabilities.c`
- **demonstrates**: timing leaks in length-prefixed and tlv parsers
- **scenario**: network protocols, file formats, data serialization

```bash
gcc -o parsing_vulns parsing_vulnerabilities.c && ./parsing_vulns
```

## Timing test files
these files demonstrate specific attack scenarios:

### Early vs late positioning
- **`early_vs_late_1.txt`** / **`early_vs_late_2.txt`** - differences at different positions
- shows how timing reveals where changes occur in files

### Similarity detection  
- **`similar_files.txt`** / **`different_files.txt`** - varying degrees of similarity
- demonstrates timing-based similarity inference

### Version control examples
- **`version_control_old.py`** / **`version_control_new.py`** - python code changes
- realistic version control diff scenarios

## Common vulnerability patterns

### Early returns
```c
// bad: bails out on first difference
for (int i = 0; i < len; i++) {
    if (a[i] != b[i]) return 0;  // timing leak!
}

// good: always check everything
uint8_t result = 0;
for (int i = 0; i < len; i++) {
    result |= a[i] ^ b[i];  // pile up differences
}
return result == 0;
```

### Conditional branches on secrets
```c
// bad: different code paths
if (secret_byte == target) {
    return process_match();    // fast
} else {
    return process_mismatch(); // slow
}

// good: use bit masks instead
uint8_t mask = (secret_byte == target) ? 0xff : 0x00;
result = (match_value & mask) | (mismatch_value & ~mask);
```

### Variable-length operations
```c
// bad: loop depends on secret length
for (int i = 0; i < strlen(secret); i++) {
    // timing reveals length
}

// good: always do max work
for (int i = 0; i < MAX_LENGTH; i++) {
    // same timing every time
}
```

## Compilation notes
Compile with flags that preserve timing:
```bash
# turn off optimizations that mess with timing
gcc -O0 -fno-builtin-memcmp -fno-builtin-strcmp file.c

# for release builds
gcc -O2 -fno-builtin-memcmp -fno-builtin-strcmp file.c

# link timing libs
gcc -o program file.c -lrt
```