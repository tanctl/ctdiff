/*
 * vulnerable random number masking
 * 
 * bunch of validation checks that bail out early.
 * timing tells you which check failed.
 * 
 * if random number is tiny: fails fast on first check
 * if it has bad pattern: fails on second check  
 * if it matches weak value: fails slow on fourth check
 * 
 * seen in token generators, nonce validation, gaming systems
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

// simulate secure random number generation
uint32_t generate_secure_random() {
    // in real code, this would use /dev/urandom or similar
    // for demonstration, we'll use a simple PRNG
    static uint32_t seed = 0x12345678;
    seed = seed * 1103515245 + 12345;
    return seed;
}

// bad: exits early on each validation step
int validate_random_token_vulnerable(uint32_t token) {
    printf("validating token: 0x%08x\n", token);
    
    // first check: big enough?
    if (token < 1000) {
        printf("token rejected: below minimum threshold\n");
        return 0; // bails out fast
    }
    
    // check 2: must not be too predictable (avoid sequential patterns)
    if ((token & 0xffff) == ((token >> 16) & 0xffff)) {
        printf("token rejected: predictable pattern detected\n");
        return 0; // early exit - fast
    }
    
    // check 3: must have sufficient entropy (hamming weight check)
    int bit_count = __builtin_popcount(token);
    if (bit_count < 8 || bit_count > 24) {
        printf("token rejected: insufficient entropy\n");
        return 0; // early exit - medium speed
    }
    
    // check 4: must not match known weak values
    uint32_t weak_values[] = {0x12345678, 0xdeadbeef, 0xcafebabe, 0xfeedface};
    for (int i = 0; i < 4; i++) {
        if (token == weak_values[i]) {
            printf("token rejected: matches known weak value\n");
            return 0; // early exit - slow (depends on position)
        }
    }
    
    // check 5: expensive validation for tokens that pass initial checks
    uint32_t hash = token;
    for (int i = 0; i < 1000; i++) {
        hash = hash * 31 + token; // expensive computation
    }
    
    if (hash % 100 == 0) {
        printf("token rejected: failed statistical test\n");
        return 0; // slow rejection after expensive computation
    }
    
    printf("token accepted: passed all validation checks\n");
    return 1; // slowest path - all checks completed
}

// simulate session token generation with vulnerable validation
int generate_session_token_vulnerable(char* output_token) {
    const int max_attempts = 10;
    
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        uint32_t random_value = generate_secure_random();
        
        if (validate_random_token_vulnerable(random_value)) {
            sprintf(output_token, "session_%08x", random_value);
            printf("generated valid session token: %s\n", output_token);
            return 1;
        }
        printf("attempt %d failed, retrying...\n", attempt + 1);
    }
    
    printf("failed to generate valid token after %d attempts\n", max_attempts);
    return 0;
}

// demonstrate timing differences based on validation path
void validation_timing_demo() {
    printf("\n=== random token validation timing demo ===\n");
    printf("measuring validation times for different token characteristics...\n\n");
    
    // test tokens that fail at different validation stages
    uint32_t test_tokens[] = {
        500,          // fails threshold check (very fast)
        0x12341234,   // fails pattern check (fast)
        0x00000001,   // fails entropy check (medium)
        0xdeadbeef,   // fails weak value check (slow)
        0x87654321,   // passes most checks but fails final stat test
        0x9abcdef0,   // passes all checks (slowest)
        100,          // fails threshold (very fast)
        0xffffffff,   // fails entropy (medium)
        0xcafebabe,   // fails weak value (slow)
        0x13579bdf    // might pass all checks
    };
    
    for (int i = 0; i < 10; i++) {
        struct timespec start, end;
        
        printf("\ntest %d:\n", i + 1);
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run validation multiple times to amplify timing differences
        int result = 0;
        for (int j = 0; j < 1000; j++) {
            result = validate_random_token_vulnerable(test_tokens[i]);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("token: 0x%08x | time: %8lld ns | result: %s\n", 
               test_tokens[i], duration, result ? "valid" : "invalid");
    }
    
    printf("\nvulnerability: timing reveals which validation stage failed!\n");
    printf("attackers can learn about token generation patterns and requirements.\n");
}

// demonstrate information leakage through timing patterns
void token_analysis_demo() {
    printf("\n=== token analysis through timing demo ===\n");
    printf("analyzing token characteristics through validation timing...\n\n");
    
    // generate multiple tokens and analyze timing patterns
    for (int batch = 0; batch < 3; batch++) {
        printf("batch %d - generating and analyzing tokens:\n", batch + 1);
        
        for (int i = 0; i < 5; i++) {
            uint32_t token = generate_secure_random();
            struct timespec start, end;
            
            clock_gettime(CLOCK_MONOTONIC, &start);
            int valid = validate_random_token_vulnerable(token);
            clock_gettime(CLOCK_MONOTONIC, &end);
            
            long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                               (end.tv_nsec - start.tv_nsec);
            
            printf("  token 0x%08x | time: %6lld ns | valid: %s\n", 
                   token, duration, valid ? "yes" : "no");
        }
        printf("\n");
    }
    
    printf("vulnerability: consistent timing patterns reveal token generation logic!\n");
    printf("attackers can infer validation rules and generate tokens more efficiently.\n");
}

int main() {
    printf("vulnerable random number masking demo\n");
    printf("=====================================\n\n");
    
    // simulate session token generation
    char session_token[32];
    if (generate_session_token_vulnerable(session_token)) {
        printf("session established with token: %s\n", session_token);
    }
    
    // demonstrate timing-based validation analysis
    validation_timing_demo();
    
    // demonstrate token analysis through timing
    token_analysis_demo();
    
    printf("\nto fix this vulnerability, use constant-time validation!\n");
    printf("see random_masking_secure.c for the safe implementation.\n");
    
    return 0;
}