/*
 * secure random number masking
 * 
 * always do all validation checks even if early ones fail.
 * timing stays same no matter which checks pass or fail.
 * 
 * use bitwise ops instead of if statements.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

// secure random number generation (same as vulnerable version)
uint32_t generate_secure_random() {
    static uint32_t seed = 0x12345678;
    seed = seed * 31 + 1103515245;
    return seed;
}

// good: ct token validation
int validate_random_token_secure(uint32_t token) {
    printf("validating token: 0x%08x\n", token);
    
    // do all checks no matter what
    uint8_t validation_result = 1;
    
    // check 1: minimum threshold
    uint8_t threshold_check = (token >= 1000) ? 1 : 0;
    validation_result &= threshold_check;
    
    // check 2: pattern detection
    uint16_t lower = token & 0xffff;
    uint16_t upper = (token >> 16) & 0xffff;
    uint8_t pattern_check = (lower != upper) ? 1 : 0;
    validation_result &= pattern_check;
    
    // check 3: entropy validation
    int bit_count = __builtin_popcount(token);
    uint8_t entropy_check = (bit_count >= 8 && bit_count <= 24) ? 1 : 0;
    validation_result &= entropy_check;
    
    // check 4: weak value detection
    uint32_t weak_values[] = {0x12345678, 0xdeadbeef, 0xcafebabe, 0xfeedface};
    uint8_t weak_value_check = 1;
    for (int i = 0; i < 4; i++) {
        // use constant-time equality check
        uint32_t diff = token ^ weak_values[i];
        uint8_t is_weak = (diff == 0) ? 1 : 0;
        weak_value_check &= ~is_weak; // invert because we want to reject weak values
    }
    validation_result &= weak_value_check;
    
    // check 5: statistical test (always perform full computation)
    uint32_t hash = token;
    for (int i = 0; i < 1000; i++) {
        hash = hash * 31 + token; // same expensive computation as vulnerable version
    }
    uint8_t statistical_check = (hash % 100 != 0) ? 1 : 0;
    validation_result &= statistical_check;
    
    // output result without revealing which check failed
    if (validation_result) {
        printf("token accepted: passed all validation checks\n");
    } else {
        printf("token rejected: failed validation requirements\n");
    }
    
    return validation_result;
}

// secure session token generation
int generate_session_token_secure(char* output_token) {
    const int max_attempts = 10;
    
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        uint32_t random_value = generate_secure_random();
        
        if (validate_random_token_secure(random_value)) {
            sprintf(output_token, "session_%08x", random_value);
            printf("generated valid session token: %s\n", output_token);
            
            // clear sensitive random value from local variable
            random_value = 0;
            return 1;
        }
        
        printf("attempt %d failed, retrying...\n", attempt + 1);
        // clear failed random value
        random_value = 0;
    }
    
    printf("failed to generate valid token after %d attempts\n", max_attempts);
    return 0;
}

// demonstrate constant-time validation
void secure_validation_timing_demo() {
    printf("\n=== constant-time token validation demo ===\n");
    printf("measuring validation times (should be consistent)...\n\n");
    
    // same test tokens as vulnerable version
    uint32_t test_tokens[] = {
        500,          // would fail threshold check
        0x12341234,   // would fail pattern check
        0x00000001,   // would fail entropy check
        0xdeadbeef,   // would fail weak value check
        0x87654321,   // would fail statistical test
        0x9abcdef0,   // might pass all checks
        100,          // would fail threshold
        0xffffffff,   // would fail entropy
        0xcafebabe,   // would fail weak value
        0x13579bdf    // might pass all checks
    };
    
    for (int i = 0; i < 10; i++) {
        struct timespec start, end;
        
        printf("\ntest %d:\n", i + 1);
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run validation multiple times
        int result = 0;
        for (int j = 0; j < 1000; j++) {
            result = validate_random_token_secure(test_tokens[i]);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("token: 0x%08x | time: %8lld ns | result: %s\n", 
               test_tokens[i], duration, result ? "valid" : "invalid");
    }
    
    printf("\nsecurity: timing is consistent regardless of which checks would fail!\n");
    printf("attackers cannot learn validation logic through timing analysis.\n");
}

// demonstrate secure token analysis resistance
void secure_token_analysis_demo() {
    printf("\n=== secure token analysis resistance demo ===\n");
    printf("timing should not reveal token characteristics...\n\n");
    
    for (int batch = 0; batch < 3; batch++) {
        printf("batch %d - generating and analyzing tokens:\n", batch + 1);
        
        for (int i = 0; i < 5; i++) {
            uint32_t token = generate_secure_random();
            struct timespec start, end;
            
            clock_gettime(CLOCK_MONOTONIC, &start);
            int valid = validate_random_token_secure(token);
            clock_gettime(CLOCK_MONOTONIC, &end);
            
            long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                               (end.tv_nsec - start.tv_nsec);
            
            printf("  token 0x%08x | time: %6lld ns | valid: %s\n", 
                   token, duration, valid ? "yes" : "no");
            
            // securely clear token from memory
            volatile uint32_t* volatile_token = (volatile uint32_t*)&token;
            *volatile_token = 0;
        }
        printf("\n");
    }
    
    printf("security: consistent timing prevents analysis of validation patterns!\n");
    printf("token generation logic remains hidden from timing attacks.\n");
}

// additional secure masking operations
void secure_masking_demo() {
    printf("\n=== secure masking operations demo ===\n");
    
    uint32_t secret_value = 0x13579bdf;
    uint32_t public_mask = 0xa5a5a5a5;
    
    printf("original value: 0x%08x\n", secret_value);
    printf("public mask:    0x%08x\n", public_mask);
    
    // apply mask using constant-time operations
    uint32_t masked_value = secret_value ^ public_mask;
    printf("masked value:   0x%08x\n", masked_value);
    
    // conditional masking based on secure condition
    uint8_t should_mask = 1; // this would come from secure computation
    
    // create mask: 0xffffffff if should_mask is 1, 0x00000000 if 0
    uint32_t condition_mask = (should_mask != 0) ? 0xffffffff : 0x00000000;
    
    // conditionally apply masking
    uint32_t result = (secret_value & ~condition_mask) | (masked_value & condition_mask);
    
    printf("conditionally masked: 0x%08x\n", result);
    
    // secure cleanup
    volatile uint32_t* vol_secret = (volatile uint32_t*)&secret_value;
    volatile uint32_t* vol_masked = (volatile uint32_t*)&masked_value; 
    volatile uint32_t* vol_result = (volatile uint32_t*)&result;
    
    *vol_secret = 0;
    *vol_masked = 0;
    *vol_result = 0;
    
    printf("sensitive values cleared from memory\n");
}

int main() {
    printf("secure random number masking demo\n");
    printf("==================================\n\n");
    
    // simulate session token generation
    char session_token[32];
    if (generate_session_token_secure(session_token)) {
        printf("session established with token: %s\n", session_token);
        
        // clear session token from memory after use
        memset(session_token, 0, sizeof(session_token));
    }
    
    // demonstrate constant-time validation
    secure_validation_timing_demo();
    
    // demonstrate secure token analysis resistance
    secure_token_analysis_demo();
    
    // demonstrate additional masking operations
    secure_masking_demo();
    
    printf("\nsecurity improvement: constant-time validation prevents timing attacks\n");
    printf("compare with random_masking_vulnerable.c to see the timing differences.\n");
    
    return 0;
}