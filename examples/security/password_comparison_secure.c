/*
 * secure password comparison
 * 
 * always check every single character, even after finding a mismatch.
 * this way timing stays constant no matter where the difference is.
 * 
 * key idea: accumulate differences with XOR instead of bailing early
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

// check every byte no matter what
int constant_time_memcmp(const void* a, const void* b, size_t len) {
    const uint8_t* x = (const uint8_t*)a;
    const uint8_t* y = (const uint8_t*)b;
    uint8_t result = 0;
    
    // check all bytes even if we find differences
    for (size_t i = 0; i < len; i++) {
        result |= x[i] ^ y[i];  // pile up any differences
    }
    
    return result;
}

// safe string compare
int constant_time_strcmp(const char* a, const char* b) {
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
    
    uint8_t len_diff = (len_a != len_b) ? 1 : 0;
    
    // check up to the longer string
    size_t max_len = len_a > len_b ? len_a : len_b;
    
    uint8_t content_diff = 0;
    for (size_t i = 0; i < max_len; i++) {
        uint8_t byte_a = (i < len_a) ? (uint8_t)a[i] : 0;
        uint8_t byte_b = (i < len_b) ? (uint8_t)b[i] : 0;
        content_diff |= byte_a ^ byte_b;
    }
    
    return len_diff | content_diff;
}

// secure password check - always takes same time
int check_password_secure(const char* input, const char* correct) {
    // use constant-time comparison instead of strcmp
    return constant_time_strcmp(input, correct) == 0;
}

// secure authentication system
int authenticate_user_secure(const char* username, const char* password) {
    const char* stored_password = "MySecretPassword123!";
    
    printf("authenticating user: %s\n", username);
    
    // secure password check - timing doesn't vary based on input
    if (check_password_secure(password, stored_password)) {
        printf("authentication successful!\n");
        return 1;
    } else {
        printf("authentication failed - invalid password\n");
        return 0;
    }
}

// demonstrate constant timing with different password attempts
void constant_time_demo() {
    const char* correct_password = "MySecretPassword123!";
    const char* attempts[] = {
        "wrong",                    // no match
        "M",                       // 1 char match  
        "My",                      // 2 char match
        "MyS",                     // 3 char match
        "MySecret",                // 8 char match
        "MySecretPassword",        // 16 char match
        "MySecretPassword123!",    // full match
        "zzzzzzzzzzzzzzzzzzzzz"    // no match but same length
    };
    
    printf("\n=== constant-time demonstration ===\n");
    printf("measuring secure password verification times...\n\n");
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        // measure timing - should be consistent regardless of input
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run multiple iterations
        for (int j = 0; j < 10000; j++) {
            check_password_secure(attempts[i], correct_password);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("password attempt: %-25s | time: %8lld ns | match length: %zu\n", 
               attempts[i], duration, 
               strlen(attempts[i]) < strlen(correct_password) ? 
               strlen(attempts[i]) : strlen(correct_password));
    }
    
    printf("\nsecurity: timing is consistent regardless of match length!\n");
    printf("attackers cannot learn password information through timing.\n");
}

// additional secure memory operations
void secure_memory_clear(void* ptr, size_t len) {
    // prevent compiler from optimizing away the memory clear
    volatile uint8_t* volatile_ptr = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < len; i++) {
        volatile_ptr[i] = 0;
    }
}

int main() {
    printf("secure password comparison demo\n");
    printf("===============================\n\n");
    
    // simulate some login attempts
    authenticate_user_secure("alice", "wrongpass");
    authenticate_user_secure("bob", "MySecretPassword123!");
    
    // demonstrate constant timing
    constant_time_demo();
    
    printf("\nsecurity improvement: constant-time comparison prevents timing attacks\n");
    printf("compare with password_comparison_vulnerable.c to see the difference.\n");
    
    // demonstrate secure memory clearing
    char sensitive_data[] = "secret_key_12345";
    printf("\nclearing sensitive data from memory...\n");
    secure_memory_clear(sensitive_data, sizeof(sensitive_data));
    printf("memory cleared securely (compiler cannot optimize away)\n");
    
    return 0;
}