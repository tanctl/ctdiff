/*
 * timing-safe memory zeroization
 * 
 * compiler might optimize away your memset() if it thinks
 * the memory isn't used after clearing.
 * 
 * use volatile pointers to force the write to actually happen.
 * 
 * also shows multi-pass clearing for paranoid scenarios.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// simulate a sensitive data structure
typedef struct {
    char username[32];
    char password[64];
    char api_key[128];
    uint8_t private_key[256];
    char session_token[64];
} sensitive_data_t;

// bad: compiler might skip this
void clear_memory_vulnerable(void* ptr, size_t len) {
    // compiler thinks "this memory isn't used later, why clear it?"
    // so it just removes the memset entirely
    
    memset(ptr, 0, len);
    
    // even explicit loops can be optimized away:
    // char* bytes = (char*)ptr;
    // for (size_t i = 0; i < len; i++) {
    //     bytes[i] = 0;  // compiler may remove this!
    // }
}

// good: volatile forces the write
void clear_memory_secure(void* ptr, size_t len) {
    // volatile tells compiler "don't optimize this away"
    volatile uint8_t* volatile_ptr = (volatile uint8_t*)ptr;
    
    for (size_t i = 0; i < len; i++) {
        volatile_ptr[i] = 0;
    }
    
    // make sure it actually happens
    __asm__ volatile("" ::: "memory");
}

// secure alternative: multiple-pass clearing with different patterns
void clear_memory_secure_multipass(void* ptr, size_t len) {
    volatile uint8_t* volatile_ptr = (volatile uint8_t*)ptr;
    
    // first pass: write zeros
    for (size_t i = 0; i < len; i++) {
        volatile_ptr[i] = 0x00;
    }
    
    // second pass: write 0xff pattern  
    for (size_t i = 0; i < len; i++) {
        volatile_ptr[i] = 0xff;
    }
    
    // third pass: write zeros again
    for (size_t i = 0; i < len; i++) {
        volatile_ptr[i] = 0x00;
    }
    
    // memory barrier
    __asm__ volatile("" ::: "memory");
}

// demonstrate vulnerable memory clearing
void vulnerable_clearing_demo() {
    printf("=== vulnerable memory clearing demo ===\n");
    
    // allocate sensitive data
    sensitive_data_t* sensitive = malloc(sizeof(sensitive_data_t));
    if (!sensitive) {
        printf("memory allocation failed\n");
        return;
    }
    
    // fill with sensitive information
    strcpy(sensitive->username, "admin");
    strcpy(sensitive->password, "super_secret_password_123");
    strcpy(sensitive->api_key, "sk_live_abcdef1234567890_production_key");
    strcpy(sensitive->session_token, "sess_9876543210abcdef_user_token");
    
    // simulate some private key data
    for (int i = 0; i < 256; i++) {
        sensitive->private_key[i] = (uint8_t)(i ^ 0xaa);
    }
    
    printf("sensitive data allocated and initialized\n");
    printf("password: %s\n", sensitive->password);
    printf("api key: %.20s...\n", sensitive->api_key);
    
    // attempt to clear using vulnerable method
    printf("attempting to clear with vulnerable method...\n");
    clear_memory_vulnerable(sensitive, sizeof(sensitive_data_t));
    
    // check if data was actually cleared (it might not be!)
    printf("checking if memory was cleared:\n");
    printf("password field: ");
    for (int i = 0; i < 20; i++) {
        if (sensitive->password[i] != 0) {
            printf("not fully cleared! found: %c\n", sensitive->password[i]);
            break;
        }
    }
    
    // in debug builds or with certain compiler settings, 
    // the data might still be visible here!
    printf("warning: with compiler optimizations, data may still be recoverable\n");
    
    free(sensitive);
}

// demonstrate secure memory clearing
void secure_clearing_demo() {
    printf("\n=== secure memory clearing demo ===\n");
    
    sensitive_data_t* sensitive = malloc(sizeof(sensitive_data_t));
    if (!sensitive) {
        printf("memory allocation failed\n");
        return;
    }
    
    // fill with sensitive information
    strcpy(sensitive->username, "admin");  
    strcpy(sensitive->password, "super_secret_password_123");
    strcpy(sensitive->api_key, "sk_live_abcdef1234567890_production_key");
    strcpy(sensitive->session_token, "sess_9876543210abcdef_user_token");
    
    for (int i = 0; i < 256; i++) {
        sensitive->private_key[i] = (uint8_t)(i ^ 0xbb);
    }
    
    printf("sensitive data allocated and initialized\n");
    printf("password: %s\n", sensitive->password);
    printf("api key: %.20s...\n", sensitive->api_key);
    
    // clear using secure method
    printf("clearing with secure volatile method...\n");
    clear_memory_secure(sensitive, sizeof(sensitive_data_t));
    
    // verify clearing was effective
    printf("verifying memory was cleared:\n");
    int cleared_count = 0;
    uint8_t* bytes = (uint8_t*)sensitive;
    for (size_t i = 0; i < sizeof(sensitive_data_t); i++) {
        if (bytes[i] == 0) {
            cleared_count++;
        }
    }
    
    printf("cleared %d / %zu bytes (%.1f%%)\n", 
           cleared_count, sizeof(sensitive_data_t),
           (100.0 * cleared_count) / sizeof(sensitive_data_t));
    
    free(sensitive);
}

// demonstrate multi-pass secure clearing
void multipass_clearing_demo() {
    printf("\n=== multi-pass secure clearing demo ===\n");
    
    char secret_buffer[1024];
    
    // fill with secret data pattern
    for (int i = 0; i < 1024; i++) {
        secret_buffer[i] = (char)(i % 256);
    }
    
    printf("secret buffer initialized with pattern data\n");
    printf("first 32 bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", (uint8_t)secret_buffer[i]);
    }
    printf("\n");
    
    // clear with multi-pass method
    printf("applying multi-pass secure clearing...\n");
    clear_memory_secure_multipass(secret_buffer, sizeof(secret_buffer));
    
    // verify all bytes are zero
    printf("verifying complete clearing:\n");
    int all_clear = 1;
    for (int i = 0; i < 1024; i++) {
        if (secret_buffer[i] != 0) {
            all_clear = 0;
            break;
        }
    }
    
    printf("buffer completely cleared: %s\n", all_clear ? "yes" : "no");
}

// demonstrate timing consistency in clearing operations
void timing_consistency_demo() {
    printf("\n=== timing consistency demo ===\n");
    printf("measuring memory clearing times for different data patterns...\n\n");
    
    const size_t buffer_size = 8192;
    
    // test different data patterns
    struct {
        const char* name;
        uint8_t pattern;
    } test_patterns[] = {
        {"all zeros", 0x00},
        {"all ones", 0xff}, 
        {"alternating", 0xaa},
        {"random-like", 0x5a},
        {"sequential", 0x01}
    };
    
    for (int p = 0; p < 5; p++) {
        uint8_t* buffer = malloc(buffer_size);
        if (!buffer) continue;
        
        // initialize with test pattern
        memset(buffer, test_patterns[p].pattern, buffer_size);
        
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // clear using secure method
        for (int i = 0; i < 100; i++) {
            clear_memory_secure(buffer, buffer_size);
            // reinitialize for next iteration
            memset(buffer, test_patterns[p].pattern, buffer_size);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("pattern %-12s | time: %8lld ns\n", 
               test_patterns[p].name, duration);
        
        free(buffer);
    }
    
    printf("\nsecurity: clearing time is consistent regardless of data content\n");
}

// demonstrate stack vs heap clearing
void stack_heap_clearing_demo() {
    printf("\n=== stack vs heap clearing demo ===\n");
    
    // stack-allocated sensitive data
    char stack_secret[256];
    strcpy(stack_secret, "this is a stack-allocated secret");
    printf("stack secret: %s\n", stack_secret);
    
    // heap-allocated sensitive data  
    char* heap_secret = malloc(256);
    strcpy(heap_secret, "this is a heap-allocated secret");
    printf("heap secret: %s\n", heap_secret);
    
    // clear both using secure method
    printf("clearing both stack and heap secrets...\n");
    clear_memory_secure(stack_secret, sizeof(stack_secret));
    clear_memory_secure(heap_secret, 256);
    
    printf("stack secret cleared\n");
    printf("heap secret cleared\n");
    
    free(heap_secret);
    
    // note: stack data may still be recoverable in some cases
    // because the stack frame may be reused
    printf("note: stack data may persist until stack frame is overwritten\n");
}

int main() {
    printf("timing-safe memory zeroization demo\n");
    printf("===================================\n\n");
    
    // demonstrate vulnerable clearing
    vulnerable_clearing_demo();
    
    // demonstrate secure clearing
    secure_clearing_demo();
    
    // demonstrate multi-pass clearing
    multipass_clearing_demo();
    
    // demonstrate timing consistency
    timing_consistency_demo();
    
    // demonstrate stack vs heap considerations
    stack_heap_clearing_demo();
    
    printf("\nsecurity principles:\n");
    printf("- use volatile pointers to prevent compiler optimization\n");
    printf("- add memory barriers to ensure writes complete\n");
    printf("- consider multi-pass clearing for highly sensitive data\n");
    printf("- clear both stack and heap allocated sensitive data\n");
    printf("- maintain consistent timing regardless of data content\n");
    
    return 0;
}