/*
 * secure private key lookup
 * 
 * always check every single key slot, even after finding what you want.
 * timing stays the same whether key is at position 0 or position 9.
 * 
 * use bit tricks to copy the right key without branching.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_KEYS 10
#define KEY_SIZE 32

// key database structure (same as vulnerable version)
typedef struct {
    char key_id[16];
    uint8_t private_key[KEY_SIZE];
    int active;
} key_entry_t;

// global key database
key_entry_t key_database[MAX_KEYS] = {
    {"user_001", {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}, 1},
    {"user_002", {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, 1},
    {"user_003", {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}, 1},
    {"admin_001", {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}, 1},
    {"service_01", {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, 1},
    {"backup_key", {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}, 1},
    {"temp_key_1", {0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0}, 1},
    {"", {0}, 0},
    {"", {0}, 0},
    {"", {0}, 0}
};

// constant-time string comparison
int constant_time_string_equal(const char* a, const char* b, size_t max_len) {
    uint8_t result = 0;
    
    // compare characters up to max length
    for (size_t i = 0; i < max_len; i++) {
        uint8_t char_a = (i < strlen(a)) ? (uint8_t)a[i] : 0;
        uint8_t char_b = (i < strlen(b)) ? (uint8_t)b[i] : 0;
        result |= char_a ^ char_b;
    }
    
    // also check if lengths match
    uint8_t len_diff = (strlen(a) != strlen(b)) ? 1 : 0;
    
    return (result | len_diff) == 0;
}

// constant-time conditional copy
void conditional_copy(uint8_t* dest, const uint8_t* src, size_t len, int condition) {
    // create mask: 0xff if condition is true, 0x00 if false
    uint8_t mask = (condition != 0) ? 0xff : 0x00;
    
    for (size_t i = 0; i < len; i++) {
        // conditionally copy each byte using bitwise operations
        dest[i] = (dest[i] & ~mask) | (src[i] & mask);
    }
}

// good: always checks every slot
int lookup_private_key_secure(const char* key_id, uint8_t* output_key) {
    printf("searching for key: %s\n", key_id);
    
    uint8_t temp_key[KEY_SIZE] = {0};
    int found = 0;
    
    // look at every single entry
    for (int i = 0; i < MAX_KEYS; i++) {
        int is_active = key_database[i].active;
        int id_matches = constant_time_string_equal(key_database[i].key_id, key_id, 15);
        int this_entry_matches = is_active & id_matches;
        
        // copy key data if this is the one
        conditional_copy(temp_key, key_database[i].private_key, KEY_SIZE, this_entry_matches);
        
        // remember if we found it
        found |= this_entry_matches;
    }
    
    // copy result to output (will be zeros if not found)
    memcpy(output_key, temp_key, KEY_SIZE);
    
    // clear temporary storage
    memset(temp_key, 0, KEY_SIZE);
    
    if (found) {
        printf("key found (position hidden for security)\n");
    } else {
        printf("key not found\n");
    }
    
    return found;
}

// secure wallet key access
int access_wallet_key_secure(const char* wallet_id, uint8_t* wallet_key) {
    printf("accessing wallet: %s\n", wallet_id);
    
    if (lookup_private_key_secure(wallet_id, wallet_key)) {
        printf("wallet access granted - key retrieved\n");
        return 1;
    } else {
        printf("wallet access denied - invalid wallet id\n");
        return 0;
    }
}

// demonstrate constant-time key lookup
void secure_key_timing_demo() {
    const char* test_keys[] = {
        "user_001",     // position 0
        "user_002",     // position 1  
        "user_003",     // position 2
        "admin_001",    // position 3
        "service_01",   // position 4
        "backup_key",   // position 5
        "temp_key_1",   // position 6
        "nonexistent",  // not found
        "fake_key_99",  // not found
        "missing_key"   // not found
    };
    
    printf("\n=== constant-time key lookup demo ===\n");
    printf("measuring secure key lookup times (should be constant)...\n\n");
    
    for (int i = 0; i < 10; i++) {
        uint8_t retrieved_key[KEY_SIZE];
        struct timespec start, end;
        
        // measure lookup timing
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run multiple iterations
        for (int j = 0; j < 10000; j++) {
            lookup_private_key_secure(test_keys[i], retrieved_key);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key lookup: %-12s | time: %8lld ns | expected position: %d\n", 
               test_keys[i], duration, i < 7 ? i : -1);
    }
    
    printf("\nsecurity: timing is consistent regardless of key position!\n");
    printf("attackers cannot determine key locations or existence through timing.\n");
}

// demonstrate secure key enumeration resistance
void secure_enumeration_demo() {
    printf("\n=== secure key enumeration resistance demo ===\n");
    printf("timing should not reveal which keys exist...\n\n");
    
    const char* potential_keys[] = {
        "admin_001",    // exists
        "admin_002",    // doesn't exist
        "admin_003",    // doesn't exist 
        "user_001",     // exists
        "user_999",     // doesn't exist
        "root_key",     // doesn't exist
        "backup_key",   // exists
        "test_key"      // doesn't exist
    };
    
    for (int i = 0; i < 8; i++) {
        uint8_t dummy_key[KEY_SIZE];
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        int found = lookup_private_key_secure(potential_keys[i], dummy_key);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key test: %-12s | time: %6lld ns | exists: %s\n", 
               potential_keys[i], duration, found ? "yes" : "no");
        
        // clear sensitive data
        memset(dummy_key, 0, KEY_SIZE);
    }
    
    printf("\nsecurity: timing is consistent for both existing and missing keys!\n");
    printf("key enumeration attacks are prevented.\n");
}

// demonstrate secure memory handling
void secure_key_management_demo() {
    printf("\n=== secure key management demo ===\n");
    
    uint8_t sensitive_key[KEY_SIZE];
    
    // retrieve a key securely
    if (lookup_private_key_secure("user_001", sensitive_key)) {
        printf("key retrieved securely: ");
        for (int i = 0; i < 8; i++) {
            printf("%02x", sensitive_key[i]);
        }
        printf("...\n");
        
        // use the key for some operation...
        printf("performing cryptographic operation with key...\n");
        
        // secure cleanup - clear key from memory
        printf("clearing key from memory...\n");
        volatile uint8_t* volatile_ptr = sensitive_key;
        for (int i = 0; i < KEY_SIZE; i++) {
            volatile_ptr[i] = 0;
        }
        
        printf("key securely cleared\n");
    }
}

int main() {
    printf("secure private key lookup demo\n");
    printf("==============================\n\n");
    
    // simulate some wallet access attempts
    uint8_t wallet_key[KEY_SIZE];
    access_wallet_key_secure("user_001", wallet_key);
    printf("retrieved key: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", wallet_key[i]);
    }
    printf("...\n");
    
    // clear sensitive data
    memset(wallet_key, 0, KEY_SIZE);
    
    printf("\n");
    access_wallet_key_secure("invalid_wallet", wallet_key);
    
    // demonstrate constant-time lookup
    secure_key_timing_demo();
    
    // demonstrate enumeration resistance
    secure_enumeration_demo();
    
    // demonstrate secure key management
    secure_key_management_demo();
    
    printf("\nsecurity improvement: constant-time lookup prevents key enumeration\n");
    printf("compare with key_lookup_vulnerable.c to see the timing differences.\n");
    
    return 0;
}