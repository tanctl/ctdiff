/*
 * vulnerable private key lookup
 * 
 * searching through keys and returning as soon as you find a match.
 * timing tells you where the key was stored.
 * 
 * if key is at position 0: super fast
 * if key is at position 9: much slower
 * if key doesn't exist: slowest (checks everything)
 * 
 * real problem in crypto wallets, ssl cert stores, api systems
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_KEYS 10
#define KEY_SIZE 32

// simulated key database
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
    {"", {0}, 0}, // empty slots
    {"", {0}, 0},
    {"", {0}, 0}
};

// bad: returns as soon as key is found
int lookup_private_key_vulnerable(const char* key_id, uint8_t* output_key) {
    printf("searching for key: %s\n", key_id);
    
    for (int i = 0; i < MAX_KEYS; i++) {
        if (key_database[i].active && strcmp(key_database[i].key_id, key_id) == 0) {
            memcpy(output_key, key_database[i].private_key, KEY_SIZE);
            printf("key found at position %d\n", i);
            return 1; // timing reveals position
        }
    }
    
    printf("key not found\n");
    return 0;
}

// simulate cryptocurrency wallet key access
int access_wallet_key_vulnerable(const char* wallet_id, uint8_t* wallet_key) {
    printf("accessing wallet: %s\n", wallet_id);
    
    if (lookup_private_key_vulnerable(wallet_id, wallet_key)) {
        printf("wallet access granted - key retrieved\n");
        return 1;
    } else {
        printf("wallet access denied - invalid wallet id\n");
        return 0;
    }
}

// demonstrate timing differences based on key position
void key_position_timing_demo() {
    const char* test_keys[] = {
        "user_001",     // position 0 - fastest
        "user_002",     // position 1 - slightly slower
        "user_003",     // position 2 - slower
        "admin_001",    // position 3 - even slower
        "service_01",   // position 4 - much slower
        "backup_key",   // position 5 - very slow
        "temp_key_1",   // position 6 - slowest
        "nonexistent",  // not found - searches all positions (very slow)
        "fake_key_99",  // not found - full search
        "missing_key"   // not found - full search
    };
    
    printf("\n=== key position timing attack demo ===\n");
    printf("measuring key lookup times based on position...\n\n");
    
    for (int i = 0; i < 10; i++) {
        uint8_t retrieved_key[KEY_SIZE];
        struct timespec start, end;
        
        // measure lookup timing
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run multiple iterations to amplify timing differences
        for (int j = 0; j < 10000; j++) {
            lookup_private_key_vulnerable(test_keys[i], retrieved_key);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key lookup: %-12s | time: %8lld ns | expected position: %d\n", 
               test_keys[i], duration, i < 7 ? i : -1);
    }
    
    printf("\nvulnerability: timing reveals key position in database!\n");
    printf("attackers can determine which keys exist and their storage location.\n");
}

// demonstrate key enumeration attack
void key_enumeration_demo() {
    printf("\n=== key enumeration attack demo ===\n");
    printf("using timing to determine if keys exist...\n\n");
    
    const char* potential_keys[] = {
        "admin_001",    // exists - will be fast (position 3)
        "admin_002",    // doesn't exist - slow (full search)
        "admin_003",    // doesn't exist - slow (full search) 
        "user_001",     // exists - very fast (position 0)
        "user_999",     // doesn't exist - slow (full search)
        "root_key",     // doesn't exist - slow (full search)
        "backup_key",   // exists - slower (position 5)
        "test_key"      // doesn't exist - slow (full search)
    };
    
    for (int i = 0; i < 8; i++) {
        uint8_t dummy_key[KEY_SIZE];
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // single lookup to see timing difference
        int found = lookup_private_key_vulnerable(potential_keys[i], dummy_key);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key test: %-12s | time: %6lld ns | exists: %s\n", 
               potential_keys[i], duration, found ? "yes" : "no");
    }
    
    printf("\nvulnerability: timing differences reveal which keys exist!\n");
    printf("fast responses indicate existing keys, slow responses indicate missing keys.\n");
}

int main() {
    printf("vulnerable private key lookup demo\n");
    printf("==================================\n\n");
    
    // simulate some wallet access attempts
    uint8_t wallet_key[KEY_SIZE];
    access_wallet_key_vulnerable("user_001", wallet_key);
    printf("retrieved key: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", wallet_key[i]);
    }
    printf("...\n\n");
    
    access_wallet_key_vulnerable("invalid_wallet", wallet_key);
    
    // demonstrate position-based timing attack
    key_position_timing_demo();
    
    // demonstrate key enumeration attack
    key_enumeration_demo();
    
    printf("\nto fix this vulnerability, use constant-time key lookup!\n");
    printf("see key_lookup_secure.c for the safe implementation.\n");
    
    return 0;
}