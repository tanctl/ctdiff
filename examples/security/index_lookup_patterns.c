/*
 * ct index lookup patterns
 * 
 * searching arrays and returning early when found.
 * timing reveals where the element was stored.
 * 
 * bad: for loop with early return
 * good: always check every slot, use bit masks
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define MAX_ELEMENTS 16
#define ELEMENT_SIZE 32

// simulated lookup table
typedef struct {
    uint32_t key;
    char data[ELEMENT_SIZE];
    int active;
} table_entry_t;

// global lookup table
table_entry_t lookup_table[MAX_ELEMENTS] = {
    {0x1001, "user_data_alice", 1},
    {0x1002, "user_data_bob", 1},
    {0x1003, "user_data_charlie", 1},
    {0x2001, "admin_config_prod", 1},
    {0x2002, "admin_config_test", 1},
    {0x3001, "secret_key_primary", 1},
    {0x3002, "secret_key_backup", 1},
    {0x4001, "certificate_root_ca", 1},
    {0x4002, "certificate_intermediate", 1},
    {0x5001, "database_credentials", 1},
    {0, "", 0}, // empty slots
    {0, "", 0},
    {0, "", 0},
    {0, "", 0},
    {0, "", 0},
    {0, "", 0}
};

// bad: returns as soon as element is found
int lookup_element_vulnerable(uint32_t key, char* output_data) {
    printf("searching for key: 0x%04x\n", key);
    
    for (int i = 0; i < MAX_ELEMENTS; i++) {
        if (lookup_table[i].active && lookup_table[i].key == key) {
            strcpy(output_data, lookup_table[i].data);
            printf("found at position %d: %s\n", i, output_data);
            return 1; // timing reveals position
        }
    }
    
    printf("key not found\n");
    return 0;
}

// secure: constant-time lookup using oblivious access
int lookup_element_secure(uint32_t key, char* output_data) {
    printf("searching for key: 0x%04x\n", key);
    
    char temp_data[ELEMENT_SIZE] = {0};
    int found = 0;
    
    // always examine all entries - no early exit
    for (int i = 0; i < MAX_ELEMENTS; i++) {
        // check if this entry matches
        int is_active = lookup_table[i].active;
        int key_matches = (lookup_table[i].key == key) ? 1 : 0;
        int this_entry_matches = is_active & key_matches;
        
        // conditionally copy data using constant-time selection
        for (int j = 0; j < ELEMENT_SIZE; j++) {
            // create mask: 0xff if match, 0x00 if no match
            uint8_t mask = (this_entry_matches != 0) ? 0xff : 0x00;
            temp_data[j] = (temp_data[j] & ~mask) | (lookup_table[i].data[j] & mask);
        }
        
        // accumulate found status
        found |= this_entry_matches;
    }
    
    // copy result to output
    strcpy(output_data, temp_data);
    
    if (found) {
        printf("found (position hidden): %s\n", output_data);
    } else {
        printf("key not found\n");
    }
    
    return found;
}

// demonstrate position-based timing differences
void position_timing_demo() {
    printf("\n=== position-based timing demonstration ===\n");
    printf("measuring lookup times for keys at different positions...\n\n");
    
    // test keys at different positions
    uint32_t test_keys[] = {
        0x1001,  // position 0 - fastest
        0x1002,  // position 1 - slightly slower
        0x1003,  // position 2 - slower
        0x2001,  // position 3 - even slower
        0x3001,  // position 5 - much slower
        0x4002,  // position 8 - very slow
        0x5001,  // position 9 - slowest
        0x9999,  // not found - searches all positions (very slow)
        0x0000,  // not found - searches all positions
        0xffff   // not found - searches all positions
    };
    
    printf("vulnerable lookup timing:\n");
    for (int i = 0; i < 10; i++) {
        char data[ELEMENT_SIZE];
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run multiple iterations to amplify timing differences
        for (int j = 0; j < 10000; j++) {
            lookup_element_vulnerable(test_keys[i], data);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key: 0x%04x | time: %8lld ns\n", test_keys[i], duration);
    }
    
    printf("\nsecure lookup timing:\n");
    for (int i = 0; i < 10; i++) {
        char data[ELEMENT_SIZE];
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        for (int j = 0; j < 10000; j++) {
            lookup_element_secure(test_keys[i], data);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key: 0x%04x | time: %8lld ns\n", test_keys[i], duration);
    }
    
    printf("\nvulnerable version: timing reveals element position\n");
    printf("secure version: consistent timing regardless of position\n");
}

// constant-time array selection using bit manipulation
uint32_t select_element_secure(uint32_t* array, size_t len, size_t index) {
    uint32_t result = 0;
    
    // always access all array elements to prevent cache timing
    for (size_t i = 0; i < len; i++) {
        // create mask: 0xffffffff if i == index, 0x00000000 otherwise
        uint32_t mask = (i == index) ? 0xffffffff : 0x00000000;
        result |= array[i] & mask;
    }
    
    return result;
}

// demonstrate constant-time array selection
void array_selection_demo() {
    printf("\n=== constant-time array selection demo ===\n");
    
    uint32_t test_array[8] = {
        0x11111111, 0x22222222, 0x33333333, 0x44444444,
        0x55555555, 0x66666666, 0x77777777, 0x88888888
    };
    
    printf("array: ");
    for (int i = 0; i < 8; i++) {
        printf("0x%08x ", test_array[i]);
    }
    printf("\n\n");
    
    // test selection at different indices
    for (int index = 0; index < 10; index++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        uint32_t selected = 0;
        for (int j = 0; j < 50000; j++) {
            if (index < 8) {
                selected = select_element_secure(test_array, 8, index);
            } else {
                // out of bounds - should return 0
                selected = select_element_secure(test_array, 8, index);
            }
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("select index %d | result: 0x%08x | time: %8lld ns\n", 
               index, selected, duration);
    }
    
    printf("\nsecurity: selection timing is consistent regardless of index\n");
}

// constant-time minimum/maximum finding
uint32_t find_min_secure(uint32_t* array, size_t len) {
    if (len == 0) return 0;
    
    uint32_t min_val = array[0];
    
    // always examine all elements
    for (size_t i = 1; i < len; i++) {
        // constant-time min using bit manipulation
        uint32_t is_smaller = (array[i] < min_val) ? 0xffffffff : 0x00000000;
        min_val = (array[i] & is_smaller) | (min_val & ~is_smaller);
    }
    
    return min_val;
}

// demonstrate constant-time min/max operations
void minmax_demo() {
    printf("\n=== constant-time min/max demo ===\n");
    
    // test arrays with min at different positions
    uint32_t test_arrays[][8] = {
        {1, 5, 3, 7, 9, 2, 8, 4},    // min at position 0
        {9, 1, 7, 3, 5, 8, 2, 6},    // min at position 1
        {8, 7, 1, 9, 3, 5, 4, 2},    // min at position 2
        {5, 9, 8, 1, 7, 2, 6, 3},    // min at position 3
        {7, 4, 9, 6, 1, 8, 3, 5}     // min at position 4
    };
    
    for (int i = 0; i < 5; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        uint32_t min_val = 0;
        for (int j = 0; j < 100000; j++) {
            min_val = find_min_secure(test_arrays[i], 8);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("array %d | min: %u | time: %8lld ns\n", i, min_val, duration);
    }
    
    printf("\nsecurity: min finding time is consistent regardless of min position\n");
}

// constant-time conditional operations
void conditional_operations_demo() {
    printf("\n=== constant-time conditional operations demo ===\n");
    
    uint32_t a = 0x12345678;
    uint32_t b = 0x87654321;
    
    printf("a = 0x%08x, b = 0x%08x\n", a, b);
    
    // test conditional selection with different conditions
    int conditions[] = {0, 1, 0, 1, 0};
    
    for (int i = 0; i < 5; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        uint32_t result = 0;
        for (int j = 0; j < 100000; j++) {
            // constant-time conditional move
            uint32_t mask = (conditions[i] != 0) ? 0xffffffff : 0x00000000;
            result = (a & mask) | (b & ~mask);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("condition: %d | result: 0x%08x | time: %8lld ns\n", 
               conditions[i], result, duration);
    }
    
    printf("\nsecurity: conditional selection timing is independent of condition\n");  
}

int main() {
    printf("constant-time index lookup patterns demo\n");
    printf("========================================\n\n");
    
    // test basic lookup operations
    char data[ELEMENT_SIZE];
    lookup_element_vulnerable(0x1001, data);
    lookup_element_secure(0x1001, data);
    
    printf("\n");
    lookup_element_vulnerable(0x9999, data);
    lookup_element_secure(0x9999, data);
    
    // demonstrate position-based timing differences
    position_timing_demo();
    
    // demonstrate constant-time array selection
    array_selection_demo();
    
    // demonstrate constant-time min/max
    minmax_demo();
    
    // demonstrate conditional operations
    conditional_operations_demo();
    
    printf("\nsecurity principles for constant-time lookups:\n");
    printf("- always access all possible locations\n");
    printf("- use bit masks instead of conditional branches\n");
    printf("- accumulate results without data-dependent branching\n");
    printf("- maintain uniform memory access patterns\n");
    printf("- use conditional move operations instead of if statements\n");
    
    return 0;
}