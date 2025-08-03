/*
 * parsing timing vulnerabilities
 * 
 * length-prefixed data and tlv parsing with timing leaks.
 * different parse paths take different time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// tlv = type-length-value format
typedef struct {
    uint8_t type;
    uint8_t length; 
    uint8_t value[256];
} tlv_record_t;

// bad length-prefixed parser
int parse_length_prefixed_vulnerable(uint8_t* data, size_t data_len) {
    if (data_len < 1) return -1;
    
    uint8_t claimed_length = data[0];
    
    // vulnerable: different validation paths
    if (claimed_length == 0) {
        printf("empty record - fast path\n");
        return 1; // quick exit
    }
    
    if (claimed_length > 100) {
        printf("length too big - medium path\n");
        return -1; // medium exit after length check
    }
    
    if (data_len < claimed_length + 1) {
        printf("insufficient data - slow path\n");
        return -1; // slower exit after buffer check
    }
    
    // expensive validation for valid lengths
    uint32_t checksum = 0;
    for (int i = 1; i <= claimed_length; i++) {
        checksum += data[i] * i; // slow computation
    }
    
    if (checksum % 7 == 0) {
        printf("bad checksum - slowest path\n");
        return -1; // slowest exit after full computation
    }
    
    printf("valid record\n");
    return claimed_length;
}

// good length-prefixed parser
int parse_length_prefixed_secure(uint8_t* data, size_t data_len) {
    if (data_len < 1) return -1;
    
    uint8_t claimed_length = data[0];
    uint8_t result = 1; // assume valid
    
    // always do all checks
    uint8_t is_empty = (claimed_length == 0) ? 1 : 0;
    uint8_t is_too_big = (claimed_length > 100) ? 1 : 0;
    uint8_t insufficient_data = (data_len < claimed_length + 1) ? 1 : 0;
    
    // always compute checksum (but limit to avoid overflow)
    uint32_t checksum = 0;
    uint8_t safe_length = (claimed_length > 100) ? 100 : claimed_length;
    
    for (int i = 1; i <= safe_length && i < data_len; i++) {
        checksum += data[i] * i;
    }
    
    uint8_t bad_checksum = (checksum % 7 == 0) ? 1 : 0;
    
    // combine all validation results
    result &= ~is_empty;
    result &= ~is_too_big;
    result &= ~insufficient_data;
    result &= ~bad_checksum;
    
    if (result) {
        printf("valid record\n");
        return claimed_length;
    } else {
        printf("invalid record\n");
        return -1;
    }
}

// bad tlv parser
int parse_tlv_vulnerable(uint8_t* data, size_t data_len, tlv_record_t* output) {
    if (data_len < 2) return -1;
    
    uint8_t type = data[0];
    uint8_t length = data[1];
    
    // different validation for different types
    if (type == 0x01) {
        // string type - fast validation
        if (length == 0) return -1;
        printf("parsing string type\n");
    } else if (type == 0x02) {
        // integer type - medium validation
        if (length != 4) return -1;
        printf("parsing integer type\n");
        
        // validate integer range
        uint32_t value = *(uint32_t*)&data[2];
        if (value > 1000000) return -1;
        
    } else if (type == 0x03) {
        // complex type - slow validation
        printf("parsing complex type\n");
        
        if (length < 10) return -1;
        
        // expensive validation
        for (int i = 0; i < length; i++) {
            if (data[2 + i] == 0xff) {
                // found terminator early
                printf("early terminator found\n");
                return -1;
            }
        }
        
        // additional checksum validation
        uint32_t sum = 0;
        for (int i = 0; i < length; i++) {
            sum += data[2 + i];
        }
        
        if (sum % 13 != 0) {
            printf("checksum validation failed\n");
            return -1;
        }
        
    } else {
        printf("unknown type\n");
        return -1;
    }
    
    // copy to output
    output->type = type;
    output->length = length;
    memcpy(output->value, &data[2], length);
    
    return 2 + length;
}

// demonstrate parsing timing differences
void parsing_timing_demo() {
    printf("=== parsing timing vulnerabilities demo ===\n");
    
    // test cases with different characteristics
    struct {
        const char* name;
        uint8_t data[32];
        size_t len;
    } test_cases[] = {
        {"empty length", {0x00}, 1},
        {"too big length", {0xff, 0x01, 0x02}, 3}, 
        {"good length, bad checksum", {0x05, 0x07, 0x07, 0x07, 0x07, 0x07}, 6},
        {"good length, good checksum", {0x03, 0x01, 0x02, 0x03}, 4},
        {"insufficient data", {0x10}, 1}
    };
    
    printf("testing vulnerable parser:\n");
    for (int i = 0; i < 5; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        for (int j = 0; j < 10000; j++) {
            parse_length_prefixed_vulnerable(test_cases[i].data, test_cases[i].len);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("  %-25s: %8lld ns\n", test_cases[i].name, duration);
    }
    
    printf("\ntesting secure parser:\n");
    for (int i = 0; i < 5; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        for (int j = 0; j < 10000; j++) {
            parse_length_prefixed_secure(test_cases[i].data, test_cases[i].len);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("  %-25s: %8lld ns\n", test_cases[i].name, duration);
    }
    
    printf("\nvulnerable: timing reveals parse path taken\n");
    printf("secure: consistent timing regardless of data characteristics\n");
}

// demonstrate tlv timing differences  
void tlv_timing_demo() {
    printf("\n=== tlv parsing timing demo ===\n");
    
    // different tlv records
    struct {
        const char* name;
        uint8_t data[32];
        size_t len;
    } tlv_cases[] = {
        {"string type", {0x01, 0x05, 'h', 'e', 'l', 'l', 'o'}, 7},
        {"integer type", {0x02, 0x04, 0x00, 0x00, 0x03, 0xe8}, 6},
        {"complex valid", {0x03, 0x0d, 1,2,3,4,5,6,7,8,9,10,11,12,13}, 15},
        {"complex invalid checksum", {0x03, 0x0a, 1,1,1,1,1,1,1,1,1,1}, 12},
        {"unknown type", {0x99, 0x02, 0x01, 0x02}, 4}
    };
    
    printf("measuring tlv parsing timing:\n");
    
    for (int i = 0; i < 5; i++) {
        tlv_record_t output;
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        for (int j = 0; j < 5000; j++) {
            parse_tlv_vulnerable(tlv_cases[i].data, tlv_cases[i].len, &output);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("  %-20s: %8lld ns\n", tlv_cases[i].name, duration);
    }
    
    printf("\nvulnerability: timing reveals record type and validation path\n");
    printf("attackers can infer data structure from timing patterns\n");
}

// network protocol parsing simulation
void protocol_parsing_demo() {
    printf("\n=== network protocol parsing timing ===\n");
    
    // simulate parsing different message types
    uint8_t auth_message[] = {0x01, 0x10, 'u','s','e','r',':','p','a','s','s',
                              'w','o','r','d','1','2','3','4'};
    uint8_t data_message[] = {0x02, 0x08, 'p','a','y','l','o','a','d','!'};
    uint8_t admin_message[] = {0xff, 0x06, 'a','d','m','i','n','!'};
    
    struct {
        const char* name;
        uint8_t* data;
        size_t len;
    } messages[] = {
        {"auth message", auth_message, sizeof(auth_message)},
        {"data message", data_message, sizeof(data_message)}, 
        {"admin message", admin_message, sizeof(admin_message)}
    };
    
    printf("simulating network message parsing:\n");
    
    for (int i = 0; i < 3; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        for (int j = 0; j < 10000; j++) {
            parse_length_prefixed_vulnerable(messages[i].data, messages[i].len);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("  %-15s: %8lld ns\n", messages[i].name, duration);
    }
    
    printf("\nreal-world impact:\n");
    printf("- network protocols leak message types through timing\n");
    printf("- file format parsers reveal document structure\n");
    printf("- serialization formats expose data characteristics\n");
}

int main() {
    printf("parsing timing vulnerabilities demo\n");
    printf("===================================\n\n");
    
    // length-prefixed parsing
    parsing_timing_demo();
    
    // tlv parsing 
    tlv_timing_demo();
    
    // protocol parsing
    protocol_parsing_demo();
    
    printf("\nmitigation strategies:\n");
    printf("- always perform maximum validation work\n");
    printf("- use constant-time comparison functions\n");  
    printf("- avoid data-dependent branching in parsers\n");
    printf("- consider padding to normalize message sizes\n");
    
    return 0;
}