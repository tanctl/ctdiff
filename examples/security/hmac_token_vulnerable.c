/*
 * vulnerable hmac token validation
 * 
 * memcmp() bails out on the first wrong byte.
 * attacker can forge tokens byte by byte by measuring timing.
 * 
 * if first 3 bytes match, takes longer than if first byte is wrong.
 * keep trying until you rebuild the whole token.
 * 
 * seen in jwt attacks, api bypasses, session hijacking
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

// fake hmac for demo purposes
void simple_hmac(const char* message, const char* key, uint8_t* output) {
    // real hmac would use sha256 etc
    const char* secret_key = "super_secret_hmac_key_2023";
    
    uint32_t hash = 0x12345678;
    
    // hash the key
    for (int i = 0; key[i]; i++) {
        hash ^= (uint8_t)key[i];
        hash = (hash << 5) + hash; // simple hash function
    }
    
    // hash the message  
    for (int i = 0; message[i]; i++) {
        hash ^= (uint8_t)message[i];
        hash = (hash << 5) + hash;
    }
    
    // output 8-byte "hmac"
    for (int i = 0; i < 8; i++) {
        output[i] = (uint8_t)(hash >> (i * 4));
    }
}

// bad: memcmp exits early
int verify_token_vulnerable(const char* message, const uint8_t* provided_hmac) {
    uint8_t expected_hmac[8];
    
    simple_hmac(message, "server_key", expected_hmac);
    
    // memcmp stops at first wrong byte
    return memcmp(provided_hmac, expected_hmac, 8) == 0;
}

// simulate api request validation
int validate_api_request_vulnerable(const char* request_data, const char* token_hex) {
    // convert hex token to bytes
    uint8_t token_bytes[8];
    for (int i = 0; i < 8; i++) {
        sscanf(&token_hex[i*2], "%2hhx", &token_bytes[i]);
    }
    
    printf("validating api request: %.30s...\n", request_data);
    printf("provided token: %s\n", token_hex);
    
    if (verify_token_vulnerable(request_data, token_bytes)) {
        printf("token valid - api request authorized!\n");
        return 1;
    } else {
        printf("token invalid - api request rejected\n");
        return 0;
    }
}

// demonstrate timing attack on hmac verification
void hmac_timing_attack_demo() {
    const char* api_request = "GET /api/sensitive-data?user=admin";
    
    // generate the correct hmac for comparison
    uint8_t correct_hmac[8];
    simple_hmac(api_request, "server_key", correct_hmac);
    
    printf("\n=== hmac timing attack demonstration ===\n");
    printf("attempting to forge hmac token using timing differences...\n");
    printf("correct hmac: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", correct_hmac[i]);
    }
    printf("\n\n");
    
    // attack attempts with different levels of correctness
    uint8_t attack_attempts[][8] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // no match
        {0,    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 1st byte correct
        {0,    0,    0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 2 bytes correct
        {0,    0,    0,    0x00, 0x00, 0x00, 0x00, 0x00}, // 3 bytes correct
        {0,    0,    0,    0,    0x00, 0x00, 0x00, 0x00}, // 4 bytes correct
        {0,    0,    0,    0,    0,    0x00, 0x00, 0x00}, // 5 bytes correct
        {0,    0,    0,    0,    0,    0,    0x00, 0x00}, // 6 bytes correct
        {0,    0,    0,    0,    0,    0,    0,    0x00}  // 7 bytes correct
    };
    
    // copy correct bytes for realistic attack
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j <= i; j++) {
            attack_attempts[i][j] = correct_hmac[j];
        }
    }
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        // measure verification timing
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run many iterations to amplify timing differences
        for (int j = 0; j < 50000; j++) {
            verify_token_vulnerable(api_request, attack_attempts[i]);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("attack token: ");
        for (int k = 0; k < 8; k++) {
            printf("%02x", attack_attempts[i][k]);
        }
        printf(" | time: %8lld ns | correct bytes: %d\n", duration, i + 1);
    }
    
    printf("\nvulnerability: timing increases with number of correct bytes!\n");
    printf("attacker can forge tokens by finding bytes that take longer to reject.\n");
}

int main() {
    printf("vulnerable hmac token validation demo\n");
    printf("=====================================\n\n");
    
    // simulate some api requests
    validate_api_request_vulnerable("GET /api/public-data", "1a2b3c4d5e6f7089");
    
    // generate a valid token for demonstration
    uint8_t valid_hmac[8];
    simple_hmac("GET /api/sensitive-data?user=admin", "server_key", valid_hmac);
    char valid_token_hex[17];
    for (int i = 0; i < 8; i++) {
        sprintf(&valid_token_hex[i*2], "%02x", valid_hmac[i]);
    }
    valid_token_hex[16] = '\0';
    
    printf("\n");
    validate_api_request_vulnerable("GET /api/sensitive-data?user=admin", valid_token_hex);
    
    // demonstrate the timing attack
    hmac_timing_attack_demo();
    
    printf("\nto fix this vulnerability, use constant-time hmac verification!\n");
    printf("see hmac_token_secure.c for the safe implementation.\n");
    
    return 0;
}