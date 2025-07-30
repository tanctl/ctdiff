/*
 * secure hmac token validation
 * 
 * check every byte of the hmac even if early bytes are wrong.
 * timing stays the same no matter how many bytes match.
 * 
 * prevents byte-by-byte token forgery attacks.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

// simulate a simple hmac computation (same as vulnerable version)
void simple_hmac(const char* message, const char* key, uint8_t* output) {
    const char* secret_key = "super_secret_hmac_key_2023";
    
    uint32_t hash = 0x12345678;
    
    // hash the key
    for (int i = 0; key[i]; i++) {
        hash ^= (uint8_t)key[i];
        hash = (hash << 5) + hash;
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

// check all bytes no matter what
int constant_time_hmac_verify(const uint8_t* hmac1, const uint8_t* hmac2, size_t len) {
    uint8_t result = 0;
    
    // always check every byte
    for (size_t i = 0; i < len; i++) {
        result |= hmac1[i] ^ hmac2[i];
    }
    
    return (result == 0) ? 1 : 0;
}

// safe token check
int verify_token_secure(const char* message, const uint8_t* provided_hmac) {
    uint8_t expected_hmac[8];
    
    simple_hmac(message, "server_key", expected_hmac);
    
    // always takes same time
    int result = constant_time_hmac_verify(provided_hmac, expected_hmac, 8);
    
    // wipe the expected value
    memset(expected_hmac, 0, sizeof(expected_hmac));
    
    return result;
}

// secure api request validation
int validate_api_request_secure(const char* request_data, const char* token_hex) {
    uint8_t token_bytes[8];
    
    // convert hex token to bytes
    for (int i = 0; i < 8; i++) {
        sscanf(&token_hex[i*2], "%2hhx", &token_bytes[i]);
    }
    
    printf("validating api request: %.30s...\n", request_data);
    printf("provided token: %s\n", token_hex);
    
    if (verify_token_secure(request_data, token_bytes)) {
        printf("token valid - api request authorized!\n");
        return 1;
    } else {
        printf("token invalid - api request rejected\n");
        return 0;
    }
}

// demonstrate constant-time hmac verification
void secure_hmac_demo() {
    const char* api_request = "GET /api/sensitive-data?user=admin";
    
    // generate the correct hmac for comparison
    uint8_t correct_hmac[8];
    simple_hmac(api_request, "server_key", correct_hmac);
    
    printf("\n=== constant-time hmac verification demo ===\n");
    printf("measuring hmac verification timing (should be constant)...\n");
    printf("correct hmac: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", correct_hmac[i]);
    }
    printf("\n\n");
    
    // test with different levels of correctness
    uint8_t test_attempts[][8] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // no match
        {0,    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 1st byte correct
        {0,    0,    0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 2 bytes correct
        {0,    0,    0,    0x00, 0x00, 0x00, 0x00, 0x00}, // 3 bytes correct
        {0,    0,    0,    0,    0x00, 0x00, 0x00, 0x00}, // 4 bytes correct
        {0,    0,    0,    0,    0,    0x00, 0x00, 0x00}, // 5 bytes correct
        {0,    0,    0,    0,    0,    0,    0x00, 0x00}, // 6 bytes correct
        {0,    0,    0,    0,    0,    0,    0,    0x00}  // 7 bytes correct
    };
    
    // copy correct bytes
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j <= i; j++) {
            test_attempts[i][j] = correct_hmac[j];
        }
    }
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        // measure verification timing
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run many iterations
        for (int j = 0; j < 50000; j++) {
            verify_token_secure(api_request, test_attempts[i]);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("test token: ");
        for (int k = 0; k < 8; k++) {
            printf("%02x", test_attempts[i][k]);
        }
        printf(" | time: %8lld ns | correct bytes: %d\n", duration, i + 1);
    }
    
    printf("\nsecurity: timing is consistent regardless of correct bytes!\n");
    printf("attackers cannot use timing to forge tokens.\n");
}

// additional security features
void secure_token_cleanup_demo() {
    printf("\n=== secure token handling demo ===\n");
    
    // allocate memory for sensitive token data
    uint8_t* sensitive_token = malloc(32);
    if (!sensitive_token) {
        printf("memory allocation failed\n");
        return;
    }
    
    // simulate token generation
    simple_hmac("user_session_12345", "session_key", sensitive_token);
    
    printf("generated session token: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", sensitive_token[i]);
    }
    printf("\n");
    
    // secure cleanup - prevent data from remaining in memory
    printf("clearing sensitive token from memory...\n");
    
    // use volatile to prevent compiler optimization
    volatile uint8_t* volatile_ptr = sensitive_token;
    for (int i = 0; i < 32; i++) {
        volatile_ptr[i] = 0;
    }
    
    printf("token securely cleared\n");
    
    free(sensitive_token);
}

int main() {
    printf("secure hmac token validation demo\n");
    printf("==================================\n\n");
    
    // simulate some api requests
    validate_api_request_secure("GET /api/public-data", "1a2b3c4d5e6f7089");
    
    // generate a valid token for demonstration
    uint8_t valid_hmac[8];
    simple_hmac("GET /api/sensitive-data?user=admin", "server_key", valid_hmac);
    char valid_token_hex[17];
    for (int i = 0; i < 8; i++) {
        sprintf(&valid_token_hex[i*2], "%02x", valid_hmac[i]);
    }
    valid_token_hex[16] = '\0';
    
    printf("\n");
    validate_api_request_secure("GET /api/sensitive-data?user=admin", valid_token_hex);
    
    // demonstrate constant-time verification
    secure_hmac_demo();
    
    // demonstrate secure token cleanup
    secure_token_cleanup_demo();
    
    printf("\nsecurity improvement: constant-time hmac prevents token forgery attacks\n");
    printf("compare with hmac_token_vulnerable.c to see the timing differences.\n");
    
    return 0;
}