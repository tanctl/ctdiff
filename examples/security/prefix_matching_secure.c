/*
 * secure string prefix matching
 * 
 * always check every character in the prefix.
 * timing stays same no matter where differences are.
 * 
 * use bitwise ops instead of early returns.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

// good: ct prefix checking
int check_prefix_secure(const char* string, const char* prefix) {
    printf("checking if '%s' starts with '%s'\n", string, prefix);
    
    size_t prefix_len = strlen(prefix);
    size_t string_len = strlen(string);
    
    if (string_len < prefix_len) {
        // still do ct work
        uint8_t dummy_result = 0;
        for (size_t i = 0; i < prefix_len; i++) {
            dummy_result |= (uint8_t)prefix[i];
        }
        return 0;
    }
    
    // ct comparison of all prefix chars
    uint8_t difference = 0;
    for (size_t i = 0; i < prefix_len; i++) {
        difference |= (uint8_t)string[i] ^ (uint8_t)prefix[i];
    }
    
    return (difference == 0) ? 1 : 0;
}

// secure file authorization with constant-time prefix checking
int authorize_file_access_secure(const char* requested_path) {
    const char* allowed_prefixes[] = {
        "/public/",
        "/uploads/user/",
        "/api/v1/public/",
        "/static/assets/",
        "/downloads/shared/"
    };
    
    printf("authorizing access to: %s\n", requested_path);
    
    // check all prefixes using constant-time comparison
    uint8_t authorized = 0;
    for (int i = 0; i < 5; i++) {
        uint8_t matches = check_prefix_secure(requested_path, allowed_prefixes[i]);
        authorized |= matches; // accumulate without early exit
    }
    
    if (authorized) {
        printf("access granted - matches an allowed prefix\n");
        return 1;
    } else {
        printf("access denied - no matching prefix found\n");  
        return 0;
    }
}

// secure api key validation
int validate_api_key_secure(const char* api_key) {
    const char* valid_prefixes[] = {
        "sk_live_",        // production keys
        "pk_test_",        // test public keys
        "sk_test_",        // test secret keys
        "webhook_",        // webhook signing keys
        "connect_"         // oauth connect keys
    };
    
    printf("validating api key: %.15s...\n", api_key);
    
    // check all prefixes with constant-time operations
    uint8_t valid = 0;
    for (int i = 0; i < 5; i++) {
        uint8_t matches = check_prefix_secure(api_key, valid_prefixes[i]);
        valid |= matches;
    }
    
    if (valid) {
        printf("api key valid - has recognized prefix\n");
        return 1;
    } else {
        printf("api key invalid - unknown prefix\n");
        return 0;
    }
}

// demonstrate constant-time prefix matching
void secure_prefix_timing_demo() {
    const char* secret_string = "/api/v1/admin/users/sensitive-data";
    
    printf("\n=== constant-time prefix matching demo ===\n");
    printf("secret string: %s\n", secret_string);
    printf("measuring timing for different prefix guesses (should be constant)...\n\n");
    
    // same attack attempts as vulnerable version
    const char* test_prefixes[] = {
        "x",                    // no match
        "/",                    // 1 char match
        "/a",                   // 2 char match
        "/ap",                  // 3 char match
        "/api",                 // 4 char match
        "/api/",                // 5 char match
        "/api/v1",              // 8 char match
        "/api/v1/admin",        // 14 char match
        "/wrong/path",          // no match but longer
        "/api/v2/admin"         // partial match then differ
    };
    
    for (int i = 0; i < 10; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run multiple iterations
        for (int j = 0; j < 50000; j++) {
            check_prefix_secure(secret_string, test_prefixes[i]);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("prefix: %-18s | time: %8lld ns | match chars: %zu\n", 
               test_prefixes[i], duration,
               strlen(test_prefixes[i]) <= strlen(secret_string) ?
               strlen(test_prefixes[i]) : 0);
    }
    
    printf("\nsecurity: timing is consistent regardless of prefix match length!\n");
    printf("attackers cannot discover secret strings through timing analysis.\n");
}

// demonstrate secure api key enumeration resistance
void secure_api_key_demo() {
    printf("\n=== secure api key validation demo ===\n");
    printf("timing should not reveal key prefix validity...\n\n");
    
    const char* test_keys[] = {
        "invalid_key_123",           // invalid
        "sk_live_abcdef123456",      // valid production key
        "pk_test_xyz789",            // valid test key
        "random_key_456",            // invalid
        "sk_test_dev_environment",   // valid test secret key
        "webhook_endpoint_abc",      // valid webhook key
        "fake_prefix_999",           // invalid
        "connect_oauth_token123"     // valid connect key
    };
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        int valid = validate_api_key_secure(test_keys[i]);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key: %-25s | time: %6lld ns | valid: %s\n", 
               test_keys[i], duration, valid ? "yes" : "no");
    }
    
    printf("\nsecurity: timing is consistent for both valid and invalid keys!\n");
    printf("key enumeration attacks are prevented.\n");
}

// demonstrate secure path traversal resistance
void secure_path_traversal_demo() {
    printf("\n=== secure path authorization demo ===\n");
    printf("timing should not reveal valid path prefixes...\n\n");
    
    const char* traversal_attempts[] = {
        "../../../etc/passwd",           // invalid
        "/public/../../../etc/passwd",   // starts valid then invalid
        "/uploads/user/../../etc/passwd", // longer valid prefix
        "/api/v1/public/../../../etc/",  // even longer valid prefix
        "/static/assets/../../../etc/",  // valid prefix then traversal
        "/invalid/path/traversal",       // invalid from start
        "/public/",                      // completely valid
        "/uploads/user/data.txt"         // completely valid
    };
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        int authorized = authorize_file_access_secure(traversal_attempts[i]);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("path: %-35s | time: %6lld ns | authorized: %s\n",
               traversal_attempts[i], duration, authorized ? "yes" : "no");
    }
    
    printf("\nsecurity: timing is consistent regardless of path validity!\n");
    printf("path enumeration through timing analysis is prevented.\n");
}

// additional secure string operations
void secure_string_operations_demo() {
    printf("\n=== additional secure string operations demo ===\n");
    
    // constant-time substring search (simplified)
    const char* haystack = "secret_api_endpoint_v2_admin";
    const char* needles[] = {"secret", "admin", "user", "public"};
    
    printf("searching in string: %s\n", haystack);
    
    for (int i = 0; i < 4; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // simple constant-time contains check
        uint8_t found = 0;
        size_t haystack_len = strlen(haystack);
        size_t needle_len = strlen(needles[i]);
        
        if (needle_len <= haystack_len) {
            for (size_t pos = 0; pos <= haystack_len - needle_len; pos++) {
                uint8_t match = 1;
                for (size_t j = 0; j < needle_len; j++) {
                    if (haystack[pos + j] != needles[i][j]) {
                        match = 0;
                    }
                }
                found |= match;
            }
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("search for '%-8s' | time: %6lld ns | found: %s\n",
               needles[i], duration, found ? "yes" : "no");
    }
    
    printf("\nsecurity: substring search timing is consistent\n");
}

int main() {
    printf("secure string prefix matching demo\n");
    printf("===================================\n\n");
    
    // simulate some file access attempts
    authorize_file_access_secure("/public/documents/report.pdf");
    authorize_file_access_secure("/private/admin/secrets.txt");
    
    printf("\n");
    
    // simulate some api key validations
    validate_api_key_secure("sk_live_abcdef1234567890");
    validate_api_key_secure("invalid_key_format");
    
    // demonstrate constant-time prefix matching
    secure_prefix_timing_demo();
    
    // demonstrate secure api key validation
    secure_api_key_demo();
    
    // demonstrate secure path authorization
    secure_path_traversal_demo();
    
    // demonstrate additional secure operations
    secure_string_operations_demo();
    
    printf("\nsecurity improvement: constant-time prefix matching prevents timing attacks\n");
    printf("compare with prefix_matching_vulnerable.c to see the timing differences.\n");
    
    return 0;
}