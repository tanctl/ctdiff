/*
 * vulnerable string prefix matching
 * 
 * strncmp() quits as soon as it hits a different character.
 * timing reveals how many chars matched.
 * 
 * checking if "/api/v1/admin/secret" starts with "/api":
 * - try "/xyz": fails fast (no match)
 * - try "/api": takes longer (4 chars match)
 * - try "/api/v1": even longer (7 chars match)
 * 
 * used in path checks, api validation, route matching
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

// bad: strncmp exits on first difference
int check_prefix_vulnerable(const char* string, const char* prefix) {
    printf("checking if '%s' starts with '%s'\n", string, prefix);
    
    // strncmp bails out as soon as chars differ
    size_t prefix_len = strlen(prefix);
    return strncmp(string, prefix, prefix_len) == 0;
}

// simulate path authorization with vulnerable prefix checking
int authorize_file_access_vulnerable(const char* requested_path) {
    // list of allowed path prefixes
    const char* allowed_prefixes[] = {
        "/public/",
        "/uploads/user/",
        "/api/v1/public/",
        "/static/assets/",
        "/downloads/shared/"
    };
    
    printf("authorizing access to: %s\n", requested_path);
    
    // check each allowed prefix - vulnerable to timing attacks
    for (int i = 0; i < 5; i++) {
        if (check_prefix_vulnerable(requested_path, allowed_prefixes[i])) {
            printf("access granted - matches allowed prefix: %s\n", allowed_prefixes[i]);
            return 1;
        }
    }
    
    printf("access denied - no matching prefix found\n");
    return 0;
}

// simulate api key validation with prefix checking
int validate_api_key_vulnerable(const char* api_key) {
    // different key prefixes for different service tiers
    const char* valid_prefixes[] = {
        "sk_live_",        // production keys
        "pk_test_",        // test public keys  
        "sk_test_",        // test secret keys
        "webhook_",        // webhook signing keys
        "connect_"         // oauth connect keys
    };
    
    printf("validating api key: %.15s...\n", api_key);
    
    // check each valid prefix - timing reveals key type
    for (int i = 0; i < 5; i++) {
        if (check_prefix_vulnerable(api_key, valid_prefixes[i])) {
            printf("api key valid - type: %s\n", valid_prefixes[i]);
            return 1;
        }
    }
    
    printf("api key invalid - unknown prefix\n");
    return 0;
}

// demonstrate timing differences based on prefix match length
void prefix_timing_demo() {
    const char* secret_string = "/api/v1/admin/users/sensitive-data";
    
    printf("\n=== prefix timing attack demonstration ===\n");
    printf("secret string: %s\n", secret_string);
    printf("measuring timing for different prefix guesses...\n\n");
    
    // attack attempts with increasing prefix correctness
    const char* attack_prefixes[] = {
        "x",                    // no match - very fast
        "/",                    // 1 char match - slightly slower
        "/a",                   // 2 char match - slower  
        "/ap",                  // 3 char match - even slower
        "/api",                 // 4 char match - much slower
        "/api/",                // 5 char match - very slow
        "/api/v1",              // 8 char match - extremely slow
        "/api/v1/admin",        // 14 char match - slowest
        "/wrong/path",          // no match but longer - fast
        "/api/v2/admin"         // partial match then differ - medium
    };
    
    for (int i = 0; i < 10; i++) {
        struct timespec start, end;
        
        // measure prefix checking time
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // run multiple iterations to amplify timing differences
        for (int j = 0; j < 50000; j++) {
            check_prefix_vulnerable(secret_string, attack_prefixes[i]);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("prefix: %-18s | time: %8lld ns | match chars: %zu\n", 
               attack_prefixes[i], duration, 
               // estimate matching characters for display
               strlen(attack_prefixes[i]) <= strlen(secret_string) ?
               strlen(attack_prefixes[i]) : 0);
    }
    
    printf("\nvulnerability: timing increases with prefix match length!\n");
    printf("attackers can discover secret strings character by character.\n");
}

// demonstrate api key enumeration through timing
void api_key_enumeration_demo() {
    printf("\n=== api key enumeration attack demo ===\n");
    printf("using timing to discover valid api key prefixes...\n\n");
    
    const char* test_keys[] = {
        "invalid_key_123",           // invalid - fast (no prefix match)
        "sk_live_abcdef123456",      // valid production key - slow
        "pk_test_xyz789",            // valid test key - slow  
        "random_key_456",            // invalid - fast
        "sk_test_dev_environment",   // valid test secret key - slow
        "webhook_endpoint_abc",      // valid webhook key - slow
        "fake_prefix_999",           // invalid - fast
        "connect_oauth_token123"     // valid connect key - slow
    };
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // single validation to see timing difference
        int valid = validate_api_key_vulnerable(test_keys[i]);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("key: %-25s | time: %6lld ns | valid: %s\n", 
               test_keys[i], duration, valid ? "yes" : "no");
    }
    
    printf("\nvulnerability: timing reveals which keys have valid prefixes!\n");
    printf("attackers can enumerate key types and focus on valid formats.\n");
}

// demonstrate file path traversal detection bypass
void path_traversal_timing_demo() {
    printf("\n=== path traversal timing attack demo ===\n");
    printf("using timing to discover valid path prefixes for traversal...\n\n");
    
    const char* traversal_attempts[] = {
        "../../../etc/passwd",           // invalid - fast
        "/public/../../../etc/passwd",   // starts valid then invalid - medium  
        "/uploads/user/../../etc/passwd", // longer valid prefix - slower
        "/api/v1/public/../../../etc/",  // even longer valid prefix - very slow
        "/static/assets/../../../etc/",  // valid prefix then traversal - slow
        "/invalid/path/traversal",       // invalid from start - fast
        "/public/",                      // completely valid - medium
        "/uploads/user/data.txt"         // completely valid - medium
    };
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        int authorized = authorize_file_access_vulnerable(traversal_attempts[i]);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("path: %-35s | time: %6lld ns | authorized: %s\n",
               traversal_attempts[i], duration, authorized ? "yes" : "no");
    }
    
    printf("\nvulnerability: timing reveals valid path prefixes!\n");
    printf("attackers can discover allowed paths and craft better traversal attacks.\n");
}

int main() {
    printf("vulnerable string prefix matching demo\n");
    printf("======================================\n\n");
    
    // simulate some file access attempts
    authorize_file_access_vulnerable("/public/documents/report.pdf");
    authorize_file_access_vulnerable("/private/admin/secrets.txt");
    
    printf("\n");
    
    // simulate some api key validations
    validate_api_key_vulnerable("sk_live_abcdef1234567890");
    validate_api_key_vulnerable("invalid_key_format");
    
    // demonstrate prefix timing attack
    prefix_timing_demo();
    
    // demonstrate api key enumeration
    api_key_enumeration_demo();
    
    // demonstrate path traversal timing
    path_traversal_timing_demo();
    
    printf("\nto fix this vulnerability, use constant-time prefix matching!\n");
    printf("see prefix_matching_secure.c for the safe implementation.\n");
    
    return 0;
}