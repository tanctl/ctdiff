/*
 * vulnerable password comparison
 * 
 * strcmp() exits early when it hits the first wrong character.
 * this means timing reveals how many chars matched.
 * 
 * attack works like this:
 * - try "a" -> fails fast
 * - try "s" -> takes longer if password starts with "s"  
 * - try "se" -> even longer if password starts with "se"
 * - keep going until you get the whole password
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

// bad: exits as soon as chars differ
int check_password_vulnerable(const char* input, const char* correct) {
    // strcmp bails out on first mismatch - creates timing leak
    return strcmp(input, correct) == 0;
}

// login system with timing bug
int authenticate_user_vulnerable(const char* username, const char* password) {
    const char* stored_password = "MySecretPassword123!";
    
    printf("authenticating user: %s\n", username);
    
    if (check_password_vulnerable(password, stored_password)) {
        printf("authentication successful!\n");
        return 1;
    } else {
        printf("authentication failed - invalid password\n");
        return 0;
    }
}

// show the attack in action
void timing_attack_demo() {
    const char* correct_password = "MySecretPassword123!";
    const char* attempts[] = {
        "wrong",                    // wrong from start
        "M",                       // first char right
        "My",                      // two chars right
        "MyS",                     // three chars right
        "MySecret",                // getting warmer...
        "MySecretPassword",        // almost there
        "MySecretPassword123!",    // bingo
        "zzzzzzzzzzzzzzzzzzzzz"    // wrong but long
    };
    
    printf("\n=== timing attack demonstration ===\n");
    printf("measuring password verification times...\n\n");
    
    for (int i = 0; i < 8; i++) {
        struct timespec start, end;
        
        // time how long it takes
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // do it many times to see the difference
        for (int j = 0; j < 10000; j++) {
            check_password_vulnerable(attempts[i], correct_password);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        long long duration = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                           (end.tv_nsec - start.tv_nsec);
        
        printf("password attempt: %-25s | time: %8lld ns | match length: %zu\n", 
               attempts[i], duration, 
               strlen(attempts[i]) < strlen(correct_password) ? 
               strlen(attempts[i]) : strlen(correct_password));
    }
    
    printf("\nvulnerability: notice how timing increases with match length!\n");
    printf("an attacker can use this to guess passwords character by character.\n");
}

int main() {
    printf("vulnerable password comparison demo\n");
    printf("===================================\n\n");
    
    // simulate some login attempts
    authenticate_user_vulnerable("alice", "wrongpass");
    authenticate_user_vulnerable("bob", "MySecretPassword123!");
    
    // demonstrate the timing attack
    timing_attack_demo();
    
    printf("\nto fix this vulnerability, use constant-time comparison!\n");
    printf("see password_comparison_secure.c for the safe implementation.\n");
    
    return 0;
}