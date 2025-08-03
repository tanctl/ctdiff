/*
 * statistical timing analysis
 * 
 * t-tests and stats to see if ct code actually works.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>

#define SAMPLE_SIZE 1000
#define MAX_ITERATIONS 50000

// simple stats functions
double mean(double* values, int n) {
    double sum = 0;
    for (int i = 0; i < n; i++) {
        sum += values[i]; 
    }
    return sum / n;
}

double variance(double* values, int n, double mean_val) {
    double sum = 0;
    for (int i = 0; i < n; i++) {
        double diff = values[i] - mean_val;
        sum += diff * diff;
    }
    return sum / (n - 1);
}

// welch's t-test for unequal variances
double welch_t_test(double* sample1, int n1, double* sample2, int n2) {
    double mean1 = mean(sample1, n1);
    double mean2 = mean(sample2, n2);
    double var1 = variance(sample1, n1, mean1);
    double var2 = variance(sample2, n2, mean2);
    
    double s = sqrt(var1/n1 + var2/n2);
    return (mean1 - mean2) / s;
}

// test functions from other examples
extern int check_password_vulnerable(const char* input, const char* correct);
extern int check_password_secure(const char* input, const char* correct);

// measure timing for a specific test case
double measure_timing(int (*func)(const char*, const char*), 
                     const char* input, const char* correct, int iterations) {
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < iterations; i++) {
        func(input, correct);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

// test if ct property holds
void test_constant_time_property() {
    printf("=== statistical timing analysis ===\n");
    
    const char* correct_password = "MySecretPassword123!";
    
    // test cases: early mismatch vs late mismatch
    const char* early_mismatch = "wrong_password";
    const char* late_mismatch = "MySecretPassword999!";
    
    double vuln_early_times[SAMPLE_SIZE];
    double vuln_late_times[SAMPLE_SIZE];
    double secure_early_times[SAMPLE_SIZE];
    double secure_late_times[SAMPLE_SIZE];
    
    printf("collecting %d timing samples...\n", SAMPLE_SIZE);
    
    // collect timing samples
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        vuln_early_times[i] = measure_timing(check_password_vulnerable, 
                                           early_mismatch, correct_password, 1000);
        vuln_late_times[i] = measure_timing(check_password_vulnerable,
                                          late_mismatch, correct_password, 1000);
        secure_early_times[i] = measure_timing(check_password_secure,
                                             early_mismatch, correct_password, 1000);
        secure_late_times[i] = measure_timing(check_password_secure,
                                            late_mismatch, correct_password, 1000);
    }
    
    // analyze vulnerable implementation
    double vuln_t_stat = welch_t_test(vuln_early_times, SAMPLE_SIZE, 
                                     vuln_late_times, SAMPLE_SIZE);
    
    // analyze secure implementation  
    double secure_t_stat = welch_t_test(secure_early_times, SAMPLE_SIZE,
                                       secure_late_times, SAMPLE_SIZE);
    
    printf("\nstatistical analysis results:\n");
    printf("vulnerable implementation:\n");
    printf("  early mismatch mean: %.2f ns\n", mean(vuln_early_times, SAMPLE_SIZE));
    printf("  late mismatch mean:  %.2f ns\n", mean(vuln_late_times, SAMPLE_SIZE));
    printf("  t-statistic: %.3f\n", vuln_t_stat);
    printf("  significant difference: %s\n", fabs(vuln_t_stat) > 2.0 ? "yes" : "no");
    
    printf("\nsecure implementation:\n");
    printf("  early mismatch mean: %.2f ns\n", mean(secure_early_times, SAMPLE_SIZE));
    printf("  late mismatch mean:  %.2f ns\n", mean(secure_late_times, SAMPLE_SIZE));
    printf("  t-statistic: %.3f\n", secure_t_stat);
    printf("  significant difference: %s\n", fabs(secure_t_stat) > 2.0 ? "yes" : "no");
    
    printf("\ninterpretation:\n");
    if (fabs(vuln_t_stat) > 2.0) {
        printf("- vulnerable version shows timing leak (t > 2.0)\n");
    }
    if (fabs(secure_t_stat) <= 2.0) {
        printf("- secure version passes ct test (t <= 2.0)\n");
    }
}

// dudect-style fixed vs random testing
void dudect_style_test() {
    printf("\n=== dudect-style fixed vs random test ===\n");
    
    const char* fixed_input = "fixed_test_input_123";
    const char* correct = "MySecretPassword123!";
    
    double fixed_times[SAMPLE_SIZE];
    double random_times[SAMPLE_SIZE];
    
    // generate random inputs
    char random_inputs[SAMPLE_SIZE][32];
    srand(time(NULL));
    
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        for (int j = 0; j < 20; j++) {
            random_inputs[i][j] = 'a' + (rand() % 26);
        }
        random_inputs[i][20] = '\0';
    }
    
    printf("measuring fixed vs random input timing...\n");
    
    // measure timings
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        fixed_times[i] = measure_timing(check_password_vulnerable,
                                      fixed_input, correct, 1000);
        random_times[i] = measure_timing(check_password_vulnerable,
                                       random_inputs[i], correct, 1000);
    }
    
    double t_stat = welch_t_test(fixed_times, SAMPLE_SIZE, 
                                random_times, SAMPLE_SIZE);
    
    printf("\nfixed vs random test results:\n");
    printf("  fixed input mean:  %.2f ns\n", mean(fixed_times, SAMPLE_SIZE));
    printf("  random input mean: %.2f ns\n", mean(random_times, SAMPLE_SIZE));
    printf("  t-statistic: %.3f\n", t_stat);
    printf("  timing leak detected: %s\n", fabs(t_stat) > 2.0 ? "yes" : "no");
}

// histogram analysis
void timing_histogram_analysis() {
    printf("\n=== timing histogram analysis ===\n");
    
    const char* correct = "MySecretPassword123!";
    const char* test_input = "MySecretPassXXXX!";
    
    double times[SAMPLE_SIZE];
    
    // collect samples
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        times[i] = measure_timing(check_password_vulnerable,
                                test_input, correct, 1000);
    }
    
    // create simple histogram (10 buckets)
    double min_time = times[0], max_time = times[0];
    for (int i = 1; i < SAMPLE_SIZE; i++) {
        if (times[i] < min_time) min_time = times[i];
        if (times[i] > max_time) max_time = times[i];
    }
    
    double bucket_size = (max_time - min_time) / 10;
    int histogram[10] = {0};
    
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        int bucket = (int)((times[i] - min_time) / bucket_size);
        if (bucket >= 10) bucket = 9;
        histogram[bucket]++;
    }
    
    printf("timing distribution histogram:\n");
    for (int i = 0; i < 10; i++) {
        printf("  %6.0f-%6.0f ns: ", min_time + i * bucket_size, 
               min_time + (i+1) * bucket_size);
        for (int j = 0; j < histogram[i] / 10; j++) {
            printf("*");
        }
        printf(" (%d samples)\n", histogram[i]);
    }
    
    double mean_val = mean(times, SAMPLE_SIZE);
    double var_val = variance(times, SAMPLE_SIZE, mean_val);
    printf("\nstatistics:\n");
    printf("  mean: %.2f ns\n", mean_val);
    printf("  variance: %.2f\n", var_val);
    printf("  std dev: %.2f ns\n", sqrt(var_val));
}

int main() {
    printf("statistical timing analysis demo\n");
    printf("================================\n\n");
    
    // run statistical tests
    test_constant_time_property();
    
    // dudect-style testing
    dudect_style_test();
    
    // histogram analysis
    timing_histogram_analysis();
    
    printf("\nnote: compile other examples first to link these functions:\n");
    printf("gcc -c password_comparison_*.c\n");
    printf("gcc -o stats_test statistical_timing_test.c password_comparison_*.o -lm\n");
    
    return 0;
}