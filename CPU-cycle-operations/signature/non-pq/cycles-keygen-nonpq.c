#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <time.h>
#include <math.h>
#include <plplot/plplot.h>

#define NUM_RUNS 50
#define IGNORE_PERCENTAGE 0.2
#define IQR_MULTIPLIER 1.5
#define CPU_CLOCK_FREQUENCY 2.4e9 // 2.4 GHz in cycles per second

unsigned long long generate_rsa_key(int bits) {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    // Create a new context for key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for RSA\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Measure the start time
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Generate the RSA key pair
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize RSA keygen\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "Failed to set RSA key size\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate RSA key pair\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Measure the end time
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    unsigned long long elapsed_time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
    unsigned long long cycles = elapsed_time_ns * CPU_CLOCK_FREQUENCY / 1e9; // Convert nanoseconds to seconds and multiply by frequency

    // Clean up
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return cycles;
}

unsigned long long generate_ec_key(const char *curve_name) {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    int curve_nid = OBJ_txt2nid(curve_name);

    if (curve_nid == NID_undef) {
        fprintf(stderr, "Unknown curve name: %s\n", curve_name);
        exit(EXIT_FAILURE);
    }

    // Create a new context for key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for EC\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Measure the start time
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Generate the EC key pair
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize EC keygen\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
        fprintf(stderr, "Failed to set EC curve\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate EC key pair\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Measure the end time
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    unsigned long long elapsed_time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
    unsigned long long cycles = elapsed_time_ns * CPU_CLOCK_FREQUENCY / 1e9; // Convert nanoseconds to seconds and multiply by frequency

    // Clean up
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return cycles;
}

void calculate_statistics(unsigned long long cycles[], int num_runs, double *mean, double *std_dev) {
    double sum = 0.0;
    double sum_sq_diff = 0.0;
    int ignore_runs = num_runs * IGNORE_PERCENTAGE;
    int effective_runs = num_runs - 2 * ignore_runs;

    // Sort the cycles to calculate the IQR
    unsigned long long sorted_cycles[num_runs];
    for (int i = 0; i < num_runs; i++) {
        sorted_cycles[i] = cycles[i];
    }
    for (int i = 0; i < num_runs - 1; i++) {
        for (int j = i + 1; j < num_runs; j++) {
            if (sorted_cycles[i] > sorted_cycles[j]) {
                unsigned long long temp = sorted_cycles[i];
                sorted_cycles[i] = sorted_cycles[j];
                sorted_cycles[j] = temp;
            }
        }
    }

    // Calculate the IQR
    double q1 = sorted_cycles[ignore_runs + (effective_runs / 4)];
    double q3 = sorted_cycles[ignore_runs + (3 * effective_runs / 4)];
    double iqr = q3 - q1;

    // Calculate the mean and standard deviation excluding outliers
    for (int i = ignore_runs; i < num_runs - ignore_runs; i++) {
        if (sorted_cycles[i] >= q1 - IQR_MULTIPLIER * iqr && sorted_cycles[i] <= q3 + IQR_MULTIPLIER * iqr) {
            sum += sorted_cycles[i];
        }
    }

    int valid_runs = 0;
    for (int i = ignore_runs; i < num_runs - ignore_runs; i++) {
        if (sorted_cycles[i] >= q1 - IQR_MULTIPLIER * iqr && sorted_cycles[i] <= q3 + IQR_MULTIPLIER * iqr) {
            valid_runs++;
        }
    }

    *mean = sum / valid_runs;

    for (int i = ignore_runs; i < num_runs - ignore_runs; i++) {
        if (sorted_cycles[i] >= q1 - IQR_MULTIPLIER * iqr && sorted_cycles[i] <= q3 + IQR_MULTIPLIER * iqr) {
            sum_sq_diff += (sorted_cycles[i] - *mean) * (sorted_cycles[i] - *mean);
        }
    }

    *std_dev = sqrt(sum_sq_diff / valid_runs);
}

void plot_cycles(unsigned long long cycles[], const char *algorithm) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_plot.svg", algorithm);

    plsdev("svg"); // Use the SVG backend for plotting
    plsfnam(filename); // Set the output file name
    plinit();

    // Calculate the number of runs to ignore
    int ignore_runs = NUM_RUNS * IGNORE_PERCENTAGE;

    // Find the maximum cycle count after ignoring the first 20%
    unsigned long long max_cycles = 0;
    for (int i = ignore_runs; i < NUM_RUNS - ignore_runs; i++) {
        if (cycles[i] > max_cycles) {
            max_cycles = cycles[i];
        }
    }

    plenv(ignore_runs + 1, NUM_RUNS - ignore_runs, 0, 1.1 * max_cycles, 0, 0);
    pllab("Run", "Cycles", algorithm);

    PLFLT x[NUM_RUNS - 2 * ignore_runs];
    PLFLT y[NUM_RUNS - 2 * ignore_runs];

    for (int i = ignore_runs; i < NUM_RUNS - ignore_runs; i++) {
        x[i - ignore_runs] = i + 1;
        y[i - ignore_runs] = cycles[i];
    }

    plline(NUM_RUNS - 2 * ignore_runs, x, y);

    plend();
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // RSA key generation timings
    int rsa_key_sizes[] = {2048, 3072, 4096};
    int num_rsa_key_sizes = sizeof(rsa_key_sizes) / sizeof(rsa_key_sizes[0]);

    for (int i = 0; i < num_rsa_key_sizes; i++) {
        unsigned long long cycles[NUM_RUNS];
        for (int j = 0; j < NUM_RUNS; j++) {
            cycles[j] = generate_rsa_key(rsa_key_sizes[i]);
        }

        double mean, std_dev;
        calculate_statistics(cycles, NUM_RUNS, &mean, &std_dev);

        // Calculate the percentage of standard deviation with respect to the mean
        double std_dev_percentage = (std_dev / mean) * 100;

        printf("RSA-%d key generation:\n", rsa_key_sizes[i]);
        printf("Mean cycles: %f\n", mean);
        printf("Standard deviation: %f\n", std_dev);
        printf("Standard deviation percentage: %f%%\n", std_dev_percentage);
        printf("\n");

        // Plot the cycles
        char plot_title[256];
        snprintf(plot_title, sizeof(plot_title), "RSA-%d", rsa_key_sizes[i]);
        plot_cycles(cycles, plot_title);
    }

    // EC key generation timings
    const char *ec_curves[] = {"prime256v1", "secp384r1", "secp521r1"};
    int num_ec_curves = sizeof(ec_curves) / sizeof(ec_curves[0]);

    for (int i = 0; i < num_ec_curves; i++) {
        unsigned long long cycles[NUM_RUNS];
        for (int j = 0; j < NUM_RUNS; j++) {
            cycles[j] = generate_ec_key(ec_curves[i]);
        }

        double mean, std_dev;
        calculate_statistics(cycles, NUM_RUNS, &mean, &std_dev);

        // Calculate the percentage of standard deviation with respect to the mean
        double std_dev_percentage = (std_dev / mean) * 100;

        printf("EC key generation (%s):\n", ec_curves[i]);
        printf("Mean cycles: %f\n", mean);
        printf("Standard deviation: %f\n", std_dev);
        printf("Standard deviation percentage: %f%%\n", std_dev_percentage);
        printf("\n");

        // Plot the cycles
        plot_cycles(cycles, ec_curves[i]);
    }

    // Clean up OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
