#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/provider.h>
#include <time.h>
#include <math.h>
#include <plplot/plplot.h>

#define NUM_ITERATIONS 50
#define IGNORE_PERCENTAGE 0.2
#define IQR_MULTIPLIER 1.5
#define CPU_CLOCK_FREQUENCY 2.4e9 // 2.4 GHz in cycles per second

// Function to generate ECDH key pair for a specific curve and return the time taken
unsigned long long generate_ecdh_key(const char *curve_name, EVP_PKEY **pkey) {
    EVP_PKEY_CTX *ctx = NULL;
    struct timespec start_time, end_time;
    unsigned long long elapsed_time_ns;
    int curve_nid;

    // Get the NID for the curve name
    curve_nid = OBJ_sn2nid(curve_name);
    if (curve_nid == NID_undef) {
        fprintf(stderr, "Unknown curve name: %s\n", curve_name);
        exit(EXIT_FAILURE);
    }

    // Measure the start time for key generation
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Create a new EVP_PKEY context for ECDH
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for ECDH\n");
        exit(EXIT_FAILURE);
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize keygen for ECDH\n");
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set the curve name
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
        fprintf(stderr, "Failed to set curve name: %s\n", curve_name);
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx, pkey) <= 0) {
        fprintf(stderr, "Failed to generate ECDH key pair for curve: %s\n", curve_name);
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Measure the end time for key generation
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    elapsed_time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
    unsigned long long cycles = elapsed_time_ns * CPU_CLOCK_FREQUENCY / 1e9; // Convert nanoseconds to seconds and multiply by frequency

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

void plot_cycles(unsigned long long cycles[], const char *curve, const char *operation) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_%s_plot.svg", curve, operation);

    plsdev("svg"); // Use the SVG backend for plotting
    plsfnam(filename); // Set the output file name
    plinit();

    // Calculate the number of runs to ignore
    int ignore_runs = NUM_ITERATIONS * IGNORE_PERCENTAGE;

    // Find the maximum cycle count after ignoring the first 20%
    unsigned long long max_cycles = 0;
    for (int i = ignore_runs; i < NUM_ITERATIONS - ignore_runs; i++) {
        if (cycles[i] > max_cycles) {
            max_cycles = cycles[i];
        }
    }

    plenv(ignore_runs + 1, NUM_ITERATIONS - ignore_runs, 0, 1.1 * max_cycles, 0, 0);
    pllab("Run", "Cycles", operation);

    PLFLT x[NUM_ITERATIONS - 2 * ignore_runs];
    PLFLT y[NUM_ITERATIONS - 2 * ignore_runs];

    for (int i = ignore_runs; i < NUM_ITERATIONS - ignore_runs; i++) {
        x[i - ignore_runs] = i + 1;
        y[i - ignore_runs] = cycles[i];
    }

    plline(NUM_ITERATIONS - 2 * ignore_runs, x, y);

    plend();
}

int main(int argc, char *argv[]) {
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    EVP_PKEY *ecdh_key = NULL;
    unsigned long long keygen_cycles[NUM_ITERATIONS];
    double keygen_mean, keygen_stddev;
    const char *curves[] = {"prime256v1", "secp384r1", "secp521r1"};

    // Load the default provider
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        fprintf(stderr, "Failed to create OpenSSL library context\n");
        exit(EXIT_FAILURE);
    }
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        fprintf(stderr, "Failed to load default provider\n");
        OSSL_LIB_CTX_free(libctx);
        exit(EXIT_FAILURE);
    }

    for (int c = 0; c < 3; c++) {
        const char *curve = curves[c];
        printf("Running tests for curve: %s\n", curve);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            // Key Generation
            keygen_cycles[i] = generate_ecdh_key(curve, &ecdh_key);

            // Clean up
            if (ecdh_key) {
                EVP_PKEY_free(ecdh_key);
                ecdh_key = NULL;
            }
        }

        // Calculate statistics
        calculate_statistics(keygen_cycles, NUM_ITERATIONS, &keygen_mean, &keygen_stddev);

        // Calculate the percentage of standard deviation with respect to the mean
        double keygen_stddev_percentage = (keygen_stddev / keygen_mean) * 100;

        // Print results
        printf("Key Generation:\n");
        printf("  Mean: %.2f cycles\n", keygen_mean);
        printf("  Standard Deviation: %.2f cycles\n", keygen_stddev);
        printf("  Standard Deviation Percentage: %.2f%%\n", keygen_stddev_percentage);

        // Plot the cycles
        plot_cycles(keygen_cycles, curve, "keygen");
    }

    OSSL_PROVIDER_unload(default_prov);
    OSSL_LIB_CTX_free(libctx);

    return 0;
}
