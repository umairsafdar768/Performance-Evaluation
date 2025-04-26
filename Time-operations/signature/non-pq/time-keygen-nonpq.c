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

#define NUM_RUNS 350
#define IGNORE_PERCENTAGE 0.2
#define IQR_MULTIPLIER 1.5

double generate_rsa_key(int bits) {
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
    clock_t start_time = clock();

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
    clock_t end_time = clock();
    double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

    // Clean up
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return time_taken;
}

double generate_ec_key(const char *curve_name) {
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
    clock_t start_time = clock();

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
    clock_t end_time = clock();
    double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

    // Clean up
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return time_taken;
}

void calculate_statistics(double times[], int num_runs, double *mean, double *std_dev) {
    double sum = 0.0;
    double sum_sq_diff = 0.0;
    int ignore_runs = num_runs * IGNORE_PERCENTAGE;
    int effective_runs = num_runs - 2 * ignore_runs;

    // Sort the times to calculate the IQR
    double sorted_times[num_runs];
    for (int i = 0; i < num_runs; i++) {
        sorted_times[i] = times[i];
    }
    for (int i = 0; i < num_runs - 1; i++) {
        for (int j = i + 1; j < num_runs; j++) {
            if (sorted_times[i] > sorted_times[j]) {
                double temp = sorted_times[i];
                sorted_times[i] = sorted_times[j];
                sorted_times[j] = temp;
            }
        }
    }

    // Calculate the IQR
    double q1 = sorted_times[ignore_runs + (effective_runs / 4)];
    double q3 = sorted_times[ignore_runs + (3 * effective_runs / 4)];
    double iqr = q3 - q1;

    // Calculate the mean and standard deviation excluding outliers
    for (int i = ignore_runs; i < num_runs - ignore_runs; i++) {
        if (sorted_times[i] >= q1 - IQR_MULTIPLIER * iqr && sorted_times[i] <= q3 + IQR_MULTIPLIER * iqr) {
            sum += sorted_times[i];
        }
    }

    int valid_runs = 0;
    for (int i = ignore_runs; i < num_runs - ignore_runs; i++) {
        if (sorted_times[i] >= q1 - IQR_MULTIPLIER * iqr && sorted_times[i] <= q3 + IQR_MULTIPLIER * iqr) {
            valid_runs++;
        }
    }

    *mean = sum / valid_runs;

    for (int i = ignore_runs; i < num_runs - ignore_runs; i++) {
        if (sorted_times[i] >= q1 - IQR_MULTIPLIER * iqr && sorted_times[i] <= q3 + IQR_MULTIPLIER * iqr) {
            sum_sq_diff += (sorted_times[i] - *mean) * (sorted_times[i] - *mean);
        }
    }

    *std_dev = sqrt(sum_sq_diff / valid_runs);
}

void plot_times(double times[], const char *algorithm) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_plot.svg", algorithm);

    plsdev("svg"); // Use the SVG backend for plotting
    plsfnam(filename); // Set the output file name
    plinit();

    // Convert times to microseconds
    double times_microseconds[NUM_RUNS];
    for (int i = 0; i < NUM_RUNS; i++) {
        times_microseconds[i] = times[i] * 1000000;
    }

    // Calculate the number of runs to ignore
    int ignore_runs = NUM_RUNS * IGNORE_PERCENTAGE;

    // Find the maximum time in microseconds after ignoring the first 20%
    double max_time = 0.0;
    for (int i = ignore_runs; i < NUM_RUNS - ignore_runs; i++) {
        if (times_microseconds[i] > max_time) {
            max_time = times_microseconds[i];
        }
    }

    plenv(ignore_runs + 1, NUM_RUNS - ignore_runs, 0, 1.1 * max_time, 0, 0);
    pllab("Run", "Time (microseconds)", algorithm);

    PLFLT x[NUM_RUNS - 2 * ignore_runs];
    PLFLT y[NUM_RUNS - 2 * ignore_runs];

    for (int i = ignore_runs; i < NUM_RUNS - ignore_runs; i++) {
        x[i - ignore_runs] = i + 1;
        y[i - ignore_runs] = times_microseconds[i];
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
        double times[NUM_RUNS];
        for (int j = 0; j < NUM_RUNS; j++) {
            times[j] = generate_rsa_key(rsa_key_sizes[i]);
        }

        double mean, std_dev;
        calculate_statistics(times, NUM_RUNS, &mean, &std_dev);

        // Convert mean and standard deviation to microseconds
        mean *= 1000000;
        std_dev *= 1000000;

        // Calculate the percentage of standard deviation with respect to the mean
        double std_dev_percentage = (std_dev / mean) * 100;

        printf("RSA-%d key generation:\n", rsa_key_sizes[i]);
        printf("Mean time: %f microseconds\n", mean);
        printf("Standard deviation: %f microseconds\n", std_dev);
        printf("Standard deviation percentage: %f%%\n", std_dev_percentage);
        printf("\n");

        // Plot the times
        char plot_title[256];
        snprintf(plot_title, sizeof(plot_title), "RSA-%d", rsa_key_sizes[i]);
        plot_times(times, plot_title);
    }

    // EC key generation timings
    const char *ec_curves[] = {"prime256v1", "secp384r1", "secp521r1"};
    int num_ec_curves = sizeof(ec_curves) / sizeof(ec_curves[0]);

    for (int i = 0; i < num_ec_curves; i++) {
        double times[NUM_RUNS];
        for (int j = 0; j < NUM_RUNS; j++) {
            times[j] = generate_ec_key(ec_curves[i]);
        }

        double mean, std_dev;
        calculate_statistics(times, NUM_RUNS, &mean, &std_dev);

        // Convert mean and standard deviation to microseconds
        mean *= 1000000;
        std_dev *= 1000000;

        // Calculate the percentage of standard deviation with respect to the mean
        double std_dev_percentage = (std_dev / mean) * 100;

        printf("EC key generation (%s):\n", ec_curves[i]);
        printf("Mean time: %f microseconds\n", mean);
        printf("Standard deviation: %f microseconds\n", std_dev);
        printf("Standard deviation percentage: %f%%\n", std_dev_percentage);
        printf("\n");

        // Plot the times
        plot_times(times, ec_curves[i]);
    }

    // Clean up OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
