#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <time.h>
#include <math.h>
#include <plplot/plplot.h>

#define NUM_ITERATIONS 50
#define IGNORE_PERCENTAGE 0.2
#define IQR_MULTIPLIER 1.5
#define CPU_CLOCK_FREQUENCY 2.4e9 // 2.4 GHz in cycles per second

// Function to generate Kyber key pair for a specific variant
EVP_PKEY* generate_kyber_key(const char *variant) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    // Create a new EVP_PKEY context for Kyber
    ctx = EVP_PKEY_CTX_new_from_name(NULL, variant, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for Kyber variant: %s\n", variant);
        exit(EXIT_FAILURE);
    }

    // Generate the key pair
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize keygen for Kyber variant: %s\n", variant);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate Kyber key pair for variant: %s\n", variant);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Function to encapsulate a key using the public key
void encapsulate_key(EVP_PKEY *pkey, unsigned char **out, size_t *outlen, unsigned char **sec, size_t *seclen) {
    EVP_PKEY_CTX *ctx = NULL;

    // Create a new EVP_PKEY_CTX for encapsulation
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for encapsulation\n");
        exit(EXIT_FAILURE);
    }

    // Initialize encapsulation
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        fprintf(stderr, "Failed to initialize encapsulation\n");
        exit(EXIT_FAILURE);
    }

    // Get lengths for output and secret
    if (EVP_PKEY_encapsulate(ctx, NULL, outlen, NULL, seclen) <= 0) {
        fprintf(stderr, "Failed to determine output lengths\n");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for output and secret
    *out = OPENSSL_malloc(*outlen);
    *sec = OPENSSL_malloc(*seclen);

    if (!*out || !*sec) {
        fprintf(stderr, "Failed to allocate memory for encapsulation\n");
        exit(EXIT_FAILURE);
    }

    // Perform encapsulation
    if (EVP_PKEY_encapsulate(ctx, *out, outlen, *sec, seclen) <= 0) {
        fprintf(stderr, "Failed to encapsulate key\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
}

// Function to decapsulate a key using the private key
void decapsulate_key(EVP_PKEY *pkey, const unsigned char *in, size_t inlen, unsigned char *sec, size_t seclen) {
    EVP_PKEY_CTX *ctx = NULL;

    // Create a new EVP_PKEY_CTX for decapsulation
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for decapsulation\n");
        exit(EXIT_FAILURE);
    }

    // Initialize decapsulation
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        fprintf(stderr, "Failed to initialize decapsulation\n");
        exit(EXIT_FAILURE);
    }

    // Perform decapsulation
    if (EVP_PKEY_decapsulate(ctx, sec, &seclen, in, inlen) <= 0) {
        fprintf(stderr, "Failed to decapsulate key\n");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
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

void plot_cycles(unsigned long long cycles[], const char *algorithm, const char *operation) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_%s_plot.svg", algorithm, operation);

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
    OSSL_PROVIDER *oqsprov = NULL;
    EVP_PKEY *kyber_key = NULL;
    unsigned char *ciphertext = NULL, *secret_enc = NULL, *secret_dec = NULL;
    size_t ciphertext_len, secret_len;
    struct timespec start_time, end_time;
    unsigned long long keygen_cycles[NUM_ITERATIONS], encaps_cycles[NUM_ITERATIONS], decaps_cycles[NUM_ITERATIONS];
    double keygen_mean, keygen_stddev, encaps_mean, encaps_stddev, decaps_mean, decaps_stddev;
    const char *variants[] = {"kyber512", "kyber768", "kyber1024"};

    // Load the OQS provider
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        fprintf(stderr, "Failed to create OpenSSL library context\n");
        exit(EXIT_FAILURE);
    }
    oqsprov = OSSL_PROVIDER_load(libctx, "oqsprovider");
    if (!oqsprov) {
        fprintf(stderr, "Failed to load OQS provider\n");
        exit(EXIT_FAILURE);
    }

    for (int v = 0; v < 3; v++) {
        const char *variant = variants[v];
        printf("Running tests for variant: %s\n", variant);

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            // Key Generation
            clock_gettime(CLOCK_MONOTONIC, &start_time);
            kyber_key = generate_kyber_key(variant);
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            unsigned long long elapsed_time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
            keygen_cycles[i] = elapsed_time_ns * CPU_CLOCK_FREQUENCY / 1e9; // Convert nanoseconds to seconds and multiply by frequency

            // Encapsulation
            clock_gettime(CLOCK_MONOTONIC, &start_time);
            encapsulate_key(kyber_key, &ciphertext, &ciphertext_len, &secret_enc, &secret_len);
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            elapsed_time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
            encaps_cycles[i] = elapsed_time_ns * CPU_CLOCK_FREQUENCY / 1e9; // Convert nanoseconds to seconds and multiply by frequency

            // Decapsulation
            secret_dec = OPENSSL_malloc(secret_len);
            if (!secret_dec) {
                fprintf(stderr, "Failed to allocate memory for decapsulation\n");
                exit(EXIT_FAILURE);
            }
            clock_gettime(CLOCK_MONOTONIC, &start_time);
            decapsulate_key(kyber_key, ciphertext, ciphertext_len, secret_dec, secret_len);
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            elapsed_time_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
            decaps_cycles[i] = elapsed_time_ns * CPU_CLOCK_FREQUENCY / 1e9; // Convert nanoseconds to seconds and multiply by frequency

            // Clean up
            EVP_PKEY_free(kyber_key);
            OPENSSL_free(ciphertext);
            OPENSSL_free(secret_enc);
            OPENSSL_free(secret_dec);
        }

        // Calculate statistics
        calculate_statistics(keygen_cycles, NUM_ITERATIONS, &keygen_mean, &keygen_stddev);
        calculate_statistics(encaps_cycles, NUM_ITERATIONS, &encaps_mean, &encaps_stddev);
        calculate_statistics(decaps_cycles, NUM_ITERATIONS, &decaps_mean, &decaps_stddev);

        // Calculate the percentage of standard deviation with respect to the mean
        double keygen_stddev_percentage = (keygen_stddev / keygen_mean) * 100;
        double encaps_stddev_percentage = (encaps_stddev / encaps_mean) * 100;
        double decaps_stddev_percentage = (decaps_stddev / decaps_mean) * 100;

        // Print results
        printf("Key Generation:\n");
        printf("  Mean: %.2f cycles\n", keygen_mean);
        printf("  Standard Deviation: %.2f cycles\n", keygen_stddev);
        printf("  Standard Deviation Percentage: %.2f%%\n", keygen_stddev_percentage);
        printf("Encapsulation:\n");
        printf("  Mean: %.2f cycles\n", encaps_mean);
        printf("  Standard Deviation: %.2f cycles\n", encaps_stddev);
        printf("  Standard Deviation Percentage: %.2f%%\n", encaps_stddev_percentage);
        printf("Decapsulation:\n");
        printf("  Mean: %.2f cycles\n", decaps_mean);
        printf("  Standard Deviation: %.2f cycles\n", decaps_stddev);
        printf("  Standard Deviation Percentage: %.2f%%\n", decaps_stddev_percentage);

        // Plot the cycles
        plot_cycles(keygen_cycles, variant, "keygen");
        plot_cycles(encaps_cycles, variant, "encapsulation");
        plot_cycles(decaps_cycles, variant, "decapsulation");
    }

    OSSL_PROVIDER_unload(oqsprov);
    OSSL_LIB_CTX_free(libctx);

    return 0;
}
