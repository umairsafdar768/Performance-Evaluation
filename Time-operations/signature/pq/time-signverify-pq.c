#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <time.h>
#include <openssl/provider.h>
#include <oqs/oqs.h>
#include <math.h>
#include <plplot/plplot.h>

#define NUM_RUNS 350
#define IGNORE_PERCENTAGE 0.2
#define IQR_MULTIPLIER 1.5

// Function to generate key pair for the specified algorithm
EVP_PKEY* generate_key(const char *alg) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    // Create a new EVP_PKEY context
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for %s\n", alg);
        exit(EXIT_FAILURE);
    }

    // Generate the key pair
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize keygen for %s\n", alg);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key pair for %s\n", alg);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Function to sign XML file using private key of the specified algorithm
double sign_xml(const char *alg, EVP_PKEY *pkey, const unsigned char *xml_data, long xml_size, unsigned char **sig, unsigned int *sig_len) {
    // Measure the start time
    clock_t start_time = clock();

    // Sign the XML data
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_SignInit(md_ctx, EVP_get_digestbyname("sha256"));
    EVP_SignUpdate(md_ctx, xml_data, xml_size);
    *sig = (unsigned char *)malloc(EVP_PKEY_size(pkey));
    if (!EVP_SignFinal(md_ctx, *sig, sig_len, pkey)) {
        fprintf(stderr, "Failed to sign the XML data\n");
        exit(EXIT_FAILURE);
    }

    // Measure the end time
    clock_t end_time = clock();
    double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

    // Clean up
    EVP_MD_CTX_free(md_ctx);

    return time_taken;
}

// Function to verify signature of XML file using public key of the specified algorithm
double verify_signature(const char *alg, EVP_PKEY *pkey, const unsigned char *xml_data, long xml_size, const unsigned char *signature, int signature_len) {
    // Measure the start time
    clock_t start_time = clock();

    // Verify the signature
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(md_ctx, EVP_get_digestbyname("sha256"));
    EVP_VerifyUpdate(md_ctx, xml_data, xml_size);
    int verify_result = EVP_VerifyFinal(md_ctx, signature, signature_len, pkey);

    // Measure the end time
    clock_t end_time = clock();
    double time_taken = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

    // Clean up
    EVP_MD_CTX_free(md_ctx);

    if (verify_result != 1) {
        fprintf(stderr, "Failed to verify the signature for algorithm %s\n", alg);
        exit(EXIT_FAILURE);
    }

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

void plot_times(double times[], const char *algorithm, const char *operation) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_%s_plot.svg", algorithm, operation);

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
    pllab("Run", "Time (microseconds)", operation);

    PLFLT x[NUM_RUNS - 2 * ignore_runs];
    PLFLT y[NUM_RUNS - 2 * ignore_runs];

    for (int i = ignore_runs; i < NUM_RUNS - ignore_runs; i++) {
        x[i - ignore_runs] = i + 1;
        y[i - ignore_runs] = times_microseconds[i];
    }

    plline(NUM_RUNS - 2 * ignore_runs, x, y);

    plend();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <xml_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *xml_file = argv[1];

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqsprov) {
        fprintf(stderr, "Failed to load OQS provider\n");
        exit(EXIT_FAILURE);
    }

    // Read XML file
    FILE *xml_fp = fopen(xml_file, "r");
    if (!xml_fp) {
        fprintf(stderr, "Failed to open XML file %s\n", xml_file);
        exit(EXIT_FAILURE);
    }
    fseek(xml_fp, 0, SEEK_END);
    long xml_size = ftell(xml_fp);
    rewind(xml_fp);
    unsigned char *xml_data = (unsigned char *)malloc(xml_size + 1);
    fread(xml_data, 1, xml_size, xml_fp);
    fclose(xml_fp);

    // Algorithms to test
    const char *algorithms[] = {
        "dilithium2", 
        "dilithium3", 
        "dilithium5",
        "falcon512",
        "falcon1024",
        "sphincssha2128fsimple",
        "sphincssha2128ssimple",
        "sphincssha2192fsimple",
        "sphincsshake128fsimple"
    };
    int num_algorithms = sizeof(algorithms) / sizeof(algorithms[0]);

    // Generate keys for all specified algorithms
    EVP_PKEY* keys[num_algorithms];
    for (int i = 0; i < num_algorithms; i++) {
        keys[i] = generate_key(algorithms[i]);
    }

    // Sign XML file and verify signature using each algorithm
    for (int i = 0; i < num_algorithms; i++) {
        double sign_times[NUM_RUNS];
        double verify_times[NUM_RUNS];

        for (int j = 0; j < NUM_RUNS; j++) {
            unsigned int sig_len;
            unsigned char *signature;
            sign_times[j] = sign_xml(algorithms[i], keys[i], xml_data, xml_size, &signature, &sig_len);
            verify_times[j] = verify_signature(algorithms[i], keys[i], xml_data, xml_size, signature, sig_len);
            free(signature);
        }

        double mean_sign, std_dev_sign;
        double mean_verify, std_dev_verify;
        calculate_statistics(sign_times, NUM_RUNS, &mean_sign, &std_dev_sign);
        calculate_statistics(verify_times, NUM_RUNS, &mean_verify, &std_dev_verify);

        // Convert mean and standard deviation to microseconds
        mean_sign *= 1000000;
        std_dev_sign *= 1000000;
        mean_verify *= 1000000;
        std_dev_verify *= 1000000;

        // Calculate the percentage of standard deviation with respect to the mean
        double std_dev_percentage_sign = (std_dev_sign / mean_sign) * 100;
        double std_dev_percentage_verify = (std_dev_verify / mean_verify) * 100;

        printf("Algorithm: %s\n", algorithms[i]);
        printf("Signing - Mean time: %f microseconds, Standard deviation: %f microseconds, Standard deviation percentage: %f%%\n", mean_sign, std_dev_sign, std_dev_percentage_sign);
        printf("Verifying - Mean time: %f microseconds, Standard deviation: %f microseconds, Standard deviation percentage: %f%%\n", mean_verify, std_dev_verify, std_dev_percentage_verify);
        printf("\n");

        // Plot the times
        plot_times(sign_times, algorithms[i], "signing");
        plot_times(verify_times, algorithms[i], "verifying");
    }

    // Clean up
    for (int i = 0; i < num_algorithms; i++) {
        EVP_PKEY_free(keys[i]);
    }
    OSSL_PROVIDER_unload(oqsprov);
    EVP_cleanup();

    free(xml_data);

    return 0;
}
