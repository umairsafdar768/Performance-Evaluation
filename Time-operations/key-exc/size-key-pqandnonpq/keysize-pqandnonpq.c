#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <oqs/oqs.h>
#include <openssl/provider.h> // Include this header for OSSL_PROVIDER functions

// Function to generate ECDH key pair for a specific curve
EVP_PKEY* generate_ecdh_key(const char *curve_name) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int curve_nid;

    // Get the NID for the curve name
    curve_nid = OBJ_sn2nid(curve_name);
    if (curve_nid == NID_undef) {
        fprintf(stderr, "Unknown curve name: %s\n", curve_name);
        exit(EXIT_FAILURE);
    }

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
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate ECDH key pair for curve: %s\n", curve_name);
        EVP_PKEY_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Function to display key sizes
void display_key_sizes(EVP_PKEY *pkey, const char *alg) {
    int priv_key_len = i2d_PrivateKey(pkey, NULL);
    int pub_key_len = i2d_PUBKEY(pkey, NULL);

    printf("Algorithm: %s\n", alg);
    printf("Private key size: %d bytes\n", priv_key_len);
    printf("Public key size: %d bytes\n", pub_key_len);
}

// Function to generate Kyber key pair and display sizes
void generate_kyber_key(const char *alg) {
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create OQS_KEM for %s\n", alg);
        exit(EXIT_FAILURE);
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Failed to generate key pair for %s\n", alg);
        OQS_KEM_free(kem);
        free(public_key);
        free(secret_key);
        exit(EXIT_FAILURE);
    }

    printf("Algorithm: %s\n", alg);
    printf("Private key size: %zu bytes\n", kem->length_secret_key);
    printf("Public key size: %zu bytes\n", kem->length_public_key);

    OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
}

int main() {
    // Initialize OpenSSL
    OPENSSL_init_crypto(0, NULL);
    OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqsprov) {
        fprintf(stderr, "Failed to load OQS provider\n");
        exit(EXIT_FAILURE);
    }

    // ECDH curves to test
    const char *ecdh_curves[] = {"prime256v1", "secp384r1", "secp521r1"};
    int num_ecdh_curves = sizeof(ecdh_curves) / sizeof(ecdh_curves[0]);

    // Generate and display ECDH key sizes
    for (int i = 0; i < num_ecdh_curves; i++) {
        EVP_PKEY *pkey = generate_ecdh_key(ecdh_curves[i]);
        display_key_sizes(pkey, ecdh_curves[i]);
        EVP_PKEY_free(pkey);
    }

    // Kyber algorithms to test
    const char *kyber_algs[] = {"Kyber512", "Kyber768", "Kyber1024"};
    int num_kyber_algs = sizeof(kyber_algs) / sizeof(kyber_algs[0]);

    // Generate and display Kyber key sizes
    for (int i = 0; i < num_kyber_algs; i++) {
        generate_kyber_key(kyber_algs[i]);
    }

    // Clean up
    OSSL_PROVIDER_unload(oqsprov);
    OPENSSL_cleanup();

    return 0;
}