#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <oqs/oqs.h>
#include <openssl/provider.h> // Include this header for OSSL_PROVIDER functions

EVP_PKEY* generate_key(const char *alg) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (strncmp(alg, "RSA", 3) == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) {
            fprintf(stderr, "Failed to create EVP_PKEY_CTX for %s\n", alg);
            exit(EXIT_FAILURE);
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            fprintf(stderr, "Failed to initialize keygen for %s\n", alg);
            exit(EXIT_FAILURE);
        }

        int bits = 2048;
        if (strcmp(alg, "RSA-3072") == 0) {
            bits = 3072;
        } else if (strcmp(alg, "RSA-4096") == 0) {
            bits = 4096;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
            fprintf(stderr, "Failed to set RSA key size\n");
            exit(EXIT_FAILURE);
        }
    } else if (strncmp(alg, "prime", 5) == 0 || strncmp(alg, "secp", 4) == 0) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx) {
            fprintf(stderr, "Failed to create EVP_PKEY_CTX for %s\n", alg);
            exit(EXIT_FAILURE);
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            fprintf(stderr, "Failed to initialize keygen for %s\n", alg);
            exit(EXIT_FAILURE);
        }

        int curve_nid = NID_X9_62_prime256v1;
        if (strcmp(alg, "secp384r1") == 0) {
            curve_nid = NID_secp384r1;
        } else if (strcmp(alg, "secp521r1") == 0) {
            curve_nid = NID_secp521r1;
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
            fprintf(stderr, "Failed to set EC curve\n");
            exit(EXIT_FAILURE);
        }
    } else {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
        if (!ctx) {
            fprintf(stderr, "Failed to create EVP_PKEY_CTX for %s\n", alg);
            exit(EXIT_FAILURE);
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            fprintf(stderr, "Failed to initialize keygen for %s\n", alg);
            exit(EXIT_FAILURE);
        }
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key pair for %s\n", alg);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void display_key_sizes(EVP_PKEY *pkey, const char *alg) {
    int priv_key_len = i2d_PrivateKey(pkey, NULL);
    int pub_key_len = i2d_PUBKEY(pkey, NULL);

    printf("Algorithm: %s\n", alg);
    printf("Private key size: %d bytes\n", priv_key_len);
    printf("Public key size: %d bytes\n", pub_key_len);
}

unsigned char* sign_file(EVP_PKEY *pkey, const unsigned char *data, size_t data_len, unsigned int *sig_len) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char *sig = (unsigned char *)malloc(EVP_PKEY_size(pkey));

    EVP_SignInit(md_ctx, EVP_sha256());
    EVP_SignUpdate(md_ctx, data, data_len);
    if (!EVP_SignFinal(md_ctx, sig, sig_len, pkey)) {
        fprintf(stderr, "Failed to sign the data\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(md_ctx);
    return sig;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_to_sign>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *file_to_sign = argv[1];

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqsprov) {
        fprintf(stderr, "Failed to load OQS provider\n");
        exit(EXIT_FAILURE);
    }

    // Read file to sign
    FILE *fp = fopen(file_to_sign, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s\n", file_to_sign);
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);
    unsigned char *file_data = (unsigned char *)malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);

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
        "sphincsshake128fsimple",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
        "prime256v1",
        "secp384r1",
        "secp521r1"
    };
    int num_algorithms = sizeof(algorithms) / sizeof(algorithms[0]);

    // Generate keys and display sizes
    for (int i = 0; i < num_algorithms; i++) {
        EVP_PKEY *pkey = generate_key(algorithms[i]);
        display_key_sizes(pkey, algorithms[i]);

        // Sign the file and display signature size
        unsigned int sig_len;
        unsigned char *signature = sign_file(pkey, file_data, file_size, &sig_len);
        printf("Signature size: %u bytes\n", sig_len);
        printf("\n");

        free(signature);
        EVP_PKEY_free(pkey);
    }

    // Clean up
    OSSL_PROVIDER_unload(oqsprov);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    free(file_data);

    return 0;
}