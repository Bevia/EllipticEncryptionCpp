#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY* generateECKey() {
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pkey_ctx) {
        handleErrors();
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_X9_62_prime256v1) <= 0) {
        handleErrors();
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        handleErrors();
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    return pkey;
}

void printKey(EVP_PKEY* pkey) {
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_PrivateKey(out, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_PUBKEY(out, pkey);
    BIO_free(out);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate the ECC key pair using the new EVP API
    EVP_PKEY* pkey = generateECKey();
    if (!pkey) {
        handleErrors();
    }

    std::cout << "Generated ECC Key Pair:\n";
    printKey(pkey);

    // Free resources
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}