#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EC_KEY* generateKey() {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);  // Choose the curve
    if (!EC_KEY_generate_key(key)) {
        handleErrors();
    }
    return key;
}

void printKey(EC_KEY* key) {
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_ECPrivateKey(out, key, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_EC_PUBKEY(out, key);
    BIO_free(out);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate the ECC key pair
    EC_KEY* key = generateKey();
    if (!key) {
        handleErrors();
    }

    std::cout << "Generated ECC Key Pair:\n";
    printKey(key);

    // Free resources
    EC_KEY_free(key);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}