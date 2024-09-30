#include <iostream>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

// Helper function to print BIGNUM in hex
void print_bignum(const char* label, const BIGNUM* bn) {
    char* hex_str = BN_bn2hex(bn);
    std::cout << label << ": " << hex_str << std::endl;
    OPENSSL_free(hex_str);  // Free memory allocated by BN_bn2hex
}

// Generate random BIGNUM as private key
BIGNUM* generate_private_key(const BIGNUM* order) {
    BIGNUM* priv_key = BN_new();
    BN_rand_range(priv_key, order);  // Generate private key in range [0, order)
    return priv_key;
}

// Derive shared secret using ECDH (Elliptic Curve Diffie-Hellman)
BIGNUM* derive_shared_secret(EC_GROUP* ec_group, const EC_POINT* public_key, const BIGNUM* private_key, BN_CTX* ctx) {
    BIGNUM* shared_secret = BN_new();
    EC_POINT* shared_point = EC_POINT_new(ec_group);

    // Perform scalar multiplication on the elliptic curve (shared_point = private_key * public_key)
    if (!EC_POINT_mul(ec_group, shared_point, nullptr, public_key, private_key, ctx)) {
        std::cerr << "Error: Failed to derive shared secret." << std::endl;
        BN_free(shared_secret);
        return nullptr;
    }

    // Get x-coordinate of the resulting point (the shared secret) using the new function
    if (!EC_POINT_get_affine_coordinates(ec_group, shared_point, shared_secret, nullptr, ctx)) {
        std::cerr << "Error: Failed to get affine coordinates." << std::endl;
        BN_free(shared_secret);
        return nullptr;
    }

    EC_POINT_free(shared_point);
    return shared_secret;
}

// Hash shared secret with SHA-256 to derive AES key
void derive_aes_key_from_secret(const BIGNUM* shared_secret, unsigned char* aes_key) {
    unsigned char* secret_bin = new unsigned char[BN_num_bytes(shared_secret)];
    BN_bn2bin(shared_secret, secret_bin);  // Convert BIGNUM to binary

    // Hash the shared secret with SHA-256
    SHA256(secret_bin, BN_num_bytes(shared_secret), aes_key);

    delete[] secret_bin;
}

// AES encryption using AES-256-CBC
std::string aes_encrypt(const std::string &plaintext, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error initializing encryption context." << std::endl;
        return "";
    }

    // Initialization vector (IV)
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);  // Generate random IV

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE + AES_BLOCK_SIZE);  // Add space for IV and padding

    int len;
    int ciphertext_len = 0;

    // Initialize encryption operation (AES-256-CBC)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cerr << "Error initializing AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Copy the IV at the beginning of the ciphertext (IV is needed for decryption)
    std::memcpy(&ciphertext[0], iv, AES_BLOCK_SIZE);

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[AES_BLOCK_SIZE]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        std::cerr << "Error during AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    // Finalize encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[AES_BLOCK_SIZE + len]), &len) != 1) {
        std::cerr << "Error finalizing AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    // Resize the ciphertext to its actual length
    ciphertext.resize(AES_BLOCK_SIZE + ciphertext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// AES decryption using AES-256-CBC
std::string aes_decrypt(const std::string &ciphertext, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error initializing decryption context." << std::endl;
        return "";
    }

    // Extract the IV from the beginning of the ciphertext
    unsigned char iv[AES_BLOCK_SIZE];
    std::memcpy(iv, ciphertext.data(), AES_BLOCK_SIZE);

    std::string decrypted_text;
    decrypted_text.resize(ciphertext.size() - AES_BLOCK_SIZE);  // Adjust size for the decrypted text

    int len;
    int plaintext_len = 0;

    // Initialize decryption operation (AES-256-CBC)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cerr << "Error initializing AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&decrypted_text[0]), &len,
                          reinterpret_cast<const unsigned char*>(&ciphertext[AES_BLOCK_SIZE]),
                          ciphertext.size() - AES_BLOCK_SIZE) != 1) {
        std::cerr << "Error during AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    // Finalize decryption (handle padding)
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&decrypted_text[0]) + len, &len) != 1) {
        std::cerr << "Error finalizing AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    // Resize the decrypted text to its actual length
    decrypted_text.resize(plaintext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return decrypted_text;
}

int main() {
    // Initialize OpenSSL context
    BN_CTX* ctx = BN_CTX_new();

    // Create elliptic curve group (secp256r1 curve)
    EC_GROUP* ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_group) {
        std::cerr << "Error: Failed to create EC_GROUP." << std::endl;
        return 1;
    }

    // Get the order of the curve
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(ec_group, order, ctx);

    // Generate private keys for Alice and Bob
    BIGNUM* private_key_Alice = generate_private_key(order);
    BIGNUM* private_key_Bob = generate_private_key(order);

    print_bignum("Alice's Private Key", private_key_Alice);
    print_bignum("Bob's Private Key", private_key_Bob);

    // Generate public keys for Alice and Bob
    EC_POINT* public_key_Alice = EC_POINT_new(ec_group);
    EC_POINT* public_key_Bob = EC_POINT_new(ec_group);

    // Compute public keys (public_key = private_key * G)
    EC_POINT_mul(ec_group, public_key_Alice, private_key_Alice, nullptr, nullptr, ctx);
    EC_POINT_mul(ec_group, public_key_Bob, private_key_Bob, nullptr, nullptr, ctx);

    // Derive shared secrets (ECDH)
    BIGNUM* shared_secret_Alice = derive_shared_secret(ec_group, public_key_Bob, private_key_Alice, ctx);
    BIGNUM* shared_secret_Bob = derive_shared_secret(ec_group, public_key_Alice, private_key_Bob, ctx);

    print_bignum("Alice's Shared Secret", shared_secret_Alice);
    print_bignum("Bob's Shared Secret", shared_secret_Bob);

    // Ensure both parties have the same shared secret
    if (BN_cmp(shared_secret_Alice, shared_secret_Bob) != 0) {
        std::cerr << "Error: Shared secrets do not match!" << std::endl;
        return 1;
    }

      // Derive AES key from shared secret
    unsigned char aes_key[SHA256_DIGEST_LENGTH];
    derive_aes_key_from_secret(shared_secret_Alice, aes_key);

    // Encrypt a message using the shared AES key
    std::string plaintext = "Hello, this is a secret message!";
    std::string ciphertext = aes_encrypt(plaintext, aes_key);

    std::cout << "Encrypted message: " << ciphertext << std::endl;

    // Decrypt the message using the shared AES key
    std::string decrypted_message = aes_decrypt(ciphertext, aes_key);

    std::cout << "Decrypted message: " << decrypted_message << std::endl;

    // Clean up
    EC_GROUP_free(ec_group);
    EC_POINT_free(public_key_Alice);
    EC_POINT_free(public_key_Bob);
    BN_free(private_key_Alice);
    BN_free(private_key_Bob);
    BN_free(shared_secret_Alice);
    BN_free(shared_secret_Bob);
    BN_free(order);
    BN_CTX_free(ctx);

    return 0;
}