#include <iostream>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <sstream>
#include <cstring>

// Helper function to print BIGNUM in hex format (for debugging)
void print_bignum(const char* label, const BIGNUM* bn) {
    char* hex_str = BN_bn2hex(bn);
    std::cout << label << ": " << hex_str << std::endl;
    OPENSSL_free(hex_str);  // Free memory allocated by BN_bn2hex
}

// Generate a random private key using OpenSSL's RAND_bytes
BIGNUM* generate_private_key_openssl() {
    BIGNUM* private_key = BN_new();
    unsigned char rand_bytes[32];  // 256 bits for secp256r1 curve

    // Generate 256-bit random number
    if (!RAND_bytes(rand_bytes, sizeof(rand_bytes))) {
        std::cerr << "Error generating random bytes" << std::endl;
        return nullptr;
    }

    BN_bin2bn(rand_bytes, sizeof(rand_bytes), private_key);  // Convert bytes to BIGNUM
    return private_key;
}

// Function to perform modular inverse using the extended Euclidean algorithm (uses OpenSSL BIGNUM)
BIGNUM* mod_inv(const BIGNUM* a, const BIGNUM* p, BN_CTX* ctx) {
    BIGNUM* t = BN_new();
    BIGNUM* new_t = BN_new();
    BN_zero(t);  // t = 0
    BN_one(new_t);  // new_t = 1

    BIGNUM* r = BN_dup(p);
    BIGNUM* new_r = BN_dup(a);

    while (!BN_is_zero(new_r)) {
        BIGNUM* quotient = BN_new();
        BN_div(quotient, nullptr, r, new_r, ctx);  // quotient = r / new_r

        BIGNUM* temp_t = BN_dup(t);
        BIGNUM* temp_r = BN_dup(r);
        BN_mul(temp_t, quotient, new_t, ctx);
        BN_sub(t, t, temp_t);  // t = t - quotient * new_t
        BN_sub(r, r, temp_r);  // r = r - quotient * new_r
        BN_copy(t, new_t);
        BN_copy(r, new_r);

        BN_free(temp_t);
        BN_free(temp_r);
        BN_free(quotient);
    }

    if (BN_is_negative(t)) BN_add(t, t, p);  // If t < 0, t += p

    BN_free(new_t);
    BN_free(new_r);

    return t;
}

// Hash the shared secret using SHA-256 to derive AES key
void hash_shared_secret(const BIGNUM* shared_secret, unsigned char* aes_key) {
    unsigned char* secret_bin = new unsigned char[BN_num_bytes(shared_secret)];
    BN_bn2bin(shared_secret, secret_bin);  // Convert BIGNUM to binary

    // Hash the shared secret with SHA-256
    SHA256(secret_bin, BN_num_bytes(shared_secret), aes_key);

    delete[] secret_bin;
}

// AES-256-CBC encryption using EVP API
std::string aes_encrypt(const std::string& plaintext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Create new context
    if (!ctx) {
        std::cerr << "Error initializing encryption context." << std::endl;
        return "";
    }

    // Generate a random IV (Initialization Vector)
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);  // Create random IV

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE + AES_BLOCK_SIZE);  // Reserve space for ciphertext + IV

    int len;
    int ciphertext_len = 0;

    // Initialize the encryption operation (AES-256-CBC)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cerr << "Error initializing AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Copy IV at the start of the ciphertext (it is needed for decryption)
    std::memcpy(&ciphertext[0], iv, AES_BLOCK_SIZE);

    // Perform encryption
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[AES_BLOCK_SIZE]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        std::cerr << "Error during AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    // Finalize the encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[AES_BLOCK_SIZE + len]), &len) != 1) {
        std::cerr << "Error finalizing AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    // Resize the ciphertext string to its actual length
    ciphertext.resize(AES_BLOCK_SIZE + ciphertext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// AES-256-CBC decryption using EVP API
std::string aes_decrypt(const std::string& ciphertext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Create new context
    if (!ctx) {
        std::cerr << "Error initializing decryption context." << std::endl;
        return "";
    }

    // Extract the IV from the beginning of the ciphertext
    unsigned char iv[AES_BLOCK_SIZE];
    std::memcpy(iv, ciphertext.data(), AES_BLOCK_SIZE);

    std::string decrypted_text;
    decrypted_text.resize(ciphertext.size() - AES_BLOCK_SIZE);  // Adjust size for decrypted text

    int len;
    int plaintext_len = 0;

    // Initialize the decryption operation (AES-256-CBC)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cerr << "Error initializing AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Perform decryption
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&decrypted_text[0]), &len,
                          reinterpret_cast<const unsigned char*>(&ciphertext[AES_BLOCK_SIZE]),
                          ciphertext.size() - AES_BLOCK_SIZE) != 1) {
        std::cerr << "Error during AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    // Finalize the decryption (handle padding)
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

    // Generate private keys for two parties (Alice and Bob)
    BIGNUM* private_key_Alice = generate_private_key_openssl();
    BIGNUM* private_key_Bob = generate_private_key_openssl();

    print_bignum("Alice's Private Key", private_key_Alice);
    print_bignum("Bob's Private Key", private_key_Bob);

    // Derive shared secret (dummy placeholder; in a real case, you'd use elliptic curve scalar multiplication)
    // Here we just use one of the private keys as a mock shared secret for simplicity
    unsigned char aes_key[SHA256_DIGEST_LENGTH];
    hash_shared_secret(private_key_Alice, aes_key);  // Use Alice's private key as a mock shared secret for AES

    // Encrypt a message using the derived AES key
    std::string plaintext = "Hello, this is a secret message!";
    std::string ciphertext = aes_encrypt(plaintext, aes_key);

    std::cout << "Encrypted message: " << ciphertext << std::endl;

    // Decrypt the message using the same AES key
    std::string decrypted_message = aes_decrypt(ciphertext, aes_key);

    std::cout << "Decrypted message: " << decrypted_message << std::endl;

    // Clean up
    BN_free(private_key_Alice);
    BN_free(private_key_Bob);
    BN_CTX_free(ctx);

    return 0;
}