#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

using namespace boost::multiprecision;

// Helper function to initialize a cpp_int from a hex string
cpp_int from_hex_string(const std::string &hex_str) {
    cpp_int result;
    std::istringstream(hex_str) >> std::hex >> result;
    return result;
}

// Prime p for secp256r1
const cpp_int PRIME = from_hex_string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

// Elliptic curve parameters for secp256r1
const cpp_int A = from_hex_string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");

// Point on the elliptic curve
struct Point {
    cpp_int x, y;
    bool is_infinity = false;  // Represents point at infinity
};

// Function to perform modular inverse using the extended Euclidean algorithm
cpp_int mod_inv(cpp_int a, cpp_int p) {
    cpp_int t = 0, new_t = 1;
    cpp_int r = p, new_r = a % p;

    while (new_r != 0) {
        cpp_int quotient = r / new_r;
        std::tie(t, new_t) = std::make_pair(new_t, t - quotient * new_t);
        std::tie(r, new_r) = std::make_pair(new_r, r - quotient * new_r);
    }

    if (t < 0) t += p;
    return t;
}

// Point addition for elliptic curves
Point point_add(const Point &P, const Point &Q, const cpp_int &p) {
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;

    cpp_int lambda;
    if (P.x == Q.x && P.y == Q.y) {
        // Point Doubling
        cpp_int num = (3 * P.x * P.x + A) % p;
        cpp_int den = mod_inv((2 * P.y) % p, p);
        lambda = (num * den) % p;
    } else {
        // Point Addition
        cpp_int num = (Q.y - P.y) % p;
        cpp_int den = mod_inv((Q.x - P.x) % p, p);
        lambda = (num * den) % p;
    }

    cpp_int x_r = (lambda * lambda - P.x - Q.x) % p;
    if (x_r < 0) x_r += p;

    cpp_int y_r = (lambda * (P.x - x_r) - P.y) % p;
    if (y_r < 0) y_r += p;

    return {x_r, y_r, false};
}

// Scalar multiplication using the double-and-add algorithm
Point scalar_mult(const Point &P, cpp_int scalar, const cpp_int &p) {
    Point result = {0, 0, true};  // Point at infinity
    Point addend = P;

    while (scalar > 0) {
        if (scalar % 2 == 1) {
            result = point_add(result, addend, p);
        }
        addend = point_add(addend, addend, p);
        scalar /= 2;
    }

    return result;
}

// Generate random private key
cpp_int generate_private_key() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1, UINT64_MAX);

    cpp_int private_key = dist(gen);
    return private_key % (PRIME - 1);  // Ensure the private key is in the field of the curve
}

// Derive shared secret from ECC scalar multiplication
cpp_int derive_shared_secret(const cpp_int &private_key, const Point &public_key, const cpp_int &p) {
    Point shared_point = scalar_mult(public_key, private_key, p);
    return shared_point.x;  // Use x-coordinate as shared secret
}

// Hash the shared secret using SHA-256 to derive AES key
std::string hash_shared_secret(const cpp_int &shared_secret) {
    std::string secret_hex = shared_secret.str();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(secret_hex.c_str()), secret_hex.size(), hash);
    return std::string(reinterpret_cast<char *>(hash), SHA256_DIGEST_LENGTH);  // Return AES key
}

// AES-256-CBC encryption
std::string aes_encrypt(const std::string &plaintext, const std::string &key) {
    std::string ciphertext(plaintext.size() + AES_BLOCK_SIZE, 0);

    AES_KEY encrypt_key;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.data()), 256, &encrypt_key);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);  // Random IV
    std::copy(iv, iv + AES_BLOCK_SIZE, ciphertext.begin());

    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(plaintext.data()),
                    reinterpret_cast<unsigned char *>(&ciphertext[AES_BLOCK_SIZE]),
                    plaintext.size(), &encrypt_key, iv, AES_ENCRYPT);

    return ciphertext;
}

// AES-256-CBC decryption
std::string aes_decrypt(const std::string &ciphertext, const std::string &key) {
    std::string plaintext(ciphertext.size() - AES_BLOCK_SIZE, 0);

    AES_KEY decrypt_key;
    AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.data()), 256, &decrypt_key);

    unsigned char iv[AES_BLOCK_SIZE];
    std::copy(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE, iv);

    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(&ciphertext[AES_BLOCK_SIZE]),
                    reinterpret_cast<unsigned char *>(&plaintext[0]),
                    ciphertext.size() - AES_BLOCK_SIZE, &decrypt_key, iv, AES_DECRYPT);

    return plaintext;
}

int main() {
    // Base point (generator) for secp256r1
    Point G = {
        from_hex_string("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        from_hex_string("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CBCE33576B315ECECBB6406837BF51F"),
        false
    };

    // Generate private keys for two parties (Alice and Bob)
    cpp_int private_key_Alice = generate_private_key();
    cpp_int private_key_Bob = generate_private_key();

    // Calculate public keys
    Point public_key_Alice = scalar_mult(G, private_key_Alice, PRIME);
    Point public_key_Bob = scalar_mult(G, private_key_Bob, PRIME);

    // Derive shared secret for both parties (should match)
    cpp_int shared_secret_Alice = derive_shared_secret(private_key_Alice, public_key_Bob, PRIME);
    cpp_int shared_secret_Bob = derive_shared_secret(private_key_Bob, public_key_Alice, PRIME);

    // Ensure both parties have the same shared secret
    if (shared_secret_Alice == shared_secret_Bob) {
        std::cout << "Shared secrets match!\n";
    } else {
        std::cerr << "Shared secrets do not match!\n";
        return 1;
    }

    // Derive AES key from shared secret
    std::string aes_key = hash_shared_secret(shared_secret_Alice);

    // Encrypt a message with the shared secret (AES key)
    std::string plaintext = "Hello, this is a secret message!";
    std::string ciphertext = aes_encrypt(plaintext, aes_key);

    std::cout << "Encrypted message: " << ciphertext << std::endl;

    // Decrypt the message with the same AES key
    std::string decrypted_message = aes_decrypt(ciphertext, aes_key);

    std::cout << "Decrypted message: " << decrypted_message << std::endl;

    return 0;
}