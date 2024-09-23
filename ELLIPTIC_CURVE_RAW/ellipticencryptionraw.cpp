#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <random>
#include <sstream>

using namespace boost::multiprecision;

// Helper function to initialize a cpp_int from a hex string
cpp_int from_hex_string(const std::string& hex_str) {
    cpp_int result;
    std::istringstream(hex_str) >> std::hex >> result;
    return result;
}

// Prime p for secp256r1
const cpp_int PRIME = from_hex_string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

// Order of the secp256r1 curve (n)
const cpp_int ORDER = from_hex_string("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

// Elliptic curve parameters for secp256r1
const cpp_int A = from_hex_string("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
const cpp_int B = from_hex_string("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

// GCD function to check if a and p are coprime
cpp_int gcd(cpp_int a, cpp_int b) {
    while (b != 0) {
        cpp_int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Modulo inverse function using extended Euclidean algorithm
cpp_int mod_inv(cpp_int a, cpp_int p) {
    a %= p;  // Ensure a is in the field (mod p)
    if (gcd(a, p) != 1) {
        // If not invertible, return point at infinity case.
        std::cerr << "Warning: Value " << a << " is not invertible modulo " << p << ". Treating this case as point at infinity.\n";
        return 0;  // Return 0 for point at infinity.
    }

    cpp_int t = 0, new_t = 1;
    cpp_int r = p, new_r = a;

    while (new_r != 0) {
        cpp_int quotient = r / new_r;
        std::tie(t, new_t) = std::make_pair(new_t, t - quotient * new_t);
        std::tie(r, new_r) = std::make_pair(new_r, r - quotient * new_r);
    }

    if (r > 1) {
        std::cerr << "Error: Value " << a << " is not invertible modulo " << p << "\n";
        return 0;  // Return 0 for point at infinity.
    }
    if (t < 0) t = t + p;

    return t;
}

// Point on the elliptic curve
struct Point {
    cpp_int x, y;
    bool is_infinity = false; // This represents the point at infinity (identity element in elliptic curve group)
};

// Elliptic curve point addition
Point point_add(const Point& P, const Point& Q, const cpp_int& p) {
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;

    // If P == -Q (i.e., their x coordinates are the same but their y coordinates are negatives), return infinity
    if (P.x == Q.x && (P.y != Q.y || P.y == 0)) {
        return {0, 0, true}; // Point at infinity (P + -P = 0 or when P.y == 0 in point doubling)
    }

    cpp_int lambda;
    if (P.x == Q.x && P.y == Q.y) {
        // Point Doubling
        cpp_int num = (3 * P.x * P.x + A) % p;
        cpp_int den = (2 * P.y) % p;
        if (den == 0 || gcd(den, p) != 1) {
            // Handle the case where doubling a point with P.y == 0 returns the point at infinity
            std::cerr << "Warning: Denominator " << den << " is not invertible during point doubling. Returning point at infinity.\n";
            return {0, 0, true};  // Point at infinity
        }
        lambda = (num * mod_inv(den, p)) % p;
    } else {
        // Point Addition
        cpp_int num = (Q.y - P.y) % p;
        cpp_int den = (Q.x - P.x) % p;
        if (den == 0 || gcd(den, p) != 1) {
            std::cerr << "Warning: Denominator " << den << " is not invertible during point addition. Returning point at infinity.\n";
            return {0, 0, true};  // Point at infinity
        }
        lambda = (num * mod_inv(den, p)) % p;
    }

    cpp_int x_r = (lambda * lambda - P.x - Q.x) % p;
    if (x_r < 0) x_r += p;

    cpp_int y_r = (lambda * (P.x - x_r) - P.y) % p;
    if (y_r < 0) y_r += p;

    return {x_r, y_r, false};
}

// Scalar multiplication (double-and-add)
Point scalar_mult(const Point& P, cpp_int scalar, const cpp_int& p) {
    Point result = {0, 0, true}; // Point at infinity
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

// Generate a random private key
cpp_int generate_private_key() {
    std::random_device rd;
    std::mt19937_64 gen(rd());

    cpp_int random_value = 0;
    std::size_t bit_shift = 0;
    const std::size_t bit_chunk_size = 64;

    // Generate random 64-bit chunks to construct the large cpp_int value
    while (bit_shift < 256) {
        std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());
        cpp_int chunk = dist(gen);
        random_value += (chunk << bit_shift);
        bit_shift += bit_chunk_size;
    }

    random_value %= ORDER - 1; // Ensure random_value is less than ORDER
    random_value += 1;         // Ensure random_value is at least 1

    return random_value;
}

int main() {
    // Base point (generator) for secp256r1
    Point G = {
        from_hex_string("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        from_hex_string("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CBCE33576B315ECECBB6406837BF51F"),
        false
    };

    // Generate a random private key
    cpp_int private_key = generate_private_key();

    std::cout << "Private Key:\n" << std::hex << private_key << "\n";

    // Calculate public key based on scalar multiplication
    Point public_key = scalar_mult(G, private_key, PRIME);

    // Output public key
    std::cout << "Public Key:\n";
    std::cout << "x: " << std::hex << public_key.x << "\n";
    std::cout << "y: " << std::hex << public_key.y << "\n";

    return 0;
}