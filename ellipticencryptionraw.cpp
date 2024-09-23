#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>  // For large integers
#include <boost/multiprecision/cpp_int/serialize.hpp> // Optional: Serialization of big integers

using namespace boost::multiprecision;

const cpp_int PRIME("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);  // secp256r1 prime

// Elliptic curve parameters for secp256r1
const cpp_int A("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2C", 16);
const cpp_int B("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

struct Point {
    cpp_int x, y;
    bool is_infinity; // This represents the point at infinity (the identity element in elliptic curve group)
};

cpp_int mod_inv(cpp_int a, cpp_int p) {
    cpp_int t = 0, new_t = 1;
    cpp_int r = p, new_r = a;

    while (new_r != 0) {
        cpp_int quotient = r / new_r;

        std::tie(t, new_t) = std::make_pair(new_t, t - quotient * new_t);
        std::tie(r, new_r) = std::make_pair(new_r, r - quotient * new_r);
    }

    if (r > 1) throw std::invalid_argument("a is not invertible");
    if (t < 0) t = t + p;

    return t;
}

Point point_add(const Point& P, const Point& Q, const cpp_int& p) {
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;

    if (P.x == Q.x && P.y != Q.y) {
        return {0, 0, true}; // Point at infinity (P + -P = 0)
    }

    cpp_int lambda;
    if (P.x == Q.x && P.y == Q.y) {
        // Point Doubling
        cpp_int num = (3 * P.x * P.x + A) % p;
        cpp_int den = (2 * P.y) % p;
        lambda = (num * mod_inv(den, p)) % p;
    } else {
        // Point Addition
        cpp_int num = (Q.y - P.y) % p;
        cpp_int den = (Q.x - P.x) % p;
        lambda = (num * mod_inv(den, p)) % p;
    }

    cpp_int x_r = (lambda * lambda - P.x - Q.x) % p;
    cpp_int y_r = (lambda * (P.x - x_r) - P.y) % p;

    return {x_r, y_r, false};
}

Point scalar_mult(const Point& P, const cpp_int& scalar, const cpp_int& p) {
    Point Q = {0, 0, true};  // Start with the point at infinity (neutral element)
    Point R = P;

    cpp_int scalar_copy = scalar;

    while (scalar_copy > 0) {
        if (scalar_copy % 2 == 1) {
            Q = point_add(Q, R, p);  // Add R to the result if the corresponding bit of scalar is 1
        }
        R = point_add(R, R, p);      // Double the point R
        scalar_copy /= 2;
    }

    return Q;
}

int main() {
    // Base point (generator) for secp256r1
    Point G = {
        cpp_int("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        cpp_int("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162cbce33576b315ececbb6406837bf51f", 16),
        false
    };

    cpp_int private_key = cpp_int("0xAABBCCDDEEFF"); // Example private key (small value for demonstration)
    Point public_key = scalar_mult(G, private_key, PRIME);

    std::cout << "Public Key:\n";
    std::cout << "x: " << std::hex << public_key.x << "\n";
    std::cout << "y: " << std::hex << public_key.y << "\n";

    return 0;
}