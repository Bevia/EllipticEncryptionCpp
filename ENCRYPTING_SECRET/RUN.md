1.	Install Crypto Libraries:
You’ll need an AES encryption library like OpenSSL or a C++ wrapper for symmetric encryption.
Install OpenSSL (if not already installed):

brew install openssl
To find the exact path where Homebrew installed OpenSSL, run:
brew --prefix openssl
result:  /opt/homebrew/opt/openssl@3

2.	ECDH Key Exchange:
Modify the code to include Elliptic Curve Diffie-Hellman (ECDH) to generate a shared secret.
3.	Symmetric Encryption (AES):
Use the shared secret from ECDH to derive a key for AES encryption.

### Full Code Example:

This example includes ECC key generation, shared secret derivation via ECDH, and AES encryption/decryption using the derived shared key.

## How to run

g++ -o ecc_encryption_secret -std=c++14 ./ENCRYPTING_SECRET/ecc_encryption_secret.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

or:

g++ -std=c++11 -o ecc_ecc_encryption_secretexample ./ENCRYPTING_SECRET/ecc_encryption_secret.cpp -I/usr/local/opt/openssl@3/include -L/usr/local/opt/openssl@3/lib -lssl -lcrypto

./ecc_encryption_secret