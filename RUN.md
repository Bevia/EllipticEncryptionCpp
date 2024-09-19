## Seting up example

To run this example, you’ll need to have OpenSSL installed. You can install it using the following commands (depending on your operating system):

On Linux (Ubuntu):
sudo apt-get install libssl-dev

On macOS (using Homebrew):
brew install openssl

### Running 

g++ -std=c++11 -o ellipticencryption ellipticencryption.cpp -lssl -lcrypto

if you run into openssl installation errors find where openssl is installed:
check where OpenSSL is installed on your system. Run the following command:
brew --prefix openssl

in my case this is the route:
/opt/homebrew/opt/openssl@3

g++ -o encrypting -std=c++11 ellipticencryption.cpp -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

./encrypting

## Results:
Generated ECC Key Pair:
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCjix+GBtoPAFKBir
aHkPt+rH9CoHEp8XcmizPcOLhsuhRANCAARdN7VnNlXBDLjKKRJjHRMXYrAE+shU
MfEcbDplmNcCVHPo48Ns7E9sQzoYY7+tj4cet2Sm/4Knb9Pc6btvKPKM
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXTe1ZzZVwQy4yikSYx0TF2KwBPrI
VDHxHGw6ZZjXAlRz6OPDbOxPbEM6GGO/rY+HHrdkpv+Cp2/T3Om7byjyjA==
-----END PUBLIC KEY-----

