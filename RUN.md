## Seting up example

To run this example, you’ll need to have OpenSSL installed. You can install it using the following commands (depending on your operating system):

On Linux (Ubuntu):
sudo apt-get install libssl-dev

On macOS (using Homebrew):
brew install openssl

### Running 

g++ -std=c++11 -o eccellipticencryption_example ellipticencryption.cpp -lssl -lcrypto
