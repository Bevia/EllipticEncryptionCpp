### running the raw file:
/opt/homebrew/opt/boost

## ellipticencryptionraw generates private and valid public key

g++ -std=c++14 -o ellipticencryptionraw ./ELLIPTIC_CURVE_RAW/ellipticencryptionraw.cpp -I/opt/homebrew/opt/boost/include -L/opt/homebrew/opt/boost/lib -lboost_system -lboost_serialization

./ellipticencryptionraw

## ellipticencryptionrawsimple generates simple private key as DEMO

g++ -std=c++14 -o ellipticencryptionrawsimple ./ELLIPTIC_CURVE_RAW/ellipticencryptionrawsimple.cpp -I/opt/homebrew/opt/boost/include -L/opt/homebrew/opt/boost/lib -lboost_system -lboost_serialization

./ellipticencryptionrawsimple