# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(ECCProject VERSION 1.0)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the Boost package (Make sure to specify the components you need)
find_package(Boost 1.70 REQUIRED COMPONENTS serialization system)

cmake_minimum_required(VERSION 3.10)

project(ECCExample)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories for OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# Link OpenSSL libraries
add_executable(ecc_example ecc_example.cpp)
target_link_libraries(ecc_example ${OPENSSL_LIBRARIES})

message("CMakeLists.txt is being processed")