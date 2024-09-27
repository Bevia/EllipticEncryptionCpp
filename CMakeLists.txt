cmake_minimum_required(VERSION 3.10)

project(ECCExample)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Boost (for header-only libraries like Multiprecision, we only need the include directories)
find_package(Boost REQUIRED)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories for OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# Link OpenSSL libraries
add_executable(ecc_example ecc_example.cpp)
target_link_libraries(ecc_example ${OPENSSL_LIBRARIES})