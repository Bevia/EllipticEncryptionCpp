# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(ECCProject VERSION 1.0)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the Boost package (Make sure to specify the components you need)
find_package(Boost 1.70 REQUIRED COMPONENTS serialization system)

# Include Boost headers
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "Boost not found!")
endif()

# Add the executable for your project
add_executable(ecc_example src/main.cpp)

# Link Boost libraries to your executable
target_link_libraries(ecc_example ${Boost_LIBRARIES})

message("CMakeLists.txt is being processed")