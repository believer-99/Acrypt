cmake_minimum_required(VERSION 3.20)
project(HybridCryptoLib)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)
find_package(SEAL 4.1 REQUIRED)
find_package(SQLiteCpp REQUIRED)
find_package(OpenMP REQUIRED)

include_directories(
    ${PROJECT_SOURCE_DIR}/include 
    ${OpenSSL_INCLUDE_DIR}
)

set(SOURCES
    src/AES.cpp
    src/FHE/FHE_utils.cpp
    src/SE.cpp
    src/utils/String_utils.cpp
    src/KeyManager.cpp
)

add_library(hybridcrypto STATIC ${SOURCES})
target_include_directories(hybridcrypto PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(hybridcrypto PUBLIC SEAL::seal OpenSSL::SSL OpenSSL::Crypto SQLiteCpp OpenMP::OpenMP_CXX)

add_executable(main tests/main.cpp)
target_link_libraries(main PRIVATE hybridcrypto)

add_executable(se_test tests/se_test.cpp)
target_link_libraries(se_test PRIVATE hybridcrypto)

add_executable(fhe_test tests/fhe_test.cpp)
target_link_libraries(fhe_test PRIVATE hybridcrypto)

add_executable(hybrid_test tests/hybrid_test.cpp)
target_link_libraries(hybrid_test PRIVATE hybridcrypto)

add_executable(benchmark tests/benchmark.cpp)
target_link_libraries(benchmark PRIVATE hybridcrypto)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(fuzz_se tests/fuzz_se.cpp)
    target_link_libraries(fuzz_se PRIVATE hybridcrypto -fsanitize=fuzzer)
endif()