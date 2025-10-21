cmake_minimum_required(VERSION 3.20)
project(HybridCryptoLib)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)
find_package(SEAL 4.1 REQUIRED)
find_package(SQLiteCpp REQUIRED)
find_package(OpenMP REQUIRED)

find_path(ARGON2_INCLUDE_DIR
    NAMES argon2.h
    HINTS
        ${PROJECT_SOURCE_DIR}/phc-winner-argon2/include
        ${PROJECT_SOURCE_DIR}/phc-winner-argon2/src
)
find_library(ARGON2_LIBRARY
    NAMES libargon2.so.1 libargon2.so argon2
    HINTS
        ${PROJECT_SOURCE_DIR}/phc-winner-argon2
        ${PROJECT_SOURCE_DIR}/phc-winner-argon2/lib
        ${PROJECT_SOURCE_DIR}/phc-winner-argon2/build
)

if (ARGON2_INCLUDE_DIR AND ARGON2_LIBRARY)
    if (ARGON2_LIBRARY MATCHES "\\.a$")
        message(WARNING "Argon2 static library detected at ${ARGON2_LIBRARY}; skipping due to symbol clashes with SEAL. Please build/install a shared libargon2 instead.")
        set(HAVE_ARGON2 FALSE)
    else()
        set(HAVE_ARGON2 TRUE)
    endif()
else()
    set(HAVE_ARGON2 FALSE)
endif()

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

if (HAVE_ARGON2)
    target_include_directories(hybridcrypto PUBLIC ${ARGON2_INCLUDE_DIR})
    target_link_libraries(hybridcrypto PUBLIC ${ARGON2_LIBRARY})
    target_compile_definitions(hybridcrypto PUBLIC ACRYPT_HAVE_ARGON2=1)
endif()

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

add_executable(aes_test tests/aes_test.cpp)
target_link_libraries(aes_test PRIVATE hybridcrypto)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(fuzz_se tests/fuzz_se.cpp)
    target_link_libraries(fuzz_se PRIVATE hybridcrypto -fsanitize=fuzzer)
endif()