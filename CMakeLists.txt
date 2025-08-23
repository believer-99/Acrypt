cmake_minimum_required(VERSION 3.20)
project(HybridCryptoLib)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_FEATURES cxx_std_17)

# Enable common warning flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
endif()
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(SEAL 4.1 REQUIRED)
find_package(SQLiteCpp REQUIRED)
find_package(OpenMP REQUIRED)

include(FetchContent)

# nlohmann/json for serialization
FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.2 # Use a specific tag
)
FetchContent_MakeAvailable(json)

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
    src/network/TlsChannel.cpp
    src/utils/Json_utils.cpp
)

add_library(hybridcrypto STATIC ${SOURCES})
target_include_directories(hybridcrypto PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(hybridcrypto PUBLIC SEAL::seal OpenSSL::SSL OpenSSL::Crypto SQLiteCpp OpenMP::OpenMP_CXX nlohmann_json::nlohmann_json)

add_executable(main tests/main.cpp)
target_link_libraries(main PRIVATE hybridcrypto)

add_executable(se_test tests/se_test.cpp)
target_link_libraries(se_test PRIVATE hybridcrypto)

add_executable(fhe_test tests/fhe_test.cpp)
target_link_libraries(fhe_test PRIVATE hybridcrypto)

add_executable(hybrid_test tests/hybrid_test.cpp)
target_link_libraries(hybrid_test PRIVATE hybridcrypto)

add_executable(stress_se tests/stress_se.cpp)
target_link_libraries(stress_se PRIVATE hybridcrypto OpenMP::OpenMP_CXX) # Link OpenMP explicitly for tests

add_executable(benchmark tests/benchmark.cpp)
target_link_libraries(benchmark PRIVATE hybridcrypto)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(fuzz_se tests/fuzz_se.cpp)
    # Fuzzer requires specific linker flags often provided by the compiler driver
    # This might need adjustment based on your setup and compiler version.
    # -fsanitize=fuzzer links the libFuzzer main.
    # If using AFL++, the setup might be different.
    # Consider adding this only for specific build types or environments.
    target_link_libraries(fuzz_se PRIVATE hybridcrypto -fsanitize=fuzzer)
endif()

# Doxygen documentation
find_package(Doxygen) # Removed REQUIRED
if (DOXYGEN_FOUND)
  configure_file(${PROJECT_SOURCE_DIR}/Doxyfile.in ${PROJECT_BINARY_DIR}/Doxyfile @ONLY)
  add_custom_target(hybridcrypto-docs
    COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM)
else() # Added else block for user info
  message(STATUS "Doxygen not found. Documentation target 'hybridcrypto-docs' will not be available.")
endif()

# Install rules
install(TARGETS hybridcrypto
    EXPORT HybridCryptoLibTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)

install(EXPORT HybridCryptoLibTargets
    FILE HybridCryptoLibConfig.cmake
    NAMESPACE HybridCryptoLib::
    DESTINATION lib/cmake/HybridCryptoLib
)