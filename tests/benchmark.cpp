#include <chrono>
#include <iostream>
#include "SE.hpp"
#include "FHE/FHE_utils.hpp"

void benchmark_se()
{
    std::vector<uint8_t> key(AES_256_KEY_SIZE, 0);
    SE se_service(key);
    std::vector<std::string> docs(1000, "doc");
    for (size_t i = 0; i < 1000; ++i)
        docs[i] += std::to_string(i) + ".txt";

    auto start = std::chrono::high_resolution_clock::now();
    se_service.add("test_keyword", docs);
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "SSE Add Time: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
              << " us" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    se_service.search("test_keyword");
    end = std::chrono::high_resolution_clock::now();
    std::cout << "SSE Search Time: "
              << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
              << " us" << std::endl;
}

int main()
{
    benchmark_se();
    return 0;
}