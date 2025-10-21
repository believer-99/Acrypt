#include "SE.hpp"
#include "KeyManager.hpp"
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<uint8_t> key = KeyManager::generate_key(AES_256_KEY_SIZE);
    SE se_service(key, ":memory:");
    std::string input(reinterpret_cast<const char *>(data), size);
    try
    {
        se_service.add(input, {input});
        se_service.search(input);
    }
    catch (...)
    {
        // Ignore exceptions, let fuzzer continue
    }
    return 0;
}