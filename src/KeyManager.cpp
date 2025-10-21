#include "KeyManager.hpp"
#include <openssl/rand.h>
#include <fstream>
#include <stdexcept>

std::vector<uint8_t> KeyManager::generate_key(size_t key_size)
{
    std::vector<uint8_t> key(key_size);
    if (RAND_bytes(key.data(), key_size) != 1)
    {
        throw std::runtime_error("Failed to generate random key");
    }
    return key;
}

bool KeyManager::save_key(const std::vector<uint8_t> &key, const std::string &file_path)
{
    std::ofstream out(file_path, std::ios::binary);
    if (!out)
        return false;
    out.write(reinterpret_cast<const char *>(key.data()), key.size());
    out.close();
    return true;
}

std::vector<uint8_t> KeyManager::load_key(const std::string &file_path)
{
    std::ifstream in(file_path, std::ios::binary);
    if (!in)
        throw std::runtime_error("Failed to open key file");
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    return key;
}