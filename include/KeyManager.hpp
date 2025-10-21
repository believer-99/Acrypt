#pragma once

#include <vector>
#include <cstdint>
#include <string>

class KeyManager
{
public:
    static std::vector<uint8_t> generate_key(size_t key_size);
    static bool save_key(const std::vector<uint8_t> &key, const std::string &file_path);
    static std::vector<uint8_t> load_key(const std::string &file_path);
};