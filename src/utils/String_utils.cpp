#include "utils/String_utils.hpp"
#include <stdexcept>
#include <cctype>
#include <algorithm>

namespace StringUtils
{

    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    static inline bool is_base64(unsigned char c)
    {
        return (std::isalnum(c) || (c == '+') || (c == '/'));
    }

    std::string base64_encode(const std::vector<uint8_t> &bytes_to_encode)
    {
        std::string ret;
        ret.reserve(((bytes_to_encode.size() / 3) + (bytes_to_encode.size() % 3 > 0)) * 4);

        int i = 0;
        int j = 0;
        uint8_t char_array_3[3];
        uint8_t char_array_4[4];
        size_t in_len = bytes_to_encode.size();
        const uint8_t *bytes_ptr = bytes_to_encode.data();

        while (in_len--)
        {
            char_array_3[i++] = *(bytes_ptr++);
            if (i == 3)
            {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; (i < 4); i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i)
        {
            for (j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (j = 0; (j < i + 1); j++)
                ret += base64_chars[char_array_4[j]];

            while ((i++ < 3))
                ret += '=';
        }
        return ret;
    }

    std::vector<uint8_t> base64_decode(const std::string &encoded_string)
    {
        size_t in_len = encoded_string.size();
        if (in_len % 4 != 0)
            throw std::runtime_error("Base64 string length must be a multiple of 4.");

        int i = 0;
        int j = 0;
        size_t in_idx = 0;
        uint8_t char_array_4[4];
        uint8_t char_array_3[3];
        std::vector<uint8_t> ret;
        ret.reserve(in_len * 3 / 4);

        while (in_len-- && (encoded_string[in_idx] != '=') && is_base64(encoded_string[in_idx]))
        {
            char_array_4[i++] = encoded_string[in_idx];
            in_idx++;
            if (i == 4)
            {
                for (i = 0; i < 4; i++)
                {
                    size_t pos = base64_chars.find(char_array_4[i]);
                    if (pos == std::string::npos)
                        throw std::runtime_error("Invalid character in Base64 string.");
                    char_array_4[i] = static_cast<uint8_t>(pos);
                }

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; (i < 3); i++)
                    ret.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i)
        {
            for (j = i; j < 4; j++)
                char_array_4[j] = 0;

            for (j = 0; j < 4; j++)
            {
                if (j < i)
                {
                    size_t pos = base64_chars.find(char_array_4[j]);
                    if (pos == std::string::npos)
                        throw std::runtime_error("Invalid character in Base64 string during padding.");
                    char_array_4[j] = static_cast<uint8_t>(pos);
                }
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

            if (i > 1)
                ret.push_back(char_array_3[0]);
            if (i > 2)
                ret.push_back(char_array_3[1]);
        }
        return ret;
    }

}