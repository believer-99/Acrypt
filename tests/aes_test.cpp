#include "AES.hpp"
#include "utils/String_utils.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    std::vector<uint8_t> to_bytes(const std::string &input)
    {
        return std::vector<uint8_t>(input.begin(), input.end());
    }
}

int main()
{
    try
    {
        const std::string password = "correct horse battery staple";
        const std::vector<uint8_t> original_bytes = {0x00, 0x01, 0x02, 'A', 'E', 'S', '-', 'G', 'C', 'M', 0x7F, 0x00, 0xFF};
        const std::string plaintext(original_bytes.begin(), original_bytes.end());

        std::string ciphertext = encryptAES_GCM(plaintext, password);
        if (ciphertext.empty())
        {
            std::cerr << "Encrypted ciphertext should not be empty" << std::endl;
            return 1;
        }

        std::string decrypted = decryptAES_GCM(ciphertext, password);
        if (to_bytes(decrypted) != original_bytes)
        {
            std::cerr << "Decrypted bytes did not match original input" << std::endl;
            return 1;
        }

        std::string ciphertext_second = encryptAES_GCM(plaintext, password);
        if (ciphertext == ciphertext_second)
        {
            std::cerr << "Ciphertexts should differ due to fresh salt/IV" << std::endl;
            return 1;
        }

        bool tamper_detected = false;
        if (ciphertext.size() > 10)
        {
            std::string tampered = ciphertext;
            tampered[10] = static_cast<char>(tampered[10] ^ 0x01);
            try
            {
                (void)decryptAES_GCM(tampered, password);
            }
            catch (const std::exception &)
            {
                tamper_detected = true;
            }
        }
        if (!tamper_detected)
        {
            std::cerr << "Tampering with ciphertext was not detected" << std::endl;
            return 1;
        }

        bool wrong_password_detected = false;
        try
        {
            (void)decryptAES_GCM(ciphertext, "wrong password", KDFAlgorithm::PBKDF2);
        }
        catch (const std::exception &)
        {
            wrong_password_detected = true;
        }
        if (!wrong_password_detected)
        {
            std::cerr << "Decryption should have failed with wrong password" << std::endl;
            return 1;
        }

        std::string ciphertext_pbkdf2 = encryptAES_GCM(plaintext, password, KDFAlgorithm::PBKDF2);
        std::string decrypted_pbkdf2 = decryptAES_GCM(ciphertext_pbkdf2, password, KDFAlgorithm::PBKDF2);
        if (to_bytes(decrypted_pbkdf2) != original_bytes)
        {
            std::cerr << "PBKDF2 decrypt output mismatch" << std::endl;
            return 1;
        }

        std::cout << "AES-GCM password-based encryption tests passed" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "AES-GCM test failure: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
