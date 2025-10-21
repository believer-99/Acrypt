#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include "AES.hpp"
#include "KeyManager.hpp"

void print_hex(const std::string &label, const std::vector<uint8_t> &data)
{
    std::cout << label << ": ";
    for (uint8_t byte : data)
    {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

int main()
{
    try
    {
        std::cout << "--- Testing AES-256-GCM ---" << std::endl;

        std::vector<uint8_t> key = KeyManager::generate_key(AES_256_KEY_SIZE);
        KeyManager::save_key(key, "aes_key.bin");
        AES aes_cipher(key);
        std::cout << "[+] AES object created with a 32-byte key." << std::endl;

        std::string original_str = "This is a super secret message for AES-256-GCM!";
        std::vector<uint8_t> plaintext(original_str.begin(), original_str.end());
        print_hex("Plaintext", plaintext);

        std::cout << "\n[Test 1: Encryption with Random IV]" << std::endl;
        std::vector<uint8_t> encrypted_blob = aes_cipher.encrypt(plaintext);
        print_hex("Encrypted (IV || Ciphertext || Tag)", encrypted_blob);
        std::cout << "  Total encrypted blob size: " << encrypted_blob.size() << " bytes" << std::endl;
        std::cout << "  (Expected: " << GCM_IV_SIZE << " (IV) + " << plaintext.size() << " (Ciphertext) + " << GCM_TAG_SIZE << " (Tag) = " << GCM_IV_SIZE + plaintext.size() + GCM_TAG_SIZE << " bytes)" << std::endl;

        std::vector<uint8_t> decrypted_text = aes_cipher.decrypt(encrypted_blob);
        print_hex("Decrypted", decrypted_text);
        std::string decrypted_str(decrypted_text.begin(), decrypted_text.end());
        std::cout << "Decrypted string: " << decrypted_str << std::endl;

        if (decrypted_str == original_str)
        {
            std::cout << "[✔] Random IV Test PASSED!" << std::endl;
        }
        else
        {
            std::cout << "[✘] Random IV Test FAILED!" << std::endl;
            return 1;
        }

        std::cout << "\n[Test 2: Deterministic Encryption with Fixed IV]" << std::endl;
        std::vector<uint8_t> fixed_iv(GCM_IV_SIZE, 0x01);
        print_hex("Fixed IV", fixed_iv);

        std::vector<uint8_t> encrypted_blob_det1 = aes_cipher.encrypt_deterministic(plaintext, fixed_iv);
        print_hex("Encrypted Det 1 (IV || CT || Tag)", encrypted_blob_det1);
        std::vector<uint8_t> encrypted_blob_det2 = aes_cipher.encrypt_deterministic(plaintext, fixed_iv);
        print_hex("Encrypted Det 2 (IV || CT || Tag)", encrypted_blob_det2);

        if (encrypted_blob_det1 == encrypted_blob_det2)
        {
            std::cout << "[✔] Deterministic encryption produced identical blobs." << std::endl;
        }
        else
        {
            std::cout << "[✘] Deterministic encryption FAILED to produce identical blobs." << std::endl;
        }

        std::vector<uint8_t> decrypted_text_det = aes_cipher.decrypt(encrypted_blob_det1);
        print_hex("Decrypted Det", decrypted_text_det);
        std::string decrypted_str_det(decrypted_text_det.begin(), decrypted_text_det.end());
        std::cout << "Decrypted Det string: " << decrypted_str_det << std::endl;

        if (decrypted_str_det == original_str)
        {
            std::cout << "[✔] Deterministic Encryption/Decryption Test PASSED!" << std::endl;
        }
        else
        {
            std::cout << "[✘] Deterministic Encryption/Decryption Test FAILED!" << std::endl;
            return 1;
        }

        std::cout << "\n[Test 3: Tampering Detection]" << std::endl;
        std::vector<uint8_t> tampered_blob = encrypted_blob;
        if (tampered_blob.size() > GCM_IV_SIZE + 5)
        {
            tampered_blob[GCM_IV_SIZE + 2] ^= 0xFF;
            std::cout << "[+] Tampered the encrypted blob." << std::endl;
            try
            {
                aes_cipher.decrypt(tampered_blob);
                std::cout << "[✘] Tampering Test FAILED: Decryption succeeded with tampered data." << std::endl;
                return 1;
            }
            catch (const std::runtime_error &e)
            {
                std::cout << "[✔] Tampering Test PASSED: Decryption failed as expected. Error: " << e.what() << std::endl;
            }
        }
        else
        {
            std::cout << "[!] Tampering Test SKIPPED: Ciphertext too short to tamper safely for this test." << std::endl;
        }

        std::cout << "\n--- AES-256-GCM Tests Completed ---" << std::endl;
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "An exception occurred during AES tests: " << e.what() << std::endl;
        return 1;
    }
}