#include <iostream>
#include <vector>
#include <numeric>
#include <stdexcept>
#include "FHE/FHE_utils.hpp"
#include "seal/seal.h"
#include "KeyManager.hpp"

void assert_fhe_true(bool condition, const std::string &test_name)
{
    if (!condition)
    {
        std::cerr << "[FHE TEST FAILED] " << test_name << std::endl;
        throw std::runtime_error("Assertion failed in FHE test: " + test_name);
    }
    std::cout << "[FHE TEST PASSED] " << test_name << std::endl;
}

void test_scalar_operations(FHEUtils &fhe)
{
    std::cout << "\n--- Testing FHE Scalar Operations ---" << std::endl;
    int64_t num1 = 25;
    int64_t num2 = 17;
    int64_t expected_sum = num1 + num2;
    int64_t expected_prod = num1 * num2;

    std::cout << "[+] Encrypting numbers: " << num1 << " and " << num2 << std::endl;
    std::string mac1, mac2;
    seal::Ciphertext enc1 = fhe.encrypt(num1, &mac1);
    seal::Ciphertext enc2 = fhe.encrypt(num2, &mac2);

    std::cout << "[+] Performing homomorphic addition..." << std::endl;
    seal::Ciphertext encrypted_sum_ct = fhe.add(enc1, enc2);
    int64_t decrypted_sum = fhe.decrypt(encrypted_sum_ct);
    std::cout << "[+] Decrypted Sum: " << decrypted_sum << " (Expected: " << expected_sum << ")" << std::endl;
    assert_fhe_true(decrypted_sum == expected_sum, "Scalar homomorphic addition");

    std::cout << "[+] Performing homomorphic multiplication..." << std::endl;
    seal::Ciphertext encrypted_prod_ct = fhe.multiply(enc1, enc2);
    int64_t decrypted_prod = fhe.decrypt(encrypted_prod_ct);
    std::cout << "[+] Decrypted Product: " << decrypted_prod << " (Expected: " << expected_prod << ")" << std::endl;
    assert_fhe_true(decrypted_prod == expected_prod, "Scalar homomorphic multiplication");

    std::cout << "[+] Saving and loading ciphertext..." << std::endl;
    fhe.save_ciphertext(enc1, "test_ciphertext.bin");
    seal::Ciphertext loaded_ct = fhe.load_ciphertext("test_ciphertext.bin");
    int64_t loaded_decrypted = fhe.decrypt(loaded_ct, mac1);
    assert_fhe_true(loaded_decrypted == num1, "Ciphertext serialization");
}

void test_vector_operations(FHEUtils &fhe)
{
    std::cout << "\n--- Testing FHE Vector (Batched) Operations ---" << std::endl;
    std::vector<uint64_t> vec1 = {11, 22, 33, 44};
    std::vector<uint64_t> vec2 = {5, 6, 7, 8};
    size_t test_vec_size = vec1.size();

    std::cout << "[+] Encrypting vectors..." << std::endl;
    std::string mac1, mac2;
    seal::Ciphertext enc_vec1 = fhe.encrypt_vector(vec1, &mac1);
    seal::Ciphertext enc_vec2 = fhe.encrypt_vector(vec2, &mac2);

    std::vector<uint64_t> expected_vec_sum(test_vec_size);
    for (size_t i = 0; i < test_vec_size; ++i)
        expected_vec_sum[i] = vec1[i] + vec2[i];

    std::cout << "[+] Performing homomorphic vector addition..." << std::endl;
    seal::Ciphertext encrypted_vec_sum_ct = fhe.add(enc_vec1, enc_vec2);
    std::vector<uint64_t> decrypted_vec_sum = fhe.decrypt_vector(encrypted_vec_sum_ct);

    bool vec_sum_ok = decrypted_vec_sum.size() >= test_vec_size;
    std::cout << "[+] Decrypted Vector Sum (first " << test_vec_size << " elements): ";
    for (size_t i = 0; i < test_vec_size; ++i)
    {
        std::cout << decrypted_vec_sum[i] << " ";
        if (i < decrypted_vec_sum.size() && decrypted_vec_sum[i] != expected_vec_sum[i])
            vec_sum_ok = false;
        else if (i >= decrypted_vec_sum.size())
            vec_sum_ok = false;
    }
    std::cout << std::endl;
    assert_fhe_true(vec_sum_ok, "Vector homomorphic addition");

    std::vector<uint64_t> expected_vec_prod(test_vec_size);
    for (size_t i = 0; i < test_vec_size; ++i)
        expected_vec_prod[i] = vec1[i] * vec2[i];

    std::cout << "[+] Performing homomorphic vector multiplication..." << std::endl;
    seal::Ciphertext encrypted_vec_prod_ct = fhe.multiply(enc_vec1, enc_vec2);
    std::vector<uint64_t> decrypted_vec_prod = fhe.decrypt_vector(encrypted_vec_prod_ct);

    bool vec_prod_ok = decrypted_vec_prod.size() >= test_vec_size;
    std::cout << "[+] Decrypted Vector Product (first " << test_vec_size << " elements): ";
    for (size_t i = 0; i < test_vec_size; ++i)
    {
        std::cout << decrypted_vec_prod[i] << " ";
        if (i < decrypted_vec_prod.size() && decrypted_vec_prod[i] != expected_vec_prod[i])
            vec_prod_ok = false;
        else if (i >= decrypted_vec_prod.size())
            vec_prod_ok = false;
    }
    std::cout << std::endl;
    assert_fhe_true(vec_prod_ok, "Vector homomorphic multiplication");
}

int main()
{
    try
    {
        std::cout << "[+] Initializing FHE Utilities for testing...\n";
        std::vector<uint8_t> mac_key = KeyManager::generate_key(32);
        KeyManager::save_key(mac_key, "fhe_mac_key.bin");
        FHEConfig config; // Use default parameters
        FHEUtils fhe(config, mac_key);

        test_scalar_operations(fhe);
        test_vector_operations(fhe);

        std::cout << "\n[✔] All FHE tests completed successfully!" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "An exception occurred during FHE tests: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}