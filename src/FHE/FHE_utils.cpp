#include "FHE/FHE_utils.hpp"
#include <openssl/hmac.h>
#include <openssl/sha.h> // Explicitly include for SHA256_DIGEST_LENGTH
#include <sstream>
#include <fstream>
#include <iostream>
// #include <omp.h>
#include "utils/String_utils.hpp"

using namespace seal;

FHEUtils::FHEUtils(const FHEConfig &config, const std::vector<uint8_t> &mac_key)
    : mac_key(mac_key)
{
    std::cout << "[+] Initializing FHE Utilities with poly_modulus_degree=" << config.poly_modulus_degree
              << ", plain_modulus_bits=" << config.plain_modulus_bits << std::endl;

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(config.poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(config.poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(config.poly_modulus_degree, config.plain_modulus_bits));
    context = std::make_shared<SEALContext>(parms);

    if (!context->parameters_set())
    {
        throw std::runtime_error("Invalid SEAL parameters");
    }

    keygen = std::make_unique<KeyGenerator>(*context);
    secret_key = keygen->secret_key();
    keygen->create_public_key(public_key);
    keygen->create_relin_keys(relin_keys);
    encryptor = std::make_unique<Encryptor>(*context, public_key);
    decryptor = std::make_unique<Decryptor>(*context, secret_key);
    evaluator = std::make_unique<Evaluator>(*context);
    batch_encoder = std::make_unique<BatchEncoder>(*context);
}

std::string FHEUtils::compute_hmac(const seal::Ciphertext &ct)
{
    if (mac_key.empty())
        return "";
    std::stringstream ss;
    ct.save(ss);
    std::string ct_data = ss.str();
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), mac_key.data(), mac_key.size(),
         reinterpret_cast<const unsigned char *>(ct_data.c_str()), ct_data.size(), hmac, nullptr);
    return StringUtils::base64_encode(std::vector<uint8_t>(hmac, hmac + SHA256_DIGEST_LENGTH));
}

seal::Ciphertext FHEUtils::encrypt(int64_t value, std::string *mac)
{
    seal::Plaintext plain;
    std::vector<uint64_t> input(batch_encoder->slot_count(), 0ULL);
    input[0] = static_cast<uint64_t>(value);
    batch_encoder->encode(input, plain);
    seal::Ciphertext encrypted;
#pragma omp parallel
    {
#pragma omp single
        encryptor->encrypt(plain, encrypted);
    }
    if (mac && !mac_key.empty())
        *mac = compute_hmac(encrypted);
    return encrypted;
}

seal::Ciphertext FHEUtils::encrypt_vector(const std::vector<uint64_t> &values, std::string *mac)
{
    seal::Plaintext plain;
    batch_encoder->encode(values, plain);
    seal::Ciphertext encrypted;
#pragma omp parallel
    {
#pragma omp single
        encryptor->encrypt(plain, encrypted);
    }
    if (mac && !mac_key.empty())
        *mac = compute_hmac(encrypted);
    return encrypted;
}

int64_t FHEUtils::decrypt(const seal::Ciphertext &encrypted, const std::string &mac)
{
    if (!mac.empty() && !mac_key.empty())
    {
        std::string computed_mac = compute_hmac(encrypted);
        if (computed_mac != mac)
        {
            throw std::runtime_error("HMAC verification failed");
        }
    }
    seal::Plaintext plain;
    decryptor->decrypt(encrypted, plain);
    std::vector<uint64_t> decoded;
    batch_encoder->decode(plain, decoded);
    return static_cast<int64_t>(decoded[0]);
}

std::vector<uint64_t> FHEUtils::decrypt_vector(const seal::Ciphertext &encrypted, const std::string &mac)
{
    if (!mac.empty() && !mac_key.empty())
    {
        std::string computed_mac = compute_hmac(encrypted);
        if (computed_mac != mac)
        {
            throw std::runtime_error("HMAC verification failed");
        }
    }
    seal::Plaintext plain;
    decryptor->decrypt(encrypted, plain);
    std::vector<uint64_t> result;
    batch_encoder->decode(plain, result);
    return result;
}

seal::Ciphertext FHEUtils::add(const seal::Ciphertext &a, const seal::Ciphertext &b)
{
    seal::Ciphertext result;
    evaluator->add(a, b, result);
    return result;
}

seal::Ciphertext FHEUtils::multiply(const seal::Ciphertext &a, const seal::Ciphertext &b)
{
    seal::Ciphertext result;
    evaluator->multiply(a, b, result);
    evaluator->relinearize_inplace(result, relin_keys);
    return result;
}

seal::Ciphertext FHEUtils::compare_greater(const seal::Ciphertext &a, const seal::Ciphertext &b)
{
    seal::Ciphertext diff;
    evaluator->sub(a, b, diff);
    seal::Ciphertext result = diff; // Simplified; actual comparison requires polynomial evaluation
    evaluator->relinearize_inplace(result, relin_keys);
    return result;
}

void FHEUtils::save_ciphertext(const seal::Ciphertext &ct, const std::string &file_path)
{
    std::ofstream out(file_path, std::ios::binary);
    ct.save(out);
    out.close();
}

seal::Ciphertext FHEUtils::load_ciphertext(const std::string &file_path)
{
    std::ifstream in(file_path, std::ios::binary);
    seal::Ciphertext ct;
    ct.load(*context, in);
    in.close();
    return ct;
}