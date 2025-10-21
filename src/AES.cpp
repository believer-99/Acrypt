#include "AES.hpp"
#include "utils/String_utils.hpp"
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
#include <random>
#include <limits>
#include <memory>

#ifdef ACRYPT_HAVE_ARGON2
#include <argon2.h>
#endif

namespace
{
    constexpr uint32_t PBKDF2_ITERATIONS = 200000;
#ifdef ACRYPT_HAVE_ARGON2
    constexpr uint32_t ARGON2_TIME_COST = 3;
    constexpr uint32_t ARGON2_MEMORY_COST_KIB = 1 << 16; // 64 MiB
    constexpr uint32_t ARGON2_PARALLELISM = 1;
#endif

    void secure_zero_memory(void *ptr, size_t len)
    {
        if (!ptr || len == 0)
        {
            return;
        }
        volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
        while (len--)
        {
            *p++ = 0;
        }
    }

    void secure_zero(std::vector<uint8_t> &buffer)
    {
        if (!buffer.empty())
        {
            secure_zero_memory(buffer.data(), buffer.size());
        }
    }

    void secure_zero(std::string &buffer)
    {
        if (!buffer.empty())
        {
            secure_zero_memory(buffer.data(), buffer.size());
        }
    }

    std::vector<uint8_t> generate_secure_random_bytes(size_t size)
    {
        std::vector<uint8_t> output(size);
        std::random_device rd;
        std::uniform_int_distribution<int> dist(0, std::numeric_limits<uint8_t>::max());
        for (auto &byte : output)
        {
            byte = static_cast<uint8_t>(dist(rd));
        }
        return output;
    }

    std::vector<uint8_t> derive_key_pbkdf2(const std::vector<uint8_t> &password_bytes, const std::vector<uint8_t> &salt, size_t key_len)
    {
        std::vector<uint8_t> key(key_len);
        if (1 != PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password_bytes.data()), static_cast<int>(password_bytes.size()), salt.data(), salt.size(), PBKDF2_ITERATIONS, EVP_sha256(), key_len, key.data()))
        {
            secure_zero(key);
            throw std::runtime_error("PBKDF2 key derivation failed");
        }
        return key;
    }

#ifdef ACRYPT_HAVE_ARGON2
    std::vector<uint8_t> derive_key_argon2id(const std::vector<uint8_t> &password_bytes, const std::vector<uint8_t> &salt, size_t key_len)
    {
        std::vector<uint8_t> key(key_len);
        int rc = argon2id_hash_raw(ARGON2_TIME_COST, ARGON2_MEMORY_COST_KIB, ARGON2_PARALLELISM, password_bytes.data(), password_bytes.size(), salt.data(), salt.size(), key.data(), key_len);
        if (rc != ARGON2_OK)
        {
            secure_zero(key);
            throw std::runtime_error("Argon2id key derivation failed");
        }
        return key;
    }
#endif

    std::vector<uint8_t> derive_key_from_password(const std::string &password, const std::vector<uint8_t> &salt, size_t key_len, KDFAlgorithm kdf)
    {
        std::vector<uint8_t> password_bytes(password.begin(), password.end());
        try
        {
            if (kdf == KDFAlgorithm::PBKDF2)
            {
                auto key = derive_key_pbkdf2(password_bytes, salt, key_len);
                secure_zero(password_bytes);
                return key;
            }
#ifdef ACRYPT_HAVE_ARGON2
            if (kdf == KDFAlgorithm::Argon2id)
            {
                auto key = derive_key_argon2id(password_bytes, salt, key_len);
                secure_zero(password_bytes);
                return key;
            }
#else
            (void)kdf;
#endif
            auto fallback = derive_key_pbkdf2(password_bytes, salt, key_len);
            secure_zero(password_bytes);
            return fallback;
        }
        catch (...)
        {
            secure_zero(password_bytes);
            throw;
        }
    }

} // namespace

AES::AES(const std::vector<uint8_t> &key)
{
    if (key.size() != AES_256_KEY_SIZE)
    {
        throw std::invalid_argument("AES key must be " + std::to_string(AES_256_KEY_SIZE) + " bytes for AES-256.");
    }
    key_ = key;
}

AES::~AES()
{
    secure_zero(key_);
}

std::vector<uint8_t> AES::gcm_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &aad)
{
    EVP_CIPHER_CTX *ctx_raw = EVP_CIPHER_CTX_new();
    if (!ctx_raw)
    {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(ctx_raw, &EVP_CIPHER_CTX_free);

    int len = 0;
    int ciphertext_len = 0;
    std::vector<uint8_t> ciphertext_buf;
    std::vector<uint8_t> tag(GCM_TAG_SIZE);

    try
    {
        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw std::runtime_error("Failed to initialize GCM encryption");

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr))
            throw std::runtime_error("Failed to set GCM IV length");

        if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), iv.data()))
            throw std::runtime_error("Failed to set GCM key and IV");

        if (!aad.empty())
        {
            if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size()))
                throw std::runtime_error("Failed to process AAD");
        }

        ciphertext_buf.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext_buf.data(), &len, plaintext.data(), plaintext.size()))
            throw std::runtime_error("GCM EncryptUpdate failed");
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext_buf.data() + len, &len))
            throw std::runtime_error("GCM EncryptFinal failed");
        ciphertext_len += len;
        ciphertext_buf.resize(ciphertext_len);

        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()))
            throw std::runtime_error("Failed to get GCM tag");

        std::vector<uint8_t> result;
        result.reserve(iv.size() + ciphertext_buf.size() + tag.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext_buf.begin(), ciphertext_buf.end());
        result.insert(result.end(), tag.begin(), tag.end());

        secure_zero(ciphertext_buf);
        secure_zero(tag);
        ctx.reset();
        return result;
    }
    catch (...)
    {
        secure_zero(ciphertext_buf);
        secure_zero(tag);
        ctx.reset();
        throw;
    }
}

std::vector<uint8_t> AES::gcm_decrypt(const std::vector<uint8_t> &iv_ciphertext_tag_blob, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &aad)
{
    EVP_CIPHER_CTX *ctx_raw = EVP_CIPHER_CTX_new();
    if (!ctx_raw)
    {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(ctx_raw, &EVP_CIPHER_CTX_free);

    int len = 0;
    int plaintext_len = 0;
    int ret_val = 0;
    std::vector<uint8_t> plaintext_buf;

    if (iv_ciphertext_tag_blob.size() < GCM_TAG_SIZE)
    {
        throw std::runtime_error("Ciphertext too short to contain a tag.");
    }
    std::vector<uint8_t> ciphertext(iv_ciphertext_tag_blob.begin(), iv_ciphertext_tag_blob.end() - GCM_TAG_SIZE);
    std::vector<uint8_t> tag(iv_ciphertext_tag_blob.end() - GCM_TAG_SIZE, iv_ciphertext_tag_blob.end());

    try
    {
        if (!EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw std::runtime_error("Failed to initialize GCM decryption");

        if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr))
            throw std::runtime_error("Failed to set GCM IV length");

        if (!EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key_.data(), iv.data()))
            throw std::runtime_error("Failed to set GCM key and IV for decryption");

        if (!aad.empty())
        {
            if (!EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size()))
                throw std::runtime_error("Failed to process AAD during decryption");
        }

        plaintext_buf.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        if (!EVP_DecryptUpdate(ctx.get(), plaintext_buf.data(), &len, ciphertext.data(), ciphertext.size()))
            throw std::runtime_error("GCM DecryptUpdate failed");
        plaintext_len = len;

        if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag.data()))
            throw std::runtime_error("Failed to set GCM expected tag");

        ret_val = EVP_DecryptFinal_ex(ctx.get(), plaintext_buf.data() + len, &len);

        if (ret_val > 0)
        {
            plaintext_len += len;
            plaintext_buf.resize(plaintext_len);
            secure_zero(ciphertext);
            secure_zero(tag);
            ctx.reset();
            return plaintext_buf;
        }
        else
        {
            secure_zero(ciphertext);
            secure_zero(tag);
            secure_zero(plaintext_buf);
            ctx.reset();
            throw std::runtime_error("GCM decryption failed: Tag verification failed or other error.");
        }
    }
    catch (...)
    {
        secure_zero(ciphertext);
        secure_zero(tag);
        secure_zero(plaintext_buf);
        ctx.reset();
        throw;
    }
}

std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t> &plaintext)
{
    std::vector<uint8_t> iv = generate_secure_random_bytes(GCM_IV_SIZE);
    auto blob = gcm_encrypt(plaintext, iv);
    secure_zero(iv);
    return blob;
}

std::vector<uint8_t> AES::encrypt_deterministic(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &provided_iv)
{
    if (provided_iv.size() != GCM_IV_SIZE)
    {
        throw std::invalid_argument("Provided IV must be " + std::to_string(GCM_IV_SIZE) + " bytes for GCM.");
    }
    return gcm_encrypt(plaintext, provided_iv);
}

std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t> &iv_ciphertext_tag_blob)
{
    if (iv_ciphertext_tag_blob.size() < GCM_IV_SIZE + GCM_TAG_SIZE)
    {
        throw std::runtime_error("Input data too short to contain IV, ciphertext, and tag.");
    }

    std::vector<uint8_t> iv(iv_ciphertext_tag_blob.begin(), iv_ciphertext_tag_blob.begin() + GCM_IV_SIZE);
    std::vector<uint8_t> ciphertext_with_tag(iv_ciphertext_tag_blob.begin() + GCM_IV_SIZE, iv_ciphertext_tag_blob.end());
    return gcm_decrypt(ciphertext_with_tag, iv);
}

std::string encryptAES_GCM(const std::string &plain, const std::string &password, KDFAlgorithm kdf)
{
    std::vector<uint8_t> salt = generate_secure_random_bytes(KDF_SALT_SIZE);
    std::vector<uint8_t> derived_key;
    std::vector<uint8_t> plaintext_bytes(plain.begin(), plain.end());
    std::vector<uint8_t> blob;
    std::vector<uint8_t> packaged;
    std::string encoded;

    try
    {
        derived_key = derive_key_from_password(password, salt, AES_256_KEY_SIZE, kdf);
        AES aes(derived_key);
        blob = aes.encrypt(plaintext_bytes);

        packaged.reserve(salt.size() + blob.size());
        packaged.insert(packaged.end(), salt.begin(), salt.end());
        packaged.insert(packaged.end(), blob.begin(), blob.end());

        encoded = StringUtils::base64_encode(packaged);
    }
    catch (...)
    {
        secure_zero(salt);
        secure_zero(derived_key);
        secure_zero(plaintext_bytes);
        secure_zero(blob);
        secure_zero(packaged);
        throw;
    }

    secure_zero(salt);
    secure_zero(derived_key);
    secure_zero(plaintext_bytes);
    secure_zero(blob);
    secure_zero(packaged);

    return encoded;
}

std::string decryptAES_GCM(const std::string &cipher, const std::string &password, KDFAlgorithm kdf)
{
    std::vector<uint8_t> combined;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> blob;
    std::vector<uint8_t> derived_key;
    std::vector<uint8_t> plaintext_bytes;
    std::string plaintext;

    try
    {
        combined = StringUtils::base64_decode(cipher);
        if (combined.size() < KDF_SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE)
        {
            throw std::runtime_error("Ciphertext blob too small for salt, IV, and tag");
        }

        salt.assign(combined.begin(), combined.begin() + KDF_SALT_SIZE);
        blob.assign(combined.begin() + KDF_SALT_SIZE, combined.end());

        derived_key = derive_key_from_password(password, salt, AES_256_KEY_SIZE, kdf);
        AES aes(derived_key);
        plaintext_bytes = aes.decrypt(blob);
        plaintext.assign(plaintext_bytes.begin(), plaintext_bytes.end());
    }
    catch (...)
    {
        secure_zero(combined);
        secure_zero(salt);
        secure_zero(blob);
        secure_zero(derived_key);
        secure_zero(plaintext_bytes);
        secure_zero(plaintext);
        throw;
    }

    secure_zero(combined);
    secure_zero(salt);
    secure_zero(blob);
    secure_zero(derived_key);
    secure_zero(plaintext_bytes);

    return plaintext;
}