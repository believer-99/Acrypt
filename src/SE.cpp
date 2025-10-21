#include "SE.hpp"
#include "utils/String_utils.hpp"
#include <stdexcept>
#include <algorithm>
#include <openssl/sha.h>

std::string SE::convert_bytes_to_string(const std::vector<uint8_t> &data)
{
    return std::string(data.begin(), data.end());
}

std::vector<uint8_t> SE::derive_iv(const std::string &input)
{
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char *>(input.c_str()), input.size(), hash.data());
    hash.resize(GCM_IV_SIZE);
    return hash;
}

SE::SE(const std::vector<uint8_t> &key_param, const std::string &db_path)
    : aes(key_param)
{
    db = std::make_unique<SQLite::Database>(db_path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
    db->exec("CREATE TABLE IF NOT EXISTS index_table (keyword TEXT PRIMARY KEY, doc_ids TEXT)");
}

void SE::add(const std::string &keyword, const std::vector<std::string> &docIDs)
{
    if (keyword.empty())
        throw std::invalid_argument("Keyword cannot be empty");
    std::string encryptedKeywordBase64 = encryptKeyword(keyword);
    std::string doc_ids_str;
    for (const auto &docID : docIDs)
    {
        doc_ids_str += encryptDocID(docID) + ",";
    }
    if (!doc_ids_str.empty())
        doc_ids_str.pop_back();

    SQLite::Statement query(*db, "INSERT OR REPLACE INTO index_table (keyword, doc_ids) VALUES (?, ?)");
    query.bind(1, encryptedKeywordBase64);
    query.bind(2, doc_ids_str);
    query.exec();
}

std::vector<std::string> SE::search(const std::string &keyword)
{
    std::vector<std::string> keywords;
    std::string current;
    for (char c : keyword)
    {
        if (c == '&')
        {
            if (!current.empty())
                keywords.push_back(current);
            current.clear();
        }
        else
        {
            current += c;
        }
    }
    if (!current.empty())
        keywords.push_back(current);

    std::vector<std::string> result;
    bool first = true;
    for (const auto &kw : keywords)
    {
        if (kw.empty())
            continue;
        std::string encryptedKeywordBase64 = encryptKeyword(kw);
        SQLite::Statement query(*db, "SELECT doc_ids FROM index_table WHERE keyword = ?");
        query.bind(1, encryptedKeywordBase64);
        if (query.executeStep())
        {
            std::string doc_ids_str = query.getColumn(0).getString();
            std::vector<std::string> doc_ids;
            std::string current_id;
            for (char c : doc_ids_str)
            {
                if (c == ',')
                {
                    if (!current_id.empty())
                        doc_ids.push_back(current_id);
                    current_id.clear();
                }
                else
                {
                    current_id += c;
                }
            }
            if (!current_id.empty())
                doc_ids.push_back(current_id);
            if (first)
            {
                result = doc_ids;
                first = false;
            }
            else
            {
                std::vector<std::string> intersection;
                std::set_intersection(result.begin(), result.end(), doc_ids.begin(), doc_ids.end(),
                                      std::back_inserter(intersection));
                result = intersection;
            }
        }
        else
        {
            return {};
        }
    }
    return result;
}

std::string SE::encryptKeyword(const std::string &keyword)
{
    std::vector<uint8_t> input(keyword.begin(), keyword.end());
    std::vector<uint8_t> iv = derive_iv(keyword);
    std::vector<uint8_t> encrypted_blob = aes.encrypt_deterministic(input, iv);
    return StringUtils::base64_encode(encrypted_blob);
}

std::string SE::encryptDocID(const std::string &docID)
{
    std::vector<uint8_t> input(docID.begin(), docID.end());
    std::vector<uint8_t> iv = derive_iv(docID);
    std::vector<uint8_t> encrypted_blob = aes.encrypt_deterministic(input, iv);
    return StringUtils::base64_encode(encrypted_blob);
}

std::string SE::decryptDocIDFromBase64(const std::string &base64_encrypted_docID)
{
    std::vector<uint8_t> iv_ciphertext_tag_blob = StringUtils::base64_decode(base64_encrypted_docID);
    std::vector<uint8_t> decrypted_docID_bytes = aes.decrypt(iv_ciphertext_tag_blob);
    return convert_bytes_to_string(decrypted_docID_bytes);
}