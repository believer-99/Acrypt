#pragma once

#include <vector>
#include <string>
#include "AES.hpp"
#include <SQLiteCpp/SQLiteCpp.h>

class SE
{
private:
    AES aes;
    std::unique_ptr<SQLite::Database> db;
    std::vector<uint8_t> derive_iv(const std::string &input);

    std::string encryptKeyword(const std::string &keyword);
    std::string encryptDocID(const std::string &docID);
    static std::string convert_bytes_to_string(const std::vector<uint8_t> &data);

public:
    SE(const std::vector<uint8_t> &key, const std::string &db_path = "sse_index.db");
    void add(const std::string &keyword, const std::vector<std::string> &docIDs);
    std::vector<std::string> search(const std::string &keyword);
    std::string decryptDocIDFromBase64(const std::string &base64_encrypted_docID);
};