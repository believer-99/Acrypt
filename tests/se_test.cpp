#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>
#include "SE.hpp"
#include "AES.hpp"
#include "KeyManager.hpp"

bool compare_string_vectors_sorted(std::vector<std::string> v1, std::vector<std::string> v2)
{
    std::sort(v1.begin(), v1.end());
    std::sort(v2.begin(), v2.end());
    return v1 == v2;
}

void assert_true(bool condition, const std::string &test_name)
{
    if (!condition)
    {
        std::cerr << "[SE TEST FAILED] " << test_name << std::endl;
        throw std::runtime_error("Assertion failed in SE test: " + test_name);
    }
    std::cout << "[SE TEST PASSED] " << test_name << std::endl;
}

void test_edge_cases(SE &se_service)
{
    try
    {
        se_service.add("", {"doc1.txt"});
        std::cerr << "[SE TEST FAILED] Empty keyword should throw" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << "[SE TEST PASSED] Empty keyword rejected: " << e.what() << std::endl;
    }

    se_service.add("empty_docs", {});
    std::vector<std::string> result = se_service.search("empty_docs");
    assert_true(result.empty(), "Empty document list search");

    std::vector<std::string> large_docs(1000, "doc");
    for (size_t i = 0; i < 1000; ++i)
        large_docs[i] += std::to_string(i) + ".txt";
    se_service.add("large_dataset", large_docs);
    result = se_service.search("large_dataset");
    assert_true(result.size() == 1000, "Large dataset search");
}

int main()
{
    try
    {
        std::cout << "--- Running SE Tests (with AES-256-GCM and Base64) ---" << std::endl;

        std::vector<uint8_t> sse_key = KeyManager::generate_key(AES_256_KEY_SIZE);
        KeyManager::save_key(sse_key, "sse_key_test.bin");
        SE se_service(sse_key, ":memory:");

        std::string keyword1 = "document_encryption";
        std::vector<std::string> docs_k1 = {"confidential_report.docx", "meeting_notes_final.pdf"};

        std::string keyword2 = "image_processing";
        std::vector<std::string> docs_k2 = {"landscape.jpg", "portrait_edit.png", "architecture.tiff"};

        se_service.add(keyword1, docs_k1);
        se_service.add(keyword2, docs_k2);
        std::cout << "[+] Added documents for keyword1 and keyword2." << std::endl;

        std::vector<std::string> found_encrypted_k1 = se_service.search(keyword1);
        assert_true(found_encrypted_k1.size() == docs_k1.size(), "Search keyword1: Correct number of results");

        std::vector<std::string> decrypted_k1_results;
        for (const auto &enc_doc_id : found_encrypted_k1)
        {
            decrypted_k1_results.push_back(se_service.decryptDocIDFromBase64(enc_doc_id));
        }
        assert_true(compare_string_vectors_sorted(decrypted_k1_results, docs_k1), "Search keyword1: Decrypted results match originals");

        std::vector<std::string> found_encrypted_k2 = se_service.search(keyword2);
        assert_true(found_encrypted_k2.size() == docs_k2.size(), "Search keyword2: Correct number of results");

        std::vector<std::string> decrypted_k2_results;
        for (const auto &enc_doc_id : found_encrypted_k2)
        {
            decrypted_k2_results.push_back(se_service.decryptDocIDFromBase64(enc_doc_id));
        }
        assert_true(compare_string_vectors_sorted(decrypted_k2_results, docs_k2), "Search keyword2: Decrypted results match originals");

        std::vector<std::string> result_nonexistent = se_service.search("keyword_that_does_not_exist");
        assert_true(result_nonexistent.empty(), "Search for non-existent keyword");

        std::string new_doc_k1 = "archive_summary.txt";
        se_service.add(keyword1, {new_doc_k1});

        std::vector<std::string> updated_docs_k1 = docs_k1;
        updated_docs_k1.push_back(new_doc_k1);

        found_encrypted_k1 = se_service.search(keyword1);
        assert_true(found_encrypted_k1.size() == updated_docs_k1.size(), "Search keyword1 after adding more: Correct number");

        decrypted_k1_results.clear();
        for (const auto &enc_doc_id : found_encrypted_k1)
        {
            decrypted_k1_results.push_back(se_service.decryptDocIDFromBase64(enc_doc_id));
        }
        assert_true(compare_string_vectors_sorted(decrypted_k1_results, updated_docs_k1), "Search keyword1 after adding more: Decrypted results match");

        std::string keyword1_caps = "Document_Encryption";
        std::vector<std::string> docs_k1_caps = {"capitalized_doc.txt"};
        se_service.add(keyword1_caps, docs_k1_caps);

        std::vector<std::string> found_encrypted_k1_caps = se_service.search(keyword1_caps);
        assert_true(found_encrypted_k1_caps.size() == docs_k1_caps.size(), "Search Keyword1_caps: Correct number");

        std::vector<std::string> decrypted_k1_caps_results;
        for (const auto &enc_id : found_encrypted_k1_caps)
        {
            decrypted_k1_caps_results.push_back(se_service.decryptDocIDFromBase64(enc_id));
        }
        assert_true(compare_string_vectors_sorted(decrypted_k1_caps_results, docs_k1_caps), "Search Keyword1_caps: Decrypted results match");

        found_encrypted_k1 = se_service.search(keyword1);
        assert_true(found_encrypted_k1.size() == updated_docs_k1.size(), "Re-Search keyword1 (unaffected by caps): Correct number");

        std::vector<std::string> conjunctive_result = se_service.search("document_encryption&image_processing");
        assert_true(conjunctive_result.empty(), "Conjunctive search with no overlap");

        test_edge_cases(se_service);

        std::cout << "\n[✔] All SE tests passed successfully!" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "An exception occurred during SE tests: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}