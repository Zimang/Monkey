//
// Created by zimang on 2024/9/26.
//
// AESEncryption.cpp
#include "AESEncryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

const int AES_BLOCK_SIZE = 16;

std::string AESEncryption::encrypt(const std::string& data, const std::string& key) {
    return aesEncrypt(data, key);
}

std::string AESEncryption::decrypt(const std::string& data, const std::string& key) {
    return aesDecrypt(data, key);
}

std::string AESEncryption::aesEncrypt(const std::string& data, const std::string& key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context");

    // Generate an initialization vector (IV)
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (!RAND_bytes(iv.data(), AES_BLOCK_SIZE)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    // Initialize encryption
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.data()), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption initialization failed");
    }

    std::vector<unsigned char> encrypted(data.size() + AES_BLOCK_SIZE);
    int len;
    if (1 != EVP_EncryptUpdate(ctx, encrypted.data(), &len,
                               reinterpret_cast<const unsigned char*>(data.data()), data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }
    int encrypted_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed");
    }
    encrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Append IV to the encrypted data for use during decryption
    std::string result(reinterpret_cast<char*>(iv.data()), AES_BLOCK_SIZE);
    result += std::string(reinterpret_cast<char*>(encrypted.data()), encrypted_len);
    return result;
}

std::string AESEncryption::aesDecrypt(const std::string& data, const std::string& key) {
    if (data.size() < AES_BLOCK_SIZE) {
        throw std::runtime_error("Data too short to contain IV");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context");

    // Extract the IV from the encrypted data
    const unsigned char *iv = reinterpret_cast<const unsigned char*>(data.data());
    const unsigned char *ciphertext = reinterpret_cast<const unsigned char*>(data.data() + AES_BLOCK_SIZE);
    int ciphertext_len = data.size() - AES_BLOCK_SIZE;

    // Initialize decryption
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.data()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption initialization failed");
    }

    std::vector<unsigned char> decrypted(ciphertext_len + AES_BLOCK_SIZE);
    int len;
    if (1 != EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }
    int decrypted_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed");
    }
    decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(decrypted.data()), decrypted_len);
}