//
// Created by zimang on 2024/9/27.
//

#include "PBKDF2KeyDerivation.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

PBKDF2KeyDerivation::PBKDF2KeyDerivation(const std::string& password, const std::vector<uint8_t>& salt,
                                         int iterations, size_t keyLength, const std::string& hashFunction)
    : password(password), salt(salt), iterations(iterations), keyLength(keyLength), hashFunction(hashFunction) {}

std::vector<uint8_t> PBKDF2KeyDerivation::deriveKey() {
    std::vector<uint8_t> derivedKey(keyLength);

    // 使用 OpenSSL 的 PBKDF2 函数派生密钥
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                          salt.data(), salt.size(),
                          iterations, EVP_sha256(), // 假设使用 SHA-256
                          keyLength, derivedKey.data()) == 0) {
        throw std::runtime_error("PBKDF2 key derivation failed");
                          }

    return derivedKey;
}

std::string PBKDF2KeyDerivation::getAlgorithmName() const {
    return "PBKDF2";
}
