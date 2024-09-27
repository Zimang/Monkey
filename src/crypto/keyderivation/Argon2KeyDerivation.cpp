//
// Created by zimang on 2024/9/27.
//

#include "Argon2KeyDerivation.h"
#include <stdexcept>
#include <iostream>  // 仅作演示使用，实际开发中可能不需要
#include <argon2.h>  // 使用 Argon2 库
#include <cstdint>

Argon2KeyDerivation::Argon2KeyDerivation(const std::string& password, const std::vector<uint8_t>& salt,
                                         int iterations, size_t keyLength, int memoryCost, int parallelism)
    : password(password), salt(salt), iterations(iterations), keyLength(keyLength),
      memoryCost(memoryCost), parallelism(parallelism) {
    if (memoryCost <= 0 || parallelism <= 0) {
        throw std::runtime_error("Argon2 requires memory cost and parallelism to be set.");
    }
}

std::vector<uint8_t> Argon2KeyDerivation::deriveKey() {
    std::vector<uint8_t> derivedKey(keyLength);

    // 使用 Argon2 库派生密钥
    int result = argon2i_hash_raw(iterations, memoryCost, parallelism,
                                  password.data(), password.size(),
                                  salt.data(), salt.size(),
                                  derivedKey.data(), keyLength);
    if (result != ARGON2_OK) {
        throw std::runtime_error("Argon2 key derivation failed");
    }

    return derivedKey;
}

std::string Argon2KeyDerivation::getAlgorithmName() const {
    return "Argon2";
}
