//
// Created by zimang on 2024/9/27.
//

#include "KeyDerivationBuilder.h"
#include <openssl/rand.h>
#include <stdexcept>

KeyDerivationBuilder::KeyDerivationBuilder(const std::string& password)
    : password(password), iterations(10000), keyLength(32), hashFunction("SHA-256"),
      algorithm(KeyDerivationAlgorithm::PBKDF2), memoryCost(0), parallelism(0) {
    salt = generateSalt(16);  // 默认生成16字节的随机盐
}

KeyDerivationBuilder& KeyDerivationBuilder::setSalt(const std::vector<uint8_t>& customSalt) {
    this->salt = customSalt;
    return *this;
}

KeyDerivationBuilder& KeyDerivationBuilder::setIterations(int customIterations) {
    this->iterations = customIterations;
    return *this;
}

KeyDerivationBuilder& KeyDerivationBuilder::setKeyLength(size_t customKeyLength) {
    this->keyLength = customKeyLength;
    return *this;
}

KeyDerivationBuilder& KeyDerivationBuilder::setHashFunction(const std::string& customHashFunction) {
    this->hashFunction = customHashFunction;
    return *this;
}

KeyDerivationBuilder& KeyDerivationBuilder::setAlgorithm(KeyDerivationAlgorithm algorithm) {
    this->algorithm = algorithm;
    return *this;
}

KeyDerivationBuilder& KeyDerivationBuilder::setMemoryCost(int memoryCost) {
    if (algorithm != KeyDerivationAlgorithm::ARGON2) {
        throw std::runtime_error("Memory cost is only applicable for Argon2.");
    }
    this->memoryCost = memoryCost;
    return *this;
}

KeyDerivationBuilder& KeyDerivationBuilder::setParallelism(int parallelism) {
    if (algorithm != KeyDerivationAlgorithm::ARGON2) {
        throw std::runtime_error("Parallelism is only applicable for Argon2.");
    }
    this->parallelism = parallelism;
    return *this;
}

std::unique_ptr<IKeyDerivation> KeyDerivationBuilder::build() const {
    switch (algorithm) {
        case KeyDerivationAlgorithm::PBKDF2:
            return std::make_unique<PBKDF2KeyDerivation>(password, salt, iterations, keyLength, hashFunction);
        case KeyDerivationAlgorithm::ARGON2:
            if (memoryCost <= 0 || parallelism <= 0) {
                throw std::runtime_error("Argon2 requires memory cost and parallelism to be set.");
            }
            return std::make_unique<Argon2KeyDerivation>(password, salt, iterations, keyLength, memoryCost, parallelism);
        default:
            throw std::runtime_error("Unsupported key derivation algorithm");
    }
}

std::vector<uint8_t> KeyDerivationBuilder::generateSalt(size_t length) const {
    std::vector<uint8_t> salt(length);
    if (RAND_bytes(salt.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    return salt;
}
