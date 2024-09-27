//
// Created by zimang on 2024/9/26.
//
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include "../../../src/crypto/keyderivation/PBKDF2KeyDerivation.h"
#include "../../../src/crypto/keyderivation/Argon2KeyDerivation.h"
#include "../../../src/crypto/keyderivation/KeyDerivationBuilder.h"

// 测试 PBKDF2 密钥派生
TEST(KeyDerivationTest, PBKDF2KeyDerivationTest) {
    std::string password = "testpassword";
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int iterations = 10000;
    size_t keyLength = 32;  // 32 字节密钥

    PBKDF2KeyDerivation pbkdf2(password, salt, iterations, keyLength, "SHA-256");

    // 执行派生并检查结果长度
    std::vector<uint8_t> derivedKey = pbkdf2.deriveKey();
    EXPECT_EQ(derivedKey.size(), keyLength);

    // 打印派生出的密钥（可选）
    std::cout << "PBKDF2 derived key: ";
    for (auto byte : derivedKey) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    // 检查派生出的密钥是否不为空
    EXPECT_FALSE(derivedKey.empty());
}

// 测试 Argon2 密钥派生
TEST(KeyDerivationTest, Argon2KeyDerivationTest) {
    std::string password = "testpassword";
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int iterations = 3;
    size_t keyLength = 32;  // 32 字节密钥
    int memoryCost = 1 << 12;  // 4MB
    int parallelism = 1;

    Argon2KeyDerivation argon2(password, salt, iterations, keyLength, memoryCost, parallelism);

    // 执行派生并检查结果长度
    std::vector<uint8_t> derivedKey = argon2.deriveKey();
    EXPECT_EQ(derivedKey.size(), keyLength);

    // 打印派生出的密钥（可选）
    std::cout << "Argon2 derived key: ";
    for (auto byte : derivedKey) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    // 检查派生出的密钥是否不为空
    EXPECT_FALSE(derivedKey.empty());
}

// 测试 Builder 模式
TEST(KeyDerivationTest, BuilderPBKDF2Test) {
    KeyDerivationBuilder builder("testpassword");
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // 使用 PBKDF2 配置 Builder
    builder.setSalt(salt)
           .setIterations(10000)
           .setKeyLength(32)
           .setAlgorithm(KeyDerivationAlgorithm::PBKDF2);

    auto keyDerivation = builder.build();

    // 执行派生并检查结果
    std::vector<uint8_t> derivedKey = keyDerivation->deriveKey();
    EXPECT_EQ(derivedKey.size(), 32);
    EXPECT_EQ(keyDerivation->getAlgorithmName(), "PBKDF2");

    // 检查派生出的密钥是否不为空
    EXPECT_FALSE(derivedKey.empty());
}

// 测试 Builder 模式 Argon2
TEST(KeyDerivationTest, BuilderArgon2Test) {
    KeyDerivationBuilder builder("testpassword");
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // 使用 Argon2 配置 Builder
    builder.setSalt(salt)
           .setIterations(3)
           .setKeyLength(32)
           .setMemoryCost(1 << 12)  // 4MB
           .setParallelism(1)
           .setAlgorithm(KeyDerivationAlgorithm::ARGON2);

    auto keyDerivation = builder.build();

    // 执行派生并检查结果
    std::vector<uint8_t> derivedKey = keyDerivation->deriveKey();
    EXPECT_EQ(derivedKey.size(), 32);
    EXPECT_EQ(keyDerivation->getAlgorithmName(), "Argon2");

    // 检查派生出的密钥是否不为空
    EXPECT_FALSE(derivedKey.empty());
}
