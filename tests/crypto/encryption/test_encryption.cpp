//
// Created by zimang on 2024/9/26.
//
#include <gtest/gtest.h>
#include "../../../src/crypto/encryption/AESEncryption.h"  // AESEncryption 类的头文件

// 测试用例1：加密和解密功能是否正常
TEST(AESEncryptionTest, EncryptDecryptTest) {
    AESEncryption aes;
    std::string key = "thisisaverysecurekeyof256bits!";
    std::string plaintext = "Hello, AES Encryption!";

    // 执行加密
    std::string encrypted = aes.encrypt(plaintext, key);

    // 确保加密后的字符串不为空
    ASSERT_FALSE(encrypted.empty());

    // 执行解密
    std::string decrypted = aes.decrypt(encrypted, key);

    // 解密后的字符串应该等于原始明文
    ASSERT_EQ(plaintext, decrypted);
}

// 测试用例2：加密空字符串
TEST(AESEncryptionTest, EncryptEmptyString) {
    AESEncryption aes;
    std::string key = "thisisaverysecurekeyof256bits!";
    std::string plaintext = "";  // 空字符串

    // 执行加密
    std::string encrypted = aes.encrypt(plaintext, key);

    // 确保加密后的字符串不为空
    ASSERT_FALSE(encrypted.empty());

    // 执行解密
    std::string decrypted = aes.decrypt(encrypted, key);

    // 解密后的字符串应该等于原始空字符串
    ASSERT_EQ(plaintext, decrypted);
}

// 测试用例3：使用无效长度的密钥
TEST(AESEncryptionTest, InvalidKeyTest) {
    AESEncryption aes;
    std::string invalidKey = "shortkey";  // 这是一个无效的密钥，假设需要256位密钥
    std::string plaintext = "Sensitive data";

    // 尝试加密并捕捉异常
    try {
        std::string encrypted = aes.encrypt(plaintext, invalidKey);
        FAIL() << "Expected std::runtime_error due to invalid key length.";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ("Encryption initialization failed", e.what());  // 确保异常消息正确
    } catch (...) {
        FAIL() << "Expected std::runtime_error due to invalid key length.";
    }
}

// 测试用例4：重复加密解密操作是否保持一致性
TEST(AESEncryptionTest, RepeatedEncryptDecryptTest) {
    AESEncryption aes;
    std::string key = "thisisaverysecurekeyof256bits!";
    std::string plaintext = "Repeated encryption test";

    for (int i = 0; i < 100; ++i) {
        std::string encrypted = aes.encrypt(plaintext, key);
        std::string decrypted = aes.decrypt(encrypted, key);
        ASSERT_EQ(plaintext, decrypted);  // 解密后的字符串每次都应该等于原始明文
    }
}

// 测试用例5：检查密文不同性
TEST(AESEncryptionTest, CiphertextUniquenessTest) {
    AESEncryption aes;
    std::string key = "thisisaverysecurekeyof256bits!";
    std::string plaintext = "Unique ciphertext test";

    // 执行两次加密
    std::string encrypted1 = aes.encrypt(plaintext, key);
    std::string encrypted2 = aes.encrypt(plaintext, key);

    // 确保加密后的密文不同，IV的使用应该保证这个特性
    ASSERT_NE(encrypted1, encrypted2);
}

