//
// Created by zimang on 2024/9/27.
//

#ifndef KEYDERIVATIONBUILDER_H
#define KEYDERIVATIONBUILDER_H



#include "IKeyDerivation.h"
#include "PBKDF2KeyDerivation.h"
#include "Argon2KeyDerivation.h"
#include "KeyDerivationAlgorithm.h"
#include <memory>
#include <string>
#include <vector>

class KeyDerivationBuilder {
public:
    // 构造函数强制要求密码
    KeyDerivationBuilder(const std::string& password);

    // 设置盐
    KeyDerivationBuilder& setSalt(const std::vector<uint8_t>& customSalt);

    // 设置迭代次数
    KeyDerivationBuilder& setIterations(int customIterations);

    // 设置密钥长度
    KeyDerivationBuilder& setKeyLength(size_t customKeyLength);

    // 设置哈希函数
    KeyDerivationBuilder& setHashFunction(const std::string& customHashFunction);

    // 设置算法
    KeyDerivationBuilder& setAlgorithm(KeyDerivationAlgorithm algorithm);

    // Argon2 特有的参数
    KeyDerivationBuilder& setMemoryCost(int memoryCost);
    KeyDerivationBuilder& setParallelism(int parallelism);

    // 构建并返回 IKeyDerivation 实例
    std::unique_ptr<IKeyDerivation> build() const;

private:
    std::string password;
    std::vector<uint8_t> salt;
    int iterations;
    size_t keyLength;
    std::string hashFunction;
    KeyDerivationAlgorithm algorithm;

    // Argon2 特有参数
    int memoryCost;
    int parallelism;

    // 生成随机盐
    std::vector<uint8_t> generateSalt(size_t length) const;
};

#endif //KEYDERIVATIONBUILDER_H
