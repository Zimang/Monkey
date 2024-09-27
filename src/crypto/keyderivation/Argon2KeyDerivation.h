//
// Created by zimang on 2024/9/27.
//

#ifndef ARGON2KEYDERIVATION_H
#define ARGON2KEYDERIVATION_H



#include "IKeyDerivation.h"
#include <string>
#include <vector>

class Argon2KeyDerivation : public IKeyDerivation {
public:
    Argon2KeyDerivation(const std::string& password, const std::vector<uint8_t>& salt,
                        int iterations, size_t keyLength, int memoryCost, int parallelism);

    // 实现 deriveKey() 方法，生成密钥
    std::vector<uint8_t> deriveKey() override;

    // 返回 Argon2 算法名称
    std::string getAlgorithmName() const override;

private:
    std::string password;
    std::vector<uint8_t> salt;
    int iterations;
    size_t keyLength;
    int memoryCost;
    int parallelism;
};


#endif //ARGON2KEYDERIVATION_H
