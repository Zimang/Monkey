//
// Created by zimang on 2024/9/27.
//

#ifndef PBKDF2KEYDERIVATION_H
#define PBKDF2KEYDERIVATION_H



#include "IKeyDerivation.h"
#include <string>
#include <vector>

class PBKDF2KeyDerivation : public IKeyDerivation {
public:
    PBKDF2KeyDerivation(const std::string& password, const std::vector<uint8_t>& salt,
                        int iterations, size_t keyLength, const std::string& hashFunction);

    // 实现 deriveKey() 方法，生成密钥
    std::vector<uint8_t> deriveKey() override;

    // 返回 PBKDF2 算法名称
    std::string getAlgorithmName() const override;

private:
    std::string password;
    std::vector<uint8_t> salt;
    int iterations;
    size_t keyLength;
    std::string hashFunction;
};


#endif //PBKDF2KEYDERIVATION_H
