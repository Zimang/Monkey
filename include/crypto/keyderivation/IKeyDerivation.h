//
// Created by zimang on 2024/9/26.
//

#ifndef IKEYDERIVATION_H
#define IKEYDERIVATION_H

#include <cstdint>
#include <string>
#include <vector>

class IKeyDerivation {
public:
    virtual ~IKeyDerivation() = default;

    // 派生密钥的方法
    virtual std::vector<uint8_t> deriveKey() = 0;

    // 返回算法名称
    virtual std::string getAlgorithmName() const = 0;
};

#endif //IKEYDERIVATION_H
