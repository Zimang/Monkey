//
// Created by zimang on 2024/9/26.
//

#ifndef IENCRYPTION_H
#define IENCRYPTION_H

#include <string>

class IEncryption {
public:
    virtual ~IEncryption() = default;

    // 加密方法
    virtual std::string encrypt(const std::string& data, const std::string& key) = 0;

    // 解密方法
    virtual std::string decrypt(const std::string& data, const std::string& key) = 0;
};

#endif //IENCRYPTION_H
