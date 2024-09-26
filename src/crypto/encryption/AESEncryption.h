//
// Created by zimang on 2024/9/26.
//

#ifndef AESENCRYPTION_H
#define AESENCRYPTION_H


#include "IEncryption.h"
#include <openssl/evp.h>   // OpenSSL 加密库

class AESEncryption : public IEncryption {
public:
    // AES 加密实现
    std::string encrypt(const std::string& data, const std::string& key) override;

    // AES 解密实现
    std::string decrypt(const std::string& data, const std::string& key) override;

private:
    std::string aesEncrypt(const std::string& data, const std::string& key);
    std::string aesDecrypt(const std::string& data, const std::string& key);
};

#endif //AESENCRYPTION_H
