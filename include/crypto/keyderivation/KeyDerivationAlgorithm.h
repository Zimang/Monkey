//
// Created by zimang on 2024/9/26.
//

#ifndef KEYDERIVATIONALGORITHM_H
#define KEYDERIVATIONALGORITHM_H

// 支持的密钥派生算法枚举
enum class KeyDerivationAlgorithm {
    PBKDF2,
    ARGON2,
    SCRYPT  // 预留，未来可扩展
};

#endif //KEYDERIVATIONALGORITHM_H
