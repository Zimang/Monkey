# 定义密钥派生库
add_library(KeyDerivationLib
        PBKDF2KeyDerivation.cpp
)

# 包含公共头文件路径
target_include_directories(KeyDerivationLib PUBLIC ../../../include/crypto/keyderivation)