# 定义加密解密库
add_library(EncryptionLib
        AESEncryption.cpp
#RSAEncryption.cpp
#ChaCha20Encryption.cpp
)

# 包含公共头文件路径
target_include_directories(EncryptionLib PUBLIC ../../../include/crypto/encryption)