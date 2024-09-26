# 定义源文件并创建可执行文件
add_executable(Monkey main.cpp
#        ../include/encryption/IEncryption.h
#        ../include/keyderivation/IKeyDerivation.h
#        ../include/keymanagement/IKeyManagement.h
#        encryption/AESEncryption.cpp
#        encryption/AESEncryption.h
#        keyderivation/PBKDF2KeyDerivation.cpp
#        keyderivation/PBKDF2KeyDerivation.h
#        keymanagement/FileKeyManagement.cpp
#        keymanagement/FileKeyManagement.h
)

# 添加add模块的子目录
add_subdirectory(AddLib)
add_subdirectory(crypto/encryption)
add_subdirectory(crypto/keyderivation)
add_subdirectory(crypto/keymanagement)

# 将可执行文件与必要的库链接
target_link_libraries(Monkey
        EncryptionLib  # 链接加密模块
        KeyDerivationLib  # 链接密钥派生模块
        KeyManagementLib  # 链接密钥管理模块
)
