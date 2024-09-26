# 定义密钥管理库
add_library(KeyManagementLib
        FileKeyManagement.cpp
)

# 包含公共头文件路径
target_include_directories(KeyManagementLib PUBLIC ../../../include/crypto/keymanagement)