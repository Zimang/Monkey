# 编译加密模块测试文件
add_executable(TestEncryption
        ../../test_main.cpp
        test_encryption.cpp
)
# 查找 OpenSSL 库
find_package(OpenSSL REQUIRED)

# 链接加密模块库和 Google Test
target_link_libraries(TestEncryption
        EncryptionLib
        gtest
        OpenSSL::SSL
        OpenSSL::Crypto
        gtest_main
)

# 添加测试到 CTest
add_test(NAME TestEncryption COMMAND TestEncryption)
