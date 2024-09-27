# 编译密钥派生模块测试文件
add_executable(TestKeyDerivation
        ../../test_main.cpp
        test_keyderivation.cpp
)


# 链接密钥派生模块库和 Google Test
target_link_libraries(TestKeyDerivation
        KeyDerivationLib
        gtest
        gtest_main
        ${OPENSSL_LIBRARIES}  # OpenSSL 库
        ${Argon2_LIBRARIES}   # Argon2 库
)

# 添加测试到 CTest
add_test(NAME TestKeyDerivation COMMAND TestKeyDerivation)
