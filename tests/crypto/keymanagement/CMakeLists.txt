# 编译密钥管理模块测试文件
add_executable(TestKeyManagement
        test_main.cpp
        test_keymanagement.cpp
)

# 链接密钥管理模块库和 Google Test
target_link_libraries(TestKeyManagement
        KeyManagementLib
        gtest
        gtest_main
)

# 添加测试到 CTest
add_test(NAME TestKeyManagement COMMAND TestKeyManagement)
