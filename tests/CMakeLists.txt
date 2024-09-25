# 添加测试可执行文件
add_executable(MyTests test_main.cpp)

# 链接 Google Test 库
target_link_libraries(MyTests gtest gtest_main)

# 将测试注册为 CTest 测试的一部分
add_test(NAME MyTests COMMAND MyTests)
