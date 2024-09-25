#include <gtest/gtest.h>
#include "../src/AddLib/Addo.h"  // 引入需要测试的模块

// 测试 add 函数
TEST(AdditionTest, IntegerAddition) {
    EXPECT_EQ(add(3, 4), 7);  // 检查整数加法
}

TEST(AdditionTest, DoubleAddition) {
    EXPECT_DOUBLE_EQ(add(3.0, 4.5), 7.5);  // 检查浮点数加法
}


// 主测试程序入口
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
