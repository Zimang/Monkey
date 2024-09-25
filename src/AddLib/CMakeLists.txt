
# 定义模块 Addo_lib 的库
add_library(Addo_lib Addo.cpp)

# 设置头文件搜索路径，让其他模块或目标可以访问 Addo.h
target_include_directories(Addo_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})