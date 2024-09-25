# 定义源文件并创建可执行文件
add_executable(MyApp main.cpp)

# 添加add模块的子目录
add_subdirectory(AddLib)

# 将可执行文件与必要的库链接
target_link_libraries(MyApp Addo_lib)
