# 指定 CMake 最低版本和项目名称
cmake_minimum_required(VERSION 3.16)
project(Monkey)

# 设置 C++ 标准为 C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)


# 配置不同的构建类型
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# 添加源文件目录
add_subdirectory(src)
# 添加测试文件目录
add_subdirectory(tests)

# ---- Google Test Integration ----

# 使用 FetchContent 来下载 Google Test
include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/release-1.12.1.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE  # 新增这一行
)

# 提取和编译 Google Test
FetchContent_MakeAvailable(googletest)

# 启用测试功能
enable_testing()

# 查找 OpenSSL 库
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# 查找 Argon2 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(Argon2 REQUIRED libargon2)
include_directories(${Argon2_INCLUDE_DIRS})