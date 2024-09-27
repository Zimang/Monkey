# 定义密钥派生库
add_library(KeyDerivationLib
        KeyDerivationBuilder.cpp
        PBKDF2KeyDerivation.cpp
        Argon2KeyDerivation.cpp
        Argon2KeyDerivation.h
)


# 查找 OpenSSL 库
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# 查找 Argon2 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(Argon2 REQUIRED libargon2)
include_directories(${Argon2_INCLUDE_DIRS})


# 包含公共头文件路径
target_include_directories(KeyDerivationLib PUBLIC ../../../include/crypto/keyderivation)

# 链接 OpenSSL 和 Argon2 库到 KeyDerivation 库
target_link_libraries(KeyDerivationLib
        ${OPENSSL_LIBRARIES}
        ${Argon2_LIBRARIES}
)