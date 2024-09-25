#pragma once
#include <concepts>
#include <iostream>

// 定义一个 C++20 concepts 来约束类型
template <typename T>
concept Addable = requires(T a, T b) {
    { a + b } -> std::convertible_to<T>;
};

// 使用 concepts 的函数模板
template <Addable T>
T add(T a, T b) {
    return a + b;
}
