/**
 * @file container.hpp
 * @brief 内存容器别名定义
 * @details 定义使用 std::pmr 多态内存资源的容器别名，
 * 为项目提供统一的内存管理基础设施。所有容器类型
 * 均使用 polymorphic_allocator 分配器，支持运行时
 * 切换内存资源，实现与自定义内存池的无缝集成。
 */
#pragma once

#include <list>
#include <map>
#include <memory_resource>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>


namespace sec
{

} // namespace sec

namespace sec::memory
{

    using resource = std::pmr::memory_resource;

    using resource_pointer = std::add_pointer_t<resource>;

    [[nodiscard]] inline auto current_resource()
        -> resource_pointer
    {
        return std::pmr::get_default_resource();
    }

    [[nodiscard]] inline auto effective_mr(resource_pointer mr) noexcept
        -> resource_pointer
    {
        if (mr)
            return mr;
        return current_resource();
    }

    template <typename Type>
    using allocator = std::pmr::polymorphic_allocator<Type>;

    using synchronized_pool = std::pmr::synchronized_pool_resource;

    using unsynchronized_pool = std::pmr::unsynchronized_pool_resource;

    using monotonic_buffer = std::pmr::monotonic_buffer_resource;

    using string = std::pmr::string;

    template <typename Value>
    using vector = std::pmr::vector<Value>;

    template <typename Value>
    using list = std::pmr::list<Value>;

    template <typename Key, typename Value, typename Compare = std::less<Key>>
    using map = std::pmr::map<Key, Value, Compare>;

    template <typename Key, typename Value, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_map = std::pmr::unordered_map<Key, Value, Hash, KeyEqual>;

    template <typename Key, typename Hash = std::hash<Key>, typename KeyEqual = std::equal_to<Key>>
    using unordered_set = std::pmr::unordered_set<Key, Hash, KeyEqual>;

} // namespace sec::memory
