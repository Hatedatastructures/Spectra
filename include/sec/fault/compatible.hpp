/**
 * @file compatible.hpp
 * @brief 错误码标准库兼容性支持
 * @details 提供 fault::code 与 std::error_code 和
 * boost::system::error_code 的双向兼容性实现，包括
 * 错误分类、哈希支持和隐式转换特化。
 * @note 该文件实现了 std 和 boost::system 命名空间中
 * 的特化，遵循标准库扩展规则。
 * @warning 修改此文件可能影响 ABI 兼容性。
 */
#pragma once

#include <sec/fault/code.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <string>
#include <system_error>
#include <type_traits>


namespace sec::fault
{

    [[nodiscard]] inline auto cached_message(code c) noexcept
        -> const std::string &
    {
        constexpr auto code_count = static_cast<std::size_t>(code::_count);
        static const auto messages = []()
        {
            std::array<std::string, code_count + 1> arr{};
            for (std::size_t i = 0; i < code_count; ++i)
            {
                arr[i] = std::string(describe(static_cast<code>(i)));
            }
            arr[code_count] = "unknown";
            return arr;
        }();

        if (const auto index = static_cast<std::size_t>(c); index < code_count)
        {
            return messages[index];
        }
        return messages[code_count];
    }

    /**
     * @brief 错误分类实例
     * @details 单例模式，提供 fault::code 到字符串的映射。
     * 用于 std::error_code 和 boost::system::error_code 的分类查找。
     */
    class fault_category final : public std::error_category
    {
    public:
        [[nodiscard]] auto name() const noexcept
            -> const char * override
        {
            return "sec::fault";
        }

        [[nodiscard]] auto message(int c) const
            -> std::string override
        {
            return cached_message(static_cast<code>(c));
        }
    }; // class fault_category

    [[nodiscard]] inline auto category() noexcept
        -> const std::error_category &
    {
        static fault_category instance;
        return instance;
    }

    [[nodiscard]] inline auto make_error_code(code c) noexcept
        -> std::error_code
    {
        return {static_cast<int>(c), category()};
    }

} // namespace sec::fault

namespace std
{

    template <>
    struct is_error_code_enum<sec::fault::code> : std::true_type
    {
    };

    template <>
    struct hash<sec::fault::code>
    {
        [[nodiscard]] auto operator()(const sec::fault::code c) const noexcept
            -> std::size_t
        {
            return hash<int>{}(static_cast<int>(c));
        }
    };
} // namespace std

namespace boost::system
{

    template <>
    struct is_error_code_enum<sec::fault::code> : std::true_type
    {
    };

    class fault_category final : public error_category
    {
    public:
        [[nodiscard]] auto name() const noexcept
            -> const char * override
        {
            return "sec::fault";
        }

        [[nodiscard]] auto message(int c) const
            -> std::string override
        {
            return sec::fault::cached_message(static_cast<sec::fault::code>(c));
        }
    }; // class fault_category

    [[nodiscard]] inline auto category() noexcept
        -> const error_category &
    {
        static fault_category instance;
        return instance;
    }

    [[nodiscard]] inline auto make_error_code(const sec::fault::code c) noexcept
        -> error_code
    {
        return {static_cast<int>(c), category()};
    }

} // namespace boost::system
