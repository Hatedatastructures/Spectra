/**
 * @file deviant.hpp
 * @brief 异常基类定义
 * @details 定义所有自定义异常的基类，支持源位置捕获
 * 和格式化消息。基于 std::error_code 架构，提供结构化
 * 异常信息。遵循热路径无异常原则，仅用于启动阶段。
 * @warning 异常构造和复制可能分配内存，避免在内存紧张时使用。
 */
#pragma once

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <filesystem>
#include <format>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>


namespace sec::exception
{

    /**
     * @brief 异常基类
     * @details 基于 std::runtime_error 的结构化异常基类，携带
     * std::error_code、std::source_location 和格式化消息。
     * 所有自定义异常（network/protocol/security）继承此类。
     */
    class deviant : public std::runtime_error
    {
    public:
        explicit deviant(std::error_code ec, std::string_view desc = {}, const std::source_location &loc = std::source_location::current())
            : std::runtime_error(create_what(ec, desc)), ec_(ec), location_(loc)
        {
        }

        explicit deviant(const std::string &msg, const std::source_location &loc = std::source_location::current())
            : deviant(std::error_code(static_cast<int>(fault::code::generic_error), fault::category()), msg, loc)
        {
        }

        template <typename... Args>
        explicit deviant(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::format(fmt, std::forward<Args>(args)...), loc)
        {
        }

        /**
         * @brief 获取错误码
         * @return 关联的 std::error_code 引用
         */
        [[nodiscard]] auto error_code() const noexcept -> const std::error_code &
        {
            return ec_;
        }

        /**
         * @brief 获取抛出位置
         * @return 源文件名、行号、函数名
         */
        [[nodiscard]] auto location() const noexcept -> const std::source_location &
        {
            return location_;
        }

        /**
         * @brief 获取源文件名（不含路径）
         * @return 文件名字符串
         */
        [[nodiscard]] auto filename() const -> std::string
        {
            return std::filesystem::path(location_.file_name()).filename().string();
        }

        /**
         * @brief 生成格式化异常转储
         * @return 格式为 "[文件:行] [类型:码] 消息" 的字符串
         */
        [[nodiscard]] virtual auto dump() const -> std::string
        {
            return std::format("[{}:{}] [{}:{}] {}", filename(), location_.line(),
                               type_name(), ec_.value(), std::runtime_error::what());
        }

    protected:
        [[nodiscard]] virtual auto type_name() const noexcept -> std::string_view = 0;

    private:
        [[nodiscard]] static auto create_what(const std::error_code &ec, std::string_view desc) -> std::string
        {
            if (desc.empty())
            {
                return ec.message();
            }
            return std::format("{}: {}", ec.message(), desc);
        }

        std::error_code ec_;
        std::source_location location_;
    }; // class deviant

} // namespace sec::exception
