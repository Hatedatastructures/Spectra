/**
 * @file network.hpp
 * @brief 网络异常定义
 * @details 定义 network 异常类，用于处理网络配置和
 * 初始化阶段的错误。运行时网络 I/O 错误应使用错误码。
 * @warning 不要在热路径中抛出此异常。
 */
#pragma once

#include <sec/exception/deviant.hpp>


namespace sec::exception
{

    /**
     * @brief 网络异常
     * @details 用于处理网络配置和初始化阶段的错误，
     * 如 socket 创建失败、接口不存在等。
     * 运行时网络 I/O 错误应使用错误码而非异常。
     */
    class network : public deviant
    {
    public:
        explicit network(const fault::code err, const std::source_location &loc = std::source_location::current())
            : deviant(sec::fault::make_error_code(err), {}, loc)
        {
        }

        explicit network(const fault::code err, std::string_view desc, const std::source_location &loc = std::source_location::current())
            : deviant(sec::fault::make_error_code(err), desc, loc)
        {
        }

        explicit network(const std::string &msg, const std::source_location &loc = std::source_location::current())
            : deviant(msg, loc)
        {
        }

        template <typename... Args>
        explicit network(std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {
        }

        template <typename... Args>
        explicit network(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override
        {
            return "NETWORK";
        }
    }; // class network

} // namespace sec::exception
