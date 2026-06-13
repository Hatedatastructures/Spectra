/**
 * @file security.hpp
 * @brief 安全异常定义
 * @details 定义 security 异常类，用于处理安全检测、
 * 威胁分析等安全层错误。
 * @warning 避免在热路径中抛出安全异常。
 */
#pragma once

#include <sec/exception/deviant.hpp>


namespace sec::exception
{

    /**
     * @brief 安全异常
     * @details 用于处理安全检测、威胁分析等安全层错误，
     * 如证书验证失败、权限不足、安全策略违反等。
     */
    class security : public deviant
    {
    public:
        explicit security(sec::fault::code err, const std::source_location &loc = std::source_location::current())
            : deviant(sec::fault::make_error_code(err), {}, loc)
        {
        }

        explicit security(sec::fault::code err, std::string_view desc, const std::source_location &loc = std::source_location::current())
            : deviant(sec::fault::make_error_code(err), desc, loc)
        {
        }

        explicit security(const std::string &msg, const std::source_location &loc = std::source_location::current())
            : deviant(msg, loc)
        {
        }

        template <typename... Args>
        explicit security(std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {
        }

        template <typename... Args>
        explicit security(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override
        {
            return "SECURITY";
        }
    }; // class security

} // namespace sec::exception
