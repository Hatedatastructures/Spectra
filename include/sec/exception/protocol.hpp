/**
 * @file protocol.hpp
 * @brief 协议异常定义
 * @details 定义 protocol 异常类，用于处理协议解析、
 * 握手、格式验证等协议层错误。
 * @warning 避免在热路径中抛出协议异常。
 */
#pragma once

#include <sec/exception/deviant.hpp>


namespace sec::exception
{

    /**
     * @brief 协议异常
     * @details 用于处理协议解析、握手、格式验证等协议层错误，
     * 如消息格式损坏、协议版本不兼容等。
     */
    class protocol : public deviant
    {
    public:
        explicit protocol(sec::fault::code err, const std::source_location &loc = std::source_location::current())
            : deviant(sec::fault::make_error_code(err), {}, loc)
        {
        }

        explicit protocol(sec::fault::code err, std::string_view desc, const std::source_location &loc = std::source_location::current())
            : deviant(sec::fault::make_error_code(err), desc, loc)
        {
        }

        explicit protocol(const std::string &msg, const std::source_location &loc = std::source_location::current())
            : deviant(msg, loc)
        {
        }

        template <typename... Args>
        explicit protocol(std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {
        }

        template <typename... Args>
        explicit protocol(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        [[nodiscard]] auto type_name() const noexcept -> std::string_view override
        {
            return "PROTOCOL";
        }
    }; // class protocol

} // namespace sec::exception
