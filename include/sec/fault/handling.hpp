/**
 * @file handling.hpp
 * @brief 极简错误码检查适配层
 * @details 提供对 fault::code、std::error_code 和
 * boost::system::error_code 的统一错误检查接口。
 * 所有函数均为 constexpr 和 noexcept，无动态分配，
 * 专为热路径设计。
 * @warning 热路径中所有错误必须通过错误码传播，禁止使用异常。
 */
#pragma once

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <boost/asio/error.hpp>

#include <string_view>
#include <system_error>
#include <type_traits>


namespace sec::fault
{

    template <typename ErrorCode>
    [[nodiscard]] constexpr auto succeeded(const ErrorCode &ec) noexcept
        -> bool
    {
        if constexpr (std::is_same_v<ErrorCode, code>)
        {
            return ec == code::success;
        }
        else if constexpr (std::is_same_v<ErrorCode, std::error_code>)
        {
            return !ec;
        }
        else if constexpr (std::is_same_v<ErrorCode, boost::system::error_code>)
        {
            return !ec;
        }
        else
        {
            static_assert(sizeof(ErrorCode) == 0, "不支持的错误码类型");
        }
        return false;
    }

    template <typename ErrorCode>
    [[nodiscard]] constexpr auto failed(const ErrorCode &ec) noexcept
        -> bool
    {
        return !succeeded(ec);
    }

    [[nodiscard]] inline auto to_code(const boost::system::error_code &ec) noexcept
        -> code
    {
        if (!ec)
        {
            return code::success;
        }

        if (std::string_view(ec.category().name()) == "sec::fault")
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<std::int32_t>(code::_count))
            {
                return static_cast<code>(value);
            }
            return code::generic_error;
        }

        if (ec == boost::asio::error::eof)
        {
            return code::eof;
        }
        if (ec == boost::asio::error::operation_aborted)
        {
            return code::canceled;
        }
        if (ec == boost::asio::error::timed_out)
        {
            return code::timeout;
        }
        if (ec == boost::asio::error::connection_refused)
        {
            return code::connection_refused;
        }
        if (ec == boost::asio::error::connection_reset)
        {
            return code::connection_reset;
        }
        if (ec == boost::asio::error::connection_aborted)
        {
            return code::connection_aborted;
        }
        if (ec == boost::asio::error::host_unreachable)
        {
            return code::host_noreply;
        }
        if (ec == boost::asio::error::network_unreachable)
        {
            return code::net_noreply;
        }
        if (ec == boost::asio::error::no_buffer_space)
        {
            return code::resource_unavailable;
        }

        return code::io_error;
    }

    [[nodiscard]] inline auto to_code(const std::error_code &ec) noexcept
        -> code
    {
        if (!ec)
        {
            return code::success;
        }

        if (&ec.category() == &sec::fault::category())
        {
            const auto value = ec.value();
            if (value >= 0 && value < static_cast<std::int32_t>(code::_count))
            {
                return static_cast<code>(value);
            }
            return code::generic_error;
        }

        static const auto ec_refused = std::make_error_code(std::errc::connection_refused);
        static const auto ec_reset = std::make_error_code(std::errc::connection_reset);
        static const auto ec_aborted = std::make_error_code(std::errc::connection_aborted);
        static const auto ec_timeout = std::make_error_code(std::errc::timed_out);
        static const auto ec_host = std::make_error_code(std::errc::host_unreachable);
        static const auto ec_net = std::make_error_code(std::errc::network_unreachable);
        static const auto ec_cancel = std::make_error_code(std::errc::operation_canceled);

        if (ec == ec_refused) { return code::connection_refused; }
        if (ec == ec_reset) { return code::connection_reset; }
        if (ec == ec_aborted) { return code::connection_aborted; }
        if (ec == ec_timeout) { return code::timeout; }
        if (ec == ec_host) { return code::host_noreply; }
        if (ec == ec_net) { return code::net_noreply; }
        if (ec == ec_cancel) { return code::canceled; }

        return code::io_error;
    }

} // namespace sec::fault
