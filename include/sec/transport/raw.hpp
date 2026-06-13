/**
 * @file raw.hpp
 * @brief 原始套接字传输层
 * @details 提供 IP 层原始套接字，用于 ARP/ICMP 等协议操作。
 * 基于 Boost.Asio generic::raw_protocol 实现。
 */
#pragma once

#include <sec/transport/transmission.hpp>

#include <boost/system/error_code.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <system_error>


namespace sec::transport
{

    /**
     * @brief 原始套接字端点
     * @details 封装 IPv4 地址和端口号，用于原始套接字通信目标。
     */
    struct endpoint
    {
        std::uint32_t address{0};
        std::uint16_t port{0};

        [[nodiscard]] auto to_string() const -> std::string;
    };


    /**
     * @brief 原始套接字传输层
     * @details 基于 Boost.Asio generic::raw_protocol 实现 IP 层原始套接字，
     * 用于 ARP 请求/应答、ICMP 探测等底层协议操作。
     * 支持面向目标的 sendto/recvfrom 语义。
     */
    class raw final : public transmission,
                      public std::enable_shared_from_this<raw>
    {
    public:
        explicit raw(net::any_io_executor executor);

        ~raw() noexcept override;

        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return type::raw;
        }

        [[nodiscard]] auto executor() const -> executor_type override;

        [[nodiscard]] auto async_send_to(std::span<const std::byte> data, const endpoint &dest, boost::system::error_code &ec)
            -> net::awaitable<std::size_t>;

        [[nodiscard]] auto async_receive_from(std::span<std::byte> buffer, endpoint &sender, boost::system::error_code &ec)
            -> net::awaitable<std::size_t>;

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;

        void cancel() override;

    private:
        net::generic::raw_protocol::socket socket_;
    };


} // namespace sec::transport
