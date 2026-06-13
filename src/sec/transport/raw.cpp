// 原始套接字传输层实现

#include <sec/transport/raw.hpp>

#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <cstring>


namespace sec::transport
{

    // 将端点地址转换为点分十进制字符串（MSB-first，与 parse_ipv4 对应）
    auto endpoint::to_string() const -> std::string
    {
        const auto a = (address >> 24) & 0xFF;
        const auto b = (address >> 16) & 0xFF;
        const auto c = (address >> 8) & 0xFF;
        const auto d = (address >> 0) & 0xFF;
        return std::to_string(a) + "." + std::to_string(b) + "." +
               std::to_string(c) + "." + std::to_string(d);
    }


    // 构造原始套接字
    raw::raw(net::any_io_executor executor)
        : socket_{executor, net::generic::raw_protocol(AF_INET, IPPROTO_RAW)}
    {
    }


    // 析构时自动关闭套接字
    raw::~raw() noexcept
    {
        try
        {
            close();
        }
        catch (...)
        {
        }
    }


    // 获取关联的 Asio 执行器
    [[nodiscard]] auto raw::executor() const -> executor_type
    {
        return const_cast<raw*>(this)->socket_.get_executor();
    }


    // 异步发送数据到指定端点
    auto raw::async_send_to(std::span<const std::byte> data, const endpoint &dest, boost::system::error_code &ec) -> net::awaitable<std::size_t>
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        std::memcpy(&addr.sin_addr, &dest.address, sizeof(dest.address));
        addr.sin_port = 0;

        net::generic::raw_protocol::endpoint remote_ep{&addr, sizeof(addr)};

        auto bytes_transferred = co_await socket_.async_send_to(
            net::buffer(data.data(), data.size()),
            remote_ep,
            net::redirect_error(net::use_awaitable, ec));

        if (ec)
        {
            spdlog::error("raw::async_send_to: send failed: {}", ec.message());
        }

        co_return bytes_transferred;
    }


    // 异步接收数据并获取发送方端点
    auto raw::async_receive_from(std::span<std::byte> buffer, endpoint &sender, boost::system::error_code &ec) -> net::awaitable<std::size_t>
    {
        net::generic::raw_protocol::endpoint remote_ep;
        auto bytes_transferred = co_await socket_.async_receive_from(
            net::buffer(buffer.data(), buffer.size()),
            remote_ep,
            net::redirect_error(net::use_awaitable, ec));

        if (!ec)
        {
            auto *addr = reinterpret_cast<const sockaddr_in*>(remote_ep.data());
            std::memcpy(&sender.address, &addr->sin_addr, sizeof(sender.address));
        }

        co_return bytes_transferred;
    }


    // 异步读取数据（transmission 接口）
    auto raw::async_read_some(std::span<std::byte> buffer, std::error_code &ec) -> net::awaitable<std::size_t>
    {
        boost::system::error_code bec;
        auto bytes_transferred = co_await socket_.async_receive(
            net::buffer(buffer.data(), buffer.size()),
            net::redirect_error(net::use_awaitable, bec));
        ec = bec;
        co_return bytes_transferred;
    }


    // 异步写入数据（transmission 接口）
    auto raw::async_write_some(std::span<const std::byte> buffer, std::error_code &ec) -> net::awaitable<std::size_t>
    {
        boost::system::error_code bec;
        auto bytes_transferred = co_await socket_.async_send(
            net::buffer(buffer.data(), buffer.size()),
            net::redirect_error(net::use_awaitable, bec));
        ec = bec;
        co_return bytes_transferred;
    }


    // 关闭套接字
    void raw::close()
    {
        if (socket_.is_open())
        {
            socket_.close();
        }
    }


    // 取消所有未完成的异步操作
    void raw::cancel()
    {
        if (socket_.is_open())
        {
            socket_.cancel();
        }
    }


} // namespace sec::transport
