// TCP 端口扫描器实现 — 并发 TCP 连接扫描

#include <sec/scanner/port_scanner.hpp>
#include <sec/fault/code.hpp>

#include <spdlog/spdlog.h>

#include <boost/system/error_code.hpp>

#include <algorithm>


namespace sec::scanner
{

    namespace net = boost::asio;

    // 构造端口扫描器
    port_scanner::port_scanner(engine::context &ctx)
        : ctx_{ctx}
    {
    }


    // 扫描单个 TCP 端口是否开放
    auto port_scanner::scan_single_port(const std::string &ip, std::uint16_t port, std::uint16_t timeout_ms) -> net::awaitable<bool>
    {
        auto executor = co_await net::this_coro::executor;

        net::ip::tcp::socket socket{executor};
        net::ip::tcp::endpoint endpoint{
            net::ip::make_address(ip), port};

        auto timer = net::steady_timer(executor,
                                       std::chrono::milliseconds(timeout_ms));

        bool connected{false};
        bool timed_out{false};

        timer.async_wait([&](std::error_code) {
            timed_out = true;
            socket.close();
        });

        auto connect_ec = boost::system::error_code{};
        co_await socket.async_connect(endpoint,
                                      net::redirect_error(net::use_awaitable, connect_ec));

        if (!connect_ec && !timed_out)
        {
            connected = true;
        }

        timer.cancel();

        if (socket.is_open())
        {
            socket.close();
        }

        co_return connected;
    }


    // 扫描目标 IP 的多个端口
    auto port_scanner::scan(const std::string &target_ip, const port_scan_options &options, std::error_code &ec) -> net::awaitable<std::vector<std::uint16_t>>
    {
        if (options.ports.empty())
        {
            ec.clear();
            co_return std::vector<std::uint16_t>{};
        }

        auto executor = co_await net::this_coro::executor;

        std::vector<std::uint16_t> open_ports;

        for (auto port : options.ports)
        {
            auto is_open = co_await scan_single_port(
                target_ip, port, options.timeout_ms);

            if (is_open)
            {
                open_ports.push_back(port);
            }
        }

        std::sort(open_ports.begin(), open_ports.end());

        spdlog::info("Port scan {} complete: {} open ports",
                     target_ip, open_ports.size());

        ec.clear();
        co_return open_ports;
    }


} // namespace sec::scanner
