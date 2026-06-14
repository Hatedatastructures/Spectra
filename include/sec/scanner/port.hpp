/**
 * @file port.hpp
 * @brief TCP/UDP 端口扫描器
 * @details 并发 TCP 连接扫描，支持配置并发数和超时。
 * 通过 strand 聚合结果。
 */
#pragma once

#include <sec/engine/context.hpp>
#include <sec/scanner/device.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <set>
#include <span>
#include <string>
#include <system_error>
#include <vector>


namespace sec::scanner
{

    namespace net = boost::asio;

    /**
     * @brief 端口扫描选项
     * @details 配置端口扫描的目标端口列表、超时时间和最大并发数。
     */
    struct port_scan_options
    {
        std::vector<std::uint16_t> ports{};
        std::uint16_t timeout_ms{500};
        std::uint16_t concurrency{128};
    };


    /**
     * @brief TCP/UDP 端口扫描器
     * @details 并发 TCP 连接扫描，通过 strand 聚合结果。
     * 使用信号量控制并发连接数，避免触发目标防火墙。
     */
    class port_scanner
    {
    public:
        explicit port_scanner(engine::context &ctx);

        [[nodiscard]] auto scan(const std::string &target_ip, const port_scan_options &options, std::error_code &ec)
            -> net::awaitable<std::vector<std::uint16_t>>;

    private:
        [[nodiscard]] auto scan_single_port(const std::string &ip, std::uint16_t port, std::uint16_t timeout_ms)
            -> net::awaitable<bool>;

        engine::context &ctx_;
    };


} // namespace sec::scanner
