/**
 * @file mdns_scanner.hpp
 * @brief mDNS 服务发现扫描器
 * @details 通过发送 mDNS 查询到 224.0.0.251:5353 发现局域网服务。
 */
#pragma once

#include <sec/engine/context.hpp>
#include <sec/scanner/device.hpp>

#include <boost/asio.hpp>

#include <string>
#include <system_error>
#include <vector>


namespace sec::scanner
{

    namespace net = boost::asio;

    /**
     * @brief mDNS 服务发现扫描器
     * @details 通过发送 mDNS 查询到组播地址 224.0.0.251:5353 发现局域网服务，
     * 解析响应中的主机名和服务类型信息。
     */
    class mdns_scanner
    {
    public:
        explicit mdns_scanner(engine::context &ctx);

        auto scan(std::error_code &ec)
            -> net::awaitable<std::vector<device>>;

    private:
        auto build_mdns_query() const -> std::vector<std::byte>;

        auto parse_mdns_response(std::span<const std::byte> data) const
            -> std::vector<device>;

        engine::context &ctx_;
    };


} // namespace sec::scanner
