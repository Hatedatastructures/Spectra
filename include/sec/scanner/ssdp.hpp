/**
 * @file ssdp.hpp
 * @brief SSDP/UPnP 设备发现扫描器
 * @details 通过发送 M-SEARCH 到 239.255.255.250:1900 发现 UPnP 设备。
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
     * @brief SSDP/UPnP 设备发现扫描器
     * @details 通过发送 M-SEARCH 请求到组播地址 239.255.255.250:1900
     * 发现局域网中的 UPnP 设备，解析响应中的设备描述信息。
     */
    class ssdp_scanner
    {
    public:
        explicit ssdp_scanner(engine::context &ctx);

        [[nodiscard]] auto scan(std::error_code &ec)
            -> net::awaitable<std::vector<device>>;

    private:
        auto build_msearch_request() const -> std::vector<std::byte>;

        auto parse_ssdp_response(std::span<const std::byte> data) const
            -> std::vector<device>;

        engine::context &ctx_;
    };


} // namespace sec::scanner
