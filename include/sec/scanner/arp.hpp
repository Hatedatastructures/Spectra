/**
 * @file arp.hpp
 * @brief ARP 扫描器
 * @details 通过发送 ARP 请求广播并等待回复来发现局域网设备。
 * 支持子网扫描和单目标扫描。
 */
#pragma once

#include <sec/engine/context.hpp>
#include <sec/scanner/device.hpp>
#include <sec/transport/raw.hpp>

#ifdef _WIN32
#include <sec/transport/pcap.hpp>
#endif

#include <boost/asio.hpp>

#include <cstdint>
#include <string>
#include <system_error>
#include <vector>
#include <array>


namespace sec::scanner
{

    namespace net = boost::asio;

    /**
     * @brief ARP 扫描器
     * @details 通过发送 ARP 请求广播并等待回复来发现局域网设备。
     * 支持子网批量扫描和单目标精确扫描，超时由 scanner_config 控制。
     */
    class arp_scanner
    {
    public:
        explicit arp_scanner(engine::context &ctx);

        [[nodiscard]] auto scan_subnet(std::string_view subnet, std::error_code &ec)
            -> net::awaitable<std::vector<device>>;

        [[nodiscard]] auto scan_single(std::string_view target_ip, std::error_code &ec)
            -> net::awaitable<std::optional<device>>;

    private:
        auto build_arp_request(std::uint32_t sender_ip, std::uint32_t target_ip) const
            -> std::vector<std::byte>;

        auto parse_arp_reply(std::span<const std::byte> data) const
            -> std::optional<device>;

#ifdef _WIN32
        /// Windows pcap 路径的回复状态（queue + timer 唤醒）
        struct reply_state
        {
            std::vector<std::vector<std::byte>> queue;
            net::steady_timer wakeup;
            explicit reply_state(net::any_io_executor ex)
                : wakeup(std::move(ex))
            {
            }
        };

        [[nodiscard]] auto scan_subnet_pcap(std::uint32_t start_ip, std::uint32_t end_ip,
                              std::error_code &ec)
            -> net::awaitable<std::vector<device>>;

        [[nodiscard]] auto scan_single_pcap(std::uint32_t target_ip,
                              std::error_code &ec)
            -> net::awaitable<std::optional<device>>;
#endif

        engine::context &ctx_;
        std::uint16_t arp_timeout_ms_;
        std::array<std::byte, 6> sender_mac_{};
        std::uint32_t sender_ip_{0};
    };


} // namespace sec::scanner
