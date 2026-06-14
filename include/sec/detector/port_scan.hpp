/**
 * @file port_scan.hpp
 * @brief 端口扫描检测器
 * @details 监控 TCP SYN 和 UDP 包，检测端口扫描、
 * UDP 扫描和网络扫射行为。使用滑动窗口统计。
 */

#pragma once

#include <sec/decoder/frame.hpp>
#include <sec/detector/alert.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>


namespace sec::detector
{

    /**
     * @brief 端口扫描告警
     */
    struct port_scan_alert
    {
        /** @brief 扫描源 IP，主机字节序 */
        std::uint32_t source_ip{0};
        /** @brief 扫描类型 */
        std::string scan_type;
        /** @brief 目标端口数 */
        std::size_t target_count{0};
        /** @brief 检测时间 */
        std::chrono::steady_clock::time_point detected_at;
    };


    /**
     * @brief 端口扫描检测器
     * @details 使用滑动窗口追踪每个源 IP 的目标端口/目标 IP 数量，
     * 超过阈值时产生告警。
     */
    class port_scan_detector
    {
    public:
        explicit port_scan_detector(
            std::size_t syn_threshold = 10,
            std::size_t udp_threshold = 10,
            std::size_t sweep_threshold = 5,
            std::uint32_t window_seconds = 5)
            : syn_threshold_{syn_threshold}
            , udp_threshold_{udp_threshold}
            , sweep_threshold_{sweep_threshold}
            , window_seconds_{window_seconds}
        {
        }

        /**
         * @brief 处理数据包，检测端口扫描
         * @param packet 已解析的数据包
         * @return 检测到扫描时返回告警
         */
        [[nodiscard]] auto check(const decoder::packet_info &packet)
            -> std::optional<port_scan_alert>;

        /**
         * @brief 清除所有追踪状态
         */
        void reset();

    private:
        struct hit
        {
            std::uint16_t port{0};
            std::uint32_t dst_ip{0};
            std::chrono::steady_clock::time_point when;
        };

        void prune(std::deque<hit> &hits, std::chrono::steady_clock::time_point now);

        std::size_t syn_threshold_;
        std::size_t udp_threshold_;
        std::size_t sweep_threshold_;
        std::uint32_t window_seconds_;

        std::unordered_map<std::uint32_t, std::deque<hit>> tcp_tracker_;
        std::unordered_map<std::uint32_t, std::deque<hit>> udp_tracker_;
    };


} // namespace sec::detector
