/**
 * @file arp_detect.hpp
 * @brief ARP 欺骗检测器
 * @details 监控 ARP 应答报文，检测 MAC-IP 绑定冲突和
 * ARP 泛洪攻击。维护 ARP 表并报告异常。
 */

#pragma once

#include <sec/decoder/frame.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


namespace sec::mitm
{

    /**
     * @brief ARP 欺骗告警
     */
    struct arp_alert
    {
        /** @brief 冲突的 IP 地址 */
        std::uint32_t ip{0};
        /** @brief 原始 MAC 地址 */
        std::string original_mac;
        /** @brief 冲突 MAC 地址 */
        std::string conflict_mac;
        /** @brief 检测时间 */
        std::chrono::steady_clock::time_point detected_at;
        /** @brief 告警描述 */
        std::string description;
        /** @brief 告警类型标签 */
        std::string alert_type;
    };


    /**
     * @brief ARP 欺骗检测器
     * @details 维护 IP->MAC 绑定表，当同一 IP 出现不同 MAC 时
     * 产生告警。同时检测 ARP 泛洪（短时间内大量不同 MAC 对）。
     */
    class arp_detector
    {
    public:
        arp_detector() = default;

        /**
         * @brief 处理数据包，检测 ARP 欺骗
         * @param packet 已解析的数据包信息
         * @return 检测到欺骗时返回告警信息，否则返回 std::nullopt
         */
        [[nodiscard]] auto check(const decoder::packet_info &packet)
            -> std::optional<arp_alert>;

        /**
         * @brief 获取当前 ARP 绑定表的拷贝
         * @return IP->MAC 映射表
         */
        [[nodiscard]] auto arp_table() const noexcept
            -> std::unordered_map<std::uint32_t, std::string>
        {
            std::unordered_map<std::uint32_t, std::string> result;
            for (const auto &kv : bindings_)
            {
                result[kv.first] = kv.second.mac;
            }
            return result;
        }

        /**
         * @brief 清除 ARP 绑定表
         */
        void reset()
        {
            bindings_.clear();
            mac_bindings_.clear();
            flood_times_.clear();
            sweep_tracker_.clear();
        }

        /**
         * @brief 添加自身 MAC 地址（扫描时不触发 flood 告警）
         * @param mac MAC 地址字符串（AA:BB:CC:DD:EE:FF 格式）
         */
        void add_self_mac(std::string mac)
        {
            self_macs_.insert(std::move(mac));
        }

    private:
        struct binding_entry
        {
            std::string mac;
            std::chrono::steady_clock::time_point last_seen;
        };

        struct mac_ip_entry
        {
            std::unordered_map<std::uint32_t, std::chrono::steady_clock::time_point> ips;
        };

        void prune_bindings(std::chrono::steady_clock::time_point now);

        [[nodiscard]] auto check_flood(std::chrono::steady_clock::time_point now,
            const std::string &sender_mac, bool is_self) -> std::optional<arp_alert>;

        [[nodiscard]] auto check_gratuitous(std::chrono::steady_clock::time_point now,
            std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>;

        [[nodiscard]] auto check_sweep(std::chrono::steady_clock::time_point now,
            std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>;

        [[nodiscard]] auto check_conflict(std::chrono::steady_clock::time_point now,
            std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>;

        [[nodiscard]] auto check_mac_multi_ip(std::chrono::steady_clock::time_point now,
            std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>;

        std::unordered_map<std::uint32_t, binding_entry> bindings_;
        std::unordered_map<std::string, mac_ip_entry> mac_bindings_;
        std::deque<std::chrono::steady_clock::time_point> flood_times_;

        struct sweep_entry
        {
            std::uint32_t target_ip{0};
            std::chrono::steady_clock::time_point when;
        };
        std::unordered_map<std::string, std::deque<sweep_entry>> sweep_tracker_;

        std::unordered_set<std::string> self_macs_;
    };


} // namespace sec::mitm
