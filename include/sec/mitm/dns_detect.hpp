/**
 * @file dns_detect.hpp
 * @brief DNS 劫持检测器
 * @details 分析 DNS 响应报文，检测 DNS 劫持、
 * 异常低 TTL 和可疑解析结果。
 */

#pragma once

#include <sec/decoder/dns.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>


namespace sec::mitm
{

    /**
     * @brief DNS 劫持告警
     */
    struct dns_alert
    {
        /** @brief 查询域名 */
        std::string query_name;
        /** @brief 预期解析结果 */
        std::string expected_ip;
        /** @brief 实际解析结果 */
        std::string actual_ip;
        /** @brief 响应 TTL 值 */
        std::uint32_t ttl{0};
        /** @brief 检测原因 */
        std::string reason;
        /** @brief 检测时间 */
        std::chrono::steady_clock::time_point detected_at;
    };


    /**
     * @brief DNS 劫持检测器
     * @details 对比 DNS 响应中的解析结果，检测已知域名的
     * 异常解析、极低 TTL 和可疑 IP 地址。
     */
    class dns_detector
    {
    public:
        dns_detector() = default;

        /**
         * @brief 分析 DNS 解码结果，检测劫持
         * @param dns_info DNS 解码结果
         * @return 检测到劫持时返回告警，否则返回 std::nullopt
         */
        [[nodiscard]] auto check(const decoder::dns_info &dns_info)
            -> std::optional<dns_alert>;

        /**
         * @brief 添加已知的域名-IP 绑定
         * @param domain 域名
         * @param ip 预期 IP 地址
         */
        void add_known_binding(const std::string &domain, const std::string &ip)
        {
            known_bindings_[domain] = ip;
        }

        /**
         * @brief 添加可疑 IP 段
         * @param ip 可疑 IP 地址
         */
        void add_suspicious_ip(const std::string &ip)
        {
            suspicious_ips_.insert(ip);
        }

    private:
        std::unordered_map<std::string, std::string> known_bindings_;
        std::unordered_set<std::string> suspicious_ips_;
    };


} // namespace sec::mitm
