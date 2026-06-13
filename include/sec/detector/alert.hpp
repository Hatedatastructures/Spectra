/**
 * @file alert.hpp
 * @brief 告警数据模型
 * @details 定义威胁告警的严重程度、类别和结构体，
 * 供规则引擎、异常检测和 AI 推理共同使用。
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <string>


namespace sec::detector
{

    /**
     * @brief 告警严重程度
     */
    enum class severity : std::uint8_t
    {
        /** @brief 信息 */
        info,
        /** @brief 低 */
        low,
        /** @brief 中 */
        medium,
        /** @brief 高 */
        high,
        /** @brief 危急 */
        critical
    };


    /**
     * @brief 告警类别
     */
    enum class category : std::uint8_t
    {
        /** @brief ARP 欺骗 */
        arp_spoofing,
        /** @brief DNS 劫持 */
        dns_hijack,
        /** @brief TLS 剥离 */
        tls_stripping,
        /** @brief 端口扫描 */
        port_scan,
        /** @brief 暴力破解 */
        brute_force,
        /** @brief 数据外泄 */
        data_exfiltration,
        /** @brief 恶意软件通信 */
        malware_communication,
        /** @brief 可疑流量 */
        suspicious_traffic,
        /** @brief AI 异常 */
        ai_anomaly,
        /** @brief 自定义规则 */
        custom
    };


    /**
     * @brief 将严重程度枚举转为字符串
     * @param sev 严重程度
     * @return 字符串表示，如 "high"
     */
    [[nodiscard]] auto to_string(severity sev) -> std::string_view;


    /**
     * @brief 将类别枚举转为字符串
     * @param cat 类别
     * @return 字符串表示，如 "arp_spoofing"
     */
    [[nodiscard]] auto to_string(category cat) -> std::string_view;


    /**
     * @brief 威胁告警
     * @details 统一的告警数据结构，由规则引擎、统计异常
     * 和 AI 推理共用。
     */
    struct alert
    {
        /** @brief 告警严重程度 */
        severity level{severity::info};
        /** @brief 告警类别 */
        category type{category::custom};
        /** @brief 源 IP */
        std::string source_ip;
        /** @brief 目标 IP */
        std::string target_ip;
        /** @brief 告警描述 */
        std::string description;
        /** @brief 匹配的规则 ID（规则引擎产生时有效） */
        std::string rule_id;
        /** @brief 置信度 [0.0, 1.0]（AI 推理产生时有效） */
        double confidence{0.0};
        /** @brief 检测时间 */
        std::chrono::steady_clock::time_point detected_at;
    };


} // namespace sec::detector
