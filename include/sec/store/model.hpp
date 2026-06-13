/**
 * @file model.hpp
 * @brief 数据模型定义
 * @details 定义与数据库表对应的 C++ 结构体，
 * 用于 ORM 映射和数据传输。
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>


namespace sec::store
{

    /**
     * @brief 设备记录 — 对应 devices 表
     */
    struct device_record
    {
        std::int64_t id{0};
        std::string ip_address;
        std::string mac_address;
        std::string hostname;
        std::string vendor;
        std::string os_guess;
        /** @brief 开放端口列表，JSON 数组格式，如 "[22,80,443]" */
        std::string open_ports;
        /** @brief 首次发现时间，Unix 纪元秒 */
        std::int64_t first_seen{0};
        /** @brief 最后发现时间，Unix 纪元秒 */
        std::int64_t last_seen{0};
        bool is_gateway{false};
    };


    /**
     * @brief 扫描结果 — 对应 scan_results 表
     */
    struct scan_result
    {
        std::int64_t id{0};
        /** @brief 扫描类型：arp、mdns、ssdp、port */
        std::string scan_type;
        /** @brief 子网，如 "192.168.1.0/24" */
        std::string subnet;
        std::int64_t started_at{0};
        std::int64_t finished_at{0};
        std::int32_t device_count{0};
        std::int32_t open_port_count{0};
        /** @brief 状态：running、completed、failed */
        std::string status;
        std::string error_message;
    };


    /**
     * @brief 流量日志 — 对应 traffic_logs 表
     */
    struct traffic_log
    {
        std::int64_t id{0};
        std::string src_ip;
        std::string dst_ip;
        std::uint16_t src_port{0};
        std::uint16_t dst_port{0};
        /** @brief 协议号，6=TCP，17=UDP 等 */
        std::uint8_t protocol{0};
        /** @brief 时间戳，Unix 纪元微秒 */
        std::int64_t timestamp{0};
        std::int32_t packet_size{0};
        /** @brief 解码后的协议信息，如 HTTP host、DNS query 等 */
        std::string info;
    };


    /**
     * @brief 告警记录 — 对应 alerts 表
     */
    struct alert_record
    {
        std::int64_t id{0};
        /** @brief 告警类别，如 arp_spoofing、dns_hijack 等 */
        std::string category;
        /** @brief 严重程度：info、low、medium、high、critical */
        std::string severity;
        std::string source_ip;
        std::string target_ip;
        std::string description;
        std::int64_t timestamp{0};
        bool acknowledged{false};
    };

} // namespace sec::store
