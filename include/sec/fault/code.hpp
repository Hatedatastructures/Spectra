/**
 * @file code.hpp
 * @brief 全局错误码枚举定义
 * @details 定义系统通用的错误码枚举及基础辅助函数。
 * 错误码按功能分组：通用(0-10)、网络(11-20)、捕获(21-30)、
 * 协议(31-40)、安全(41-50)、扫描(51-60)、数据库(61-70)、
 * AI(71-80)、沙箱(81-90)。
 * @note 热路径必须使用错误码返回值，异常仅用于启动阶段。
 */
#pragma once

#include <cstdint>
#include <string_view>


namespace sec::fault
{

    /**
     * @enum code
     * @brief 全局错误码
     */
    enum class code : std::int32_t
    {
        /** @name 通用 (0-10) */
        ///@{
        success = 0,
        generic_error = 1,
        parse_error = 2,
        eof = 3,
        would_block = 4,
        invalid_argument = 5,
        not_supported = 6,
        io_error = 7,
        timeout = 8,
        canceled = 9,
        resource_unavailable = 10,
        ///@}

        /** @name 网络 (11-20) */
        ///@{
        connection_refused = 11,
        connection_reset = 12,
        connection_aborted = 13,
        host_noreply = 14,
        net_noreply = 15,
        dns_failed = 16,
        unreachable = 17,
        port_busy = 18,
        forbidden = 19,
        ///@}

        /** @name 捕获 (21-30) */
        ///@{
        capture_error = 21,
        pcap_open_failed = 22,
        pcap_read_failed = 23,
        pcap_filter_failed = 24,
        capture_stopped = 25,
        no_interface = 26,
        raw_socket_failed = 27,
        buffer_overflow = 28,
        ///@}

        /** @name 协议 (31-40) */
        ///@{
        protocol_error = 31,
        bad_message = 32,
        oversized_msg = 33,
        tls_hsfail = 34,
        http_parse_error = 35,
        dns_parse_error = 36,
        socks5_error = 37,
        ssh_error = 38,
        ftp_error = 39,
        smtp_error = 40,
        ///@}

        /** @name 安全 (41-50) */
        ///@{
        security_error = 41,
        arp_spoofing = 42,
        dns_hijack = 43,
        tls_stripping = 44,
        port_scan_detected = 45,
        brute_force = 46,
        data_exfiltration = 47,
        malware_detected = 48,
        suspicious_traffic = 49,
        policy_violation = 50,
        ///@}

        /** @name 扫描 (51-60) */
        ///@{
        scan_failed = 51,
        arp_failed = 52,
        mdns_failed = 53,
        ssdp_failed = 54,
        port_scan_failed = 55,
        fingerprint_failed = 56,
        device_timeout = 57,
        ///@}

        /** @name 数据库 (61-70) */
        ///@{
        db_error = 61,
        db_open_failed = 62,
        db_query_failed = 63,
        db_migration_failed = 64,
        db_constraint = 65,
        ///@}

        /** @name AI (71-80) */
        ///@{
        ai_error = 71,
        model_load_failed = 72,
        model_inference_failed = 73,
        feature_extract_failed = 74,
        invalid_input_shape = 75,
        ///@}

        /** @name 沙箱 (81-90) */
        ///@{
        sandbox_error = 81,
        payload_analysis_failed = 82,
        behavior_analysis_failed = 83,
        entropy_calculation_failed = 84,
        hash_lookup_failed = 85,
        ///@}

        _count = 86
    }; // enum class code

    [[nodiscard]] constexpr auto describe(const code value) noexcept
        -> std::string_view
    {
        switch (value)
        {
        case code::success: return "success";
        case code::generic_error: return "generic_error";
        case code::parse_error: return "parse_error";
        case code::eof: return "eof";
        case code::would_block: return "would_block";
        case code::invalid_argument: return "invalid_argument";
        case code::not_supported: return "not_supported";
        case code::io_error: return "io_error";
        case code::timeout: return "timeout";
        case code::canceled: return "canceled";
        case code::resource_unavailable: return "resource_unavailable";
        case code::connection_refused: return "connection_refused";
        case code::connection_reset: return "connection_reset";
        case code::connection_aborted: return "connection_aborted";
        case code::host_noreply: return "host_noreply";
        case code::net_noreply: return "net_noreply";
        case code::dns_failed: return "dns_failed";
        case code::unreachable: return "unreachable";
        case code::port_busy: return "port_busy";
        case code::forbidden: return "forbidden";
        case code::capture_error: return "capture_error";
        case code::pcap_open_failed: return "pcap_open_failed";
        case code::pcap_read_failed: return "pcap_read_failed";
        case code::pcap_filter_failed: return "pcap_filter_failed";
        case code::capture_stopped: return "capture_stopped";
        case code::no_interface: return "no_interface";
        case code::raw_socket_failed: return "raw_socket_failed";
        case code::buffer_overflow: return "buffer_overflow";
        case code::protocol_error: return "protocol_error";
        case code::bad_message: return "bad_message";
        case code::oversized_msg: return "oversized_msg";
        case code::tls_hsfail: return "tls_hsfail";
        case code::http_parse_error: return "http_parse_error";
        case code::dns_parse_error: return "dns_parse_error";
        case code::socks5_error: return "socks5_error";
        case code::ssh_error: return "ssh_error";
        case code::ftp_error: return "ftp_error";
        case code::smtp_error: return "smtp_error";
        case code::security_error: return "security_error";
        case code::arp_spoofing: return "arp_spoofing";
        case code::dns_hijack: return "dns_hijack";
        case code::tls_stripping: return "tls_stripping";
        case code::port_scan_detected: return "port_scan_detected";
        case code::brute_force: return "brute_force";
        case code::data_exfiltration: return "data_exfiltration";
        case code::malware_detected: return "malware_detected";
        case code::suspicious_traffic: return "suspicious_traffic";
        case code::policy_violation: return "policy_violation";
        case code::scan_failed: return "scan_failed";
        case code::arp_failed: return "arp_failed";
        case code::mdns_failed: return "mdns_failed";
        case code::ssdp_failed: return "ssdp_failed";
        case code::port_scan_failed: return "port_scan_failed";
        case code::fingerprint_failed: return "fingerprint_failed";
        case code::device_timeout: return "device_timeout";
        case code::db_error: return "db_error";
        case code::db_open_failed: return "db_open_failed";
        case code::db_query_failed: return "db_query_failed";
        case code::db_migration_failed: return "db_migration_failed";
        case code::db_constraint: return "db_constraint";
        case code::ai_error: return "ai_error";
        case code::model_load_failed: return "model_load_failed";
        case code::model_inference_failed: return "model_inference_failed";
        case code::feature_extract_failed: return "feature_extract_failed";
        case code::invalid_input_shape: return "invalid_input_shape";
        case code::sandbox_error: return "sandbox_error";
        case code::payload_analysis_failed: return "payload_analysis_failed";
        case code::behavior_analysis_failed: return "behavior_analysis_failed";
        case code::entropy_calculation_failed: return "entropy_calculation_failed";
        case code::hash_lookup_failed: return "hash_lookup_failed";
        default: return "unknown";
        }
    }

    [[nodiscard]] constexpr auto succeeded(const code c) noexcept
        -> bool
    {
        return c == code::success;
    }

    [[nodiscard]] constexpr auto failed(const code c) noexcept
        -> bool
    {
        return !succeeded(c);
    }

} // namespace sec::fault
