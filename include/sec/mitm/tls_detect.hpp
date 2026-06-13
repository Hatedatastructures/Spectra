/**
 * @file tls_detect.hpp
 * @brief TLS 降级/剥离检测器
 * @details 检测 TLS 协议降级攻击、TLS 剥离和
 * 在 ClientHello 之后出现的非 TLS 响应。
 */

#pragma once

#include <sec/decoder/tls.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>


namespace sec::mitm
{

    /**
     * @brief TLS 降级告警类型
     */
    enum class tls_alert_type : std::uint8_t
    {
        /** @brief TLS 剥离 — ClientHello 后收到非 TLS 响应 */
        stripping,
        /** @brief 协议版本降级 */
        version_downgrade
    };


    /**
     * @brief TLS 降级告警
     */
    struct tls_alert
    {
        /** @brief 告警类型 */
        tls_alert_type type{tls_alert_type::stripping};
        /** @brief 客户端 IP */
        std::uint32_t client_ip{0};
        /** @brief 服务端 IP */
        std::uint32_t server_ip{0};
        /** @brief 客户端请求的最高 TLS 版本 */
        std::string client_version;
        /** @brief 实际协商的 TLS 版本 */
        std::string negotiated_version;
        /** @brief 检测原因 */
        std::string reason;
        /** @brief 检测时间 */
        std::chrono::steady_clock::time_point detected_at;
    };


    /**
     * @brief TLS 降级/剥离检测器
     * @details 跟踪 TLS ClientHello 请求，当后续出现
     * 非 TLS 响应或版本降级时产生告警。
     */
    class tls_detector
    {
    public:
        tls_detector() = default;

        /**
         * @brief 记录 TLS ClientHello
         * @param client_ip 客户端 IP
         * @param server_ip 服务端 IP
         * @param info TLS 解码结果
         */
        auto observe_client_hello(std::uint32_t client_ip, std::uint32_t server_ip,
            const decoder::tls_info &info) -> void;

        /**
         * @brief 检查非 TLS 响应是否构成 TLS 剥离
         * @param client_ip 客户端 IP
         * @param server_ip 服务端 IP
         * @param is_tls 当前响应是否为 TLS
         * @return 检测到剥离时返回告警
         */
        [[nodiscard]] auto check_response(std::uint32_t client_ip, std::uint32_t server_ip,
            bool is_tls) -> std::optional<tls_alert>;

        /**
         * @brief 检查 TLS 版本降级
         * @param client_ip 客户端 IP
         * @param server_ip 服务端 IP
         * @param info TLS 解码结果
         * @return 检测到降级时返回告警
         */
        [[nodiscard]] auto check_version_downgrade(std::uint32_t client_ip,
            std::uint32_t server_ip, const decoder::tls_info &info) -> std::optional<tls_alert>;

    private:
        struct tls_session
        {
            std::string client_version;
            std::chrono::steady_clock::time_point observed_at;
        };

        std::unordered_map<std::uint64_t, tls_session> pending_sessions_;

        auto make_key(std::uint32_t client_ip, std::uint32_t server_ip) noexcept
            -> std::uint64_t;
    };


} // namespace sec::mitm
