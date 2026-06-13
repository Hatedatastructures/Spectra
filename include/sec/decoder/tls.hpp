/**
 * @file tls.hpp
 * @brief TLS ClientHello 解码器
 * @details 解析 TLS ClientHello 消息，提取 SNI、支持的版本、
 * 密码套件列表，并计算 JA3 指纹。
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>


namespace sec::decoder
{

    /**
     * @brief TLS ClientHello 解码结果
     */
    struct tls_info
    {
        /** @brief TLS 记录层版本 */
        std::uint16_t record_version{0};
        /** @brief ClientHello 中的客户端版本 */
        std::uint16_t client_version{0};
        /** @brief Server Name Indication 域名 */
        std::string sni;
        /** @brief 支持的 TLS 版本列表（从扩展中提取） */
        std::vector<std::uint16_t> supported_versions;
        /** @brief 密码套件 ID 列表 */
        std::vector<std::uint16_t> cipher_suites;
        /** @brief 扩展类型 ID 列表 */
        std::vector<std::uint16_t> extensions;
        /** @brief 椭圆曲线列表 */
        std::vector<std::uint16_t> elliptic_curves;
        /** @brief 椭圆曲线点格式列表 */
        std::vector<std::uint8_t> ec_point_formats;
        /** @brief JA3 指纹字符串 */
        std::string ja3;
    };


    /**
     * @brief TLS ClientHello 解码器
     * @details 从 TCP 载荷中识别 TLS 记录并解析 ClientHello，
     * 提取 SNI、密码套件、扩展等信息，计算 JA3 指纹。
     */
    class tls_decoder
    {
    public:
        tls_decoder() = default;

        /**
         * @brief 尝试解码 TLS ClientHello
         * @param payload TCP 载荷数据
         * @return 识别并解析成功返回 tls_info，否则返回 std::nullopt
         */
        [[nodiscard]] auto decode(std::span<const std::byte> payload) noexcept
            -> std::optional<tls_info>;
    };

} // namespace sec::decoder
