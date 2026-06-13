/**
 * @file socks5.hpp
 * @brief SOCKS5 协议解码器
 * @details 识别 SOCKS5 握手消息，提取版本号、认证方法和目标地址。
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>


namespace sec::decoder
{

    /**
     * @brief SOCKS5 解码结果
     */
    struct socks5_info
    {
        /** @brief SOCKS 版本号，应为 5 */
        std::uint8_t version{0};
        /** @brief 客户端支持的认证方法数量 */
        std::uint8_t method_count{0};
        /** @brief 目标地址 */
        std::string target_address;
        /** @brief 目标端口 */
        std::uint16_t target_port{0};
        /** @brief 命令类型：1=CONNECT，2=BIND，3=UDP ASSOCIATE */
        std::uint8_t command{0};
    };


    /**
     * @brief SOCKS5 协议解码器
     */
    class socks5_decoder
    {
    public:
        socks5_decoder() = default;

        [[nodiscard]] auto decode(std::span<const std::byte> payload) noexcept
            -> std::optional<socks5_info>;
    };

} // namespace sec::decoder
