/**
 * @file ssh.hpp
 * @brief SSH 协议解码器
 * @details 识别 SSH 握手消息，提取协议版本和客户端/服务器标识。
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>


namespace sec::decoder
{

    /**
     * @brief SSH 解码结果
     */
    struct ssh_info
    {
        /** @brief 协议版本字符串，如 "2.0" */
        std::string protocol_version;
        /** @brief 软件版本和注释 */
        std::string software_version;
        /** @brief 是否为服务器标识 */
        bool is_server{false};
    };


    /**
     * @brief SSH 协议解码器
     */
    class ssh_decoder
    {
    public:
        ssh_decoder() = default;

        [[nodiscard]] auto decode(std::span<const std::byte> payload) noexcept
            -> std::optional<ssh_info>;
    };

} // namespace sec::decoder
