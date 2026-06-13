/**
 * @file smtp.hpp
 * @brief SMTP 协议解码器
 * @details 识别 SMTP 命令/响应，提取命令类型、参数和响应码。
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>


namespace sec::decoder
{

    /**
     * @brief SMTP 消息类型
     */
    enum class smtp_message_type : std::uint8_t
    {
        /** @brief 客户端命令 */
        command,
        /** @brief 服务器响应 */
        response,
        /** @brief 无法识别 */
        unknown
    };


    /**
     * @brief SMTP 解码结果
     */
    struct smtp_info
    {
        /** @brief 消息类型 */
        smtp_message_type type{smtp_message_type::unknown};
        /** @brief SMTP 命令，如 EHLO、MAIL、RCPT、DATA */
        std::string command;
        /** @brief 命令参数或响应文本 */
        std::string argument;
        /** @brief 服务器响应码（仅响应消息） */
        std::int32_t status_code{0};
    };


    /**
     * @brief SMTP 协议解码器
     */
    class smtp_decoder
    {
    public:
        smtp_decoder() = default;

        [[nodiscard]] auto decode(std::span<const std::byte> payload) noexcept
            -> std::optional<smtp_info>;
    };

} // namespace sec::decoder
