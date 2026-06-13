/**
 * @file ftp.hpp
 * @brief FTP 协议解码器
 * @details 识别 FTP 命令/响应，提取命令类型、参数和响应码。
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>


namespace sec::decoder
{

    /**
     * @brief FTP 消息类型
     */
    enum class ftp_message_type : std::uint8_t
    {
        /** @brief 客户端命令 */
        command,
        /** @brief 服务器响应 */
        response,
        /** @brief 无法识别 */
        unknown
    };


    /**
     * @brief FTP 解码结果
     */
    struct ftp_info
    {
        /** @brief 消息类型 */
        ftp_message_type type{ftp_message_type::unknown};
        /** @brief FTP 命令，如 USER、PASS、RETR */
        std::string command;
        /** @brief 命令参数或响应文本 */
        std::string argument;
        /** @brief 服务器响应码（仅响应消息） */
        std::int32_t status_code{0};
    };


    /**
     * @brief FTP 协议解码器
     */
    class ftp_decoder
    {
    public:
        ftp_decoder() = default;

        [[nodiscard]] auto decode(std::span<const std::byte> payload) noexcept
            -> std::optional<ftp_info>;
    };

} // namespace sec::decoder
