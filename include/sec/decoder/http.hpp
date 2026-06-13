/**
 * @file http.hpp
 * @brief HTTP 协议解码器
 * @details 解析 HTTP 请求/响应，提取 method、URI、Host、
 * User-Agent、状态码等信息，支持分块传输编码。
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>


namespace sec::decoder
{

    /**
     * @brief HTTP 消息类型
     */
    enum class http_message_type : std::uint8_t
    {
        /** @brief 请求消息 */
        request,
        /** @brief 响应消息 */
        response,
        /** @brief 无法识别 */
        unknown
    };


    /**
     * @brief HTTP 解码结果
     * @details 包含从 HTTP 消息中提取的关键字段。
     */
    struct http_info
    {
        /** @brief 消息类型（请求/响应/未知） */
        http_message_type type{http_message_type::unknown};
        /** @brief 请求方法，如 GET、POST */
        std::string method;
        /** @brief 请求 URI */
        std::string uri;
        /** @brief HTTP 版本，如 "1.1" */
        std::string version;
        /** @brief 状态码（仅响应） */
        std::int32_t status_code{0};
        /** @brief Host 头部值 */
        std::string host;
        /** @brief User-Agent 头部值 */
        std::string user_agent;
        /** @brief Content-Type 头部值 */
        std::string content_type;
        /** @brief Content-Length 值，-1 表示未指定 */
        std::int64_t content_length{-1};
        /** @brief 载荷体切片 */
        std::span<const std::byte> body{};
    };


    /**
     * @brief HTTP 协议解码器
     * @details 从 TCP 载荷中识别并解析 HTTP 请求/响应。
     * 支持分块传输编码，提取常用头部字段。
     */
    class http_decoder
    {
    public:
        http_decoder() = default;

        /**
         * @brief 尝试解码 HTTP 消息
         * @param payload TCP 载荷数据
         * @return 识别成功返回 http_info，否则返回 std::nullopt
         */
        [[nodiscard]] auto decode(std::span<const std::byte> payload) noexcept
            -> std::optional<http_info>;
    };

} // namespace sec::decoder
