/**
 * @file dns.hpp
 * @brief DNS 协议解码器
 * @details 解析 DNS wire format，提取查询名、记录类型、
 * 响应数据。支持 CNAME 链式解析和常见记录类型。
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
     * @brief DNS 记录类型枚举
     */
    enum class dns_record_type : std::uint16_t
    {
        /** @brief IPv4 地址记录 */
        a = 1,
        /** @brief 名称服务器记录 */
        ns = 2,
        /** @brief 规范名称记录 */
        cname = 5,
        /** @brief 邮件交换记录 */
        mx = 15,
        /** @brief 文本记录 */
        txt = 16,
        /** @brief IPv6 地址记录 */
        aaaa = 28,
        /** @brief 服务记录 */
        srv = 33,
        /** @brief 未知记录类型 */
        unknown = 0
    };


    /**
     * @brief DNS 查询/回答条目
     */
    struct dns_entry
    {
        /** @brief 域名 */
        std::string name;
        /** @brief 记录类型 */
        dns_record_type type{dns_record_type::unknown};
        /** @brief 记录数据（如 IP 地址文本表示） */
        std::string data;
        /** @brief TTL 值（秒） */
        std::uint32_t ttl{0};
    };


    /**
     * @brief DNS 解码结果
     */
    struct dns_info
    {
        /** @brief 事务 ID */
        std::uint16_t transaction_id{0};
        /** @brief 是否为响应 */
        bool is_response{false};
        /** @brief 操作码 */
        std::uint8_t opcode{0};
        /** @brief 响应码 */
        std::uint8_t rcode{0};
        /** @brief 查询条目列表 */
        std::vector<dns_entry> questions;
        /** @brief 回答条目列表 */
        std::vector<dns_entry> answers;
    };


    /**
     * @brief DNS 协议解码器
     * @details 解析 DNS 查询和响应消息的 wire format，
     * 提取域名、记录类型、TTL 和响应数据。
     */
    class dns_decoder
    {
    public:
        dns_decoder() = default;

        /**
         * @brief 尝试解码 DNS 消息
         * @param payload UDP 载荷数据
         * @return 解析成功返回 dns_info，否则返回 std::nullopt
         */
        [[nodiscard]] auto decode(std::span<const std::byte> payload) noexcept
            -> std::optional<dns_info>;
    };

} // namespace sec::decoder
