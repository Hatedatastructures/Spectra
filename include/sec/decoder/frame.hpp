/**
 * @file frame.hpp
 * @brief 原始数据包帧解析器
 * @details 解析 Ethernet II / IPv4 / TCP / UDP 协议头，
 * 提取源/目的 IP、端口、协议号、时间戳和载荷切片。
 */

#pragma once

#include <sec/decoder/util.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>


namespace sec::decoder
{

    /**
     * @brief ARP 包解析结果
     * @details 从 ARP 报文提取的操作码、发送方/目标 MAC 和 IP。
     */
    struct arp_packet
    {
        /** @brief ARP 操作码（1=请求, 2=应答） */
        std::uint16_t opcode{0};
        /** @brief 发送方 MAC 地址（6 字节） */
        std::array<std::byte, 6> sender_mac{};
        /** @brief 发送方 IP 地址，主机字节序 */
        std::uint32_t sender_ip{0};
        /** @brief 目标 MAC 地址（6 字节） */
        std::array<std::byte, 6> target_mac{};
        /** @brief 目标 IP 地址，主机字节序 */
        std::uint32_t target_ip{0};
    };


    /**
     * @brief 解析后的数据包信息
     * @details 包含从 Ethernet+IP+TCP/UDP 头部提取的所有关键字段，
     * payload 指向传输层载荷（不含 TCP/UDP 头）。
     * 对于 ARP 包，arp 字段包含解析结果，IP/端口字段为 0。
     */
    struct packet_info
    {
        /** @brief 源 IPv4 地址，主机字节序 */
        std::uint32_t src_ip{0};
        /** @brief 目的 IPv4 地址，主机字节序 */
        std::uint32_t dst_ip{0};
        /** @brief 源端口号 */
        std::uint16_t src_port{0};
        /** @brief 目的端口号 */
        std::uint16_t dst_port{0};
        /** @brief IP 协议号，6=TCP，17=UDP，0=ARP 等 */
        std::uint8_t protocol{0};
        /** @brief TCP flags（仅 TCP 包有效，比特位含义：SYN=0x02, ACK=0x10 等） */
        std::uint8_t tcp_flags{0};
        /** @brief 捕获时间戳 */
        std::chrono::microseconds timestamp{};
        /** @brief 传输层载荷切片 */
        std::span<const std::byte> payload{};
        /** @brief ARP 包解析结果（仅 ARP 包有效） */
        std::optional<arp_packet> arp{};
    };


    /**
     * @brief 原始数据包帧解析器
     * @details 逐步剥离 Ethernet II -> IPv4 -> TCP/UDP 头部，
     * 提取 packet_info。不处理分片、IP 选项等边缘情况。
     */
    class frame_parser
    {
    public:
        frame_parser() = default;

        /**
         * @brief 解析原始数据包
         * @param raw_data 从 pcap 捕获的完整帧数据（含 Ethernet 头）
         * @param ec 错误码输出
         * @return 解析成功返回 packet_info，帧格式错误返回 std::nullopt
         */
        [[nodiscard]] auto parse(std::span<const std::byte> raw_data, std::error_code &ec) noexcept
            -> std::optional<packet_info>;
    };

    // ip_to_string / mac_to_string / read_u{8,16,32}_be 由 <sec/decoder/util.hpp> 提供

} // namespace sec::decoder
