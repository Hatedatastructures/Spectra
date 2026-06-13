/**
 * @file util.hpp
 * @brief 解码器公共工具函数
 * @details 提供 IP/MAC 格式化、大端整数读取等被多个解码器/扫描器/MITM 共用的原语。
 *           消除历史重复实现（4 个文件各自匿名命名空间维护同名函数）。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>

namespace sec::decoder
{
    /**
     * @brief 将主机字节序 IPv4 地址转为点分十进制字符串
     * @param ip 主机字节序 IPv4 地址
     * @return 点分十进制字符串，如 "192.168.1.1"
     */
    [[nodiscard]] inline auto ip_to_string(std::uint32_t ip) -> std::string
    {
        return std::to_string((ip >> 24) & 0xFF) + "." +
               std::to_string((ip >> 16) & 0xFF) + "." +
               std::to_string((ip >> 8) & 0xFF) + "." +
               std::to_string(ip & 0xFF);
    }


    /**
     * @brief 将 6 字节 MAC 地址格式化为 "XX:XX:XX:XX:XX:XX"
     */
    [[nodiscard]] inline auto mac_to_string(std::span<const std::byte, 6> mac) -> std::string
    {
        char buf[18]{};
        std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                      static_cast<unsigned>(mac[0]),
                      static_cast<unsigned>(mac[1]),
                      static_cast<unsigned>(mac[2]),
                      static_cast<unsigned>(mac[3]),
                      static_cast<unsigned>(mac[4]),
                      static_cast<unsigned>(mac[5]));
        return buf;
    }


    /**
     * @brief 重载：裸指针版本（要求指针至少 6 字节可读）
     */
    [[nodiscard]] inline auto mac_to_string(const std::byte *data) -> std::string
    {
        return mac_to_string(std::span<const std::byte, 6>{data, 6});
    }


    /**
     * @brief 读取 1 字节（与大端读取对称的辅助函数）
     */
    [[nodiscard]] inline auto read_u8(const std::byte *p) noexcept -> std::uint8_t
    {
        return static_cast<std::uint8_t>(*p);
    }


    /**
     * @brief 读取大端 16 位无符号整数
     */
    [[nodiscard]] inline auto read_u16_be(const std::byte *p) noexcept -> std::uint16_t
    {
        return (static_cast<std::uint16_t>(p[0]) << 8) |
               (static_cast<std::uint16_t>(p[1]));
    }


    /**
     * @brief 读取大端 32 位无符号整数
     */
    [[nodiscard]] inline auto read_u32_be(const std::byte *p) noexcept -> std::uint32_t
    {
        return (static_cast<std::uint32_t>(p[0]) << 24) |
               (static_cast<std::uint32_t>(p[1]) << 16) |
               (static_cast<std::uint32_t>(p[2]) << 8) |
               (static_cast<std::uint32_t>(p[3]));
    }

} // namespace sec::decoder
