/**
 * @file device.hpp
 * @brief 设备数据模型
 * @details 定义局域网设备的核心数据结构，包含 IP/MAC 地址、
 * 主机名、厂商、开放端口、操作系统猜测等信息。
 */
#pragma once

#include <sec/memory/container.hpp>

#include <chrono>
#include <cstdint>


namespace sec::scanner
{

    /**
     * @brief 局域网设备数据模型
     * @details 包含设备的网络标识（IP/MAC）、主机信息（名称/厂商/OS）、
     * 安全信息（开放端口）和元数据（最后发现时间/网关标志）。
     * 以 MAC 地址作为设备唯一标识。
     */
    struct device
    {
        memory::string ip_address{};
        memory::string mac_address{};
        memory::string hostname{};
        memory::string vendor{};
        memory::vector<std::uint16_t> open_ports{};
        memory::string os_guess{};
        std::chrono::steady_clock::time_point last_seen{};
        bool is_gateway{false};

        [[nodiscard]] auto operator==(const device &other) const noexcept -> bool
        {
            return mac_address == other.mac_address;
        }

        [[nodiscard]] auto operator!=(const device &other) const noexcept -> bool
        {
            return !(*this == other);
        }
    };


} // namespace sec::scanner
