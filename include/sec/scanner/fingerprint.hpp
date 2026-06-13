/**
 * @file fingerprint.hpp
 * @brief 设备指纹识别
 * @details 通过 MAC OUI 前缀匹配 IEEE 数据库识别厂商，
 * 结合开放端口关联服务签名进行设备识别。
 */
#pragma once

#include <sec/scanner/device.hpp>

#include <cstdint>
#include <string>


namespace sec::scanner
{

    /**
     * @brief 设备指纹识别器
     * @details 通过 MAC OUI 前缀匹配 IEEE 数据库识别设备厂商，
     * 结合开放端口关联服务签名推测操作系统。识别结果直接更新到 device 结构。
     */
    class fingerprint
    {
    public:
        [[nodiscard]] static auto lookup_vendor(std::string_view mac_address)
            -> std::string;

        [[nodiscard]] static auto guess_os(const device &dev)
            -> std::string;

        static void identify(device &dev);
    };


} // namespace sec::scanner
