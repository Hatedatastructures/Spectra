/**
 * @file persist.hpp
 * @brief 扫描结果持久化协调器
 * @details 编排扫描记录生命周期和设备 upsert，
 * 提供 open_ports 向量转 JSON 的辅助函数。
 */

#pragma once

#include <sec/store/database.hpp>
#include <sec/store/model.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>


namespace sec::store
{

    /**
     * @brief 扫描结果持久化协调器
     * @details 编排扫描记录的完整生命周期：begin_scan 创建记录，
     * save_devices 批量 upsert 设备，end_scan/end_scan_error 完成/标记失败。
     */
    class scan_persister
    {
    public:
        explicit scan_persister(database &db) noexcept;

        [[nodiscard]] auto begin_scan(std::string_view scan_type, std::string_view subnet, std::error_code &ec) noexcept
            -> std::int64_t;

        [[nodiscard]] auto save_devices(const std::vector<device_record> &devices, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto end_scan(std::int64_t scan_id, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto end_scan_error(std::int64_t scan_id, std::string_view error, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] static auto ports_to_json(
            const std::vector<std::uint16_t> &ports) -> std::string;

    private:
        database &db_;
    };

} // namespace sec::store
