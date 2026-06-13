/**
 * @file query.hpp
 * @brief 数据库查询辅助类
 * @details 为每张表提供类型安全的 CRUD 操作，
 * 封装 SQL 语句准备与参数绑定。
 */

#pragma once

#include <sec/store/database.hpp>
#include <sec/store/model.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>


namespace sec::store
{

    /**
     * @brief 设备表查询辅助类
     * @details 提供 devices 表的 upsert、按 IP 查询、全量查询、
     * 更新最后发现时间和计数操作。
     */
    class device_query
    {
    public:
        explicit device_query(database &db) noexcept;

        [[nodiscard]] auto upsert(const device_record &rec, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto find_by_ip(std::string_view ip, std::error_code &ec) noexcept
            -> std::optional<device_record>;

        [[nodiscard]] auto find_all(std::error_code &ec) noexcept
            -> std::vector<device_record>;

        [[nodiscard]] auto update_last_seen(std::string_view ip, std::int64_t timestamp, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto count(std::error_code &ec) noexcept -> std::int64_t;

    private:
        database &db_;
    };


    /**
     * @brief 扫描记录查询辅助类
     * @details 提供 scan_results 表的插入、状态更新、完成标记和最近查询操作。
     */
    class scan_query
    {
    public:
        explicit scan_query(database &db) noexcept;

        [[nodiscard]] auto insert(const scan_result &rec, std::error_code &ec) noexcept
            -> std::int64_t;

        /**
         * @brief 扫描状态更新参数
         */
        struct status_update
        {
            std::string_view status;
            std::string_view error;
        };

        /**
         * @brief 扫描完成统计参数
         */
        struct scan_completion
        {
            std::int32_t devices{0};
            std::int32_t ports{0};
        };

        [[nodiscard]] auto update_status(std::int64_t id, const status_update &upd, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto finish(std::int64_t id, const scan_completion &completion, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto find_recent(int limit, std::error_code &ec) noexcept
            -> std::vector<scan_result>;

    private:
        database &db_;
    };


    /**
     * @brief 流量日志查询辅助类
     * @details 提供 traffic_logs 表的单条/批量插入和按时间范围查询。
     */
    class traffic_query
    {
    public:
        explicit traffic_query(database &db) noexcept;

        [[nodiscard]] auto insert(const traffic_log &rec, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto insert_batch(const std::vector<traffic_log> &logs, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto find_by_time_range(std::int64_t from_ts, std::int64_t to_ts, std::error_code &ec) noexcept
            -> std::vector<traffic_log>;

    private:
        database &db_;
    };


    /**
     * @brief 告警记录查询辅助类
     * @details 提供 alerts 表的插入、确认和按严重程度/未确认查询。
     */
    class alert_query
    {
    public:
        explicit alert_query(database &db) noexcept;

        [[nodiscard]] auto insert(const alert_record &rec, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto acknowledge(std::int64_t id, std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto find_unacknowledged(std::error_code &ec) noexcept
            -> std::vector<alert_record>;

        [[nodiscard]] auto find_by_severity(std::string_view severity, std::error_code &ec) noexcept
            -> std::vector<alert_record>;

        [[nodiscard]] auto count_unacknowledged(std::error_code &ec) noexcept
            -> std::int64_t;

    private:
        database &db_;
    };


    [[nodiscard]] auto read_device(statement &stmt) noexcept -> device_record;
    [[nodiscard]] auto read_scan_result(statement &stmt) noexcept -> scan_result;
    [[nodiscard]] auto read_traffic_log(statement &stmt) noexcept -> traffic_log;
    [[nodiscard]] auto read_alert(statement &stmt) noexcept -> alert_record;

} // namespace sec::store
