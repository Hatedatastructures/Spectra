/**
 * @file migration.hpp
 * @brief 数据库 Schema 迁移管理
 * @details 版本化迁移系统，维护 schema_versions 表，
 * 按序执行 SQL 迁移脚本。
 */

#pragma once

#include <sec/store/database.hpp>

#include <cstdint>
#include <string_view>
#include <system_error>


namespace sec::store
{

    /**
     * @brief 数据库迁移管理器
     */
    class migration_manager
    {
    public:
        explicit migration_manager(database &db) noexcept;

        [[nodiscard]] auto current_version(std::error_code &ec) noexcept -> std::int64_t;

        [[nodiscard]] auto migrate(std::error_code &ec) noexcept -> bool;

    private:
        [[nodiscard]] auto ensure_version_table(std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto apply_migration(std::int64_t version, std::string_view sql, std::error_code &ec) noexcept -> bool;

        database &db_;
    };

} // namespace sec::store
