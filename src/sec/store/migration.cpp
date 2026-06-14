// 数据库 Schema 迁移实现

#include <sec/store/migration.hpp>
#include <sec/fault/compatible.hpp>
#include <sec/fault/code.hpp>

#include <sqlite3.h>

#include <array>


namespace sec::store
{

    namespace
    {

        struct migration_entry
        {
            std::int64_t version;
            std::string_view sql;
        };

        constexpr std::array migrations{
            migration_entry{1,
                "CREATE TABLE IF NOT EXISTS devices ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ip_address TEXT NOT NULL,"
                "mac_address TEXT NOT NULL DEFAULT '',"
                "hostname TEXT NOT NULL DEFAULT '',"
                "vendor TEXT NOT NULL DEFAULT '',"
                "os_guess TEXT NOT NULL DEFAULT '',"
                "open_ports TEXT NOT NULL DEFAULT '[]',"
                "first_seen INTEGER NOT NULL DEFAULT 0,"
                "last_seen INTEGER NOT NULL DEFAULT 0,"
                "is_gateway INTEGER NOT NULL DEFAULT 0,"
                "UNIQUE(ip_address)"
                ");"
                "CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);"
                "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);"},

            migration_entry{2,
                "CREATE TABLE IF NOT EXISTS scan_results ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "scan_type TEXT NOT NULL,"
                "subnet TEXT NOT NULL DEFAULT '',"
                "started_at INTEGER NOT NULL DEFAULT 0,"
                "finished_at INTEGER NOT NULL DEFAULT 0,"
                "device_count INTEGER NOT NULL DEFAULT 0,"
                "open_port_count INTEGER NOT NULL DEFAULT 0,"
                "status TEXT NOT NULL DEFAULT 'running',"
                "error_message TEXT NOT NULL DEFAULT ''"
                ");"
                "CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_results(status);"},

            migration_entry{3,
                "CREATE TABLE IF NOT EXISTS traffic_logs ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "src_ip TEXT NOT NULL,"
                "dst_ip TEXT NOT NULL,"
                "src_port INTEGER NOT NULL DEFAULT 0,"
                "dst_port INTEGER NOT NULL DEFAULT 0,"
                "protocol INTEGER NOT NULL DEFAULT 0,"
                "timestamp INTEGER NOT NULL DEFAULT 0,"
                "packet_size INTEGER NOT NULL DEFAULT 0,"
                "info TEXT NOT NULL DEFAULT ''"
                ");"
                "CREATE INDEX IF NOT EXISTS idx_traffic_src ON traffic_logs(src_ip);"
                "CREATE INDEX IF NOT EXISTS idx_traffic_dst ON traffic_logs(dst_ip);"
                "CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_logs(timestamp);"},

            migration_entry{4,
                "CREATE TABLE IF NOT EXISTS alerts ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "category TEXT NOT NULL,"
                "severity TEXT NOT NULL DEFAULT 'info',"
                "source_ip TEXT NOT NULL DEFAULT '',"
                "target_ip TEXT NOT NULL DEFAULT '',"
                "description TEXT NOT NULL DEFAULT '',"
                "timestamp INTEGER NOT NULL DEFAULT 0,"
                "acknowledged INTEGER NOT NULL DEFAULT 0"
                ");"
                "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);"
                "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);"
                "CREATE INDEX IF NOT EXISTS idx_alerts_cat ON alerts(category);"},
            // v5: 沙箱分析结果表
            migration_entry{5,
                "CREATE TABLE IF NOT EXISTS analysis_results ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "target_path TEXT NOT NULL,"
                "target_hash TEXT NOT NULL DEFAULT '',"
                "vm_name TEXT NOT NULL DEFAULT '',"
                "submitted_at INTEGER NOT NULL DEFAULT 0,"
                "completed_at INTEGER NOT NULL DEFAULT 0,"
                "status TEXT NOT NULL DEFAULT 'pending',"
                "score INTEGER NOT NULL DEFAULT 0,"
                "report_path TEXT NOT NULL DEFAULT '',"
                "summary TEXT NOT NULL DEFAULT ''"
                ");"
                "CREATE INDEX IF NOT EXISTS idx_analysis_score ON analysis_results(score);"
                "CREATE INDEX IF NOT EXISTS idx_analysis_ts ON analysis_results(submitted_at);",
            },
        };

    } // anonymous namespace


    // 构造迁移管理器
    migration_manager::migration_manager(database &db) noexcept
        : db_{db}
    {
    }


    // 查询当前数据库 Schema 版本号
    [[nodiscard]] auto migration_manager::current_version(std::error_code &ec) noexcept -> std::int64_t
    {
        auto stmt = db_.prepare(
            "SELECT MAX(version) FROM schema_versions", ec);
        if (!stmt.is_valid()) return 0;

        auto rc = stmt.step();
        if (rc != SQLITE_ROW)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return 0;
        }

        ec.clear();
        return stmt.column_int64(0);
    }


    // 执行所有未应用的数据库迁移，自动跳过已应用的版本
    [[nodiscard]] auto migration_manager::migrate(std::error_code &ec) noexcept -> bool
    {
        if (!ensure_version_table(ec))
            return false;

        auto version = current_version(ec);
        if (ec) return false;

        for (const auto &m : migrations)
        {
            if (m.version <= version)
                continue;

            if (!apply_migration(m.version, m.sql, ec))
                return false;
        }

        ec.clear();
        return true;
    }


    // 确保 schema_versions 版本记录表存在
    [[nodiscard]] auto migration_manager::ensure_version_table(std::error_code &ec) noexcept -> bool
    {
        return db_.execute(
            "CREATE TABLE IF NOT EXISTS schema_versions ("
            "version INTEGER PRIMARY KEY,"
            "applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
            ");",
            ec);
    }


    // 执行单条数据库迁移并在版本表中记录，失败时自动回滚
    [[nodiscard]] auto migration_manager::apply_migration(std::int64_t version, std::string_view sql, std::error_code &ec) noexcept -> bool
    {
        transaction_guard txn{db_};

        if (!db_.execute(sql, ec))
            return false;

        auto stmt = db_.prepare(
            "INSERT INTO schema_versions (version) VALUES (?)", ec);
        if (!stmt.is_valid()) return false;

        if (!stmt.bind(1, version)) return false;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_migration_failed);
            return false;
        }

        if (!txn.commit())
        {
            ec = fault::make_error_code(fault::code::db_migration_failed);
            return false;
        }

        return true;
    }


} // namespace sec::store
