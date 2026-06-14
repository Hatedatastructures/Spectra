// 数据库查询辅助类实现

#include <sec/store/query.hpp>
#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <sqlite3.h>


namespace sec::store
{

    // ---- device_query ----

    // 构造设备查询对象
    device_query::device_query(database &db) noexcept
        : db_{db}
    {
    }


    // 插入或更新设备记录（按 IP 地址冲突合并）
    [[nodiscard]] auto device_query::upsert(const device_record &rec, std::error_code &ec) noexcept -> bool
    {
        auto stmt = db_.prepare(
            "INSERT INTO devices (ip_address, mac_address, hostname, vendor, "
            "os_guess, open_ports, first_seen, last_seen, is_gateway) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip_address) DO UPDATE SET "
            "mac_address=excluded.mac_address, "
            "hostname=excluded.hostname, "
            "vendor=excluded.vendor, "
            "os_guess=excluded.os_guess, "
            "open_ports=excluded.open_ports, "
            "last_seen=excluded.last_seen, "
            "is_gateway=excluded.is_gateway",
            ec);
        if (!stmt.is_valid()) return false;

        if (!stmt.bind(1, rec.ip_address)) return false;
        if (!stmt.bind(2, rec.mac_address)) return false;
        if (!stmt.bind(3, rec.hostname)) return false;
        if (!stmt.bind(4, rec.vendor)) return false;
        if (!stmt.bind(5, rec.os_guess)) return false;
        if (!stmt.bind(6, rec.open_ports)) return false;
        if (!stmt.bind(7, rec.first_seen)) return false;
        if (!stmt.bind(8, rec.last_seen)) return false;
        if (!stmt.bind(9, rec.is_gateway ? 1 : 0)) return false;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return false;
        }

        ec.clear();
        return true;
    }


    // 根据 IP 地址查询设备记录
    [[nodiscard]] auto device_query::find_by_ip(std::string_view ip, std::error_code &ec) noexcept -> std::optional<device_record>
    {
        auto stmt = db_.prepare(
            "SELECT id, ip_address, mac_address, hostname, vendor, os_guess, "
            "open_ports, first_seen, last_seen, is_gateway "
            "FROM devices WHERE ip_address = ?",
            ec);
        if (!stmt.is_valid()) return std::nullopt;

        if (!stmt.bind(1, ip)) return std::nullopt;

        if (stmt.step() != SQLITE_ROW)
        {
            ec.clear();
            return std::nullopt;
        }

        ec.clear();
        return read_device(stmt);
    }


    // 查询所有设备记录，按最后出现时间降序排列
    [[nodiscard]] auto device_query::find_all(std::error_code &ec) noexcept -> std::vector<device_record>
    {
        auto stmt = db_.prepare(
            "SELECT id, ip_address, mac_address, hostname, vendor, os_guess, "
            "open_ports, first_seen, last_seen, is_gateway "
            "FROM devices ORDER BY last_seen DESC",
            ec);
        if (!stmt.is_valid()) return {};

        auto results = std::vector<device_record>{};
        while (stmt.step() == SQLITE_ROW)
        {
            results.push_back(read_device(stmt));
        }

        ec.clear();
        return results;
    }


    // 统计设备总数
    [[nodiscard]] auto device_query::count(std::error_code &ec) noexcept -> std::int64_t
    {
        auto stmt = db_.prepare("SELECT COUNT(*) FROM devices", ec);
        if (!stmt.is_valid()) return 0;

        if (stmt.step() != SQLITE_ROW)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return 0;
        }

        ec.clear();
        return stmt.column_int64(0);
    }


    // ---- scan_query ----

    // 构造扫描结果查询对象
    scan_query::scan_query(database &db) noexcept
        : db_{db}
    {
    }


    // 插入扫描结果记录
    [[nodiscard]] auto scan_query::insert(const scan_result &rec, std::error_code &ec) noexcept -> std::int64_t
    {
        auto stmt = db_.prepare(
            "INSERT INTO scan_results "
            "(scan_type, subnet, started_at, finished_at, device_count, "
            "open_port_count, status, error_message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ec);
        if (!stmt.is_valid()) return 0;

        if (!stmt.bind(1, rec.scan_type)) return 0;
        if (!stmt.bind(2, rec.subnet)) return 0;
        if (!stmt.bind(3, rec.started_at)) return 0;
        if (!stmt.bind(4, rec.finished_at)) return 0;
        if (!stmt.bind(5, rec.device_count)) return 0;
        if (!stmt.bind(6, rec.open_port_count)) return 0;
        if (!stmt.bind(7, rec.status)) return 0;
        if (!stmt.bind(8, rec.error_message)) return 0;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return 0;
        }

        ec.clear();
        return db_.last_insert_rowid();
    }


    // 更新扫描结果的状态和错误信息
    [[nodiscard]] auto scan_query::update_status(std::int64_t id, const status_update &upd, std::error_code &ec) noexcept -> bool
    {
        auto stmt = db_.prepare(
            "UPDATE scan_results SET status = ?, error_message = ? WHERE id = ?",
            ec);
        if (!stmt.is_valid()) return false;

        if (!stmt.bind(1, upd.status)) return false;
        if (!stmt.bind(2, upd.error)) return false;
        if (!stmt.bind(3, id)) return false;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return false;
        }

        ec.clear();
        return true;
    }


    // 标记扫描完成并写入统计结果
    [[nodiscard]] auto scan_query::finish(std::int64_t id, const scan_completion &completion, std::error_code &ec) noexcept -> bool
    {
        auto stmt = db_.prepare(
            "UPDATE scan_results SET status = 'completed', "
            "finished_at = strftime('%s','now'), "
            "device_count = ?, open_port_count = ? WHERE id = ?",
            ec);
        if (!stmt.is_valid()) return false;

        if (!stmt.bind(1, completion.devices)) return false;
        if (!stmt.bind(2, completion.ports)) return false;
        if (!stmt.bind(3, id)) return false;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return false;
        }

        ec.clear();
        return true;
    }


    // 查询最近的扫描结果
    [[nodiscard]] auto scan_query::find_recent(std::size_t limit, std::error_code &ec) noexcept -> std::vector<scan_result>
    {
        auto stmt = db_.prepare(
            "SELECT id, scan_type, subnet, started_at, finished_at, "
            "device_count, open_port_count, status, error_message "
            "FROM scan_results ORDER BY started_at DESC LIMIT ?",
            ec);
        if (!stmt.is_valid()) return {};

        if (!stmt.bind(1, static_cast<std::int64_t>(limit))) return {};

        auto results = std::vector<scan_result>{};
        while (stmt.step() == SQLITE_ROW)
        {
            results.push_back(read_scan_result(stmt));
        }

        ec.clear();
        return results;
    }


    // ---- traffic_query ----

    // 构造流量日志查询对象
    traffic_query::traffic_query(database &db) noexcept
        : db_{db}
    {
    }


    // 插入单条流量日志记录
    [[nodiscard]] auto traffic_query::insert(const traffic_log &rec, std::error_code &ec) noexcept -> bool
    {
        auto stmt = db_.prepare(
            "INSERT INTO traffic_logs "
            "(src_ip, dst_ip, src_port, dst_port, protocol, "
            "timestamp, packet_size, info) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ec);
        if (!stmt.is_valid()) return false;

        if (!stmt.bind(1, rec.src_ip)) return false;
        if (!stmt.bind(2, rec.dst_ip)) return false;
        if (!stmt.bind(3, rec.src_port)) return false;
        if (!stmt.bind(4, rec.dst_port)) return false;
        if (!stmt.bind(5, rec.protocol)) return false;
        if (!stmt.bind(6, rec.timestamp)) return false;
        if (!stmt.bind(7, rec.packet_size)) return false;
        if (!stmt.bind(8, rec.info)) return false;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return false;
        }

        ec.clear();
        return true;
    }


    // 按时间范围查询流量日志
    [[nodiscard]] auto traffic_query::find_by_time_range(std::int64_t from_ts, std::int64_t to_ts, std::error_code &ec) noexcept -> std::vector<traffic_log>
    {
        auto stmt = db_.prepare(
            "SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, "
            "timestamp, packet_size, info "
            "FROM traffic_logs WHERE timestamp BETWEEN ? AND ? "
            "ORDER BY timestamp DESC",
            ec);
        if (!stmt.is_valid()) return {};

        if (!stmt.bind(1, from_ts)) return {};
        if (!stmt.bind(2, to_ts)) return {};

        auto results = std::vector<traffic_log>{};
        while (stmt.step() == SQLITE_ROW)
        {
            results.push_back(read_traffic_log(stmt));
        }

        ec.clear();
        return results;
    }


    // ---- alert_query ----

    // 构造告警查询对象
    alert_query::alert_query(database &db) noexcept
        : db_{db}
    {
    }


    // 插入告警记录
    [[nodiscard]] auto alert_query::insert(const alert_record &rec, std::error_code &ec) noexcept -> bool
    {
        auto stmt = db_.prepare(
            "INSERT INTO alerts "
            "(category, severity, source_ip, target_ip, description, "
            "timestamp, acknowledged) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ec);
        if (!stmt.is_valid()) return false;

        if (!stmt.bind(1, rec.category)) return false;
        if (!stmt.bind(2, rec.severity)) return false;
        if (!stmt.bind(3, rec.source_ip)) return false;
        if (!stmt.bind(4, rec.target_ip)) return false;
        if (!stmt.bind(5, rec.description)) return false;
        if (!stmt.bind(6, rec.timestamp)) return false;
        if (!stmt.bind(7, rec.acknowledged ? 1 : 0)) return false;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return false;
        }

        ec.clear();
        return true;
    }


    // 将指定告警标记为已确认
    [[nodiscard]] auto alert_query::acknowledge(std::int64_t id, std::error_code &ec) noexcept -> bool
    {
        auto stmt = db_.prepare(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
            ec);
        if (!stmt.is_valid()) return false;

        if (!stmt.bind(1, id)) return false;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return false;
        }

        ec.clear();
        return true;
    }


    // 查询所有未确认的告警记录
    [[nodiscard]] auto alert_query::find_unacknowledged(std::error_code &ec) noexcept -> std::vector<alert_record>
    {
        auto stmt = db_.prepare(
            "SELECT id, category, severity, source_ip, target_ip, "
            "description, timestamp, acknowledged "
            "FROM alerts WHERE acknowledged = 0 ORDER BY timestamp DESC",
            ec);
        if (!stmt.is_valid()) return {};

        auto results = std::vector<alert_record>{};
        while (stmt.step() == SQLITE_ROW)
        {
            results.push_back(read_alert(stmt));
        }

        ec.clear();
        return results;
    }


    // 统计未确认告警数
    [[nodiscard]] auto alert_query::count_unacknowledged(std::error_code &ec) noexcept -> std::int64_t
    {
        auto stmt = db_.prepare(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0",
            ec);
        if (!stmt.is_valid()) return 0;

        if (stmt.step() == SQLITE_ROW)
        {
            auto count = stmt.column_int64(0);
            ec.clear();
            return count;
        }

        return 0;
    }


    // ---- row readers ----

    // 从当前预编译语句行读取设备记录
    auto read_device(statement &stmt) noexcept -> device_record
    {
        device_record rec;
        rec.id = stmt.column_int64(0);
        rec.ip_address = stmt.column_string(1);
        rec.mac_address = stmt.column_string(2);
        rec.hostname = stmt.column_string(3);
        rec.vendor = stmt.column_string(4);
        rec.os_guess = stmt.column_string(5);
        rec.open_ports = stmt.column_string(6);
        rec.first_seen = stmt.column_int64(7);
        rec.last_seen = stmt.column_int64(8);
        rec.is_gateway = stmt.column_int(9) != 0;
        return rec;
    }


    // 从当前预编译语句行读取扫描结果记录
    auto read_scan_result(statement &stmt) noexcept -> scan_result
    {
        scan_result rec;
        rec.id = stmt.column_int64(0);
        rec.scan_type = stmt.column_string(1);
        rec.subnet = stmt.column_string(2);
        rec.started_at = stmt.column_int64(3);
        rec.finished_at = stmt.column_int64(4);
        rec.device_count = stmt.column_int(5);
        rec.open_port_count = stmt.column_int(6);
        rec.status = stmt.column_string(7);
        rec.error_message = stmt.column_string(8);
        return rec;
    }


    // 从当前预编译语句行读取流量日志记录
    auto read_traffic_log(statement &stmt) noexcept -> traffic_log
    {
        traffic_log rec;
        rec.id = stmt.column_int64(0);
        rec.src_ip = stmt.column_string(1);
        rec.dst_ip = stmt.column_string(2);
        rec.src_port = static_cast<std::uint16_t>(stmt.column_int(3));
        rec.dst_port = static_cast<std::uint16_t>(stmt.column_int(4));
        rec.protocol = static_cast<std::uint8_t>(stmt.column_int(5));
        rec.timestamp = stmt.column_int64(6);
        rec.packet_size = stmt.column_int(7);
        rec.info = stmt.column_string(8);
        return rec;
    }


    // 从当前预编译语句行读取告警记录
    auto read_alert(statement &stmt) noexcept -> alert_record
    {
        alert_record rec;
        rec.id = stmt.column_int64(0);
        rec.category = stmt.column_string(1);
        rec.severity = stmt.column_string(2);
        rec.source_ip = stmt.column_string(3);
        rec.target_ip = stmt.column_string(4);
        rec.description = stmt.column_string(5);
        rec.timestamp = stmt.column_int64(6);
        rec.acknowledged = stmt.column_int(7) != 0;
        return rec;
    }


    // ---- analysis_query ----

    analysis_query::analysis_query(database &db) noexcept
        : db_{db}
    {
    }

    [[nodiscard]] auto analysis_query::insert(const analysis_record &rec, std::error_code &ec) noexcept
        -> std::int64_t
    {
        auto stmt = db_.prepare(
            "INSERT INTO analysis_results "
            "(target_path, target_hash, vm_name, submitted_at, completed_at, "
            "status, score, report_path, summary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ec);
        if (!stmt.is_valid()) return 0;

        if (!stmt.bind(1, rec.target_path)) return 0;
        if (!stmt.bind(2, rec.target_hash)) return 0;
        if (!stmt.bind(3, rec.vm_name)) return 0;
        if (!stmt.bind(4, rec.submitted_at)) return 0;
        if (!stmt.bind(5, rec.completed_at)) return 0;
        if (!stmt.bind(6, rec.status)) return 0;
        if (!stmt.bind(7, static_cast<int>(rec.score))) return 0;
        if (!stmt.bind(8, rec.report_path)) return 0;
        if (!stmt.bind(9, rec.summary)) return 0;

        if (stmt.step() != SQLITE_DONE)
        {
            ec = fault::make_error_code(fault::code::db_query_failed);
            return 0;
        }

        ec.clear();
        return db_.last_insert_rowid();
    }

    [[nodiscard]] auto analysis_query::find_by_id(std::int64_t id, std::error_code &ec) noexcept
        -> std::optional<analysis_record>
    {
        auto stmt = db_.prepare(
            "SELECT id, target_path, target_hash, vm_name, "
            "submitted_at, completed_at, status, score, report_path, summary "
            "FROM analysis_results WHERE id = ?",
            ec);
        if (!stmt.is_valid()) return std::nullopt;
        if (!stmt.bind(1, id)) return std::nullopt;

        if (stmt.step() == SQLITE_ROW)
        {
            ec.clear();
            return read_analysis(stmt);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto analysis_query::find_recent(std::size_t limit, std::error_code &ec) noexcept
        -> std::vector<analysis_record>
    {
        auto stmt = db_.prepare(
            "SELECT id, target_path, target_hash, vm_name, "
            "submitted_at, completed_at, status, score, report_path, summary "
            "FROM analysis_results ORDER BY submitted_at DESC LIMIT ?",
            ec);
        if (!stmt.is_valid()) return {};
        if (!stmt.bind(1, static_cast<std::int64_t>(limit))) return {};

        auto results = std::vector<analysis_record>{};
        while (stmt.step() == SQLITE_ROW)
        {
            results.push_back(read_analysis(stmt));
        }
        ec.clear();
        return results;
    }


    [[nodiscard]] auto read_analysis(statement &stmt) noexcept -> analysis_record
    {
        analysis_record rec;
        rec.id = stmt.column_int64(0);
        rec.target_path = stmt.column_string(1);
        rec.target_hash = stmt.column_string(2);
        rec.vm_name = stmt.column_string(3);
        rec.submitted_at = stmt.column_int64(4);
        rec.completed_at = stmt.column_int64(5);
        rec.status = stmt.column_string(6);
        rec.score = static_cast<std::uint8_t>(stmt.column_int(7));
        rec.report_path = stmt.column_string(8);
        rec.summary = stmt.column_string(9);
        return rec;
    }


} // namespace sec::store
