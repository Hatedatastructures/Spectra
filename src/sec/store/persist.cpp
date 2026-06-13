// 扫描结果持久化协调器实现

#include <sec/store/persist.hpp>
#include <sec/store/query.hpp>
#include <sec/fault/code.hpp>

#include <chrono>


namespace sec::store
{

    // 构造扫描持久化协调器
    scan_persister::scan_persister(database &db) noexcept
        : db_{db}
    {
    }


    // 创建新的扫描记录并标记为运行中
    [[nodiscard]] auto scan_persister::begin_scan(std::string_view scan_type, std::string_view subnet, std::error_code &ec) noexcept -> std::int64_t
    {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        scan_result rec;
        rec.scan_type = scan_type;
        rec.subnet = subnet;
        rec.started_at = now;
        rec.status = "running";

        scan_query query{db_};
        return query.insert(rec, ec);
    }


    // 批量保存或更新设备记录
    [[nodiscard]] auto scan_persister::save_devices(const std::vector<device_record> &devices, std::error_code &ec) noexcept -> bool
    {
        device_query query{db_};

        for (const auto &dev : devices)
        {
            if (!query.upsert(dev, ec))
                return false;
        }

        ec.clear();
        return true;
    }


    // 正常结束扫描并写入统计结果
    [[nodiscard]] auto scan_persister::end_scan(std::int64_t scan_id, std::error_code &ec) noexcept -> bool
    {
        device_query dev_query{db_};
        auto device_count = dev_query.count(ec);
        if (ec) return false;

        scan_query scan_query_{db_};
        return scan_query_.finish(scan_id, scan_query::scan_completion{static_cast<std::int32_t>(device_count), 0}, ec);
    }


    // 异常结束扫描并记录错误信息
    [[nodiscard]] auto scan_persister::end_scan_error(std::int64_t scan_id, std::string_view error, std::error_code &ec) noexcept -> bool
    {
        scan_query query{db_};
        return query.update_status(scan_id, scan_query::status_update{"failed", error}, ec);
    }


    // 将端口列表序列化为 JSON 数组字符串
    [[nodiscard]] auto scan_persister::ports_to_json(const std::vector<std::uint16_t> &ports) -> std::string
    {
        if (ports.empty()) return "[]";

        auto result = std::string{"["};
        for (std::size_t i = 0; i < ports.size(); ++i)
        {
            if (i > 0) result += ',';
            result += std::to_string(ports[i]);
        }
        result += ']';
        return result;
    }


} // namespace sec::store
