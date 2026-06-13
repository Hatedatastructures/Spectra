#pragma once

#include <sec/store/persist.hpp>
#include <sec/store/database.hpp>
#include <sec/store/model.hpp>
#include <sec/scanner/device.hpp>

#include <chrono>
#include <string_view>
#include <vector>

namespace sec::store
{
    /// 将扫描发现的设备持久化到数据库（创建 scan 记录、upsert devices、结束 scan）
    inline void persist_devices(
        scan_persister &pers,
        database &db,
        std::vector<scanner::device> &devices,
        std::string_view scan_type,
        std::string_view subnet)
    {
        if (devices.empty())
        {
            return;
        }

        auto ec = std::error_code{};
        auto scan_id = pers.begin_scan(scan_type, subnet, ec);
        if (ec)
        {
            return;
        }

        auto records = std::vector<device_record>{};
        records.reserve(devices.size());

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

        for (const auto &dev : devices)
        {
            auto rec = device_record{};
            rec.ip_address = std::string{dev.ip_address};
            rec.mac_address = std::string{dev.mac_address};
            rec.hostname = std::string{dev.hostname};
            rec.vendor = std::string{dev.vendor};
            rec.os_guess = std::string{dev.os_guess};

            if (!dev.open_ports.empty())
            {
                rec.open_ports = scan_persister::ports_to_json(
                    std::vector<std::uint16_t>{dev.open_ports.begin(), dev.open_ports.end()});
            }

            rec.first_seen = now;
            rec.last_seen = now;
            rec.is_gateway = dev.is_gateway;
            records.push_back(std::move(rec));
        }

        if (!pers.save_devices(records, ec))
        {
            static_cast<void>(pers.end_scan_error(scan_id, ec.message(), ec));
            return;
        }

        static_cast<void>(pers.end_scan(scan_id, ec));
    }
}
