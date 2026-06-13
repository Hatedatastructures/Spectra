// ARP 欺骗检测器实现

#include <sec/mitm/arp_detect.hpp>

#include <sec/decoder/frame.hpp>
#include <sec/decoder/util.hpp>

#include <chrono>


namespace sec::mitm
{

    namespace
    {

        using sec::decoder::mac_to_string;

        auto mac_equal(const std::byte *a, const std::byte *b) -> bool
        {
            for (int i = 0; i < 6; ++i)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        constexpr std::chrono::seconds binding_ttl{600}; // 10 分钟

    } // anonymous namespace


    void arp_detector::prune_bindings(std::chrono::steady_clock::time_point now)
    {
        // 清理 bindings_ 中超期条目
        for (auto it = bindings_.begin(); it != bindings_.end(); )
        {
            if ((now - it->second.last_seen) > binding_ttl)
            {
                it = bindings_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        // 清理 mac_bindings_ 中超期 IP
        for (auto it = mac_bindings_.begin(); it != mac_bindings_.end(); )
        {
            auto &ips = it->second.ips;
            for (auto ip_it = ips.begin(); ip_it != ips.end(); )
            {
                if ((now - ip_it->second) > binding_ttl)
                {
                    ip_it = ips.erase(ip_it);
                }
                else
                {
                    ++ip_it;
                }
            }
            if (ips.empty())
            {
                it = mac_bindings_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }


    namespace
    {

        constexpr std::chrono::seconds flood_window{1};
        constexpr std::size_t flood_threshold{50};
        constexpr std::chrono::seconds sweep_window{5};
        constexpr std::size_t sweep_threshold{20};
        constexpr std::size_t mac_multi_ip_threshold{3};

    } // anonymous namespace


    [[nodiscard]] auto arp_detector::check_flood(std::chrono::steady_clock::time_point now,
        const std::string &sender_mac, bool is_self) -> std::optional<arp_alert>
    {
        if (!is_self)
        {
            flood_times_.push_back(now);
        }
        while (!flood_times_.empty() && (now - flood_times_.front()) > flood_window)
        {
            flood_times_.pop_front();
        }
        if (flood_times_.size() > flood_threshold)
        {
            arp_alert alert;
            alert.detected_at = now;
            alert.alert_type = "arp_flood";
            alert.description = "ARP flood: " + std::to_string(flood_times_.size()) + " packets in 1s";
            flood_times_.clear();
            return alert;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto arp_detector::check_gratuitous(std::chrono::steady_clock::time_point now,
        std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>
    {
        arp_alert alert;
        alert.ip = sender_ip;
        alert.original_mac = sender_mac;
        alert.conflict_mac = sender_mac;
        alert.detected_at = now;
        alert.alert_type = "gratuitous_arp";
        alert.description = "Gratuitous ARP from " + sender_mac;
        return alert;
    }

    [[nodiscard]] auto arp_detector::check_sweep(std::chrono::steady_clock::time_point now,
        std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>
    {
        auto &sweep = sweep_tracker_[sender_mac];
        sweep.push_back({sender_ip, now});
        while (!sweep.empty() && (now - sweep.front().when) > sweep_window)
        {
            sweep.pop_front();
        }
        if (sweep.size() > sweep_threshold)
        {
            arp_alert alert;
            alert.ip = sender_ip;
            alert.original_mac = sender_mac;
            alert.detected_at = now;
            alert.alert_type = "arp_sweep";
            alert.description = "ARP sweep: " + std::to_string(sweep.size()) + " requests in 5s from " + sender_mac;
            sweep.clear();
            return alert;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto arp_detector::check_conflict(std::chrono::steady_clock::time_point now,
        std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>
    {
        auto it = bindings_.find(sender_ip);
        if (it != bindings_.end())
        {
            if (it->second.mac != sender_mac)
            {
                arp_alert alert;
                alert.ip = sender_ip;
                alert.original_mac = it->second.mac;
                alert.conflict_mac = sender_mac;
                alert.detected_at = now;
                alert.alert_type = "ip_mac_conflict";
                alert.description = "IP-MAC conflict: " + std::to_string(sender_ip);
                return alert;
            }
            it->second.last_seen = now;
        }
        else
        {
            bindings_[sender_ip] = {sender_mac, now};
        }
        return std::nullopt;
    }

    [[nodiscard]] auto arp_detector::check_mac_multi_ip(std::chrono::steady_clock::time_point now,
        std::uint32_t sender_ip, const std::string &sender_mac) -> std::optional<arp_alert>
    {
        auto &mac_entry = mac_bindings_[sender_mac];
        mac_entry.ips[sender_ip] = now;
        if (mac_entry.ips.size() > mac_multi_ip_threshold)
        {
            arp_alert alert;
            alert.ip = sender_ip;
            alert.original_mac = sender_mac;
            alert.detected_at = now;
            alert.alert_type = "mac_multi_ip";
            alert.description = "MAC " + sender_mac + " associated with " + std::to_string(mac_entry.ips.size()) + " IPs";
            return alert;
        }
        return std::nullopt;
    }


    [[nodiscard]] auto arp_detector::check(const decoder::packet_info &packet)
        -> std::optional<arp_alert>
    {
        if (!packet.arp.has_value())
        {
            return std::nullopt;
        }

        const auto &arp = *packet.arp;
        const auto now = std::chrono::steady_clock::now();
        const auto sender_mac = mac_to_string(arp.sender_mac.data());
        const bool is_self = (self_macs_.find(sender_mac) != self_macs_.end());

        prune_bindings(now);

        // ARP flood
        if (auto flood = check_flood(now, sender_mac, is_self))
            return flood;

        if (arp.opcode != 1 && arp.opcode != 2)
            return std::nullopt;

        const auto sender_ip = arp.sender_ip;

        // Gratuitous ARP
        if (arp.opcode == 1 && arp.sender_ip == arp.target_ip)
            return check_gratuitous(now, sender_ip, sender_mac);

        if (is_self)
            return std::nullopt;

        // ARP sweep
        if (arp.opcode == 1)
            if (auto sweep = check_sweep(now, sender_ip, sender_mac))
                return sweep;

        // IP-MAC 绑定冲突
        if (auto conflict = check_conflict(now, sender_ip, sender_mac))
            return conflict;

        // MAC 多 IP
        return check_mac_multi_ip(now, sender_ip, sender_mac);
    }


} // namespace sec::mitm
