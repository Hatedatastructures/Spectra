// 端口扫描检测器实现

#include <sec/detector/port_scan_detector.hpp>

#include <sstream>


namespace sec::detector
{


    void port_scan_detector::reset()
    {
        tcp_tracker_.clear();
        udp_tracker_.clear();
    }


    auto port_scan_detector::prune(std::deque<hit> &hits,
        std::chrono::steady_clock::time_point now) -> void
    {
        const std::chrono::seconds window{window_seconds_};
        while (!hits.empty() && (now - hits.front().when) > window)
        {
            hits.pop_front();
        }
    }


    [[nodiscard]] auto port_scan_detector::check(const decoder::packet_info &packet)
        -> std::optional<port_scan_alert>
    {
        const auto now = std::chrono::steady_clock::now();

        // TCP SYN 扫描检测（TCP 协议号 = 6）
        if (packet.protocol == 6)
        {
            // SYN = 0x02（仅 SYN 置位，无 ACK）
            const bool is_syn = (packet.tcp_flags & 0x02) && !(packet.tcp_flags & 0x10);

            if (is_syn)
            {
                auto &hits = tcp_tracker_[packet.src_ip];
                hits.push_back({packet.dst_port, packet.dst_ip, now});
                prune(hits, now);
                if (hits.empty())
                {
                    tcp_tracker_.erase(packet.src_ip);
                }

                // 统计唯一目标端口
                std::unordered_set<std::uint16_t> unique_ports;
                for (const auto &h : hits)
                {
                    unique_ports.insert(h.port);
                }

                if (unique_ports.size() >= syn_threshold_)
                {
                    port_scan_alert alert;
                    alert.source_ip = packet.src_ip;
                    alert.scan_type = "tcp_syn_scan";
                    alert.target_count = unique_ports.size();
                    alert.detected_at = now;
                    hits.clear();
                    return alert;
                }

                // 网络扫射检测：同端口不同目标 IP
                std::unordered_map<std::uint16_t, std::unordered_set<std::uint32_t>> port_targets;
                for (const auto &h : hits)
                {
                    port_targets[h.port].insert(h.dst_ip);
                }
                for (const auto &[port, targets] : port_targets)
                {
                    if (targets.size() >= sweep_threshold_)
                    {
                        port_scan_alert alert;
                        alert.source_ip = packet.src_ip;
                        alert.scan_type = "network_sweep";
                        alert.target_count = targets.size();
                        alert.detected_at = now;
                        hits.clear();
                        return alert;
                    }
                }
            }
        }

        // UDP 扫描检测（UDP 协议号 = 17）
        if (packet.protocol == 17)
        {
            auto &hits = udp_tracker_[packet.src_ip];
            hits.push_back({packet.dst_port, packet.dst_ip, now});
            prune(hits, now);
            if (hits.empty())
            {
                udp_tracker_.erase(packet.src_ip);
            }

            std::unordered_set<std::uint16_t> unique_ports;
            for (const auto &h : hits)
            {
                unique_ports.insert(h.port);
            }

            if (unique_ports.size() >= udp_threshold_)
            {
                port_scan_alert alert;
                alert.source_ip = packet.src_ip;
                alert.scan_type = "udp_scan";
                alert.target_count = unique_ports.size();
                alert.detected_at = now;
                hits.clear();
                return alert;
            }
        }

        return std::nullopt;
    }


} // namespace sec::detector
