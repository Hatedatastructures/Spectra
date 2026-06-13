// 流量特征提取实现

#include <sec/ai/feature.hpp>

#include <sec/decoder/frame.hpp>

#include <cmath>
#include <algorithm>


namespace sec::ai
{


    feature_extractor::feature_extractor(int window_seconds) noexcept
        : window_seconds_{window_seconds}
    {
    }


    void feature_extractor::observe(const decoder::packet_info &frame)
    {
        auto now = std::chrono::steady_clock::now();
        auto &w = windows_[frame.src_ip];

        if (w.packet_count == 0)
        {
            w.first_time = now;
            w.last_time = now;
        }
        else
        {
            auto delta = std::chrono::duration_cast<std::chrono::microseconds>(
                now - w.last_time);
            w.total_interval += delta;
            w.last_time = now;
        }

        ++w.packet_count;
        w.total_bytes += frame.payload.size();
        w.dst_ips.insert(frame.dst_ip);
        w.dst_ports.insert(frame.dst_port);
        w.src_ports.insert(frame.src_port);

        if (frame.protocol == 6)
        {
            ++w.tcp_count;
        }
        else if (frame.protocol == 17)
        {
            ++w.udp_count;
        }
    }


    [[nodiscard]] auto feature_extractor::extract(std::uint32_t ip) const
        -> feature_vector
    {
        auto it = windows_.find(ip);
        if (it == windows_.end())
        {
            return feature_vector{};
        }

        const auto &w = it->second;
        feature_vector feat{};
        feat.fill(0.0);

        // 时间窗口（秒）
        double elapsed = std::max(1.0,
            static_cast<double>(window_seconds_));

        if (w.packet_count > 1)
        {
            auto duration = std::chrono::duration_cast<
                std::chrono::duration<double>>(w.last_time - w.first_time);
            elapsed = std::max(1.0, duration.count());
        }

        // packet_rate: 每秒包数
        feat[static_cast<std::size_t>(feature_index::packet_rate)] =
            static_cast<double>(w.packet_count) / elapsed;

        // byte_rate: 每秒字节数
        feat[static_cast<std::size_t>(feature_index::byte_rate)] =
            static_cast<double>(w.total_bytes) / elapsed;

        // avg_packet_size: 平均包大小
        feat[static_cast<std::size_t>(feature_index::avg_packet_size)] =
            static_cast<double>(w.total_bytes) /
            static_cast<double>(std::max<std::uint64_t>(1, w.packet_count));

        // unique_destinations
        feat[static_cast<std::size_t>(feature_index::unique_destinations)] =
            static_cast<double>(w.dst_ips.size());

        // unique_ports
        feat[static_cast<std::size_t>(feature_index::unique_ports)] =
            static_cast<double>(w.dst_ports.size());

        // tcp_ratio
        feat[static_cast<std::size_t>(feature_index::tcp_ratio)] =
            static_cast<double>(w.tcp_count) /
            static_cast<double>(std::max<std::uint64_t>(1, w.packet_count));

        // udp_ratio
        feat[static_cast<std::size_t>(feature_index::udp_ratio)] =
            static_cast<double>(w.udp_count) /
            static_cast<double>(std::max<std::uint64_t>(1, w.packet_count));

        // 计算目标端口熵
        std::unordered_map<std::uint16_t, std::uint64_t> dst_port_counts;
        for (auto port : w.dst_ports)
        {
            dst_port_counts[port] = 1;
        }
        feat[static_cast<std::size_t>(feature_index::port_entropy)] = compute_entropy(dst_port_counts,
            w.packet_count);

        // 计算源端口熵
        std::unordered_map<std::uint16_t, std::uint64_t> src_port_counts;
        for (auto port : w.src_ports)
        {
            src_port_counts[port] = 1;
        }
        feat[static_cast<std::size_t>(feature_index::src_port_entropy)] = compute_entropy(src_port_counts,
            w.packet_count);

        // total_packets
        feat[static_cast<std::size_t>(feature_index::total_packets)] =
            static_cast<double>(w.packet_count);

        // total_bytes
        feat[static_cast<std::size_t>(feature_index::total_bytes)] =
            static_cast<double>(w.total_bytes);

        // avg_interval: 平均包间隔（微秒）
        if (w.packet_count > 1)
        {
            feat[static_cast<std::size_t>(feature_index::avg_interval)] =
                static_cast<double>(w.total_interval.count()) /
                static_cast<double>(w.packet_count - 1);
        }

        return feat;
    }


    [[nodiscard]] auto feature_extractor::tracked_ips() const
        -> std::vector<std::uint32_t>
    {
        std::vector<std::uint32_t> ips;
        ips.reserve(windows_.size());
        for (const auto &[ip, _] : windows_)
        {
            ips.push_back(ip);
        }
        return ips;
    }


    void feature_extractor::remove(std::uint32_t ip)
    {
        windows_.erase(ip);
    }


    void feature_extractor::reset()
    {
        windows_.clear();
    }


    auto feature_extractor::compute_entropy(
        const std::unordered_map<std::uint16_t, std::uint64_t> &counts,
        std::uint64_t total) const -> double
    {
        if (counts.empty() || total == 0)
        {
            return 0.0;
        }

        double entropy = 0.0;
        for (const auto &[_, count] : counts)
        {
            double p = static_cast<double>(count) /
                static_cast<double>(total);
            if (p > 0.0)
            {
                entropy -= p * std::log2(p);
            }
        }
        return entropy;
    }


} // namespace sec::ai
