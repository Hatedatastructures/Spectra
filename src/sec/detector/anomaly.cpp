// 统计异常检测器实现

#include <sec/detector/anomaly.hpp>
#include <sec/decoder/util.hpp>

#include <cmath>
#include <sstream>
#include <vector>


namespace sec::detector
{


    anomaly_detector::anomaly_detector(anomaly_config cfg) noexcept
        : config_{std::move(cfg)}
    {
    }


    [[nodiscard]] auto anomaly_detector::observe(const decoder::packet_info &frame)
        -> std::optional<alert>
    {
        update_stats(frame.src_ip, frame.dst_ip,
            static_cast<std::uint16_t>(frame.payload.size()));

        auto result = check_anomaly(frame.src_ip);

        // C2 信标检测
        if (!result.has_value())
        {
            auto beacon = check_beacon(frame.src_ip, frame.dst_ip);
            if (beacon.has_value())
            {
                result = std::move(beacon);
            }
        }

        // 每 100 次调用执行一次全局惰性清理
        if ((++observe_counter_) % 100 == 0)
        {
            prune_stale_ips();
        }

        return result;
    }


    [[nodiscard]] auto anomaly_detector::get_stats(std::uint32_t ip) const
        -> const ip_stats *
    {
        auto it = stats_.find(ip);
        if (it != stats_.end())
        {
            return &it->second;
        }
        return nullptr;
    }


    [[nodiscard]] auto anomaly_detector::tracked_count() const noexcept -> std::size_t
    {
        return stats_.size();
    }


    void anomaly_detector::reset()
    {
        stats_.clear();
        destinations_.clear();
    }


    void anomaly_detector::update_stats(std::uint32_t ip, std::uint32_t dst_ip,
        std::uint16_t packet_size)
    {
        auto now = std::chrono::steady_clock::now();
        auto &s = stats_[ip];

        auto prev_count = s.packet_count;
        s.packet_count += 1;
        s.total_bytes += packet_size;
        s.last_update = now;

        // 追踪唯一目标（带 TTL）
        constexpr std::chrono::seconds dest_ttl{600}; // 10 分钟
        auto &dests = destinations_[ip];
        dests[dst_ip] = now;

        // 惰性清理超期目标
        for (auto it = dests.begin(); it != dests.end(); )
        {
            if ((now - it->second) > dest_ttl)
            {
                it = dests.erase(it);
            }
            else
            {
                ++it;
            }
        }
        s.unique_destinations = dests.size();

        // 指数移动平均更新
        if (prev_count == 0)
        {
            s.window_start_time = now;
            s.window_start_count = 0;
            return;
        }

        // 计算瞬时字节值
        double instant_byte = static_cast<double>(packet_size);
        double delta_byte = instant_byte - s.byte_ema;
        s.byte_ema += config_.alpha * delta_byte;
        s.byte_var += config_.alpha * (delta_byte * delta_byte - s.byte_var);

        // 窗口内真实包速率
        const std::chrono::seconds window{config_.window_seconds};
        auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - s.window_start_time);
        if (elapsed.count() >= static_cast<double>(config_.window_seconds))
        {
            // 窗口过期，重置
            s.window_start_count = s.packet_count;
            s.window_start_time = now;
        }

        double window_elapsed = elapsed.count();
        double instant_rate = (window_elapsed > 0.0)
            ? static_cast<double>(s.packet_count - s.window_start_count) / window_elapsed
            : 0.0;
        double delta_rate = instant_rate - s.rate_ema;
        s.rate_ema += config_.alpha * delta_rate;
        s.rate_var += config_.alpha * (delta_rate * delta_rate - s.rate_var);
    }


    auto anomaly_detector::check_anomaly(std::uint32_t ip) -> std::optional<alert>
    {
        auto it = stats_.find(ip);
        if (it == stats_.end())
        {
            return std::nullopt;
        }

        const auto &s = it->second;

        // 观测次数不足，跳过检测
        if (s.packet_count < config_.min_observations)
        {
            return std::nullopt;
        }

        // 计算标准差
        auto byte_stddev = std::sqrt(std::max(0.0, s.byte_var));
        auto rate_stddev = std::sqrt(std::max(0.0, s.rate_var));

        // 计算最近一个包的字节偏差
        double avg_bytes = static_cast<double>(s.total_bytes) /
            static_cast<double>(s.packet_count);
        double byte_zscore = (byte_stddev > 0.0)
            ? std::abs(avg_bytes - s.byte_ema) / byte_stddev
            : 0.0;

        // 窗口内速率偏差
        double current_rate = 0.0;
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(
                std::chrono::steady_clock::now() - s.window_start_time);
            if (elapsed.count() > 0.0)
            {
                current_rate = static_cast<double>(s.packet_count - s.window_start_count) / elapsed.count();
            }
        }
        double rate_zscore = (rate_stddev > 0.0)
            ? std::abs(current_rate - s.rate_ema) / rate_stddev
            : 0.0;

        // 唯一目标数量侦察检测
        if (s.unique_destinations > 20)
        {
            std::ostringstream desc;
            desc << "Reconnaissance from " << decoder::ip_to_string(ip)
                 << ": contacted " << s.unique_destinations << " unique destinations";

            alert a;
            a.level = severity::medium;
            a.type = category::suspicious_traffic;
            a.source_ip = decoder::ip_to_string(ip);
            a.description = desc.str();
            a.confidence = std::min(1.0, s.unique_destinations / 100.0);
            a.detected_at = std::chrono::steady_clock::now();
            return a;
        }

        // 检查是否超过阈值
        if (byte_zscore <= config_.sigma_threshold &&
            rate_zscore <= config_.sigma_threshold)
        {
            return std::nullopt;
        }

        // 产生告警
        std::ostringstream desc;
        desc << "Statistical anomaly from " << decoder::ip_to_string(ip)
             << ": byte_z=" << byte_zscore
             << " rate_z=" << rate_zscore
             << " packets=" << s.packet_count
             << " bytes=" << s.total_bytes;

        alert a;
        a.level = severity::medium;
        a.type = category::suspicious_traffic;
        a.source_ip = decoder::ip_to_string(ip);
        a.description = desc.str();
        a.confidence = std::min(1.0,
            std::max(byte_zscore, rate_zscore) / 10.0);
        a.detected_at = std::chrono::steady_clock::now();
        return a;
    }


    void anomaly_detector::prune_stale_ips()
    {
        auto now = std::chrono::steady_clock::now();
        constexpr std::chrono::seconds stale_ttl{600}; // 10 分钟不活跃视为过期

        for (auto it = stats_.begin(); it != stats_.end(); )
        {
            if ((now - it->second.last_update) > stale_ttl)
            {
                destinations_.erase(it->first);
                it = stats_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }


    auto anomaly_detector::check_beacon(std::uint32_t src_ip, std::uint32_t dst_ip)
        -> std::optional<alert>
    {
        // 构建 key = src_ip << 32 | dst_ip
        auto key = (static_cast<std::uint64_t>(src_ip) << 32) |
                   static_cast<std::uint64_t>(dst_ip);

        auto &track = beacon_tracks_[key];
        auto now = std::chrono::steady_clock::now();

        // 记录时间戳，保留最近 20 个
        track.timestamps.push_back(now);
        if (track.timestamps.size() > 20)
        {
            track.timestamps.pop_front();
        }

        // 至少需要 10 次连接才能判定
        if (track.timestamps.size() < 10 || track.alerted)
        {
            return std::nullopt;
        }

        // 计算间隔序列
        auto intervals = std::vector<double>{};
        for (std::size_t i = 1; i < track.timestamps.size(); ++i)
        {
            auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
                track.timestamps[i] - track.timestamps[i - 1]).count();
            intervals.push_back(static_cast<double>(delta));
        }

        // 计算均值和标准差
        auto sum = 0.0;
        for (auto v : intervals) sum += v;
        auto mean = sum / intervals.size();

        if (mean < 1000.0) return std::nullopt;  // 间隔 < 1 秒不算信标（太频繁）

        auto sq_sum = 0.0;
        for (auto v : intervals)
        {
            sq_sum += (v - mean) * (v - mean);
        }
        auto stddev = std::sqrt(sq_sum / intervals.size());

        // 变异系数 CV = stddev / mean
        // CV < 0.3 表示间隔非常规律（信标行为）
        auto cv = mean > 0 ? stddev / mean : 1.0;
        if (cv >= 0.3) return std::nullopt;

        track.alerted = true;

        alert a;
        a.level = severity::high;
        a.type = category::suspicious_traffic;
        a.source_ip = decoder::ip_to_string(src_ip);
        a.description = "Possible C2 beacon: periodic connection to " +
            decoder::ip_to_string(dst_ip) + " every " +
            std::to_string(static_cast<int>(mean / 1000)) +
            "s (CV=" + std::to_string(cv).substr(0, 4) + ")";
        a.detected_at = now;
        return a;
    }


} // namespace sec::detector
