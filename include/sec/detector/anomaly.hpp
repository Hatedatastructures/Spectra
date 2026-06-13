/**
 * @file anomaly.hpp
 * @brief 统计异常检测器
 * @details 为每个 IP 维护流量统计基线，使用指数移动平均
 * 检测偏离基线的异常流量模式。
 */

#pragma once

#include <sec/detector/alert.hpp>
#include <sec/decoder/frame.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>


namespace sec::detector
{

    /**
     * @brief 单个 IP 的流量统计
     */
    struct ip_stats
    {
        /** @brief 数据包计数 */
        std::uint64_t packet_count{0};
        /** @brief 总字节数 */
        std::uint64_t total_bytes{0};
        /** @brief 唯一目标 IP 数 */
        std::uint64_t unique_destinations{0};
        /** @brief 上次更新时间 */
        std::chrono::steady_clock::time_point last_update;
        /** @brief 速率窗口起始包计数 */
        std::uint64_t window_start_count{0};
        /** @brief 速率窗口起始时间 */
        std::chrono::steady_clock::time_point window_start_time;
        /** @brief 包速率的指数移动平均 */
        double rate_ema{0.0};
        /** @brief 包速率的指数移动方差 */
        double rate_var{0.0};
        /** @brief 字节均值的指数移动平均 */
        double byte_ema{0.0};
        /** @brief 字节均值的指数移动方差 */
        double byte_var{0.0};
    };


    /**
     * @brief 异常检测配置参数
     */
    struct anomaly_config
    {
        /** @brief 指数移动平均平滑系数 */
        double alpha{0.1};
        /** @brief 标准差倍数阈值 */
        double sigma_threshold{3.0};
        /** @brief 最小观测次数，低于此值不检测 */
        std::uint64_t min_observations{10};
        /** @brief 统计窗口时长（秒） */
        int window_seconds{60};
    };


    /**
     * @brief 统计异常检测器
     * @details 为每个源 IP 维护流量基线统计，当当前观测值
     * 超过 EMA + N*stddev 时产生异常告警。
     */
    class anomaly_detector
    {
    public:
        explicit anomaly_detector(anomaly_config cfg = {}) noexcept;

        /**
         * @brief 处理数据包，更新统计并检测异常
         * @param frame 帧解析信息
         * @return 检测到异常时返回告警
         */
        [[nodiscard]] auto observe(const decoder::packet_info &frame)
            -> std::optional<alert>;

        /**
         * @brief 获取指定 IP 的统计信息
         * @param ip IP 地址
         * @return 统计信息指针，不存在返回 nullptr
         */
        [[nodiscard]] auto get_stats(std::uint32_t ip) const -> const ip_stats *;

        /**
         * @brief 获取当前跟踪的 IP 数量
         */
        [[nodiscard]] auto tracked_count() const noexcept -> std::size_t;

        /**
         * @brief 清除所有统计基线
         */
        void reset();

    private:
        void update_stats(std::uint32_t ip, std::uint32_t dst_ip,
            std::uint16_t packet_size);

        auto check_anomaly(std::uint32_t ip) -> std::optional<alert>;

        void prune_stale_ips();

        anomaly_config config_;
        std::unordered_map<std::uint32_t, ip_stats> stats_;
        std::unordered_map<std::uint32_t, std::unordered_map<std::uint32_t, std::chrono::steady_clock::time_point>> destinations_;
        std::uint64_t observe_counter_{0};
    };


} // namespace sec::detector
