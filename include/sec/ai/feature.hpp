/**
 * @file feature.hpp
 * @brief 流量特征提取
 * @details 将数据包流转换为固定维度特征向量，
 * 供 AI 模型推理使用。包含包速率、平均大小、
 * 连接数、唯一目标数、协议分布、端口熵等指标。
 */

#pragma once

#include <sec/decoder/frame.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>


namespace sec::ai
{

    /**
     * @brief 特征向量维度
     */
    constexpr std::size_t feature_dim{12};

    /**
     * @brief 特征向量类型
     */
    using feature_vector = std::array<double, feature_dim>;

    /**
     * @brief 特征向量各维度索引
     */
    enum class feature_index : std::size_t
    {
        /** @brief 每秒数据包数 */
        packet_rate = 0,
        /** @brief 每秒字节数 */
        byte_rate = 1,
        /** @brief 平均包大小 */
        avg_packet_size = 2,
        /** @brief 唯一目标 IP 数 */
        unique_destinations = 3,
        /** @brief 唯一目标端口数 */
        unique_ports = 4,
        /** @brief TCP 包占比 */
        tcp_ratio = 5,
        /** @brief UDP 包占比 */
        udp_ratio = 6,
        /** @brief 目标端口熵 */
        port_entropy = 7,
        /** @brief 源端口熵 */
        src_port_entropy = 8,
        /** @brief 总数据包数 */
        total_packets = 9,
        /** @brief 总字节数 */
        total_bytes = 10,
        /** @brief 平均包间隔（微秒） */
        avg_interval = 11
    };


    /**
     * @brief 流量特征提取器
     * @details 跟踪每个源 IP 的流量统计，在时间窗口内
     * 聚合计算特征向量。用于 AI 异常检测模型输入。
     */
    class feature_extractor
    {
    public:
        /**
         * @param window_seconds 统计时间窗口（秒）
         */
        explicit feature_extractor(int window_seconds = 60) noexcept;

        /**
         * @brief 处理数据包，更新统计
         * @param frame 帧解析信息
         */
        void observe(const decoder::packet_info &frame);

        /**
         * @brief 提取指定 IP 的特征向量
         * @param ip 源 IP 地址
         * @return 特征向量，IP 不存在时返回零向量
         */
        [[nodiscard]] auto extract(std::uint32_t ip) const -> feature_vector;

        /**
         * @brief 获取当前跟踪的 IP 列表
         */
        [[nodiscard]] auto tracked_ips() const -> std::vector<std::uint32_t>;

        /**
         * @brief 清除指定 IP 的统计
         */
        void remove(std::uint32_t ip);

        /**
         * @brief 清除所有统计
         */
        void reset();

    private:
        /**
         * @brief 单个 IP 的窗口内统计
         */
        struct ip_window
        {
            std::uint64_t packet_count{0};
            std::uint64_t total_bytes{0};
            std::unordered_set<std::uint32_t> dst_ips;
            std::unordered_set<std::uint16_t> dst_ports;
            std::unordered_set<std::uint16_t> src_ports;
            std::uint64_t tcp_count{0};
            std::uint64_t udp_count{0};
            std::chrono::steady_clock::time_point first_time;
            std::chrono::steady_clock::time_point last_time;
            std::chrono::microseconds total_interval{0};
        };

        auto compute_entropy(const std::unordered_map<std::uint16_t, std::uint64_t> &counts,
            std::uint64_t total) const -> double;

        int window_seconds_;
        std::unordered_map<std::uint32_t, ip_window> windows_;
    };


} // namespace sec::ai
