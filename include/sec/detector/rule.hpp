/**
 * @file rule.hpp
 * @brief 规则引擎
 * @details 类 Snort 规则解析与匹配。支持按协议、端口、
 * 内容关键字和阈值触发告警。
 */

#pragma once

#include <sec/detector/alert.hpp>
#include <sec/decoder/frame.hpp>

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>


namespace sec::detector
{

    /**
     * @brief 规则动作
     */
    enum class rule_action : std::uint8_t
    {
        /** @brief 产生告警 */
        alert,
        /** @brief 仅记录 */
        log,
        /** @brief 丢弃 */
        drop
    };


    /**
     * @brief 规则协议
     */
    enum class rule_protocol : std::uint8_t
    {
        /** @brief TCP */
        tcp,
        /** @brief UDP */
        udp,
        /** @brief ICMP */
        icmp,
        /** @brief IP（任意协议） */
        ip
    };


    /**
     * @brief 规则地址匹配条件
     */
    struct rule_address
    {
        /** @brief IP 地址，0 表示任意 */
        std::uint32_t ip{0};
        /** @brief 子网掩码位数，0 表示匹配任意 */
        std::uint8_t mask{0};
        /** @brief 端口号，0 表示任意 */
        std::uint16_t port{0};
        /** @brief 是否匹配任意 */
        bool any{true};
    };


    /**
     * @brief 内容匹配选项
     */
    struct content_option
    {
        /** @brief 要匹配的字节模式 */
        std::string pattern;
        /** @brief 是否大小写不敏感 */
        bool nocase{false};
        /** @brief 偏移量，-1 表示不限制 */
        std::int32_t offset{-1};
        /** @brief 深度，-1 表示不限制 */
        std::int32_t depth{-1};
    };


    /**
     * @brief 检测规则
     * @details 一条完整的检测规则，包含匹配条件和告警参数。
     */
    struct rule
    {
        /** @brief 规则 ID */
        std::string id;
        /** @brief 规则动作 */
        rule_action action{rule_action::alert};
        /** @brief 匹配协议 */
        rule_protocol protocol{rule_protocol::ip};
        /** @brief 源地址条件 */
        rule_address source;
        /** @brief 目标地址条件 */
        rule_address destination;
        /** @brief 内容匹配选项列表 */
        std::vector<content_option> contents;
        /** @brief 告警消息 */
        std::string message;
        /** @brief 告警严重程度 */
        severity level{severity::medium};
        /** @brief 告警类别 */
        category type{category::custom};
        /** @brief 触发阈值（秒内匹配次数） */
        std::uint32_t threshold_count{0};
        /** @brief 阈值时间窗口（秒） */
        std::uint32_t threshold_seconds{0};
        /** @brief 是否启用 */
        bool enabled{true};
    };


    /**
     * @brief 规则引擎
     * @details 管理检测规则集，对解码后的数据包执行
     * 规则匹配，产生告警。
     */
    class rule_engine
    {
    public:
        rule_engine() = default;

        /**
         * @brief 添加检测规则
         * @param r 检测规则
         */
        void add_rule(rule r);

        /**
         * @brief 按规则 ID 移除规则
         * @param id 规则 ID
         * @return 是否成功移除
         */
        auto remove_rule(const std::string &id) -> bool;

        /**
         * @brief 对数据包执行规则匹配
         * @param frame 帧解析信息
         * @param payload 传输层载荷
         * @return 匹配到的告警列表，无匹配返回空
         */
        [[nodiscard]] auto match(const decoder::packet_info &frame,
            std::span<const std::byte> payload) -> std::vector<alert>;

        /**
         * @brief 获取当前规则数量
         */
        [[nodiscard]] auto rule_count() const noexcept -> std::size_t;

        /**
         * @brief 清除所有规则
         */
        void clear();

    private:
        auto match_address(const rule_address &addr, std::uint32_t ip,
            std::uint16_t port) const -> bool;

        auto match_content(const content_option &opt,
            std::span<const std::byte> payload) const -> bool;

        auto check_threshold(const rule &r) -> bool;

        struct hit_record
        {
            std::chrono::steady_clock::time_point when;
        };

        std::vector<rule> rules_;
        std::unordered_map<std::string, std::deque<hit_record>> threshold_counters_;
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> cooldown_;
    };


} // namespace sec::detector
