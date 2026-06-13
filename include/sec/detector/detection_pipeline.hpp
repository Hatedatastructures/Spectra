/**
 * @file detection_pipeline.hpp
 * @brief 检测管线
 * @details 将解码器输出接入规则引擎、统计异常检测和
 * AI 异常模型，统一输出告警。订阅解码器管线，
 * 分发数据包到各检测器。
 */

#pragma once

#include <sec/decoder/pipeline.hpp>
#include <sec/detector/alert.hpp>
#include <sec/detector/rule_engine.hpp>
#include <sec/detector/anomaly.hpp>
#include <sec/detector/port_scan_detector.hpp>

#include <functional>
#include <vector>


namespace sec::detector
{


    /**
     * @brief 检测管线回调类型
     */
    using detection_callback = std::function<void(const alert &)>;


    /**
     * @brief 检测管线
     * @details 订阅解码器输出，将解码后的数据包分发到
     * 规则引擎、统计异常检测器和 AI 模型，收集告警并
     * 通知下游订阅者。
     */
    class detection_pipeline
    {
    public:
        /**
         * @brief 构造检测管线
         * @param decoder 解码器管线引用
         */
        explicit detection_pipeline(decoder::pipeline &decoder) noexcept;

        ~detection_pipeline() noexcept;

        /**
         * @brief 启动检测管线，订阅解码器
         */
        void start();

        /**
         * @brief 停止检测管线，取消订阅
         */
        void stop();

        /**
         * @brief 订阅告警通知
         * @param cb 告警回调
         * @return 订阅句柄
         */
        [[nodiscard]] auto subscribe(detection_callback cb) -> std::size_t;

        /**
         * @brief 取消告警订阅
         * @param handle 订阅句柄
         */
        void unsubscribe(std::size_t handle);

        /**
         * @brief 获取规则引擎引用
         */
        [[nodiscard]] auto rules() noexcept -> rule_engine &
        {
            return rules_;
        }

        /**
         * @brief 获取异常检测器引用
         */
        [[nodiscard]] auto anomaly() noexcept -> anomaly_detector &
        {
            return anomaly_;
        }

        /**
         * @brief 获取端口扫描检测器引用
         */
        [[nodiscard]] auto port_scan() noexcept -> port_scan_detector &
        {
            return port_scan_;
        }

    private:
        void on_decoded(const decoder::decoded_packet &pkt);

        void emit_alert(alert a);

        void load_default_rules();

        decoder::pipeline &decoder_;
        std::size_t decoder_handle_{0};

        rule_engine rules_;
        anomaly_detector anomaly_;
        port_scan_detector port_scan_;

        std::vector<detection_callback> subscribers_;
        std::size_t sub_next_{0};
        bool running_{false};
    };


} // namespace sec::detector
