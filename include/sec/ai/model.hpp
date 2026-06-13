/**
 * @file model.hpp
 * @brief AI 模型加载与推理管线
 * @details 将特征提取器的输出接入 ONNX 推理，
 * 输出异常分数。提供高层 API 供检测管线调用。
 */

#pragma once

#include <sec/ai/feature.hpp>
#include <sec/ai/runtime.hpp>
#include <sec/detector/alert.hpp>

#include <cstdint>
#include <optional>
#include <string>


namespace sec::ai
{

    /**
     * @brief 异常检测模型配置
     */
    struct model_config
    {
        /** @brief ONNX 模型文件路径 */
        std::string model_path;
        /** @brief 异常分数阈值，超过此值产生告警 */
        double anomaly_threshold{0.8};
        /** @brief 特征提取时间窗口（秒） */
        int feature_window{60};
        /** @brief 会话名称 */
        std::string session_name{"anomaly_detector"};
    };


    /**
     * @brief 异常检测模型
     * @details 高层 API，组合特征提取和 ONNX 推理。
     * 当异常分数超过阈值时产生告警。
     */
    class anomaly_model
    {
    public:
        explicit anomaly_model(model_config cfg = {});

        ~anomaly_model() noexcept;

        /**
         * @brief 加载模型
         * @return 成功返回 true
         */
        [[nodiscard]] auto load() -> bool;

        /**
         * @brief 处理数据包，更新特征
         * @param frame 帧解析信息
         */
        void observe(const decoder::packet_info &frame);

        /**
         * @brief 对指定 IP 执行推理
         * @param ip 源 IP 地址
         * @return 超过阈值时返回告警
         */
        [[nodiscard]] auto detect(std::uint32_t ip) -> std::optional<detector::alert>;

        /**
         * @brief 获取特征提取器引用
         */
        [[nodiscard]] auto extractor() noexcept -> feature_extractor &
        {
            return extractor_;
        }

        /**
         * @brief 模型是否已加载
         */
        [[nodiscard]] auto is_loaded() const noexcept -> bool;

    private:
        model_config config_;
        feature_extractor extractor_;
        inference_session *session_{nullptr};
        bool loaded_{false};
    };


} // namespace sec::ai
