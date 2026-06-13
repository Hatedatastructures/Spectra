/**
 * @file runtime.hpp
 * @brief ONNX Runtime 封装
 * @details 管理 ONNX Runtime 环境、会话和推理。
 * 提供 Singleton 环境 + 多会话管理。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>


namespace sec::ai
{

    /**
     * @brief ONNX 推理输入/输出张量描述
     */
    struct tensor_info
    {
        /** @brief 张量名称 */
        std::string name;
        /** @brief 维度大小列表 */
        std::vector<std::int64_t> shape;
    };


    /**
     * @brief 推理结果
     */
    struct inference_result
    {
        /** @brief 输出张量数据 */
        std::vector<float> output;
        /** @brief 输出形状 */
        std::vector<std::int64_t> output_shape;
        /** @brief 异常分数 [0.0, 1.0] */
        double anomaly_score{0.0};
        /** @brief 推理是否成功 */
        bool success{false};
    };


    /**
     * @brief ONNX Runtime 推理会话
     * @details 封装单个 ONNX 模型的加载和推理。
     * 支持动态 batch 和固定维度输入。
     */
    class inference_session
    {
    public:
        inference_session() noexcept;

        ~inference_session() noexcept;

        /**
         * @brief 加载 ONNX 模型文件
         * @param model_path 模型文件路径 (.onnx)
         * @return 成功返回 true
         */
        [[nodiscard]] auto load(const std::string &model_path) -> bool;

        /**
         * @brief 运行推理
         * @param input 输入特征数据
         * @param input_shape 输入形状
         * @return 推理结果
         */
        [[nodiscard]] auto run(const std::vector<float> &input,
            const std::vector<std::int64_t> &input_shape) -> inference_result;

        /**
         * @brief 获取模型输入信息
         */
        [[nodiscard]] auto input_info() const -> const tensor_info &;

        /**
         * @brief 获取模型输出信息
         */
        [[nodiscard]] auto output_info() const -> const tensor_info &;

        /**
         * @brief 模型是否已加载
         */
        [[nodiscard]] auto is_loaded() const noexcept -> bool;

    private:
        struct impl;
        std::unique_ptr<impl> impl_;
    };


    /**
     * @brief AI 推理管理器
     * @details 全局 ONNX 环境管理，负责会话创建和生命周期。
     */
    class runtime_manager
    {
    public:
        /**
         * @brief 获取全局运行时实例
         */
        [[nodiscard]] static auto instance() -> runtime_manager &;

        /**
         * @brief 创建新的推理会话
         * @param name 会话名称
         * @param model_path ONNX 模型文件路径
         * @return 成功返回 true
         */
        [[nodiscard]] auto create_session(const std::string &name,
            const std::string &model_path) -> bool;

        /**
         * @brief 获取指定会话
         * @param name 会话名称
         * @return 推理会话指针，不存在返回 nullptr
         */
        [[nodiscard]] auto get_session(const std::string &name) -> inference_session *;

        /**
         * @brief 移除指定会话
         */
        void remove_session(const std::string &name);

    private:
        runtime_manager();

        struct impl;
        std::unique_ptr<impl> impl_;
    };


} // namespace sec::ai
