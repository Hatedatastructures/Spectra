/**
 * @file forest.hpp
 * @brief Isolation Forest 无监督异常检测
 * @details 纯 C++ 实现，零外部依赖。从网络流量特征自动学习正常基线，
 * 检测偏离模式。不需要标注数据，不需要预训练模型。
 *
 * 算法原理：
 * - 随机选择特征 + 随机切分值构建 isolation tree
 * - 异常点更容易被隔离（路径短）
 * - 多棵树取平均路径 → 异常分数 [0,1]
 */
#pragma once

#include <cstdint>
#include <vector>

namespace sec::detector
{
    /**
     * @brief Isolation Forest 异常检测器
     */
    class isolation_forest
    {
    public:
        /**
         * @brief 构造
         * @param num_trees 树数量（默认 100）
         * @param max_samples 每棵树子采样大小（默认 256）
         */
        explicit isolation_forest(std::uint32_t num_trees = 100,
                                   std::uint32_t max_samples = 256) noexcept;

        /**
         * @brief 用样本集训练 forest
         * @param samples 特征向量列表，每个向量的维度必须一致
         */
        void train(const std::vector<std::vector<double>> &samples);

        /**
         * @brief 计算特征向量的异常分数
         * @param features 特征向量
         * @return 异常分数 [0,1]，越接近 1 越异常
         */
        [[nodiscard]] auto score(const std::vector<double> &features) const -> double;

        /**
         * @brief 是否已训练
         */
        [[nodiscard]] auto is_trained() const noexcept -> bool;

        /**
         * @brief 获取特征维度
         */
        [[nodiscard]] auto feature_count() const noexcept -> std::uint32_t;

    private:
        /**
         * @brief isolation tree 节点（扁平存储）
         */
        struct node
        {
            /** @brief 切分特征索引，-1=叶节点 */
            std::int32_t split_feature{-1};
            /** @brief 切分值 */
            double split_value{0.0};
            /** @brief 左子节点索引，-1=无 */
            std::int32_t left{-1};
            /** @brief 右子节点索引，-1=无 */
            std::int32_t right{-1};
            /** @brief 叶节点的样本数（用于计算路径长度归一化） */
            std::int32_t size{0};
        };

        /**
         * @brief 递归构建 isolation tree
         * @return 根节点在 nodes_ 中的索引
         */
        auto build_tree(const std::vector<std::vector<double>> &samples,
                        std::uint32_t depth) -> std::int32_t;

        /**
         * @brief 在单棵树中计算路径长度
         * @param node_idx 起始节点索引
         * @param features 查询特征
         * @param depth 当前深度
         * @return 路径长度（叶节点按 c(size) 归一化）
         */
        [[nodiscard]] auto path_length(std::int32_t node_idx,
                                        const std::vector<double> &features,
                                        std::uint32_t depth) const -> double;

        /**
         * @brief 归一化因子 c(n) = 2*H(n-1) - 2*(n-1)/n
         */
        [[nodiscard]] static auto c_factor(std::uint32_t n) -> double;

        std::vector<node> nodes_;
        std::vector<std::int32_t> tree_roots_;
        std::uint32_t num_trees_;
        std::uint32_t max_samples_;
        std::uint32_t max_depth_;
        std::uint32_t feature_count_{0};
        bool trained_{false};
    };

} // namespace sec::detector
