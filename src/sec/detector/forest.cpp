// Isolation Forest 实现 — 纯 C++，零外部依赖

#include <sec/detector/forest.hpp>

#include <algorithm>
#include <cmath>
#include <random>
#include <spdlog/spdlog.h>

namespace sec::detector
{
    isolation_forest::isolation_forest(std::uint32_t num_trees,
                                       std::uint32_t max_samples) noexcept
        : num_trees_{num_trees}
        , max_samples_{max_samples}
        , max_depth_{static_cast<std::uint32_t>(std::ceil(std::log2(
              static_cast<double>(max_samples > 0 ? max_samples : 1))))}
    {
    }


    void isolation_forest::train(const std::vector<std::vector<double>> &samples)
    {
        if (samples.empty())
        {
            spdlog::warn("isolation_forest: empty training set");
            return;
        }

        feature_count_ = static_cast<std::uint32_t>(samples[0].size());
        nodes_.clear();
        tree_roots_.clear();
        tree_roots_.reserve(num_trees_);

        auto rng = std::mt19937{std::random_device{}()};

        for (std::uint32_t t = 0; t < num_trees_; ++t)
        {
            // 子采样
            auto sub = std::vector<std::vector<double>>{};
            auto n = std::min(static_cast<std::size_t>(max_samples_), samples.size());
            if (n == samples.size())
            {
                sub = samples;
            }
            else
            {
                // 简单随机不放回采样
                auto indices = std::vector<std::size_t>(samples.size());
                for (std::size_t i = 0; i < indices.size(); ++i) indices[i] = i;
                std::shuffle(indices.begin(), indices.end(), rng);
                sub.reserve(n);
                for (std::size_t i = 0; i < n; ++i)
                {
                    sub.push_back(samples[indices[i]]);
                }
            }

            auto root = build_tree(sub, 0);
            tree_roots_.push_back(root);
        }

        trained_ = true;
        spdlog::info("isolation_forest: trained {} trees, {} nodes, {} features",
                     tree_roots_.size(), nodes_.size(), feature_count_);
    }


    auto isolation_forest::score(const std::vector<double> &features) const -> double
    {
        if (!trained_ || tree_roots_.empty())
        {
            return 0.0;
        }

        // 计算平均路径长度
        auto total_path = 0.0;
        for (auto root : tree_roots_)
        {
            total_path += path_length(root, features, 0);
        }
        auto avg_path = total_path / static_cast<double>(tree_roots_.size());

        // 异常分数 s = 2^(-E(h) / c(n))
        auto cn = c_factor(max_samples_);
        auto anomaly_score = std::pow(2.0, -avg_path / cn);
        return anomaly_score;
    }


    [[nodiscard]] auto isolation_forest::is_trained() const noexcept -> bool
    {
        return trained_;
    }


    [[nodiscard]] auto isolation_forest::feature_count() const noexcept -> std::uint32_t
    {
        return feature_count_;
    }


    auto isolation_forest::build_tree(const std::vector<std::vector<double>> &samples,
                                      std::uint32_t depth) -> std::int32_t
    {
        // 终止条件：样本数 ≤ 1 或达到最大深度
        if (samples.size() <= 1 || depth >= max_depth_)
        {
            auto idx = static_cast<std::int32_t>(nodes_.size());
            nodes_.push_back({-1, 0.0, -1, -1, static_cast<std::int32_t>(samples.size())});
            return idx;
        }

        auto rng = std::mt19937{std::random_device{}()};

        // 随机选择一个特征，计算 min/max
        auto feat = std::uniform_int_distribution<std::uint32_t>(0, feature_count_ - 1)(rng);
        auto min_val = std::numeric_limits<double>::max();
        auto max_val = std::numeric_limits<double>::lowest();

        for (const auto &s : samples)
        {
            if (feat < s.size())
            {
                min_val = std::min(min_val, s[feat]);
                max_val = std::max(max_val, s[feat]);
            }
        }

        // 所有样本在该维度相同值 → 叶节点
        if (min_val >= max_val)
        {
            auto idx = static_cast<std::int32_t>(nodes_.size());
            nodes_.push_back({-1, 0.0, -1, -1, static_cast<std::int32_t>(samples.size())});
            return idx;
        }

        // 随机切分值
        auto split = std::uniform_real_distribution<double>(min_val, max_val)(rng);

        // 分割样本
        auto left_samples = std::vector<std::vector<double>>{};
        auto right_samples = std::vector<std::vector<double>>{};

        for (const auto &s : samples)
        {
            if (feat < s.size() && s[feat] < split)
            {
                left_samples.push_back(s);
            }
            else
            {
                right_samples.push_back(s);
            }
        }

        // 递归构建子树
        auto left_child = build_tree(left_samples, depth + 1);
        auto right_child = build_tree(right_samples, depth + 1);

        auto idx = static_cast<std::int32_t>(nodes_.size());
        nodes_.push_back({static_cast<std::int32_t>(feat), split, left_child, right_child, 0});
        return idx;
    }


    auto isolation_forest::path_length(std::int32_t node_idx,
                                        const std::vector<double> &features,
                                        std::uint32_t depth) const -> double
    {
        if (node_idx < 0 || node_idx >= static_cast<std::int32_t>(nodes_.size()))
        {
            return static_cast<double>(depth);
        }

        const auto &n = nodes_[static_cast<std::size_t>(node_idx)];

        // 叶节点
        if (n.split_feature < 0)
        {
            if (n.size <= 1)
            {
                return static_cast<double>(depth);
            }
            return static_cast<double>(depth) + c_factor(static_cast<std::uint32_t>(n.size));
        }

        // 内部节点：按切分值走左或右
        auto feat = static_cast<std::size_t>(n.split_feature);
        if (feat < features.size() && features[feat] < n.split_value)
        {
            return path_length(n.left, features, depth + 1);
        }
        return path_length(n.right, features, depth + 1);
    }


    auto isolation_forest::c_factor(std::uint32_t n) -> double
    {
        if (n <= 1) return 0.0;
        // c(n) = 2*H(n-1) - 2*(n-1)/n, H(i) ≈ ln(i) + 0.5772156649
        constexpr auto euler = 0.5772156649015329;
        auto h = std::log(static_cast<double>(n - 1)) + euler;
        return 2.0 * h - 2.0 * static_cast<double>(n - 1) / static_cast<double>(n);
    }

} // namespace sec::detector
