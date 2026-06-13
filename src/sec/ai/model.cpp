// AI 异常检测模型实现

#include <sec/ai/model.hpp>

#include <cmath>
#include <cstring>


namespace sec::ai
{


    anomaly_model::anomaly_model(model_config cfg)
        : config_{std::move(cfg)}
        , extractor_{config_.feature_window}
    {
    }


    anomaly_model::~anomaly_model() noexcept = default;


    [[nodiscard]] auto anomaly_model::load() -> bool
    {
        if (config_.model_path.empty())
        {
            return false;
        }

        auto &mgr = runtime_manager::instance();
        bool ok = mgr.create_session(
            config_.session_name, config_.model_path);

        if (ok)
        {
            session_ = mgr.get_session(config_.session_name);
            loaded_ = (session_ != nullptr);
        }

        return loaded_;
    }


    void anomaly_model::observe(const decoder::packet_info &frame)
    {
        extractor_.observe(frame);
    }


    [[nodiscard]] auto anomaly_model::detect(std::uint32_t ip)
        -> std::optional<detector::alert>
    {
        auto feat = extractor_.extract(ip);
        if (feat.empty())
        {
            return std::nullopt;
        }

        if (!loaded_ || session_ == nullptr)
        {
            return std::nullopt;
        }

        // 将 double 特征向量转为 float 以供 ONNX 推理
        std::vector<float> input(feature_dim);
        for (std::size_t i = 0; i < feature_dim; ++i)
        {
            input[i] = static_cast<float>(feat[i]);
        }

        // 构造输入形状: {1, feature_dim}
        std::vector<std::int64_t> shape{1,
            static_cast<std::int64_t>(feature_dim)};

        auto result = session_->run(input, shape);
        if (!result.success)
        {
            return std::nullopt;
        }

        double score = result.anomaly_score;
        if (score < config_.anomaly_threshold)
        {
            return std::nullopt;
        }

        // 构造告警
        detector::alert a{};
        a.level = detector::severity::high;
        a.type = detector::category::ai_anomaly;
        a.source_ip = ip;
        a.confidence = score;
        a.description = "AI anomaly detected, score="
            + std::to_string(score);
        a.detected_at = std::chrono::steady_clock::now();

        return a;
    }


    [[nodiscard]] auto anomaly_model::is_loaded() const noexcept -> bool
    {
        return loaded_;
    }


} // namespace sec::ai
