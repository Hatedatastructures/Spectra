/**
 * @file ai_chat.hpp
 * @brief AI 对话管理器（本地 ONNX + 远程 SSE 双模式）
 */
#pragma once

#include <sec/config.hpp>
#include <sec/ai/feature.hpp>
#include <sec/ai/model.hpp>
#include <sec/decoder/frame.hpp>
#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace sec::tui
{
    /**
     * @brief AI 工作模式
     */
    enum class ai_mode : std::uint8_t
    {
        /** @brief 禁用 */
        off,
        /** @brief 本地 ONNX 推理 */
        local,
        /** @brief 远程 API 流式 */
        remote
    };

    /**
     * @brief 远程 API 协议类型
     */
    enum class api_protocol : std::uint8_t
    {
        /** @brief OpenAI /v1/chat/completions */
        openai,
        /** @brief Anthropic /v1/messages */
        anthropic
    };

    /**
     * @brief 对话消息
     */
    struct chat_message
    {
        enum class role : std::uint8_t { user, assistant, system };
        role who;
        std::string content;
        bool streaming{false};
        std::chrono::steady_clock::time_point timestamp{std::chrono::steady_clock::now()};
    };

    /**
     * @brief 远程 API 配置（支持 OpenAI + Anthropic 双协议）
     */
    struct remote_config
    {
        std::string endpoint{"https://api.openai.com/v1/chat/completions"};
        std::string api_key;
        std::string model{"gpt-4o"};
        api_protocol protocol{api_protocol::openai};
        std::uint16_t max_tokens{4096};
        float temperature{0.7f};
    };

    /**
     * @brief AI 对话管理器
     * @details 双模式：本地 ONNX 异常检测 + 远程 API 流式（OpenAI / Anthropic）。
     */
    class ai_chat
    {
    public:
        explicit ai_chat(const sec::ai_config &ai_cfg);
        ~ai_chat() noexcept;

        void set_remote(const remote_config &cfg);
        void set_mode(ai_mode mode);
        [[nodiscard]] auto mode() const noexcept -> ai_mode;

        /**
         * @brief 发送消息并获取回复
         * @param text 用户输入
         * @param on_chunk 流式回调（远程多次调用，本地一次整段）
         * @param on_done 完成回调
         */
        auto send(const std::string &text,
                  std::function<void(std::string_view)> on_chunk,
                  std::function<void()> on_done) -> void;

        void abort();
        [[nodiscard]] auto history() const -> const std::vector<chat_message> &;
        void clear_history();
        void set_system_prompt(std::string prompt);
        void observe_packet(const decoder::packet_info &frame);
        [[nodiscard]] auto is_generating() const noexcept -> bool;
        [[nodiscard]] auto load_local_model() -> bool;

    private:
        void do_local_inference(const std::string &text,
                                 std::function<void(std::string_view)> on_chunk,
                                 std::function<void()> on_done);
        void do_remote_request(const std::string &text,
                                std::function<void(std::string_view)> on_chunk,
                                std::function<void()> on_done);

        sec::ai_config ai_cfg_;
        remote_config remote_cfg_;
        ai_mode mode_{ai_mode::off};
        std::string system_prompt_;
        std::vector<chat_message> history_;

        std::unique_ptr<sec::ai::anomaly_model> local_model_;
        sec::ai::feature_extractor extractor_;

        boost::asio::io_context remote_ioc_;
        std::optional<boost::asio::executor_work_guard<
            boost::asio::io_context::executor_type>> remote_work_;
        std::thread remote_thread_;

        std::atomic<bool> generating_{false};
        std::atomic<bool> abort_flag_{false};
        mutable std::mutex history_mutex_;
    };

} // namespace sec::tui
