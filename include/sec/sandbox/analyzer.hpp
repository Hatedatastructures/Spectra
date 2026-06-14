/**
 * @file analyzer.hpp
 * @brief 沙箱分析编排器
 * @details 协调 VM 后端 + 监控器 + 存储，执行完整分析流程：
 * restore → start → copy → exec → monitor → stop → report → store。
 */
#pragma once

#include <sec/sandbox/types.hpp>
#include <sec/sandbox/vm_backend.hpp>
#include <sec/sandbox/monitor.hpp>
#include <sec/engine/context.hpp>
#include <sec/store/database.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <string>

namespace net = boost::asio;

namespace sec::sandbox
{
    /**
     * @brief 沙箱分析编排器
     */
    class analyzer
    {
    public:
        analyzer(engine::context &ctx, store::database &db,
                 std::unique_ptr<vm_backend> vm, std::unique_ptr<monitor> mon);

        /**
         * @brief 提交文件进行沙箱分析
         * @param target 分析目标（文件路径/Guest 文件名等）
         * @param ec 错误码
         * @return 分析结果
         */
        auto submit(analysis_target target, std::error_code &ec)
            -> net::awaitable<analysis_result>;

    private:
        auto run_analysis(analysis_target target) -> net::awaitable<analysis_result>;
        auto calculate_score(const std::vector<behavior_event> &events) -> std::uint8_t;
        auto generate_summary(const analysis_result &result) -> std::string;

        engine::context &ctx_;
        store::database &db_;
        std::unique_ptr<vm_backend> vm_;
        std::unique_ptr<monitor> mon_;
        sandbox_config cfg_;
    };

} // namespace sec::sandbox
