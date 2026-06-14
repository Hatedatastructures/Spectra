// 沙箱分析编排器实现

#include <sec/sandbox/analyzer.hpp>
#include <sec/sandbox/report.hpp>

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <thread>

namespace sec::sandbox
{
    analyzer::analyzer(engine::context &ctx, store::database &db,
                       std::unique_ptr<vm_backend> vm, std::unique_ptr<monitor> mon)
        : ctx_{ctx}
        , db_{db}
        , vm_{std::move(vm)}
        , mon_{std::move(mon)}
    {
    }


    auto analyzer::submit(analysis_target target, std::error_code &ec) -> net::awaitable<analysis_result>
    {
        spdlog::info("Sandbox submit: file='{}' sha256='{}'", target.local_path, target.sha256);
        auto now = std::chrono::system_clock::now();
        auto ts = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        auto result = analysis_result{};
        result.status = analysis_status::running;
        result.submitted_at = static_cast<std::int64_t>(ts);

        co_await run_analysis(std::move(target));
        // run_analysis 内部设置 result
        ec.clear();
        co_return result;
    }


    auto analyzer::run_analysis(analysis_target target) -> net::awaitable<analysis_result>
    {
        auto result = analysis_result{};
        result.status = analysis_status::running;

        auto ec = std::error_code{};
        auto ignore_ec = std::error_code{};

        // 1. 恢复快照
        spdlog::info("Sandbox: restoring snapshot '{}' on VM '{}'",
                     cfg_.snapshot_name, cfg_.vm_name);
        co_await vm_->restore_snapshot(cfg_.vm_name, cfg_.snapshot_name, ec);
        if (ec)
        {
            result.status = analysis_status::failed;
            result.summary = "Failed to restore snapshot: " + ec.message();
            co_return result;
        }

        // 2. 启动 VM
        spdlog::info("Sandbox: starting VM '{}'", cfg_.vm_name);
        co_await vm_->start(cfg_.vm_name, ec);
        if (ec)
        {
            result.status = analysis_status::failed;
            result.summary = "Failed to start VM: " + ec.message();
            co_return result;
        }

        // 3. 等待 Guest 就绪
        spdlog::info("Sandbox: waiting for guest to be ready");
        co_await vm_->wait_for_guest(cfg_.vm_name, 60000, ec);
        if (ec)
        {
            result.status = analysis_status::failed;
            result.summary = "Guest did not become ready: " + ec.message();
            co_await vm_->stop(cfg_.vm_name, ignore_ec);
            co_return result;
        }

        // 4. 复制文件到 Guest
        spdlog::info("Sandbox: copying '{}' to guest workdir", target.local_path);
        co_await vm_->copy_to_guest(cfg_.vm_name, target.local_path,
                                    cfg_.guest_workdir, ec);
        if (ec)
        {
            result.status = analysis_status::failed;
            result.summary = "Failed to copy file to guest: " + ec.message();
            co_await vm_->stop(cfg_.vm_name, ignore_ec);
            co_return result;
        }

        // 5. 开始监控
        spdlog::info("Sandbox: starting behavior monitor");
        mon_->start(cfg_.vm_name, ec);

        // 6. 在 Guest 内执行文件
        spdlog::info("Sandbox: executing '{}' in guest", target.filename);
        auto exec_cmd = std::string{"\""} + cfg_.guest_workdir + "\\" + target.filename +
                        "\" " + target.arguments;
        co_await vm_->exec_in_guest(cfg_.vm_name, exec_cmd, ec);

        // 7. 等待分析超时（或监控检测到退出）
        spdlog::info("Sandbox: monitoring for {} seconds", cfg_.timeout_seconds);
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds{cfg_.timeout_seconds};
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (!vm_->is_running(cfg_.vm_name)) break;
            std::this_thread::sleep_for(std::chrono::seconds{2});
        }

        // 8. 停止监控
        mon_->stop();
        result.events = mon_->events();

        // 9. 计算威胁评分
        result.score = calculate_score(result.events);
        result.summary = generate_summary(result);
        result.status = analysis_status::completed;

        // 10. 生成报告
        result.report_path = report::generate(target, result, cfg_);

        // 11. 关机并恢复快照
        spdlog::info("Sandbox: stopping VM and restoring clean snapshot");
        co_await vm_->stop(cfg_.vm_name, ignore_ec);
        co_await vm_->restore_snapshot(cfg_.vm_name, cfg_.snapshot_name, ignore_ec);

        auto now = std::chrono::system_clock::now();
        result.completed_at = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count());

        spdlog::info("Sandbox: analysis complete, score={}, events={}",
                     result.score, result.events.size());
        co_return result;
    }


    auto analyzer::calculate_score(const std::vector<behavior_event> &events) -> std::uint8_t
    {
        // 简化评分模型：按事件类型和可疑模式加权
        auto score = std::uint8_t{0};
        for (const auto &ev : events)
        {
            // 网络连接到外部 IP
            if (ev.kind == event_kind::network) score += 5;
            // DNS 解析到可疑域名
            if (ev.kind == event_kind::dns) score += 3;
            // 进程注入或异常创建
            if (ev.kind == event_kind::process && ev.operation == "inject") score += 15;
            if (ev.kind == event_kind::process && ev.operation == "create") score += 2;
            // 注册表修改（自启动）
            if (ev.kind == event_kind::registry &&
                ev.target.find("Run") != std::string::npos) score += 10;
            // 文件删除
            if (ev.kind == event_kind::file && ev.operation == "delete") score += 5;
        }
        return std::min(score, std::uint8_t{100});
    }


    auto analyzer::generate_summary(const analysis_result &result) -> std::string
    {
        auto ss = std::ostringstream{};
        ss << "Score: " << static_cast<int>(result.score) << "/100. "
           << result.events.size() << " behavior events captured.";

        if (result.score >= 70)
        {
            ss << " **HIGH RISK** - likely malicious.";
        }
        else if (result.score >= 40)
        {
            ss << " Medium risk - suspicious behavior detected.";
        }
        else
        {
            ss << " Low risk - no significant suspicious behavior.";
        }
        return ss.str();
    }

} // namespace sec::sandbox
