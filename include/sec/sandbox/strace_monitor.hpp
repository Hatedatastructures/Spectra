/**
 * @file strace_monitor.hpp
 * @brief Linux Guest 行为监控（通过 strace）
 * @details 在 Linux Guest 内运行 strace，收集进程/文件/网络行为。
 */
#pragma once

#include <sec/sandbox/monitor.hpp>
#include <sec/sandbox/types.hpp>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

namespace sec::sandbox
{
    class strace_monitor : public monitor
    {
    public:
        strace_monitor();
        ~strace_monitor() override;

        auto start(std::string_view vm_name, std::error_code &ec) -> void override;
        auto stop() -> void override;
        [[nodiscard]] auto events() const -> const std::vector<behavior_event> & override;
        [[nodiscard]] auto is_running() const -> bool override;

    private:
        std::atomic<bool> running_{false};
        std::vector<behavior_event> events_;
        std::string vm_name_;
    };

} // namespace sec::sandbox
