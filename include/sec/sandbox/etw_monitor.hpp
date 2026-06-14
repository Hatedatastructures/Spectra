/**
 * @file etw_monitor.hpp
 * @brief ETW/sysmon 行为监控器
 * @details Phase 1：通过 Windows ETW 实时 trace session 收集 Guest 行为。
 * 监听 Kernel-Process/File/Network provider，解析为 behavior_event。
 */
#pragma once

#include <sec/sandbox/monitor.hpp>
#include <sec/sandbox/types.hpp>

#include <atomic>
#include <thread>
#include <vector>

namespace sec::sandbox
{
    /**
     * @brief ETW 实时行为监控
     */
    class etw_monitor : public monitor
    {
    public:
        etw_monitor();
        ~etw_monitor() override;

        auto start(std::string_view vm_name, std::error_code &ec) -> void override;
        auto stop() -> void override;
        [[nodiscard]] auto events() const -> const std::vector<behavior_event> & override;
        [[nodiscard]] auto is_running() const -> bool override;

    private:
        void collect_loop();

        std::atomic<bool> running_{false};
        std::thread collect_thread_;
        std::vector<behavior_event> events_;
        std::string vm_name_;
        std::chrono::steady_clock::time_point start_time_;
    };

} // namespace sec::sandbox
