// ETW 行为监控实现 — Phase 1 简化版
// 用 VBoxManage guestcontrol 收集 Guest 内的进程/文件/网络活动
// Phase 3 替换为真正的 VMI 监控

#include <sec/sandbox/etw_monitor.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <sstream>

namespace sec::sandbox
{
    etw_monitor::etw_monitor() = default;


    etw_monitor::~etw_monitor()
    {
        stop();
    }


    auto etw_monitor::start(std::string_view vm_name, std::error_code &ec) -> void
    {
        if (running_)
        {
            return;
        }
        vm_name_ = std::string{vm_name};
        running_ = true;
        start_time_ = std::chrono::steady_clock::now();
        events_.clear();
        collect_thread_ = std::thread{[this]() { collect_loop(); }};
        spdlog::info("ETW monitor started for VM '{}'", vm_name_);
        ec.clear();
    }


    auto etw_monitor::stop() -> void
    {
        if (!running_) return;
        running_ = false;
        if (collect_thread_.joinable())
        {
            collect_thread_.join();
        }
        spdlog::info("ETW monitor stopped, collected {} events", events_.size());
    }


    [[nodiscard]] auto etw_monitor::events() const -> const std::vector<behavior_event> &
    {
        return events_;
    }


    [[nodiscard]] auto etw_monitor::is_running() const -> bool
    {
        return running_;
    }


    void etw_monitor::collect_loop()
    {
        // Phase 1 简化实现：定期用 VBoxManage 查询 Guest 内进程列表和网络连接
        // Phase 3 替换为 VMI（DRAKVUF）实时监控
        auto vm = vm_name_;
        while (running_)
        {
            // 查询进程列表
            // VBoxManage guestcontrol <vm> run --exe cmd.exe -- /c tasklist /fo csv
            // 解析输出并与上一次对比，新进程记为 behavior_event
            // Phase 1 先占位，后续完善
            std::this_thread::sleep_for(std::chrono::seconds{2});
        }
    }

} // namespace sec::sandbox
