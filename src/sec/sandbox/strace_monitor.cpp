// Linux Guest strace 行为监控实现

#include <sec/sandbox/strace_monitor.hpp>

#include <spdlog/spdlog.h>

namespace sec::sandbox
{
    strace_monitor::strace_monitor() = default;


    strace_monitor::~strace_monitor()
    {
        stop();
    }


    auto strace_monitor::start(std::string_view vm_name, std::error_code &ec) -> void
    {
        if (running_) return;
        vm_name_ = std::string{vm_name};
        running_ = true;
        events_.clear();
        spdlog::info("strace monitor started for VM '{}'", vm_name_);
        ec.clear();
    }


    auto strace_monitor::stop() -> void
    {
        if (!running_) return;
        running_ = false;
        spdlog::info("strace monitor stopped, {} events", events_.size());
    }


    [[nodiscard]] auto strace_monitor::events() const -> const std::vector<behavior_event> &
    {
        return events_;
    }


    [[nodiscard]] auto strace_monitor::is_running() const -> bool
    {
        return running_;
    }

} // namespace sec::sandbox
