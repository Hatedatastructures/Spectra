// 线程安全 UI 事件队列

#include <sec/tui/event.hpp>

namespace sec::tui
{

    void ui_event_queue::push(ui_event ev)
    {
        auto lock = std::lock_guard<std::mutex>{mutex_};
        queue_.push_back(std::move(ev));
    }

    auto ui_event_queue::poll_all() -> std::vector<ui_event>
    {
        auto lock = std::lock_guard<std::mutex>{mutex_};
        auto result = std::vector<ui_event>{};
        result.reserve(queue_.size());
        for (auto &ev : queue_)
        {
            result.push_back(std::move(ev));
        }
        queue_.clear();
        return result;
    }

} // namespace sec::tui
