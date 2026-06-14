/**
 * @file event.hpp
 * @brief 线程安全 UI 事件队列，替代 ftxui::ScreenInteractive::Post()
 */
#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace sec::tui
{
    enum class ui_event_type : std::uint8_t
    {
        chat_user_message,
        chat_assistant_chunk,
        chat_assistant_done,
        chat_system_output,
        refresh_sidebar,
        force_redraw,
        key_press,
    };

    struct ui_event
    {
        ui_event_type type{ui_event_type::force_redraw};
        std::string payload;
    };

    class ui_event_queue
    {
    public:
        void push(ui_event ev);
        [[nodiscard]] auto poll_all() -> std::vector<ui_event>;

    private:
        std::mutex mutex_;
        std::deque<ui_event> queue_;
    };

} // namespace sec::tui
