/**
 * @file status_bar.hpp
 * @brief 底部状态栏组件
 * @details 显示 AI 模式、扫描进度、设备数、告警数、时间。
 */
#pragma once

#include <sec/tui/terminal_renderer.hpp>
#include <sec/tui/layout.hpp>

#include <chrono>

namespace sec::tui
{
    class application;
}

namespace sec::tui::components
{
    /**
     * @brief 状态栏
     */
    class status_bar
    {
    public:
        explicit status_bar(application &app);

        auto paint(Term::Window &win, const panel_rect &rect) -> void;

    private:
        application &app_;

        std::int64_t cached_dev_count_{0};
        std::int64_t cached_alert_count_{0};
        std::chrono::steady_clock::time_point cache_stamp_;
    };

} // namespace sec::tui::components
