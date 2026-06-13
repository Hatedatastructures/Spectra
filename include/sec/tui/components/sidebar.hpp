/**
 * @file sidebar.hpp
 * @brief 侧边栏组件
 * @details 可折叠侧边栏，含设备/告警/扫描三个标签页。
 */
#pragma once

#include <sec/tui/terminal_renderer.hpp>
#include <sec/tui/layout.hpp>

#include <cpp-terminal/key.hpp>

#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace sec::tui
{
    class application;
}

namespace sec::tui::components
{
    /**
     * @brief 侧边栏
     */
    class sidebar
    {
    public:
        explicit sidebar(application &app);

        auto paint(Term::Window &win, const panel_rect &rect) -> void;
        [[nodiscard]] auto width() const -> int;
        [[nodiscard]] auto is_collapsed() const -> bool;
        void toggle();
        auto handle_key(const Term::Key &key) -> bool;

    private:
        application &app_;
        int width_{30};
        bool collapsed_{true};

        enum class tab : std::uint8_t { devices, alerts, scans };
        tab active_tab_{tab::devices};

        struct cached_devices
        {
            std::vector<std::string> ip;
            std::vector<std::string> host;
        };
        struct cached_alerts
        {
            std::vector<std::int64_t> id;
            std::vector<std::string> severity;
            std::vector<std::string> description;
        };
        struct cached_scans
        {
            std::vector<std::string> scan_type;
            std::vector<std::string> subnet;
            std::vector<std::string> status;
        };

        cached_devices devices_;
        cached_alerts alerts_;
        cached_scans scans_;
        std::mutex cache_mutex_;
        std::chrono::steady_clock::time_point devices_stamp_;
        std::chrono::steady_clock::time_point alerts_stamp_;
        std::chrono::steady_clock::time_point scans_stamp_;

        void refresh_devices_if_needed();
        void refresh_alerts_if_needed();
        void refresh_scans_if_needed();
    };

} // namespace sec::tui::components
