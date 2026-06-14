/**
 * @file sidebar.hpp
 * @brief 侧边栏组件
 * @details 可折叠侧边栏，含设备/告警/扫描三个标签页。
 */
#pragma once

#include <sec/tui/theme.hpp>
#include <sec/tui/terminal.hpp>
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

        void paint(Term::Window &win, const panel_rect &rect);
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

        // paint 子方法（拆分自 paint，避免函数体 > 120 行）
        struct paint_ctx
        {
            Term::Window &win;
            std::size_t col0;
            std::size_t content_start;
            std::size_t row_limit;
            std::size_t col_limit;
            std::size_t max_cols;
            const theme_palette &theme;
        };

        void paint_devices_panel(const paint_ctx &ctx);
        void paint_alerts_panel(const paint_ctx &ctx);
        void paint_scans_panel(const paint_ctx &ctx);
    };

} // namespace sec::tui::components
