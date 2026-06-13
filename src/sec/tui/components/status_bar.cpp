// 状态栏实现 — AI 模式 / 设备数 / 告警数 / 时间

#include <sec/tui/components/status_bar.hpp>
#include <sec/tui/application.hpp>
#include <sec/tui/ai_chat.hpp>

#include <chrono>
#include <ctime>
#include <string>

namespace sec::tui::components
{

    namespace
    {
        constexpr auto cache_ttl = std::chrono::seconds{2};
    } // anonymous namespace


    status_bar::status_bar(application &app)
        : app_{app}
    {
    }


    auto status_bar::paint(Term::Window &win, const panel_rect &rect) -> void
    {
        try
        {
            auto now = std::chrono::steady_clock::now();
            if (now - cache_stamp_ >= cache_ttl)
            {
                cache_stamp_ = now;
                auto dev_ec = std::error_code{};
                cached_dev_count_ = app_.device_query().count(dev_ec);
                auto alert_ec = std::error_code{};
                cached_alert_count_ = app_.alert_query().count_unacknowledged(alert_ec);
            }

            auto mode = app_.chat().mode();
            auto mode_str = std::string{"AI:OFF"};
            auto &th = app_.theme();
            auto mode_color = th.secondary_text;

            if (mode == ai_mode::remote)
            {
                mode_str = "AI:REMOTE";
                mode_color = th.info;
            }

            auto t_now = std::chrono::system_clock::now();
            auto t = std::chrono::system_clock::to_time_t(t_now);
            auto tm = std::localtime(&t);
            char time_buf[16]{};
            std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm);

            // 绘制状态栏内容到 Window
            auto col = static_cast<std::size_t>(rect.col);
            auto row = static_cast<std::size_t>(rect.row);
            auto max_cols = static_cast<std::size_t>(rect.cols);

            if (row < 1 || row > win.rows() || col < 1 || max_cols == 0) return;

            auto end_col = std::min(col + max_cols - 1, static_cast<std::size_t>(win.columns()));

            // 背景填充
            win.fill_bg(col, row, end_col, row, th.background);

            auto pos = col;
            auto limit = col + max_cols;

            // 模式标签
            auto label = " " + mode_str + " ";
            for (auto i = std::size_t{0}; i < label.size() && pos < limit; ++i, ++pos)
            {
                if (pos > win.columns()) break;
                win.set_char(pos, row, static_cast<char32_t>(label[i]));
                win.set_fg(pos, row, mode_color);
                win.set_style(pos, row, Term::Style::Bold);
            }

            // 分隔符
            auto sep = std::string{" | "};
            for (auto i = std::size_t{0}; i < sep.size() && pos < limit; ++i, ++pos)
            {
                if (pos > win.columns()) break;
                win.set_char(pos, row, static_cast<char32_t>(sep[i]));
                win.set_fg(pos, row, th.dim_text);
                win.set_style(pos, row, Term::Style::Dim);
            }

            // 设备数
            auto dev_str = "Devices: " + std::to_string(cached_dev_count_);
            for (auto i = std::size_t{0}; i < dev_str.size() && pos < limit; ++i, ++pos)
            {
                if (pos > win.columns()) break;
                win.set_char(pos, row, static_cast<char32_t>(dev_str[i]));
                win.set_fg(pos, row, th.accent);
            }

            // 分隔符
            for (auto i = std::size_t{0}; i < sep.size() && pos < limit; ++i, ++pos)
            {
                if (pos > win.columns()) break;
                win.set_char(pos, row, static_cast<char32_t>(sep[i]));
                win.set_fg(pos, row, th.dim_text);
                win.set_style(pos, row, Term::Style::Dim);
            }

            // 告警数
            auto alert_str = "Alerts: " + std::to_string(cached_alert_count_);
            auto alert_color = cached_alert_count_ > 0 ? th.error : th.success;
            for (auto i = std::size_t{0}; i < alert_str.size() && pos < limit; ++i, ++pos)
            {
                if (pos > win.columns()) break;
                win.set_char(pos, row, static_cast<char32_t>(alert_str[i]));
                win.set_fg(pos, row, alert_color);
            }

            // 时间 — 右对齐
            auto time_str = std::string{time_buf} + " ";
            if (time_str.size() < max_cols)
            {
                auto time_start = static_cast<std::size_t>(rect.col + rect.cols - static_cast<int>(time_str.size()));
                if (time_start >= col)
                {
                    for (auto i = std::size_t{0}; i < time_str.size() && time_start + i <= static_cast<std::size_t>(win.columns()); ++i)
                    {
                        win.set_char(time_start + i, row, static_cast<char32_t>(time_str[i]));
                        win.set_fg(time_start + i, row, th.dim_text);
                        win.set_style(time_start + i, row, Term::Style::Dim);
                    }
                }
            }
        }
        catch (const std::exception &)
        {
            // 静默失败
        }
    }


} // namespace sec::tui::components
