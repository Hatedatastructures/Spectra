// 侧边栏实现 — 可折叠，含设备/告警/扫描三个标签页

#include <sec/tui/components/side.hpp>
#include <sec/tui/application.hpp>
#include <sec/tui/chat.hpp>

#include <cpp-terminal/key.hpp>

#include <string>

namespace sec::tui::components
{

    namespace
    {
        constexpr auto cache_ttl = std::chrono::seconds{2};

        auto severity_color(const std::string &severity, const theme_palette &th) -> Term::Color
        {
            if (severity == "critical") return th.error;
            if (severity == "high") return th.high_severity;
            if (severity == "medium") return th.warning;
            return th.success;
        }

        auto scan_status_color(const std::string &status, const theme_palette &th) -> Term::Color
        {
            if (status == "running") return th.warning;
            if (status == "failed") return th.error;
            return th.success;
        }
    } // anonymous namespace


    sidebar::sidebar(application &app)
        : app_{app}
    {
    }


    void sidebar::refresh_devices_if_needed()
    {
        auto now = std::chrono::steady_clock::now();
        if (now - devices_stamp_ < cache_ttl)
        {
            return;
        }

        auto ec = std::error_code{};
        auto src = app_.device_query().find_all(ec);
        if (ec)
        {
            return;
        }

        devices_stamp_ = now;

        auto lock = std::lock_guard<std::mutex>{cache_mutex_};
        devices_.ip.clear();
        devices_.host.clear();

        auto count = std::size_t{0};
        for (const auto &dev : src)
        {
            if (count >= 50) break;
            devices_.ip.push_back(std::string{dev.ip_address});
            auto h = dev.hostname.empty() ? std::string{"-"} : std::string{dev.hostname};
            if (h.size() > 12) h.resize(12);
            devices_.host.push_back(std::move(h));
            ++count;
        }
    }


    void sidebar::refresh_alerts_if_needed()
    {
        auto now = std::chrono::steady_clock::now();
        if (now - alerts_stamp_ < cache_ttl)
        {
            return;
        }

        auto ec = std::error_code{};
        auto src = app_.alert_query().find_unacknowledged(ec);
        if (ec)
        {
            return;
        }

        alerts_stamp_ = now;

        auto lock = std::lock_guard<std::mutex>{cache_mutex_};
        alerts_.id.clear();
        alerts_.severity.clear();
        alerts_.description.clear();

        auto count = std::size_t{0};
        for (const auto &a : src)
        {
            if (count >= 50) break;
            alerts_.id.push_back(a.id);
            alerts_.severity.push_back(a.severity);
            auto desc = a.description;
            if (desc.size() > 24) { desc.resize(22); desc += ".."; }
            alerts_.description.push_back(std::move(desc));
            ++count;
        }
    }


    void sidebar::refresh_scans_if_needed()
    {
        auto now = std::chrono::steady_clock::now();
        if (now - scans_stamp_ < cache_ttl)
        {
            return;
        }

        auto ec = std::error_code{};
        auto src = app_.scan_query().find_recent(20, ec);
        if (ec)
        {
            return;
        }

        scans_stamp_ = now;

        auto lock = std::lock_guard<std::mutex>{cache_mutex_};
        scans_.scan_type.clear();
        scans_.subnet.clear();
        scans_.status.clear();

        for (const auto &s : src)
        {
            scans_.scan_type.push_back(s.scan_type);
            scans_.subnet.push_back(s.subnet);
            scans_.status.push_back(s.status);
        }
    }


    void sidebar::paint(Term::Window &win, const panel_rect &rect)
    {
        if (collapsed_ || rect.cols <= 0 || rect.rows <= 0)
        {
            return;
        }

        auto col0 = static_cast<std::size_t>(rect.col);
        auto row0 = static_cast<std::size_t>(rect.row);
        auto max_rows = static_cast<std::size_t>(rect.rows);
        auto max_cols = static_cast<std::size_t>(rect.cols);

        if (col0 < 1 || row0 < 1) return;

        auto col_limit = std::min(col0 + max_cols, static_cast<std::size_t>(win.columns()) + 1);
        auto row_limit = std::min(row0 + max_rows, static_cast<std::size_t>(win.rows()) + 1);

        auto &th = app_.theme();

        // 绘制 Tab 栏
        auto tabs = std::vector<std::pair<std::string, bool>>{
            {"Dev", active_tab_ == tab::devices},
            {"Alert", active_tab_ == tab::alerts},
            {"Scan", active_tab_ == tab::scans},
        };

        auto tab_col = col0;
        for (const auto &[label, active] : tabs)
        {
            auto display = std::string{" "} + label + " ";
            for (auto i = std::size_t{0}; i < display.size() && tab_col < col_limit; ++i, ++tab_col)
            {
                win.set_char(tab_col, row0, static_cast<char32_t>(display[i]));
                if (active)
                {
                    win.set_fg(tab_col, row0, th.success);
                    win.set_bg(tab_col, row0, th.active_tab_bg);
                    win.set_style(tab_col, row0, Term::Style::Bold);
                }
                else
                {
                    win.set_fg(tab_col, row0, th.dim_text);
                }
            }
        }

        // 分隔线
        if (row0 + 1 < row_limit)
        {
            for (auto c = col0; c < col_limit; ++c)
            {
                win.set_char(c, row0 + 1, U'─');
                win.set_fg(c, row0 + 1, th.border);
            }
        }

        // 内容区从第 2 行开始
        auto content_start = row0 + 2;
        if (content_start >= row_limit) return;

        auto ctx = paint_ctx{win, col0, content_start, row_limit, col_limit, max_cols, th};

        try
        {
            if (active_tab_ == tab::devices)
            {
                paint_devices_panel(ctx);
            }
            else if (active_tab_ == tab::alerts)
            {
                paint_alerts_panel(ctx);
            }
            else
            {
                paint_scans_panel(ctx);
            }
        }
        catch (const std::exception &)
        {
            auto msg = std::string{"  (error loading data)"};
            for (auto i = std::size_t{0}; i < msg.size() && i < max_cols; ++i)
            {
                win.set_char(col0 + i, content_start, static_cast<char32_t>(msg[i]));
                win.set_fg(col0 + i, content_start, th.dim_text);
                win.set_style(col0 + i, content_start, Term::Style::Dim);
            }
        }
    }


    void sidebar::paint_devices_panel(const paint_ctx &ctx)
    {
        refresh_devices_if_needed();
        auto lock = std::lock_guard<std::mutex>{cache_mutex_};

        if (devices_.ip.empty())
        {
            auto msg = std::string{"  No devices"};
            for (auto i = std::size_t{0}; i < msg.size() && ctx.col0 + i < ctx.col_limit; ++i)
            {
                ctx.win.set_char(ctx.col0 + i, ctx.content_start, static_cast<char32_t>(msg[i]));
                ctx.win.set_fg(ctx.col0 + i, ctx.content_start, ctx.theme.dim_text);
                ctx.win.set_style(ctx.col0 + i, ctx.content_start, Term::Style::Dim);
            }
            return;
        }

        // 表头
        auto header = std::string{" IP            Host"};
        for (auto i = std::size_t{0}; i < header.size() && ctx.col0 + i < ctx.col_limit; ++i)
        {
            ctx.win.set_char(ctx.col0 + i, ctx.content_start, static_cast<char32_t>(header[i]));
            ctx.win.set_fg(ctx.col0 + i, ctx.content_start, ctx.theme.header_text);
            ctx.win.set_style(ctx.col0 + i, ctx.content_start, Term::Style::Bold);
        }

        for (std::size_t idx = 0; idx < devices_.ip.size(); ++idx)
        {
            auto line_row = ctx.content_start + 1 + idx;
            if (line_row >= ctx.row_limit) break;

            auto line = std::string{" "} + devices_.ip[idx];
            while (line.size() < 16) line += ' ';
            line += devices_.host[idx];

            for (auto i = std::size_t{0}; i < line.size() && ctx.col0 + i < ctx.col_limit; ++i)
            {
                ctx.win.set_char(ctx.col0 + i, line_row, static_cast<char32_t>(line[i]));
                ctx.win.set_fg(ctx.col0 + i, line_row, ctx.theme.body_text);
            }
        }
    }


    void sidebar::paint_alerts_panel(const paint_ctx &ctx)
    {
        refresh_alerts_if_needed();
        auto lock = std::lock_guard<std::mutex>{cache_mutex_};

        if (alerts_.id.empty())
        {
            auto msg = std::string{"  No alerts"};
            for (auto i = std::size_t{0}; i < msg.size() && i < ctx.max_cols; ++i)
            {
                ctx.win.set_char(ctx.col0 + i, ctx.content_start, static_cast<char32_t>(msg[i]));
                ctx.win.set_fg(ctx.col0 + i, ctx.content_start, ctx.theme.dim_text);
                ctx.win.set_style(ctx.col0 + i, ctx.content_start, Term::Style::Dim);
            }
            return;
        }

        for (std::size_t idx = 0; idx < alerts_.id.size(); ++idx)
        {
            auto line_row = ctx.content_start + idx;
            if (line_row >= ctx.row_limit) break;

            auto line = " [" + std::to_string(alerts_.id[idx]) + "] " + alerts_.description[idx];
            auto color = severity_color(alerts_.severity[idx], ctx.theme);

            for (auto i = std::size_t{0}; i < line.size() && ctx.col0 + i < ctx.col_limit; ++i)
            {
                ctx.win.set_char(ctx.col0 + i, line_row, static_cast<char32_t>(line[i]));
                ctx.win.set_fg(ctx.col0 + i, line_row, color);
            }
        }
    }


    void sidebar::paint_scans_panel(const paint_ctx &ctx)
    {
        refresh_scans_if_needed();
        auto lock = std::lock_guard<std::mutex>{cache_mutex_};

        if (scans_.scan_type.empty())
        {
            auto msg = std::string{"  No scans"};
            for (auto i = std::size_t{0}; i < msg.size() && i < ctx.max_cols; ++i)
            {
                ctx.win.set_char(ctx.col0 + i, ctx.content_start, static_cast<char32_t>(msg[i]));
                ctx.win.set_fg(ctx.col0 + i, ctx.content_start, ctx.theme.dim_text);
                ctx.win.set_style(ctx.col0 + i, ctx.content_start, Term::Style::Dim);
            }
            return;
        }

        for (std::size_t idx = 0; idx < scans_.scan_type.size(); ++idx)
        {
            auto line_row = ctx.content_start + idx;
            if (line_row >= ctx.row_limit) break;

            auto line = " " + scans_.scan_type[idx] + " " + scans_.subnet[idx] + " " + scans_.status[idx];
            auto color = scan_status_color(scans_.status[idx], ctx.theme);

            for (auto i = std::size_t{0}; i < line.size() && ctx.col0 + i < ctx.col_limit; ++i)
            {
                ctx.win.set_char(ctx.col0 + i, line_row, static_cast<char32_t>(line[i]));
                ctx.win.set_fg(ctx.col0 + i, line_row, color);
            }
        }
    }


    auto sidebar::width() const -> int
    {
        return collapsed_ ? 0 : width_;
    }

    auto sidebar::is_collapsed() const -> bool
    {
        return collapsed_;
    }


    void sidebar::toggle()
    {
        collapsed_ = !collapsed_;
    }


    auto sidebar::handle_key(const Term::Key &key) -> bool
    {
        if (key == Term::Key::ArrowLeft)
        {
            if (active_tab_ == tab::alerts) active_tab_ = tab::devices;
            else if (active_tab_ == tab::scans) active_tab_ = tab::alerts;
            return true;
        }
        if (key == Term::Key::ArrowRight)
        {
            if (active_tab_ == tab::devices) active_tab_ = tab::alerts;
            else if (active_tab_ == tab::alerts) active_tab_ = tab::scans;
            return true;
        }
        return false;
    }


} // namespace sec::tui::components
