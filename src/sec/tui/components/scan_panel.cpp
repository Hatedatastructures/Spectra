// 扫描面板实现 — 最近扫描记录

#include <sec/tui/components/scan_panel.hpp>

#include <ftxui/dom/elements.hpp>
#include <sec/util/format.hpp>

#include <string>


namespace sec::tui::components
{

    scan_panel::scan_panel(application &app)
        : app_{app}
    {
    }


    auto scan_panel::render() -> ftxui::Component
    {
        return ftxui::Renderer([this]()
        {
            auto ec = std::error_code{};
            auto scans = app_.scan_query().find_recent(20, ec);
            if (ec || scans.empty())
            {
                return ftxui::text("  No scan history") | ftxui::dim;
            }

            auto rows = std::vector<ftxui::Element>{};
            rows.push_back(ftxui::hbox({
                ftxui::text(" ID  ") | ftxui::bold,
                ftxui::text("Type    ") | ftxui::bold,
                ftxui::text("Devs ") | ftxui::bold,
                ftxui::text("Status    ") | ftxui::bold,
                ftxui::text("Time") | ftxui::bold | ftxui::flex,
            }));

            for (const auto &scan : scans)
            {
                auto color = ftxui::Color{80, 250, 123};
                if (scan.status == "running") color = ftxui::Color{241, 250, 140};
                else if (scan.status == "failed") color = ftxui::Color{255, 121, 198};

                rows.push_back(ftxui::hbox({
                    ftxui::text(" " + std::to_string(scan.id) + "  ") | ftxui::dim,
                    ftxui::text(scan.scan_type + (scan.scan_type.size() < 7 ? std::string(7 - scan.scan_type.size(), ' ') : " ")),
                    ftxui::text(std::to_string(scan.device_count) + "    "),
                    ftxui::text(scan.status + (scan.status.size() < 9 ? std::string(9 - scan.status.size(), ' ') : " ")) | ftxui::color(color),
                    ftxui::text(util::format_time(scan.started_at)) | ftxui::flex,
                }));
            }

            return ftxui::vbox(std::move(rows));
        });
    }


} // namespace sec::tui::components
