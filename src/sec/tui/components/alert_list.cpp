// 告警列表实现 — 未确认告警按严重程度着色

#include <sec/tui/components/alert_list.hpp>

#include <ftxui/dom/elements.hpp>

#include <string>


namespace sec::tui::components
{

    alert_list::alert_list(application &app)
        : app_{app}
    {
    }


    auto alert_list::render() -> ftxui::Component
    {
        return ftxui::Renderer([this]()
        {
            auto ec = std::error_code{};
            auto alerts = app_.alert_query().find_unacknowledged(ec);
            if (ec || alerts.empty())
            {
                return ftxui::text("  No unacknowledged alerts") | ftxui::dim;
            }

            auto rows = std::vector<ftxui::Element>{};
            rows.push_back(ftxui::hbox({
                ftxui::text(" ID  ") | ftxui::bold,
                ftxui::text("Severity  ") | ftxui::bold,
                ftxui::text("Category       ") | ftxui::bold,
                ftxui::text("Description") | ftxui::bold | ftxui::flex,
            }));

            for (const auto &alert : alerts)
            {
                auto color = ftxui::Color{80, 250, 123};
                if (alert.severity == "critical") color = ftxui::Color{255, 121, 198};
                else if (alert.severity == "high") color = ftxui::Color{255, 140, 48};
                else if (alert.severity == "medium") color = ftxui::Color{241, 250, 140};

                rows.push_back(ftxui::hbox({
                    ftxui::text(" " + std::to_string(alert.id) + "  ") | ftxui::dim,
                    ftxui::text(alert.severity + (alert.severity.size() < 8 ? std::string(8 - alert.severity.size(), ' ') : " ")) | ftxui::color(color),
                    ftxui::text(alert.category + (alert.category.size() < 15 ? std::string(15 - alert.category.size(), ' ') : " ")),
                    ftxui::text(alert.description) | ftxui::flex,
                }));
            }

            return ftxui::vbox(std::move(rows));
        });
    }


} // namespace sec::tui::components
