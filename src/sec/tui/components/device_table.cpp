// 设备表格实现 — 已发现设备列表

#include <sec/tui/components/device_table.hpp>

#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>

#include <string>


namespace sec::tui::components
{

    device_table::device_table(application &app)
        : app_{app}
    {
    }


    auto device_table::render() -> ftxui::Component
    {
        return ftxui::Renderer([this]()
        {
            auto ec = std::error_code{};
            auto devices = app_.device_query().find_all(ec);
            if (ec || devices.empty())
            {
                return ftxui::text("  No devices discovered yet") | ftxui::dim;
            }

            auto rows = std::vector<std::vector<std::string>>{};
            rows.push_back({"ID", "IP", "MAC", "Hostname", "Vendor"});
            for (const auto &dev : devices)
            {
                rows.push_back({
                    std::to_string(dev.id),
                    std::string{dev.ip_address},
                    std::string{dev.mac_address},
                    dev.hostname.empty() ? "-" : dev.hostname,
                    dev.vendor.empty() ? "-" : dev.vendor,
                });
            }

            auto tbl = ftxui::Table{rows};
            tbl.SelectAll().Border(ftxui::LIGHT);
            tbl.SelectRow(0).Decorate(ftxui::bold);
            tbl.SelectRow(0).SeparatorVertical(ftxui::LIGHT);
            tbl.SelectColumn(0).Decorate(ftxui::dim);

            return tbl.Render();
        });
    }


} // namespace sec::tui::components
