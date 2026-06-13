// 流量视图实现 — 最近流量日志

#include <sec/tui/components/traffic_view.hpp>

#include <ftxui/dom/elements.hpp>

#include <chrono>
#include <string>


namespace sec::tui::components
{

    traffic_view::traffic_view(application &app)
        : app_{app}
    {
    }


    auto traffic_view::render() -> ftxui::Component
    {
        return ftxui::Renderer([this]()
        {
            auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            auto ec = std::error_code{};
            auto logs = app_.traffic_query().find_by_time_range(now_epoch - 3600, 0, ec);
            if (ec || logs.empty())
            {
                return ftxui::text("  No traffic in the last hour") | ftxui::dim;
            }

            auto rows = std::vector<ftxui::Element>{};
            rows.push_back(ftxui::hbox({
                ftxui::text(" ID  ") | ftxui::bold,
                ftxui::text("Source                ") | ftxui::bold,
                ftxui::text("Destination           ") | ftxui::bold,
                ftxui::text("Proto ") | ftxui::bold,
                ftxui::text("Size") | ftxui::bold | ftxui::flex,
            }));

            for (const auto &log : logs)
            {
                auto src = std::string{log.src_ip} + ":" + std::to_string(log.src_port);
                auto dst = std::string{log.dst_ip} + ":" + std::to_string(log.dst_port);
                if (src.size() < 21) src += std::string(21 - src.size(), ' ');
                if (dst.size() < 21) dst += std::string(21 - dst.size(), ' ');

                rows.push_back(ftxui::hbox({
                    ftxui::text(" " + std::to_string(log.id) + "  ") | ftxui::dim,
                    ftxui::text(src),
                    ftxui::text(dst),
                    ftxui::text(std::to_string(static_cast<int>(log.protocol)) + "    "),
                    ftxui::text(std::to_string(log.packet_size)) | ftxui::flex,
                }));
            }

            return ftxui::vbox(std::move(rows));
        });
    }


} // namespace sec::tui::components
