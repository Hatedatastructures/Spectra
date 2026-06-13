/**
 * @file scan_panel.hpp
 * @brief 扫描历史面板组件
 */
#pragma once

#include <sec/tui/application.hpp>

#include <ftxui/component/component.hpp>

namespace sec::tui::components
{
    class scan_panel
    {
    public:
        explicit scan_panel(application &app);
        [[nodiscard]] auto render() -> ftxui::Component;

    private:
        application &app_;
    };
} // namespace sec::tui::components
