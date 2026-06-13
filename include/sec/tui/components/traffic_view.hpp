/**
 * @file traffic_view.hpp
 * @brief 流量查看面板组件
 */
#pragma once

#include <sec/tui/application.hpp>

#include <ftxui/component/component.hpp>

namespace sec::tui::components
{
    class traffic_view
    {
    public:
        explicit traffic_view(application &app);
        [[nodiscard]] auto render() -> ftxui::Component;

    private:
        application &app_;
    };
} // namespace sec::tui::components
