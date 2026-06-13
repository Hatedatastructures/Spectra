/**
 * @file alert_list.hpp
 * @brief 告警列表组件
 */
#pragma once

#include <sec/tui/application.hpp>

#include <ftxui/component/component.hpp>

namespace sec::tui::components
{
    class alert_list
    {
    public:
        explicit alert_list(application &app);
        [[nodiscard]] auto render() -> ftxui::Component;

    private:
        application &app_;
    };
} // namespace sec::tui::components
