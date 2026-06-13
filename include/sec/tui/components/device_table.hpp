/**
 * @file device_table.hpp
 * @brief 设备表格组件
 * @details 在侧边栏设备标签页中显示已发现设备列表。
 */
#pragma once

#include <sec/tui/application.hpp>

#include <ftxui/component/component.hpp>

namespace sec::tui::components
{
    class device_table
    {
    public:
        explicit device_table(application &app);
        [[nodiscard]] auto render() -> ftxui::Component;

    private:
        application &app_;
    };
} // namespace sec::tui::components
