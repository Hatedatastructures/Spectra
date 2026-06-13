/**
 * @file layout.hpp
 * @brief TUI 面板布局计算器
 */
#pragma once

namespace sec::tui
{
    struct panel_rect
    {
        int row{0};
        int col{0};
        int rows{0};
        int cols{0};
    };

    struct layout
    {
        panel_rect sidebar;
        panel_rect chat;
        panel_rect input_area;
        panel_rect status;
        int sidebar_width{20};
        bool sidebar_visible{true};

        static auto calculate(int term_rows, int term_cols, int sidebar_w, bool sidebar_vis) -> layout;
    };

} // namespace sec::tui
