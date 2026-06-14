/**
 * @file layout.hpp
 * @brief TUI 面板布局计算器
 */
#pragma once

#include <cstdint>

namespace sec::tui
{
    /**
     * @brief 侧栏可见性
     */
    enum class sidebar_state : std::uint8_t
    {
        /** @brief 展开 */
        visible,
        /** @brief 折叠 */
        hidden
    };

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

        static auto calculate(int term_rows, int term_cols, int sidebar_w, sidebar_state state) -> layout;
    };

} // namespace sec::tui
