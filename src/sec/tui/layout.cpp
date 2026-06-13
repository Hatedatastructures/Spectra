// TUI 面板布局计算（1-based 坐标，匹配 Term::Window）

#include <sec/tui/layout.hpp>

#include <algorithm>

namespace sec::tui
{

    auto layout::calculate(int term_rows, int term_cols, int sidebar_w, bool sidebar_vis) -> layout
    {
        auto rows = std::max(term_rows, 10);
        auto cols = std::max(term_cols, 20);

        auto lo = layout{};
        lo.sidebar_visible = sidebar_vis;
        lo.sidebar_width = sidebar_vis ? sidebar_w : 0;

        auto sw = lo.sidebar_width;

        // Term::Window 使用 1-based 坐标：row∈[1,rows], col∈[1,cols]
        // sidebar 占 col[1,sw]，分隔线在 col=sw+1，chat 从 col=sw+2 开始
        // 无 sidebar 时所有从 col=1 开始

        if (sw > 0)
        {
            // sidebar: col [1, sw]，行 [1, rows-4]
            lo.sidebar.row = 1;
            lo.sidebar.col = 1;
            lo.sidebar.rows = rows - 4;
            lo.sidebar.cols = sw;

            // chat: col [sw+2, cols]，行 [1, rows-4]
            auto chat_col = sw + 2;
            lo.chat.row = 1;
            lo.chat.col = chat_col;
            lo.chat.rows = rows - 4;
            lo.chat.cols = std::max(1, cols - sw - 1);
        }
        else
        {
            lo.sidebar.row = 1;
            lo.sidebar.col = 1;
            lo.sidebar.rows = 0;
            lo.sidebar.cols = 0;

            lo.chat.row = 1;
            lo.chat.col = 1;
            lo.chat.rows = rows - 4;
            lo.chat.cols = cols;
        }

        // input: 底部 3 行区域（分隔线 + 输入行 + 空），chat 列范围
        lo.input_area.row = rows - 3;
        lo.input_area.col = lo.chat.col;
        lo.input_area.rows = 3;
        lo.input_area.cols = lo.chat.cols;

        // status: 最底 1 行，全宽
        lo.status.row = rows;
        lo.status.col = 1;
        lo.status.rows = 1;
        lo.status.cols = cols;

        return lo;
    }

} // namespace sec::tui
