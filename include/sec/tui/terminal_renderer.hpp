/**
 * @file terminal_renderer.hpp
 * @brief 扁平化样式文档模型 + Term::Window 绘制器
 */
#pragma once

#include <cpp-terminal/color.hpp>
#include <cpp-terminal/window.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sec::tui
{
    struct styled_segment
    {
        std::string text;
        Term::Color fg{Term::Color(255, 255, 255)};
        Term::Color bg{Term::Color::Name::Default};
        bool bold{false};
        bool italic{false};
        bool dim{false};
        bool underline{false};
    };

    using styled_line = std::vector<styled_segment>;
    using styled_document = std::vector<styled_line>;

    /// UTF-8 解码：返回码点和消耗字节数
    [[nodiscard]] auto utf8_decode(std::string_view s, std::size_t pos) -> std::pair<char32_t, std::size_t>;

    /// 单个码点的显示宽度（CJK/emoji 宽字符返回 2，其余返回 1）
    [[nodiscard]] auto display_width_cp(char32_t cp) -> int;

    /// 判断码点是否零宽（ZWJ、VS1-16、skin tone、组合标记等）
    /// 注意：VS15/VS16 在 parse_grapheme_cluster 中单独处理（影响前字符宽度）
    [[nodiscard]] auto is_zero_width_cp(char32_t cp) -> bool;

    /// 图元簇信息：主字符 + 后续零宽修饰符构成的一个显示单元
    struct grapheme_cluster
    {
        int width{0};          ///< 簇的总显示宽度（已考虑 VS15/VS16 调整）
        std::size_t byte_len{0};///< 簇消耗的字节数
        char32_t first_cp{0};  ///< 簇首码点（用于绘制）
    };

    /// 解析从 pos 开始的一个图元簇
    /// 处理：VS16 提升前字符到 2 宽、VS15 降前字符到 1 宽、
    /// 跳过 ZWJ/skin tone/组合标记等零宽字符
    [[nodiscard]] auto parse_grapheme_cluster(std::string_view s, std::size_t pos) -> grapheme_cluster;

    /// 整个字符串的显示宽度（UTF-8 解码后逐字符累加）
    [[nodiscard]] auto display_width(std::string_view s) -> int;

    class terminal_renderer
    {
    public:
        static void paint(Term::Window &win, int start_row, int start_col,
                          int max_rows, int max_cols,
                          const styled_document &doc, int scroll_offset = 0);
    };

    /// 自动换行：将超长行拆分为多条 styled_line
    /// @param indent 续行前缀（如列表缩进、引用竖线），会加到每个换行后的行首
    auto wrap_document(const styled_document &doc, int max_cols,
                       std::string_view indent = {}) -> styled_document;

} // namespace sec::tui
