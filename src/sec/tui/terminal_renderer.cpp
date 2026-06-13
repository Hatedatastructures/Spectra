// 扁平化样式文档绘制器（1-based 坐标，带边界保护，支持 UTF-8 宽字符）

#include <sec/tui/terminal_renderer.hpp>

#include <cpp-terminal/style.hpp>

namespace sec::tui
{

    auto utf8_decode(std::string_view s, std::size_t pos) -> std::pair<char32_t, std::size_t>
    {
        if (pos >= s.size()) return {0, 0};
        auto byte = static_cast<unsigned char>(s[pos]);
        char32_t cp = 0;
        std::size_t len;
        if (byte <= 0x7F) { cp = byte; len = 1; }
        else if ((byte & 0xE0) == 0xC0) { cp = static_cast<char32_t>(byte & 0x1F); len = 2; }
        else if ((byte & 0xF0) == 0xE0) { cp = static_cast<char32_t>(byte & 0x0F); len = 3; }
        else if ((byte & 0xF8) == 0xF0) { cp = static_cast<char32_t>(byte & 0x07); len = 4; }
        else { cp = byte; len = 1; }

        for (std::size_t i = 1; i < len && pos + i < s.size(); ++i)
        {
            cp = (cp << 6) | static_cast<char32_t>(static_cast<unsigned char>(s[pos + i]) & 0x3F);
        }
        return {cp, len};
    }


    auto display_width_cp(char32_t cp) -> int
    {
        if (cp >= 0x1100 && (
            (cp <= 0x115F) ||
            (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
            (cp >= 0xAC00 && cp <= 0xD7A3) ||
            (cp >= 0xF900 && cp <= 0xFAFF) ||
            (cp >= 0xFE10 && cp <= 0xFE19) ||
            (cp >= 0xFE30 && cp <= 0xFE6F) ||
            (cp >= 0xFF01 && cp <= 0xFF60) ||
            (cp >= 0xFFE0 && cp <= 0xFFE6) ||
            (cp >= 0x1F300 && cp <= 0x1F9FF)))
        {
            return 2;
        }
        return 1;
    }


    auto display_width(std::string_view s) -> int
    {
        auto w = 0;
        auto pos = std::size_t{0};
        while (pos < s.size())
        {
            auto gc = parse_grapheme_cluster(s, pos);
            if (gc.byte_len == 0) break;
            w += gc.width;
            pos += gc.byte_len;
        }
        return w;
    }


    auto is_zero_width_cp(char32_t cp) -> bool
    {
        // ZWJ（零宽连接符）— 用于 emoji 序列
        if (cp == 0x200D) return true;
        // VS1-VS16（变体选择符）— VS15/VS16 由 cluster 单独处理
        if (cp >= 0xFE00 && cp <= 0xFE0F) return true;
        // VS17-VS32（补充变体选择符）
        if (cp >= 0xE0100 && cp <= 0xE01EF) return true;
        // skin tone 修饰符（用于 emoji 肤色）
        if (cp >= 0x1F3FB && cp <= 0x1F3FF) return true;
        // 组合附加符号
        if (cp >= 0x0300 && cp <= 0x036F) return true;
        // 零宽空格、不可见字符
        if (cp == 0x200B || cp == 0x200C || cp == 0x200E || cp == 0x200F) return true;
        // 双向控制字符
        if (cp >= 0x202A && cp <= 0x202E) return true;
        // 通用不可见字符
        if (cp >= 0x2060 && cp <= 0x206F) return true;
        // BOM
        if (cp == 0xFEFF) return true;
        return false;
    }


    auto parse_grapheme_cluster(std::string_view s, std::size_t pos) -> grapheme_cluster
    {
        auto [cp, len] = utf8_decode(s, pos);
        if (cp == 0 || len == 0) return {};

        auto gc = grapheme_cluster{};
        gc.first_cp = cp;
        gc.byte_len = len;
        gc.width = display_width_cp(cp);

        auto cur = pos + len;

        // VS16（U+FE0F）提升前字符到 2 宽；VS15（U+FE0E）降到 1 宽
        if (cur < s.size())
        {
            auto [cp2, len2] = utf8_decode(s, cur);
            if (cp2 == 0xFE0F && gc.width < 2)
            {
                gc.width = 2;
                gc.byte_len += len2;
                cur += len2;
            }
            else if (cp2 == 0xFE0E && gc.width > 1)
            {
                gc.width = 1;
                gc.byte_len += len2;
                cur += len2;
            }
        }

        // 跳过后续零宽字符（ZWJ、skin tone、组合标记等）
        // 这些字符视觉上 0 宽，但会作为 cluster 一部分被消费
        while (cur < s.size())
        {
            auto [cp_n, len_n] = utf8_decode(s, cur);
            if (cp_n == 0 || len_n == 0) break;
            if (is_zero_width_cp(cp_n))
            {
                gc.byte_len += len_n;
                cur += len_n;
            }
            else
            {
                break;
            }
        }

        return gc;
    }


    namespace
    {
        // Term::Window 每个 cell 只存一个 Style，按优先级折叠
        void apply_style_mask(Term::Window &win, std::size_t col, std::size_t row, const styled_segment &seg)
        {
            if (seg.bold) { win.set_style(col, row, Term::Style::Bold); return; }
            if (seg.italic) { win.set_style(col, row, Term::Style::Italic); return; }
            if (seg.underline) { win.set_style(col, row, Term::Style::Underline); return; }
            if (seg.dim) { win.set_style(col, row, Term::Style::Dim); return; }
        }

        void paint_cell(Term::Window &win, std::size_t col, std::size_t row,
                        char32_t cp, const styled_segment &seg)
        {
            win.set_char(col, row, cp);
            win.set_fg(col, row, seg.fg);
            if (seg.bg != Term::Color::Name::Default)
            {
                win.set_bg(col, row, seg.bg);
            }
            apply_style_mask(win, col, row, seg);
        }
    }


    void terminal_renderer::paint(Term::Window &win, int start_row, int start_col,
                                  int max_rows, int max_cols,
                                  const styled_document &doc, int scroll_offset)
    {
        if (max_rows <= 0 || max_cols <= 0) return;

        auto win_rows = static_cast<int>(win.rows());
        auto win_cols = static_cast<int>(win.columns());

        auto visible_lines = max_rows;
        auto doc_size = static_cast<int>(doc.size());
        auto start_line = std::max(0, scroll_offset);
        auto end_line = std::min(start_line + visible_lines, doc_size);

        for (auto line_idx = start_line; line_idx < end_line; ++line_idx)
        {
            auto screen_row = start_row + (line_idx - start_line);

            if (screen_row < 1 || screen_row > win_rows) continue;

            auto col = start_col;
            auto col_limit = start_col + max_cols;

            for (const auto &seg : doc[static_cast<std::size_t>(line_idx)])
            {
                if (col >= col_limit) break;

                auto byte_pos = std::size_t{0};
                while (byte_pos < seg.text.size() && col < col_limit)
                {
                    auto gc = parse_grapheme_cluster(seg.text, byte_pos);
                    if (gc.byte_len == 0) break;

                    auto wide = gc.width == 2;
                    if (wide && col + 1 >= col_limit) break;

                    if (col >= 1 && col <= win_cols)
                    {
                        auto c = static_cast<std::size_t>(col);
                        auto r = static_cast<std::size_t>(screen_row);

                        paint_cell(win, c, r, gc.first_cp, seg);

                        // 宽字符第二 cell：传播 fg/bg/style，消除背景缝隙
                        if (wide && col + 1 <= win_cols)
                        {
                            paint_cell(win, static_cast<std::size_t>(col + 1), r, U' ', seg);
                        }
                    }

                    col += gc.width;
                    byte_pos += gc.byte_len;
                }
            }
        }
    }


    auto wrap_document(const styled_document &doc, int max_cols, std::string_view indent) -> styled_document
    {
        if (max_cols <= 0) return doc;

        auto indent_w = display_width(indent);

        auto result = styled_document{};
        result.reserve(doc.size());

        for (const auto &line : doc)
        {
            auto current_col = 0;
            auto current_line = styled_line{};
            auto first_chunk = true;

            auto ensure_indent = [&]()
            {
                if (!first_chunk && indent_w > 0)
                {
                    auto ind_seg = styled_segment{};
                    ind_seg.text = std::string{indent};
                    ind_seg.fg = Term::Color{120, 120, 120};
                    current_line.push_back(std::move(ind_seg));
                    current_col += indent_w;
                }
                first_chunk = false;
            };

            ensure_indent();

            for (const auto &seg : line)
            {
                auto byte_pos = std::size_t{0};
                while (byte_pos < seg.text.size())
                {
                    auto gc = parse_grapheme_cluster(seg.text, byte_pos);
                    if (gc.byte_len == 0) break;

                    auto char_width = gc.width;
                    auto remaining = max_cols - current_col;

                    if (remaining < char_width)
                    {
                        if (!current_line.empty())
                        {
                            result.push_back(std::move(current_line));
                            current_line = styled_line{};
                        }
                        current_col = 0;
                        ensure_indent();
                    }

                    auto chunk = seg.text.substr(byte_pos, gc.byte_len);
                    auto wrapped_seg = seg;
                    wrapped_seg.text = chunk;
                    current_line.push_back(std::move(wrapped_seg));
                    current_col += char_width;
                    byte_pos += gc.byte_len;
                }
            }

            if (!current_line.empty())
            {
                result.push_back(std::move(current_line));
            }
            else if (line.empty())
            {
                result.push_back({});
            }
        }

        return result;
    }

} // namespace sec::tui
