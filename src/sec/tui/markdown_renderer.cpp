// Markdown → styled_document 渲染器实现
// 对标 Claude Code TUI：box-drawing 边框、表格对齐、嵌套列表、竖线引用

#include <sec/tui/markdown_renderer.hpp>
#include <sec/tui/syntax_highlight.hpp>

#include <cmark-gfm.h>
#include <cmark-gfm-core-extensions.h>
#include <cmark-gfm-extension_api.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace sec::tui;

namespace
{
    auto is_block_type(cmark_node *node) -> bool
    {
        auto t = cmark_node_get_type(node);
        return (t & CMARK_NODE_TYPE_MASK) == CMARK_NODE_TYPE_BLOCK;
    }

    auto collect_all_text(cmark_node *node) -> std::string
    {
        if (!node) return {};
        auto type = cmark_node_get_type(node);
        if (type == CMARK_NODE_TEXT || type == CMARK_NODE_CODE || type == CMARK_NODE_HTML_INLINE)
        {
            auto lit = cmark_node_get_literal(node);
            return lit ? std::string{lit} : std::string{};
        }
        if (type == CMARK_NODE_SOFTBREAK) return " ";
        if (type == CMARK_NODE_LINEBREAK) return "\n";
        auto result = std::string{};
        auto child = cmark_node_first_child(node);
        while (child)
        {
            result += collect_all_text(child);
            child = cmark_node_next(child);
        }
        return result;
    }

    auto heading_color(int level, const theme_palette &th) -> Term::Color
    {
        switch (level)
        {
        case 1: return th.heading_h1;
        case 2: return th.heading_h2;
        case 3: return th.heading_h3;
        default: return th.heading_h4;
        }
    }

    // 重复 UTF-8 字符串 N 次（用于 box-drawing 字符）
    auto repeat_str(const char *s, int n) -> std::string
    {
        auto out = std::string{};
        out.reserve(std::strlen(s) * static_cast<std::size_t>(n));
        for (auto i = 0; i < n; ++i) out += s;
        return out;
    }

    auto split_lines(const styled_line &input) -> styled_document
    {
        auto result = styled_document{};
        auto current = styled_line{};

        for (const auto &seg : input)
        {
            auto pos = std::size_t{0};
            while (pos < seg.text.size())
            {
                auto nl = seg.text.find('\n', pos);
                if (nl == std::string::npos)
                {
                    auto remaining = seg.text.substr(pos);
                    auto s = seg;
                    s.text = remaining;
                    current.push_back(std::move(s));
                    break;
                }
                if (nl > pos)
                {
                    auto before = seg.text.substr(pos, nl - pos);
                    auto s = seg;
                    s.text = before;
                    current.push_back(std::move(s));
                }
                result.push_back(std::move(current));
                current = styled_line{};
                pos = nl + 1;
            }
        }

        if (!current.empty()) result.push_back(std::move(current));
        else if (input.empty()) result.push_back({});

        return result;
    }

    // 前向声明
    auto render_inline_node_impl(cmark_node *node, const theme_palette &th) -> styled_line;
    auto render_block_node_impl(cmark_node *node, const theme_palette &th, int depth, int max_cols) -> styled_document;

    auto render_inline_node_impl(cmark_node *node, const theme_palette &th) -> styled_line
    {
        if (!node) return {};

        auto type = cmark_node_get_type(node);

        switch (type)
        {
        case CMARK_NODE_TEXT:
        {
            auto lit = cmark_node_get_literal(node);
            return {styled_segment{lit ? lit : "", th.body_text}};
        }
        case CMARK_NODE_SOFTBREAK:
            return {styled_segment{" "}};
        case CMARK_NODE_LINEBREAK:
            return {styled_segment{"\n"}};
        case CMARK_NODE_CODE:
        {
            auto lit = cmark_node_get_literal(node);
            auto txt = lit ? std::string{lit} : std::string{};
            return {styled_segment{" " + txt + " ", th.code_text, th.background}};
        }
        case CMARK_NODE_EMPH:
        {
            auto result = styled_line{};
            auto child = cmark_node_first_child(node);
            while (child)
            {
                auto sub = render_inline_node_impl(child, th);
                for (auto &seg : sub)
                {
                    seg.italic = true;
                    seg.fg = th.emphasis;
                    result.push_back(std::move(seg));
                }
                child = cmark_node_next(child);
            }
            return result;
        }
        case CMARK_NODE_STRONG:
        {
            auto result = styled_line{};
            auto child = cmark_node_first_child(node);
            while (child)
            {
                auto sub = render_inline_node_impl(child, th);
                for (auto &seg : sub)
                {
                    seg.bold = true;
                    result.push_back(std::move(seg));
                }
                child = cmark_node_next(child);
            }
            return result;
        }
        case CMARK_NODE_LINK:
        {
            auto result = styled_line{};
            auto child = cmark_node_first_child(node);
            while (child)
            {
                auto sub = render_inline_node_impl(child, th);
                for (auto &seg : sub)
                {
                    seg.fg = th.info;
                    seg.underline = true;
                    result.push_back(std::move(seg));
                }
                child = cmark_node_next(child);
            }
            return result;
        }
        case CMARK_NODE_IMAGE:
        {
            auto alt = collect_all_text(cmark_node_first_child(node));
            return {styled_segment{"[img: " + alt + "]", th.raw_html}};
        }
        case CMARK_NODE_HTML_INLINE:
        {
            auto lit = cmark_node_get_literal(node);
            return {styled_segment{lit ? lit : "", th.raw_html}};
        }
        default:
        {
            auto result = styled_line{};
            auto child = cmark_node_first_child(node);
            while (child)
            {
                auto sub = render_inline_node_impl(child, th);
                for (auto &seg : sub) result.push_back(std::move(seg));
                child = cmark_node_next(child);
            }
            return result;
        }
        }
    }

    // 渲染父节点的子 block，相邻 block 之间插入一个空行作为视觉间隔。
    // 用于 document / list item / 任何容器 block 的 children。
    auto render_children_with_spacing(cmark_node *parent, const theme_palette &th, int depth, int max_cols) -> styled_document
    {
        auto result = styled_document{};
        auto child = cmark_node_first_child(parent);
        auto first = true;
        while (child)
        {
            if (is_block_type(child))
            {
                if (!first) result.push_back({});
                first = false;
                auto block = render_block_node_impl(child, th, depth, max_cols);
                for (auto &line : block) result.push_back(std::move(line));
            }
            child = cmark_node_next(child);
        }
        return result;
    }

    auto render_document(cmark_node *node, const theme_palette &th, int depth, int max_cols) -> styled_document
    {
        return render_children_with_spacing(node, th, depth, max_cols);
    }

    auto render_heading(cmark_node *node, const theme_palette &th) -> styled_document
    {
        auto level = cmark_node_get_heading_level(node);
        auto txt = collect_all_text(node);
        auto color = heading_color(level, th);
        auto w = display_width(txt);
        if (w < 1) w = 1;

        auto result = styled_document{};
        result.push_back({styled_segment{std::move(txt), color, Term::Color::Name::Default, true}});

        if (level <= 2)
        {
            result.push_back({styled_segment{std::string(w, '='), color, Term::Color::Name::Default, false, false, false, true}});
        }
        return result;
    }

    auto render_paragraph(cmark_node *node, const theme_palette &th) -> styled_document
    {
        auto combined = styled_line{};
        auto child = cmark_node_first_child(node);
        while (child)
        {
            auto sub = render_inline_node_impl(child, th);
            for (auto &seg : sub) combined.push_back(std::move(seg));
            child = cmark_node_next(child);
        }
        return split_lines(combined);
    }

    auto render_code_block(cmark_node *node, const theme_palette &th, int max_cols) -> styled_document
    {
        auto lit = cmark_node_get_literal(node);
        auto code = lit ? std::string{lit} : std::string{};
        while (!code.empty() && (code.back() == '\n' || code.back() == '\r')) code.pop_back();

        auto fence_info = cmark_node_get_fence_info(node);
        auto lang_raw = fence_info ? std::string{fence_info} : std::string{};
        auto lang = lang_raw;
        if (!lang.empty())
        {
            auto sp = lang.find(' ');
            if (sp != std::string::npos) lang = lang.substr(0, sp);
        }

        // 拆行 + 计算最大宽度
        auto lines = std::vector<std::string>{};
        {
            auto ss = std::istringstream{code};
            auto line = std::string{};
            while (std::getline(ss, line)) lines.push_back(std::move(line));
            if (lines.empty()) lines.emplace_back();
        }

        auto inner_w = 0;
        for (const auto &l : lines)
        {
            auto w = display_width(l);
            if (w > inner_w) inner_w = w;
        }
        inner_w = std::max(inner_w, 16);
        inner_w = std::min(inner_w, std::max(16, max_cols - 4));

        auto result = styled_document{};
        const auto &border = th.box_border;
        const auto &bg = th.background;

        auto pad_seg = [&](int count) -> styled_segment
        {
            return styled_segment{std::string(count, ' '), th.syn_punct, bg};
        };

        // 顶边: ╭─┤ lang ├─────╮ — 语言名用 accent 色高亮，提升辨识度
        if (!lang.empty())
        {
            auto lang_w = display_width(lang);
            auto label_w = 2 + 1 + lang_w + 1 + 1; // ─┤ + space + lang + space + ├
            auto fill = inner_w + 2 - (label_w - 2); // 减去 ─┤ ├ 占的 2 个 ─

            auto top = styled_line{};
            top.emplace_back(std::string{"╭"}, border, bg);
            top.emplace_back(std::string{"─┤ "}, border, bg);
            top.emplace_back(lang, th.accent, bg, true); // 语言名: 紫色加粗
            top.emplace_back(std::string{" ├"}, border, bg);
            if (fill > 0) top.emplace_back(repeat_str("\xe2\x94\x80", fill), border, bg);
            top.emplace_back(std::string{"╮"}, border, bg);
            result.push_back(std::move(top));
        }
        else
        {
            auto top = styled_line{};
            top.emplace_back(std::string{"╭"}, border, bg);
            top.emplace_back(repeat_str("\xe2\x94\x80", inner_w + 2), border, bg);
            top.emplace_back(std::string{"╮"}, border, bg);
            result.push_back(std::move(top));
        }

        // 内容行: │ <highlighted> <pad> │
        for (const auto &l : lines)
        {
            auto line_segs = styled_line{};
            line_segs.emplace_back(std::string{"│ "}, border, bg);

            auto highlighted = highlight_line(l, lang, th);
            auto content_w = 0;
            for (auto &hs : highlighted)
            {
                hs.bg = bg;
                content_w += display_width(hs.text);
                line_segs.push_back(std::move(hs));
            }

            if (content_w < inner_w)
            {
                line_segs.push_back(pad_seg(inner_w - content_w));
            }

            line_segs.emplace_back(std::string{" │"}, border, bg);
            result.push_back(std::move(line_segs));
        }

        // 底边: ╰─────╯
        {
            auto bot = styled_line{};
            bot.emplace_back(std::string{"╰"}, border, bg);
            bot.emplace_back(repeat_str("\xe2\x94\x80", inner_w + 2), border, bg);
            bot.emplace_back(std::string{"╯"}, border, bg);
            result.push_back(std::move(bot));
        }

        return result;
    }

    auto render_block_quote(cmark_node *node, const theme_palette &th, int depth, int max_cols) -> styled_document
    {
        auto prefix = std::string{};
        for (auto d = 0; d <= depth; ++d) prefix += "│ ";

        // 引用块内的子 block 之间保留视觉间隔
        auto inner = render_children_with_spacing(node, th, depth + 1, max_cols);

        auto result = styled_document{};
        for (auto &line : inner)
        {
            auto prefixed = styled_line{};
            prefixed.emplace_back(prefix, th.quote_bar);
            for (auto &seg : line) prefixed.push_back(std::move(seg));
            result.push_back(std::move(prefixed));
        }
        return result;
    }

    auto render_list(cmark_node *node, const theme_palette &th, int depth, int max_cols) -> styled_document
    {
        auto result = styled_document{};
        auto is_ordered = cmark_node_get_list_type(node) == CMARK_ORDERED_LIST;
        auto start = cmark_node_get_list_start(node);
        auto idx = start > 0 ? start : 1;

        auto indent_str = std::string(depth * 2, ' ');

        auto child = cmark_node_first_child(node);
        while (child)
        {
            std::string marker;
            if (is_ordered)
            {
                marker = std::to_string(idx) + ". ";
                if (marker.size() < 3) marker += std::string(3 - marker.size(), ' ');
            }
            else
            {
                switch (depth % 3)
                {
                case 0: marker = "• "; break;
                case 1: marker = "◦ "; break;
                default: marker = "⁃ "; break;
                }
            }

            // item 内的多个 block 之间也保留视觉间隔
            auto item_lines = render_children_with_spacing(child, th, depth, max_cols);

            if (!item_lines.empty())
            {
                // 第一行: indent + marker
                auto &first = item_lines[0];
                if (!indent_str.empty())
                {
                    first.insert(first.begin(), styled_segment{indent_str, th.dim_text});
                }
                first.insert(first.begin(), styled_segment{marker, is_ordered ? th.accent : th.emphasis, Term::Color::Name::Default, true});
            }

            for (auto &line : item_lines) result.push_back(std::move(line));
            ++idx;
            child = cmark_node_next(child);
        }
        return result;
    }

    auto is_numeric(const std::string &s) -> bool
    {
        if (s.empty()) return false;
        auto start = std::size_t{0};
        if (s[0] == '+' || s[0] == '-') start = 1;
        if (start >= s.size()) return false;
        auto has_digit = false;
        auto has_dot = false;
        for (auto i = start; i < s.size(); ++i)
        {
            if (std::isdigit(static_cast<unsigned char>(s[i]))) has_digit = true;
            else if (s[i] == '.' && !has_dot) has_dot = true;
            else return false;
        }
        return has_digit;
    }

    auto render_table(cmark_node *node, const theme_palette &th) -> styled_document
    {
        // Pass 1: 收集每行每 cell 的纯文本
        auto rows = std::vector<std::vector<std::string>>{};
        auto child = cmark_node_first_child(node);
        while (child)
        {
            auto type_str = cmark_node_get_type_string(child);
            if (type_str && (std::strcmp(type_str, "table_row") == 0 ||
                             std::strcmp(type_str, "table_header") == 0))
            {
                auto row = std::vector<std::string>{};
                auto cell = cmark_node_first_child(child);
                while (cell)
                {
                    row.push_back(collect_all_text(cell));
                    cell = cmark_node_next(cell);
                }
                rows.push_back(std::move(row));
            }
            child = cmark_node_next(child);
        }

        if (rows.empty()) return {};

        auto n_cols = std::size_t{0};
        for (const auto &r : rows) n_cols = std::max(n_cols, r.size());
        if (n_cols == 0) return {};

        // Pass 2: 计算每列最大宽度
        auto col_w = std::vector<int>(n_cols, 0);
        for (const auto &r : rows)
        {
            for (auto c = std::size_t{0}; c < r.size() && c < n_cols; ++c)
            {
                auto w = display_width(r[c]);
                if (w > col_w[c]) col_w[c] = w;
            }
        }

        auto result = styled_document{};
        const auto &border = th.box_border;

        auto hline = [&](const std::string &left, const std::string &mid, const std::string &right) -> styled_line
        {
            auto line = styled_line{};
            line.emplace_back(left, border);
            for (auto c = std::size_t{0}; c < n_cols; ++c)
            {
                if (c > 0) line.emplace_back(mid, border);
                line.emplace_back(repeat_str("\xe2\x94\x80", col_w[c] + 2), border);
            }
            line.emplace_back(right, border);
            return line;
        };

        // 顶边 ┌─┬─┐
        result.push_back(hline("┌", "┬", "┐"));

        for (auto r = std::size_t{0}; r < rows.size(); ++r)
        {
            auto line = styled_line{};
            line.emplace_back(std::string{"│"}, border);
            for (auto c = std::size_t{0}; c < n_cols; ++c)
            {
                auto text = (c < rows[r].size()) ? rows[r][c] : std::string{};
                auto w = display_width(text);
                auto pad = col_w[c] - w;

                line.emplace_back(std::string{" "}, border);

                auto seg = styled_segment{};
                seg.text = text;
                seg.fg = (r == 0) ? th.header_text : th.body_text;
                seg.bold = (r == 0);
                if (r == 0) seg.fg = th.heading_h3;

                // 数字右对齐，其余左对齐
                if (is_numeric(text))
                {
                    if (pad > 0) line.emplace_back(std::string(pad, ' '), border);
                    line.push_back(std::move(seg));
                }
                else
                {
                    line.push_back(std::move(seg));
                    if (pad > 0) line.emplace_back(std::string(pad, ' '), border);
                }

                line.emplace_back(std::string{" "}, border);
                line.emplace_back(std::string{"│"}, border);
            }
            result.push_back(std::move(line));

            // 表头后加分隔线
            if (r == 0 && rows.size() > 1)
            {
                result.push_back(hline("├", "┼", "┤"));
            }
        }

        // 底边 └─┴─┘
        result.push_back(hline("└", "┴", "┘"));

        return result;
    }

    auto render_fallback_children(cmark_node *node, const theme_palette &th, int depth, int max_cols) -> styled_document
    {
        return render_children_with_spacing(node, th, depth, max_cols);
    }

    auto render_block_node_impl(cmark_node *node, const theme_palette &th, int depth, int max_cols) -> styled_document
    {
        if (!node) return {{}};

        auto type = cmark_node_get_type(node);

        switch (type)
        {
        case CMARK_NODE_DOCUMENT:       return render_document(node, th, depth, max_cols);
        case CMARK_NODE_HEADING:        return render_heading(node, th);
        case CMARK_NODE_PARAGRAPH:      return render_paragraph(node, th);
        case CMARK_NODE_CODE_BLOCK:     return render_code_block(node, th, max_cols);
        case CMARK_NODE_BLOCK_QUOTE:    return render_block_quote(node, th, depth, max_cols);
        case CMARK_NODE_LIST:           return render_list(node, th, depth, max_cols);
        case CMARK_NODE_ITEM:           return render_block_node_impl(cmark_node_first_child(node), th, depth, max_cols);
        case CMARK_NODE_THEMATIC_BREAK:
        {
            auto w = std::max(20, std::min(max_cols - 4, 60));
            return {{styled_segment{repeat_str("\xe2\x94\x80", w), th.dim_text}}};
        }
        case CMARK_NODE_HTML_BLOCK:
        {
            auto lit = cmark_node_get_literal(node);
            return {{styled_segment{lit ? lit : "", th.raw_html}}};
        }
        default:
        {
            auto type_str = cmark_node_get_type_string(node);
            if (type_str && std::strcmp(type_str, "table") == 0)
                return render_table(node, th);
            if (type_str && std::strcmp(type_str, "table_row") == 0)
                return render_fallback_children(node, th, depth, max_cols);
            if (type_str && std::strcmp(type_str, "table_cell") == 0)
                return {{styled_segment{collect_all_text(node), th.body_text}}};
            return render_fallback_children(node, th, depth, max_cols);
        }
        }
    }

} // anonymous namespace


namespace sec::tui
{

    auto markdown_renderer::render(std::string_view markdown, const theme_palette &theme, int max_cols) -> styled_document
    {
        if (markdown.empty()) return {{}};

        cmark_gfm_core_extensions_ensure_registered();

        auto parser = cmark_parser_new(CMARK_OPT_DEFAULT);
        auto table_ext = cmark_find_syntax_extension("table");
        if (table_ext) cmark_parser_attach_syntax_extension(parser, table_ext);
        auto strikethrough_ext = cmark_find_syntax_extension("strikethrough");
        if (strikethrough_ext) cmark_parser_attach_syntax_extension(parser, strikethrough_ext);
        auto tasklist_ext = cmark_find_syntax_extension("tasklist");
        if (tasklist_ext) cmark_parser_attach_syntax_extension(parser, tasklist_ext);

        cmark_parser_feed(parser, markdown.data(), markdown.size());
        auto doc = cmark_parser_finish(parser);
        auto result = render_block_node_impl(doc, theme, 0, max_cols);

        cmark_node_free(doc);
        cmark_parser_free(parser);

        return result;
    }

} // namespace sec::tui
