/**
 * @file markdown_renderer.hpp
 * @brief Markdown → styled_document 渲染器
 * @details 使用 cmark-gfm 解析 Markdown 为 AST，
 * 然后遍历 AST 节点生成带样式的 styled_document（扁平文本模型）。
 */
#pragma once

#include <sec/tui/terminal_renderer.hpp>
#include <sec/tui/theme.hpp>

#include <string>
#include <string_view>

namespace sec::tui
{
    /**
     * @brief Markdown → styled_document 渲染器
     */
    class markdown_renderer
    {
    public:
        /**
         * @brief 将 Markdown 文本渲染为 styled_document
         * @param markdown 输入的 Markdown 文本
         * @param theme 当前主题调色板
         * @param max_cols 可用宽度（用于代码块/表格宽度约束），默认 80
         * @return 可显示的 styled_document
         */
        [[nodiscard]] static auto render(std::string_view markdown, const theme_palette &theme,
                                         int max_cols = 80) -> styled_document;
    };

} // namespace sec::tui
