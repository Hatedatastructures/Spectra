/**
 * @file syntax_highlight.hpp
 * @brief 简易语法高亮 — 单遍状态机分词，零外部依赖
 * @details 支持 cpp/c、python、bash、js/ts、rust、go 的基础关键字、
 * 字符串、注释、数字着色。未知语言回退到单段默认色。
 */
#pragma once

#include <sec/tui/terminal_renderer.hpp>
#include <sec/tui/theme.hpp>

#include <string>
#include <string_view>

namespace sec::tui
{
    /**
     * @brief 高亮单行代码
     * @param line 代码文本（不含换行符）
     * @param lang 语言标识（cpp/python/bash/js/rust/go 等，小写）
     * @param th 主题调色板
     * @return 着色后的 styled_line
     */
    [[nodiscard]] auto highlight_line(std::string_view line,
                                      std::string_view lang,
                                      const theme_palette &th) -> styled_line;

} // namespace sec::tui
