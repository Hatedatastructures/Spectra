/**
 * @file theme.hpp
 * @brief TUI 主题系统
 * @details 提供 dark/light/auto 三档主题切换，所有组件共享同一调色板。
 */
#pragma once

#include <cpp-terminal/color.hpp>

#include <cstdint>

namespace sec::tui
{

    enum class theme_mode : std::uint8_t
    {
        dark,
        light,
        auto_detect
    };

    struct theme_palette
    {
        // 主色：One Dark Pro 经典色板
        Term::Color success{152, 195, 121};   // #98C379 绿
        Term::Color info{97, 175, 239};       // #61AFEF 蓝
        Term::Color error{224, 108, 117};     // #E06C75 红
        Term::Color accent{198, 120, 221};    // #C678DD 紫
        Term::Color warning{229, 192, 123};   // #E5C07B 黄
        Term::Color high_severity{209, 154, 102}; // #D19A66 橙

        // 中性色
        Term::Color dim_text{92, 99, 112};    // #5C6370 注释灰
        Term::Color border{92, 99, 112};
        Term::Color placeholder{92, 99, 112};
        Term::Color body_text{171, 178, 191}; // #ABB2BF 默认文本
        Term::Color header_text{220, 224, 232}; // 高亮文本
        Term::Color secondary_text{150, 156, 168};

        Term::Color background{40, 44, 52};   // #282C34 背景
        Term::Color active_tab_bg{60, 70, 80};

        Term::Color cursor_fg{40, 44, 52};
        Term::Color cursor_bg{220, 224, 232};

        Term::Color emphasis{198, 120, 221};  // 紫
        Term::Color raw_html{86, 182, 194};   // #56B6C2 青
        Term::Color code_text{171, 178, 191};

        // 标题色：层级用色相区分，饱和度统一
        Term::Color heading_h1{97, 175, 239};   // 蓝（h1 最稳重）
        Term::Color heading_h2{152, 195, 121};  // 绿
        Term::Color heading_h3{229, 192, 123};  // 黄
        Term::Color heading_h4{198, 120, 221};  // 紫

        Term::Color streaming_cursor{97, 175, 239};

        // 语法高亮：One Dark Pro 风格
        Term::Color syn_keyword{198, 120, 221};    // 紫（关键字最有辨识度）
        Term::Color syn_string{152, 195, 121};     // 绿
        Term::Color syn_comment{92, 99, 112};      // 灰
        Term::Color syn_number{209, 154, 102};     // 橙
        Term::Color syn_function{97, 175, 239};    // 蓝
        Term::Color syn_operator{171, 178, 191};   // 默认文本色
        Term::Color syn_punct{171, 178, 191};

        // 边框/引用：柔和灰，避免抢眼
        Term::Color box_border{92, 99, 112};
        Term::Color quote_bar{92, 99, 112};
    };

    [[nodiscard]] auto make_dark_theme() -> theme_palette;
    [[nodiscard]] auto make_light_theme() -> theme_palette;
    [[nodiscard]] auto detect_terminal_background() -> bool;
    [[nodiscard]] auto resolve_theme(theme_mode mode) -> theme_palette;
    auto theme_mode_name(theme_mode mode) -> const char *;

} // namespace sec::tui
