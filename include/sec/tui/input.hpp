/**
 * @file input.hpp
 * @brief 文本输入状态机，替代 ftxui::Input()
 */
#pragma once

#include <functional>
#include <string>
#include <vector>

// 前向声明，避免暴露 cpp-terminal 头文件
namespace Term
{
    class Key;
}

namespace sec::tui
{
    class text_input
    {
    public:
        auto handle_key(const Term::Key &key) -> bool;
        auto text() const -> const std::string &;
        auto cursor_pos() const -> int;
        void clear();
        void set_text(std::string t);

        using completer_fn = std::function<std::vector<std::string>(std::string_view)>;
        void set_completer(completer_fn fn);

        /// 插入一个 UTF-8 编码的 Unicode 码点
        void insert_utf8(char32_t cp);

    private:
        // 按键处理子函数（拆分自 handle_key 以满足 Rule 3 函数体 ≤ 120 行）
        auto handle_enter() -> bool;
        auto handle_backspace() -> bool;
        auto handle_delete() -> bool;
        auto handle_arrow_left() -> bool;
        auto handle_arrow_right() -> bool;
        auto handle_home() -> bool;
        auto handle_end() -> bool;
        auto handle_history_prev() -> bool;
        auto handle_history_next() -> bool;
        auto handle_completion() -> bool;

    private:
        std::string buffer_;
        int cursor_{0};
        std::vector<std::string> history_;
        int history_index_{-1};
        completer_fn completer_;
        std::vector<std::string> completions_;
        int completion_index_{-1};
        std::string text_before_completion_;
    };

} // namespace sec::tui
