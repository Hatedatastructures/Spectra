/**
 * @file input_bar.hpp
 * @brief 输入栏组件
 * @details 命令/对话双模式输入，支持补全和历史记录。
 */
#pragma once

#include <sec/tui/terminal_renderer.hpp>
#include <sec/tui/text_input.hpp>
#include <sec/tui/layout.hpp>

#include <string>
#include <vector>

namespace sec::tui
{
    class application;
}

namespace sec::tui::components
{
    /**
     * @brief 输入栏
     */
    class input_bar
    {
    public:
        explicit input_bar(application &app);

        auto paint(Term::Window &win, const panel_rect &rect) -> void;
        void toggle_mode();
        auto handle_key(const Term::Key &key) -> bool;

    private:
        void on_submit();

        application &app_;
        text_input input_;

        enum class input_mode : std::uint8_t
        {
            command,
            chat
        };
        input_mode mode_{input_mode::command};
    };

} // namespace sec::tui::components
