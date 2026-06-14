/**
 * @file chat_panel.hpp
 * @brief 对话面板组件
 * @details 显示 AI 对话消息列表，支持流式输出和 Markdown 渲染。
 */
#pragma once

#include <sec/tui/terminal.hpp>
#include <sec/tui/markdown.hpp>
#include <sec/tui/layout.hpp>

#include <mutex>
#include <string>
#include <vector>

namespace sec::tui
{
    class application;
}

namespace sec::tui::components
{
    /**
     * @brief 对话面板
     */
    class chat_panel
    {
    public:
        explicit chat_panel(application &app);

        void paint(Term::Window &win, const panel_rect &rect);

        void add_user_message(const std::string &text);
        void append_assistant(const std::string &chunk);
        void finish_assistant();
        void add_system_output(const std::string &markdown_text);

        void scroll_to_bottom();
        void scroll_up(int lines = 1);
        void scroll_down(int lines = 1);
        void page_up();
        void page_down();
        void scroll_to_top();
        void re_render_messages(const theme_palette &theme);

        struct message_entry
        {
            enum class type : std::uint8_t { user, assistant, system } kind;
            std::string raw_text;
            styled_document rendered;
            bool is_streaming{false};
        };

    private:
        application &app_;
        std::vector<message_entry> messages_;
        std::mutex messages_mutex_;
        int scroll_offset_{0};
        bool auto_scroll_{true};
    };

} // namespace sec::tui::components
