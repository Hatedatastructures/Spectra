// 输入栏实现 — 命令/对话双模式输入，支持 UTF-8 中文显示

#include <sec/tui/components/input_bar.hpp>
#include <sec/tui/application.hpp>
#include <sec/tui/ai_chat.hpp>
#include <sec/tui/command_registry.hpp>
#include <sec/tui/components/chat_panel.hpp>
#include <sec/tui/event_queue.hpp>

#include <spdlog/spdlog.h>
#include <string>

namespace sec::tui::components
{


    input_bar::input_bar(application &app)
        : app_{app}
    {
        input_.set_completer([this](std::string_view prefix) -> std::vector<std::string>
        {
            return app_.registry().complete(std::string{prefix});
        });
    }


    auto input_bar::paint(Term::Window &win, const panel_rect &rect) -> void
    {
        auto col0 = static_cast<std::size_t>(rect.col);
        auto row0 = static_cast<std::size_t>(rect.row);
        auto max_cols = static_cast<std::size_t>(rect.cols);

        if (row0 < 1 || row0 > static_cast<std::size_t>(win.rows()) || col0 < 1 || max_cols == 0) return;

        auto &th = app_.theme();

        auto limit = col0 + max_cols;
        if (limit > static_cast<std::size_t>(win.columns()) + 1) limit = static_cast<std::size_t>(win.columns()) + 1;

        // 上边框（分隔线）
        for (auto c = col0; c < limit; ++c)
        {
            win.set_char(c, row0, U'─');
            win.set_fg(c, row0, th.border);
        }

        // 输入行
        auto input_row = row0 + 1;
        if (input_row > static_cast<std::size_t>(win.rows())) return;

        auto mode_label = std::string{};
        auto mode_color = th.accent;

        if (mode_ == input_mode::command)
        {
            mode_label = "cmd";
            mode_color = th.success;
        }
        else
        {
            mode_label = "chat";
            mode_color = th.info;
        }

        auto prompt = std::string{"["} + mode_label + "] spectra> ";
        auto pos = col0;

        for (auto i = std::size_t{0}; i < prompt.size() && pos < limit; ++i, ++pos)
        {
            win.set_char(pos, input_row, static_cast<char32_t>(prompt[i]));
            win.set_fg(pos, input_row, mode_color);
            win.set_style(pos, input_row, Term::Style::Bold);
        }

        auto &text = input_.text();
        auto cursor_byte = input_.cursor_pos();

        // 按图元簇（grapheme cluster）渲染，正确处理 emoji 序列和零宽字符
        auto byte_pos = std::size_t{0};
        auto display_col = pos;

        while (byte_pos < text.size() && display_col < limit)
        {
            auto gc = parse_grapheme_cluster(text, byte_pos);
            if (gc.byte_len == 0) break;

            auto wide = gc.width == 2;
            // 宽字符需要 2 列，检查是否越界
            if (wide && display_col + 1 >= limit) break;

            auto is_cursor_pos = (static_cast<int>(byte_pos) == cursor_byte);

            if (is_cursor_pos)
            {
                win.set_char(display_col, input_row, gc.first_cp);
                win.set_fg(display_col, input_row, th.cursor_fg);
                win.set_bg(display_col, input_row, th.cursor_bg);
                if (wide)
                {
                    win.set_char(display_col + 1, input_row, U' ');
                    win.set_fg(display_col + 1, input_row, th.cursor_fg);
                    win.set_bg(display_col + 1, input_row, th.cursor_bg);
                }
            }
            else
            {
                win.set_char(display_col, input_row, gc.first_cp);
                win.set_fg(display_col, input_row, th.body_text);
                if (wide)
                {
                    win.set_char(display_col + 1, input_row, U' ');
                }
            }

            display_col += gc.width;
            byte_pos += gc.byte_len;
        }

        // 光标在文本末尾
        if (cursor_byte == static_cast<int>(text.size()) && display_col < limit)
        {
            win.set_char(display_col, input_row, U' ');
            win.set_fg(display_col, input_row, th.cursor_fg);
            win.set_bg(display_col, input_row, th.cursor_bg);
        }

        // placeholder
        if (text.empty() && pos < limit)
        {
            auto placeholder = std::string{"Type a command or message..."};
            for (auto i = std::size_t{0}; i < placeholder.size() && pos + i < limit; ++i)
            {
                win.set_char(pos + i, input_row, static_cast<char32_t>(placeholder[i]));
                win.set_fg(pos + i, input_row, th.placeholder);
                win.set_style(pos + i, input_row, Term::Style::Dim);
            }
        }
    }


    void input_bar::toggle_mode()
    {
        mode_ = (mode_ == input_mode::command) ? input_mode::chat : input_mode::command;
    }


    auto input_bar::handle_key(const Term::Key &key) -> bool
    {
        auto submitted = input_.handle_key(key);
        if (submitted)
        {
            on_submit();
        }
        return submitted;
    }


    void input_bar::on_submit()
    {
        auto text = input_.text();
        if (text.empty())
        {
            return;
        }

        spdlog::debug("on_submit: text=[{}] ({} bytes)", text, text.size());

        input_.clear();

        if (mode_ == input_mode::command)
        {
            app_.event_queue().push({ui_event_type::chat_system_output, "> " + text});

            auto result = app_.registry().dispatch(text);

            app_.event_queue().push({ui_event_type::chat_system_output, result});
        }
        else
        {
            app_.chat_panel_->add_user_message(text);
            app_.chat_panel_->scroll_to_bottom();

            app_.chat().send(text,
                [this](std::string_view chunk)
                {
                    app_.event_queue().push({ui_event_type::chat_assistant_chunk, std::string{chunk}});
                },
                [this]()
                {
                    app_.event_queue().push({ui_event_type::chat_assistant_done, {}});
                }
            );
        }
    }


} // namespace sec::tui::components
