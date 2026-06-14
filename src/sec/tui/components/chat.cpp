// 对话面板实现 — Markdown 渲染的消息列表，支持流式追加 + 自动滚底

#include <sec/tui/components/chat.hpp>
#include <sec/tui/application.hpp>

#include <mutex>
#include <sstream>
#include <string>

namespace sec::tui::components
{

    namespace
    {
        auto prefix_for_kind(chat_panel::message_entry::type kind, const theme_palette &th) -> std::pair<std::string, Term::Color>
        {
            switch (kind)
            {
            case chat_panel::message_entry::type::user:
                return {"you", th.success};
            case chat_panel::message_entry::type::assistant:
                return {"assistant", th.info};
            case chat_panel::message_entry::type::system:
                return {"system", th.error};
            }
            return {"?", th.accent};
        }
    } // anonymous namespace


    chat_panel::chat_panel(application &app)
        : app_{app}
    {
    }


    void chat_panel::paint(Term::Window &win, const panel_rect &rect)
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};

        if (messages_.empty())
        {
            auto &th = app_.theme();
            auto welcome = styled_document{};
            welcome.push_back({});
            welcome.push_back({styled_segment{"  Welcome to Spectra TUI", th.success, Term::Color::Name::Default, true}});
            welcome.push_back({styled_segment{"  Type 'help' for available commands", th.dim_text, Term::Color::Name::Default, false, true}});
            welcome.push_back({styled_segment{"  Press Ctrl+T to switch between command and chat mode", th.dim_text, Term::Color::Name::Default, false, true}});
            welcome.push_back({});
            terminal_renderer::paint(win, rect.row, rect.col, rect.rows, rect.cols, welcome, 0);
            return;
        }

        auto full_doc = styled_document{};

        auto &th = app_.theme();

        for (auto &msg : messages_)
        {
            if (msg.kind == chat_panel::message_entry::type::user)
            {
                // 用户消息：去掉 "you" 标签，每行加 > 前缀，accent 色
                if (msg.is_streaming)
                {
                    auto ss = std::istringstream{msg.raw_text};
                    auto line = std::string{};
                    while (std::getline(ss, line))
                    {
                        auto sl = styled_line{};
                        sl.emplace_back("> ", th.accent, Term::Color::Name::Default, true);
                        sl.emplace_back(line, th.header_text);
                        full_doc.push_back(std::move(sl));
                    }
                }
                else
                {
                    for (auto &line : msg.rendered)
                    {
                        auto sl = styled_line{};
                        sl.emplace_back("> ", th.accent, Term::Color::Name::Default, true);
                        for (auto &seg : line)
                        {
                            sl.push_back(seg);
                        }
                        full_doc.push_back(std::move(sl));
                    }
                }
            }
            else
            {
                auto [prefix, color] = prefix_for_kind(msg.kind, th);
                full_doc.push_back(styled_line{styled_segment{prefix, color, Term::Color::Name::Default, true}});

                if (msg.is_streaming)
                {
                    if (msg.raw_text.empty())
                    {
                        full_doc.push_back({styled_segment{"▌", th.streaming_cursor}});
                    }
                    else
                    {
                        auto ss = std::istringstream{msg.raw_text};
                        auto line = std::string{};
                        while (std::getline(ss, line))
                        {
                            full_doc.push_back({styled_segment{line, th.body_text}});
                        }
                        if (!full_doc.empty())
                        {
                            full_doc.back().push_back(styled_segment{"▌", th.streaming_cursor});
                        }
                    }
                }
                else
                {
                    for (auto &line : msg.rendered)
                    {
                        full_doc.push_back(line);
                    }
                }
            }

            full_doc.push_back({});
        }

        auto wrapped = wrap_document(full_doc, rect.cols);
        auto total_lines = static_cast<int>(wrapped.size());
        auto max_scroll = std::max(0, total_lines - rect.rows);

        // 自动滚底：如果 offset >= 上次最大滚动值，说明用户没有手动上滚，跟随到底部
        if (auto_scroll_)
        {
            scroll_offset_ = max_scroll;
        }
        else
        {
            scroll_offset_ = std::clamp(scroll_offset_, 0, max_scroll);
            // 用户手动下滚到底时，恢复自动跟随，新消息会继续滚底
            if (scroll_offset_ >= max_scroll) auto_scroll_ = true;
        }

        terminal_renderer::paint(win, rect.row, rect.col, rect.rows, rect.cols, wrapped, scroll_offset_);
    }


    void chat_panel::add_user_message(const std::string &text)
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        auto entry = message_entry{};
        entry.kind = message_entry::type::user;
        entry.raw_text = text;
        entry.rendered = markdown_renderer::render(text, app_.theme());
        messages_.push_back(std::move(entry));
        auto_scroll_ = true;
    }


    void chat_panel::append_assistant(const std::string &chunk)
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};

        if (messages_.empty() ||
            !(messages_.back().kind == message_entry::type::assistant && messages_.back().is_streaming))
        {
            auto entry = message_entry{};
            entry.kind = message_entry::type::assistant;
            entry.is_streaming = true;
            entry.raw_text = chunk;
            messages_.push_back(std::move(entry));
        }
        else
        {
            messages_.back().raw_text += chunk;
        }

        auto_scroll_ = true;
    }


    void chat_panel::finish_assistant()
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        if (!messages_.empty() && messages_.back().kind == message_entry::type::assistant)
        {
            messages_.back().is_streaming = false;
            messages_.back().rendered = markdown_renderer::render(messages_.back().raw_text, app_.theme());
        }
    }


    void chat_panel::add_system_output(const std::string &markdown_text)
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        auto entry = message_entry{};
        entry.kind = message_entry::type::system;
        entry.raw_text = markdown_text;
        entry.rendered = markdown_renderer::render(markdown_text, app_.theme());
        messages_.push_back(std::move(entry));
        auto_scroll_ = true;
    }


    void chat_panel::scroll_to_bottom()
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        auto_scroll_ = true;
    }


    void chat_panel::scroll_up(int lines)
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        if (lines < 1) lines = 1;
        auto_scroll_ = false;
        scroll_offset_ = std::max(0, scroll_offset_ - lines);
    }


    void chat_panel::scroll_down(int lines)
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        if (lines < 1) lines = 1;
        // 不直接重置 auto_scroll_；paint 中检测到滚到底会自动恢复
        scroll_offset_ += lines;
    }


    void chat_panel::page_up()
    {
        scroll_up(10);
    }


    void chat_panel::page_down()
    {
        scroll_down(10);
    }


    void chat_panel::scroll_to_top()
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        auto_scroll_ = false;
        scroll_offset_ = 0;
    }


    void chat_panel::re_render_messages(const theme_palette &theme)
    {
        auto lock = std::lock_guard<std::mutex>{messages_mutex_};
        for (auto &msg : messages_)
        {
            if (!msg.is_streaming && !msg.raw_text.empty())
            {
                msg.rendered = markdown_renderer::render(msg.raw_text, theme);
            }
        }
    }


} // namespace sec::tui::components
