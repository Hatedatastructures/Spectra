// 文本输入状态机

#include <sec/tui/text_input.hpp>

#include <cpp-terminal/key.hpp>
#include <spdlog/spdlog.h>

namespace sec::tui
{

    static auto utf8_encode(char32_t cp) -> std::string
    {
        if (cp <= 0x7F)
        {
            return std::string{static_cast<char>(cp)};
        }
        auto out = std::string{};
        if (cp <= 0x7FF)
        {
            out += static_cast<char>(0xC0 | ((cp >> 6) & 0x1F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
        else if (cp <= 0xFFFF)
        {
            out += static_cast<char>(0xE0 | ((cp >> 12) & 0x0F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
        else if (cp <= 0x10FFFF)
        {
            out += static_cast<char>(0xF0 | ((cp >> 18) & 0x07));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
        return out;
    }

    static auto utf8_char_len(const std::string &s, int byte_pos) -> int
    {
        auto byte = static_cast<unsigned char>(s[static_cast<std::size_t>(byte_pos)]);
        if (byte <= 0x7F) return 1;
        if ((byte & 0xE0) == 0xC0) return 2;
        if ((byte & 0xF0) == 0xE0) return 3;
        if ((byte & 0xF8) == 0xF0) return 4;
        return 1;
    }

    static auto utf8_prev_char_len(const std::string &s, int byte_pos) -> int
    {
        if (byte_pos <= 0) return 0;
        // 按图元簇（grapheme cluster）回退：跳过末尾的零宽字符（ZWJ/VS/skin tone 等），
        // 找到主字符的起始字节，整簇一起删除/跨越。
        auto p = byte_pos;
        while (p > 0)
        {
            // 定位前一个 UTF-8 字符的 leading byte
            auto char_start = p - 1;
            while (char_start > 0 && (static_cast<unsigned char>(s[static_cast<std::size_t>(char_start - 1)]) & 0xC0) == 0x80)
            {
                --char_start;
            }

            // 解码该字符的码点
            auto lead = static_cast<unsigned char>(s[static_cast<std::size_t>(char_start)]);
            char32_t cp = lead;
            auto len = 1;
            if (lead <= 0x7F) { cp = lead; len = 1; }
            else if ((lead & 0xE0) == 0xC0) { cp = lead & 0x1F; len = 2; }
            else if ((lead & 0xF0) == 0xE0) { cp = lead & 0x0F; len = 3; }
            else if ((lead & 0xF8) == 0xF0) { cp = lead & 0x07; len = 4; }
            for (auto i = 1; i < len && char_start + i < static_cast<int>(s.size()); ++i)
            {
                cp = (cp << 6) | (static_cast<unsigned char>(s[static_cast<std::size_t>(char_start + i)]) & 0x3F);
            }

            // 零宽字符判断（ZWJ、VS、skin tone、组合标记等）
            auto is_zero = (cp == 0x200D) ||
                           (cp >= 0xFE00 && cp <= 0xFE0F) ||
                           (cp >= 0xE0100 && cp <= 0xE01EF) ||
                           (cp >= 0x1F3FB && cp <= 0x1F3FF) ||
                           (cp >= 0x0300 && cp <= 0x036F) ||
                           cp == 0x200B || cp == 0x200C || cp == 0x200E || cp == 0x200F ||
                           (cp >= 0x202A && cp <= 0x202E) ||
                           (cp >= 0x2060 && cp <= 0x206F) ||
                           cp == 0xFEFF;

            p = char_start;
            if (!is_zero) break;  // 主字符，停止
        }
        return byte_pos - p;
    }

    static auto utf8_display_width(const std::string &s) -> int
    {
        auto width = 0;
        auto i = std::size_t{0};
        while (i < s.size())
        {
            auto byte = static_cast<unsigned char>(s[i]);
            auto len = 1;
            if (byte <= 0x7F) len = 1;
            else if ((byte & 0xE0) == 0xC0) len = 2;
            else if ((byte & 0xF0) == 0xE0) len = 3;
            else if ((byte & 0xF8) == 0xF0) len = 4;

            auto cp = char32_t{0};
            if (len == 1) cp = byte;
            else if (len == 2) cp = ((byte & 0x1F) << 6) | (static_cast<unsigned char>(s[i + 1]) & 0x3F);
            else if (len == 3) cp = ((byte & 0x0F) << 12) | ((static_cast<unsigned char>(s[i + 1]) & 0x3F) << 6) | (static_cast<unsigned char>(s[i + 2]) & 0x3F);
            else cp = ((byte & 0x07) << 18) | ((static_cast<unsigned char>(s[i + 1]) & 0x3F) << 12) | ((static_cast<unsigned char>(s[i + 2]) & 0x3F) << 6) | (static_cast<unsigned char>(s[i + 3]) & 0x3F);

            // CJK 等宽字符占 2 列
            width += (cp >= 0x1100 && (cp <= 0x115F || (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) || (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE10 && cp <= 0xFE19) || (cp >= 0xFE30 && cp <= 0xFE6F) || (cp >= 0xFF01 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6) || (cp >= 0x1F300 && cp <= 0x1F9FF))) ? 2 : 1;
            i += static_cast<std::size_t>(len);
        }
        return width;
    }


    void text_input::insert_utf8(char32_t cp)
    {
        auto encoded = utf8_encode(cp);
        buffer_.insert(static_cast<std::size_t>(cursor_), encoded);
        cursor_ += static_cast<int>(encoded.size());
        completions_.clear();
        completion_index_ = -1;
    }


    auto text_input::handle_key(const Term::Key &key) -> bool
    {
        // 可打印 ASCII
        if (!key.hasCtrlAll() && key.isASCII())
        {
            auto ch = static_cast<char>(key);
            if (ch >= 32 && ch < 127)
            {
                spdlog::debug("text_input: ASCII ch='{}' (0x{:02x})", ch, (unsigned)ch);
                buffer_.insert(static_cast<std::size_t>(cursor_), 1, ch);
                ++cursor_;
                completions_.clear();
                completion_index_ = -1;
                return false;
            }
        }

        // Unicode 可打印字符（中文、日文等非 ASCII）
        auto val = static_cast<std::int32_t>(key);
        if (!key.hasCtrlAll() && val >= 32 && val <= 0x10FFFF && !key.iscntrl())
        {
            spdlog::debug("text_input: Unicode cp=U+{:04X}, buffer before insert: [{}]", (unsigned)val, buffer_);
            insert_utf8(static_cast<char32_t>(val));
            spdlog::debug("text_input: after insert buffer=[{}], cursor={}", buffer_, cursor_);
            return false;
        }

        switch (key)
        {
        case Term::Key::Enter:
        {
            if (!buffer_.empty())
            {
                history_.push_back(buffer_);
                history_index_ = static_cast<int>(history_.size());
            }
            return true;
        }
        case Term::Key::Backspace:
            if (cursor_ > 0)
            {
                auto prev_len = utf8_prev_char_len(buffer_, cursor_);
                buffer_.erase(static_cast<std::size_t>(cursor_ - prev_len), static_cast<std::size_t>(prev_len));
                cursor_ -= prev_len;
            }
            completions_.clear();
            completion_index_ = -1;
            return false;
        case Term::Key::Del:
            if (cursor_ < static_cast<int>(buffer_.size()))
            {
                auto len = utf8_char_len(buffer_, cursor_);
                buffer_.erase(static_cast<std::size_t>(cursor_), static_cast<std::size_t>(len));
            }
            return false;
        case Term::Key::ArrowLeft:
            if (cursor_ > 0)
            {
                cursor_ -= utf8_prev_char_len(buffer_, cursor_);
            }
            return false;
        case Term::Key::ArrowRight:
            if (cursor_ < static_cast<int>(buffer_.size()))
            {
                cursor_ += utf8_char_len(buffer_, cursor_);
            }
            return false;
        case Term::Key::Home:
            cursor_ = 0;
            return false;
        case Term::Key::End:
            cursor_ = static_cast<int>(buffer_.size());
            return false;
        case Term::Key::ArrowUp:
            if (history_index_ > 0)
            {
                --history_index_;
                buffer_ = history_[static_cast<std::size_t>(history_index_)];
                cursor_ = static_cast<int>(buffer_.size());
            }
            return false;
        case Term::Key::ArrowDown:
            if (history_index_ < static_cast<int>(history_.size()) - 1)
            {
                ++history_index_;
                buffer_ = history_[static_cast<std::size_t>(history_index_)];
                cursor_ = static_cast<int>(buffer_.size());
            }
            else if (history_index_ == static_cast<int>(history_.size()) - 1)
            {
                history_index_ = static_cast<int>(history_.size());
                buffer_.clear();
                cursor_ = 0;
            }
            return false;
        case Term::Key::Tab:
            if (completer_)
            {
                if (completions_.empty())
                {
                    text_before_completion_ = buffer_;
                    completions_ = completer_(buffer_);
                    completion_index_ = 0;
                }
                else
                {
                    ++completion_index_;
                    if (completion_index_ >= static_cast<int>(completions_.size()))
                    {
                        completion_index_ = 0;
                    }
                }
                if (!completions_.empty())
                {
                    buffer_ = completions_[static_cast<std::size_t>(completion_index_)];
                    cursor_ = static_cast<int>(buffer_.size());
                }
            }
            return false;
        default:
            return false;
        }
    }


    auto text_input::text() const -> const std::string &
    {
        return buffer_;
    }

    auto text_input::cursor_pos() const -> int
    {
        return cursor_;
    }

    void text_input::clear()
    {
        buffer_.clear();
        cursor_ = 0;
        completions_.clear();
        completion_index_ = -1;
    }

    void text_input::set_text(std::string t)
    {
        buffer_ = std::move(t);
        cursor_ = static_cast<int>(buffer_.size());
    }

    void text_input::set_completer(completer_fn fn)
    {
        completer_ = std::move(fn);
    }

} // namespace sec::tui
